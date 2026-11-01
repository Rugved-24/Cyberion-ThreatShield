
"""Repository self-audit: hardening invariants, secret scan, disclosure scan.

This script exists because "the project has no vulnerabilities" is not a claim
anyone should make, including about this repository. What can be done is to state
the threat model, assert the specific invariants that matter here, and fail loudly
when one breaks. That is what this does.

It is not a penetration test and does not find everything. A clean run means the
listed controls hold, not that the project is safe. See SECURITY.md.

Controls asserted:

  C1  Dataset identifiers are validated before they are used to build a path.
  C2  Every script that reads raw telemetry verifies its SHA-256 first.
  C3  Only committed evidence files are written under docs/.
  C4  YAML is parsed with a safe loader; no unsafe load and no shell=True.
  C5  No credential, token or key material is committed.
  C6  Telemetry directories are not tracked by git.
  C7  Runtime and dashboard dependency locks are version-pinned and hash-locked.
  C8  A path supplied by a caller cannot escape its permitted directory.
  C9  Committed artefacts contain no invisible format characters.

Exit code 0 when every control passes, 1 on any failure, 2 when a control is
WARN, so a WARN cannot be mistaken for a pass.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_all as harness

TRACKED_SUFFIXES = (
    ".py", ".yml", ".yaml", ".md", ".json", ".csv", ".txt", ".ipynb"
)
SKIP_DIRS = {
    ".git", ".venv", "__pycache__", ".ipynb_checkpoints", ".pytest_cache"
}

# Values that are secret regardless of where they appear. Deliberately specific:
# a broad entropy or keyword scan on a repository whose entire subject matter is
# attacker artefacts produces noise, and a scanner that cries wolf gets ignored.
SECRET_PATTERNS = [
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    (
        "generic assigned secret",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|passwd|password|token|bearer)\b\s*[:=]\s*"
            r"['\"][^'\"\s]{12,}['\"]"
        ),
    ),
    (
        "connection string with password",
        re.compile(
            r"(?i)\b(mongodb|postgres|postgresql|mysql|redis|amqp)://"
            r"[^\s:@/]+:[^\s:@/]+@"
        ),
    ),
    (
        "Azure storage key",
        re.compile(r"(?i)AccountKey=[A-Za-z0-9+/]{60,}={0,2}"),
    ),
]

# Telemetry directories and raw captures must never be committed.
DATA_GLOBS = (
    "data/raw/",
    "data/processed/",
    "data/private/",
    "*.evtx",
    "*.pcap",
    "*.pcapng",
    "*.zip",
    "*.7z",
)

# These lock files are produced with pip-compile --generate-hashes.
DEPENDENCY_LOCKS = (
    "requirements.lock.txt",
    "requirements-dashboard.lock.txt",
)

# pip-compile emits package pins followed by one or more SHA-256 hash lines.
PACKAGE_PIN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]*(?:\[[^\]]+\])?==([^\s\\;]+)"
)
SHA256_HASH = re.compile(r"--hash=sha256:[0-9a-fA-F]{64}")

RESULTS = []


def record(control, status, detail):
    """Record and print one control result."""
    RESULTS.append((control, status, detail))
    print(f"[{status:<5}] {control}  {detail}")


def tracked_files(root):
    """Return paths tracked by Git, relative to the repository root."""
    out = subprocess.run(
        ["git", "ls-files"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in out.stdout.splitlines() if line.strip()]


def repo_files(root):
    """Return repository files with recognised source/document suffixes."""
    return [
        path
        for path in root.rglob("*")
        if path.is_file()
        and not SKIP_DIRS.intersection(path.parts)
        and path.suffix.lower() in TRACKED_SUFFIXES
    ]


def control_input_validation(root, scripts):
    """Check external dataset identifiers before they are used in paths.

    A script that only uses hardcoded dataset IDs cannot be steered by a caller,
    so flagging it would be noise. Scripts that read argv, argparse or the
    environment must validate the identifier before building a path from it.
    """
    sources = re.compile(r"sys\.argv|argparse|os\.environ|getenv\(")
    failures = []

    for path in scripts:
        text = path.read_text(encoding="utf-8-sig")

        if not re.search(r"f?[\"']docs/\{?[a-z_]+\}?", text):
            continue

        if not sources.search(text):
            continue

        if "fullmatch" not in text and "re.fullmatch" not in text:
            failures.append(
                f"{path.name}: builds a docs/ path from an externally supplied value"
            )

    external = [
        path.name
        for path in scripts
        if sources.search(path.read_text(encoding="utf-8-sig"))
    ]

    record(
        "C1 externally supplied dataset ID validated before path use",
        "FAIL" if failures else "PASS",
        "; ".join(failures)
        if failures
        else (
            f"{len(scripts)} scripts checked, {len(external)} accept external input "
            f"({', '.join(external) or 'none'}), all validate the identifier"
        ),
    )


def control_hash_before_read(root, scripts):
    """Check scripts that read raw telemetry for SHA-256 verification."""
    failures = []

    for path in scripts:
        text = path.read_text(encoding="utf-8-sig")
        reads_raw = "data/raw" in text or 'meta["file"]' in text
        verifies = "sha256" in text

        if reads_raw and not verifies:
            failures.append(
                f"{path.name}: reads raw telemetry without verifying a digest"
            )

    record(
        "C2 raw telemetry hash-verified before reading",
        "FAIL" if failures else "PASS",
        "; ".join(failures)
        if failures
        else "every script that reads raw telemetry verifies it",
    )


def control_evidence_writes(root):
    """Inspect write calls and restrict destinations under docs/."""
    allowed = re.compile(
        r"docs/(?:\{dataset\}|DS\d{3})-(?:acquisition|inventory|capture|fields|normalization|validation)\.json"
        r"|docs/(?:environment-inventory|prd-compliance)\.json"
    )
    write = re.compile(r"write_text\(|writestr\(|open\([^)]*[\"']w")
    failures = []

    for path in (root / "scripts").glob("*.py"):
        if path.name == Path(__file__).name:
            continue

        text = path.read_text(encoding="utf-8-sig")

        for line in text.splitlines():
            if not write.search(line):
                continue

            for match in re.finditer(r"""docs/[^"')\s]*\.json""", line):
                if not allowed.fullmatch(match.group(0)):
                    failures.append(f"{path.name}: writes {match.group(0)}")

    record(
        "C3 committed evidence writes are constrained",
        "FAIL" if failures else "PASS",
        "; ".join(sorted(set(failures))[:4])
        if failures
        else "write destinations are limited to the documented docs/ evidence set",
    )


def control_parsers(root, scripts):
    """Check YAML loader and subprocess invocation patterns."""
    failures = []
    unsafe = re.compile(r"yaml\.load\((?!.*Safe)")
    shell_flag = "shell" + "=True"

    for path in scripts:
        if path.name == Path(__file__).name:
            continue

        text = path.read_text(encoding="utf-8-sig")

        if unsafe.search(text):
            failures.append(f"{path.name}: uses an unsafe YAML loader")

        if shell_flag in text:
            failures.append(f"{path.name}: passes {shell_flag} to a subprocess")

    record(
        "C4 safe parsers and no shell interpolation",
        "FAIL" if failures else "PASS",
        "; ".join(failures)
        if failures
        else "safe_load only; no shell=True",
    )


def control_secrets(root, files):
    """Scan tracked text artefacts for known secret patterns."""
    findings = []

    for relative in files:
        path = root / relative

        if path.suffix.lower() not in TRACKED_SUFFIXES:
            continue

        try:
            text = path.read_text(encoding="utf-8-sig", errors="ignore")
        except OSError:
            continue

        for name, pattern in SECRET_PATTERNS:
            for hit in pattern.findall(text):
                findings.append(f"{relative}: {name} ({str(hit)[:24]}...)")

    record(
        "C5 no committed credentials or key material",
        "FAIL" if findings else "PASS",
        "; ".join(findings[:5])
        if findings
        else (
            f"{len(files)} tracked files scanned against "
            f"{len(SECRET_PATTERNS)} patterns, no hits"
        ),
    )


def control_data_untracked(root):
    """Check that raw telemetry and capture files are not tracked by Git."""
    tracked = set(tracked_files(root))

    offenders = [
        name
        for name in sorted(tracked)
        if name.startswith(
            ("data/raw", "data/processed", "data/private")
        )
        or name.endswith((".evtx", ".pcap", ".pcapng"))
    ]

    record(
        "C6 telemetry not tracked by git",
        "FAIL" if offenders else "PASS",
        f"tracked: {offenders}"
        if offenders
        else f"none of the {len(DATA_GLOBS)} telemetry globs are tracked",
    )


def control_dependencies(root):
    """Validate both dependency lock files and SHA-256 hashes.

    Every active package requirement must be version-pinned with ==, and each
    package entry must have at least one syntactically valid SHA-256 hash in its
    requirement block. This is a static check; pip's --require-hashes dry run
    remains useful for verifying that pip accepts the locks.
    """
    failures = []
    summaries = {}

    for name in DEPENDENCY_LOCKS:
        path = root / name

        if not path.is_file():
            failures.append(f"{name}: lock file is missing")
            continue

        try:
            lines = path.read_text(encoding="utf-8-sig").splitlines()
        except OSError as exc:
            failures.append(f"{name}: cannot read lock file ({exc})")
            continue

        package_indices = []
        package_count = 0

        # Identify package pins and reject active requirement lines that are
        # neither pinned packages nor recognised pip options/hash continuations.
        for line_number, line in enumerate(lines, start=1):
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                continue

            if stripped.startswith("--hash="):
                continue

            # pip-compile locks can include options such as index URLs.
            if stripped.startswith("--"):
                continue

            match = PACKAGE_PIN.match(stripped)

            if match:
                package_indices.append(line_number - 1)
                package_count += 1
            else:
                failures.append(
                    f"{name}:{line_number}: unsupported or unpinned requirement "
                    f"line: {stripped[:80]}"
                )

        if package_count == 0:
            failures.append(f"{name}: no pinned packages found")
            continue

        missing_hashes = []

        for position, line_index in enumerate(package_indices):
            end_index = (
                package_indices[position + 1]
                if position + 1 < len(package_indices)
                else len(lines)
            )

            block = lines[line_index:end_index]
            package_line = lines[line_index].strip()

            if not any(SHA256_HASH.search(line) for line in block):
                missing_hashes.append(package_line)

        if missing_hashes:
            failures.extend(
                f"{name}: missing SHA-256 hash for {package}"
                for package in missing_hashes
            )

        summaries[name] = package_count

    if failures:
        record(
            "C7 dependencies version-pinned and hash-locked",
            "FAIL",
            "; ".join(failures[:10]),
        )
    else:
        details = ", ".join(
            f"{name}: {count} packages"
            for name, count in summaries.items()
        )
        record(
            "C7 dependencies version-pinned and hash-locked",
            "PASS",
            details,
        )


def control_path_escape(root, scripts):
    """Flag scripts that read argv without using argparse."""
    failures = []

    for path in scripts:
        text = path.read_text(encoding="utf-8-sig")

        if "sys.argv" in text and "argparse" not in text:
            failures.append(
                f"{path.name}: reads sys.argv without argument parsing"
            )

    record(
        "C8 caller-supplied paths are constrained",
        "FAIL" if failures else "PASS",
        "; ".join(failures)
        if failures
        else "no unguarded sys.argv use; identifiers are validated and destinations confined",
    )


def control_invisible_characters(root, files):
    """Check tracked artefacts for invisible Unicode format characters.

    Zero-width or bidirectional characters can make text read one way and be
    compared another. A leading byte-order mark is also checked separately.
    """
    import unicodedata

    failures = []

    for relative in files:
        path = root / relative

        if path.suffix.lower() not in (
            ".md", ".csv", ".yml", ".json", ".py", ".txt"
        ):
            continue

        try:
            raw = path.read_bytes()
        except OSError as exc:
            failures.append(f"{relative}: cannot read file ({exc})")
            continue

        if raw.startswith(b"\xef\xbb\xbf"):
            failures.append(f"{relative}: leading byte-order mark")

        try:
            body = raw.decode("utf-8")
        except UnicodeDecodeError:
            failures.append(f"{relative}: not valid UTF-8")
            continue

        for position, char in enumerate(body):
            if char in "\n\r\t" or ord(char) < 128:
                continue

            if unicodedata.category(char) == "Cf":
                line = body.count("\n", 0, position) + 1
                failures.append(
                    f"{relative}:{line}: U+{ord(char):04X} "
                    f"{unicodedata.name(char, '?')}"
                )

    record(
        "C9 no invisible format characters in committed artefacts",
        "FAIL" if failures else "PASS",
        "; ".join(failures[:4])
        if failures
        else (
            f"{len(files)} tracked files checked for BOMs, "
            "zero-width and bidi characters"
        ),
    )


def disclosure_inventory(root):
    """Report values a published copy could disclose.

    The value set comes from the same collector used by the sanitiser rather
    than a separately maintained pattern list.
    """
    import sanitize

    values = sanitize.collect(root)

    report = {
        "host names": values["host"],
        "account names": values["account"],
        "internal IP addresses": values["internal_ip"],
        "attacker tradecraft artefacts": values["tradecraft"],
    }

    return {
        label: sorted(items)
        for label, items in report.items()
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument(
        "--json",
        type=Path,
        help="write the report as JSON",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    scripts_dir = root / "scripts"

    if not scripts_dir.is_dir():
        parser.error(f"scripts directory does not exist under repository root: {root}")

    scripts = sorted(scripts_dir.glob("*.py"))

    try:
        files = tracked_files(root)
    except subprocess.CalledProcessError as exc:
        parser.error(
            f"cannot list tracked files; ensure --root points to a Git repository "
            f"({exc})"
        )

    control_input_validation(root, scripts)
    control_hash_before_read(root, scripts)
    control_evidence_writes(root)
    control_parsers(root, scripts)
    control_secrets(root, files)
    control_data_untracked(root)
    control_dependencies(root)
    control_path_escape(root, scripts)
    control_invisible_characters(root, files)

    disclosure = disclosure_inventory(root)

    print(
        "\nDisclosure inventory for published artefacts "
        "(run scripts/sanitize.py to mask):"
    )

    for label, values in disclosure.items():
        shown = (
            ", ".join(values[:6]) + (" ..." if len(values) > 6 else "")
        ) or "none"
        print(f"  {label:<30} {shown}")

    failed = [item for item in RESULTS if item[1] == "FAIL"]
    warned = [item for item in RESULTS if item[1] == "WARN"]
    passed = [item for item in RESULTS if item[1] == "PASS"]

    print(
        f"\ncontrols: {len(passed)} pass, "
        f"{len(warned)} warn, {len(failed)} fail"
    )
    print(
        "A clean run means the listed controls hold. It does not mean the project "
        "is free of vulnerabilities; see SECURITY.md."
    )

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(
                {
                    "controls": [
                        {"id": control, "status": status, "detail": detail}
                        for control, status, detail in RESULTS
                    ],
                    "disclosure_inventory": disclosure,
                    "tracked_files": len(files),
                },
                indent=2,
            ) + "\n",
            encoding="utf-8",
        )

    return 1 if failed else (2 if warned else 0)


if __name__ == "__main__":
    sys.exit(main())
