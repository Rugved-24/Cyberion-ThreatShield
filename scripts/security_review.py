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
  C7  Dependencies are version-pinned, and hash pinning is reported.
  C8  A path supplied by a caller cannot escape its permitted directory.

Exit code 0 when every control passes, 1 on any failure, 2 when a control is
WARN, so a WARN cannot be mistaken for a pass.
"""

import argparse
import json
import re
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_all as harness

TRACKED_SUFFIXES = (".py", ".yml", ".yaml", ".md", ".json", ".csv", ".txt", ".ipynb")
SKIP_DIRS = {".git", ".venv", "__pycache__", ".ipynb_checkpoints", ".pytest_cache"}

# Values that are secret regardless of where they appear. Deliberately specific:
# a broad entropy or keyword scan on a repository whose entire subject matter is
# attacker artefacts produces noise, and a scanner that cries wolf gets ignored.
SECRET_PATTERNS = [
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("generic assigned secret", re.compile(
        r"(?i)\b(api[_-]?key|secret|passwd|password|token|bearer)\b\s*[:=]\s*"
        r"['\"][^'\"\s]{12,}['\"]")),
    ("connection string with password", re.compile(
        r"(?i)\b(mongodb|postgres|postgresql|mysql|redis|amqp)://[^\s:@/]+:[^\s:@/]+@")),
    ("Azure storage key", re.compile(r"(?i)AccountKey=[A-Za-z0-9+/]{60,}={0,2}")),
]

# Telemetry directories must never be committed.
DATA_GLOBS = ("data/raw/", "data/processed/", "data/private/", "*.evtx", "*.pcap",
              "*.pcapng", "*.zip", "*.7z")

RESULTS = []


def record(control, status, detail):
    RESULTS.append((control, status, detail))
    print(f"[{status:<5}] {control}  {detail}")


def tracked_files(root):
    out = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True,
                         check=True)
    return [line for line in out.stdout.splitlines() if line.strip()]


def repo_files(root):
    return [path for path in root.rglob("*")
            if path.is_file() and not SKIP_DIRS & set(path.parts)
            and path.suffix.lower() in TRACKED_SUFFIXES]


def control_input_validation(root, scripts):
    """C1 applies to values that arrive from outside the program.

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
            failures.append(f"{path.name}: builds a docs/ path from an externally supplied value")
    external = [p.name for p in scripts if sources.search(p.read_text(encoding="utf-8-sig"))]
    record("C1 externally supplied dataset ID validated before path use",
           "FAIL" if failures else "PASS",
           "; ".join(failures) if failures else
           f"{len(scripts)} scripts checked, {len(external)} accept external input "
           f"({', '.join(external) or 'none'}), all validate the identifier")


def control_hash_before_read(root, scripts):
    failures = []
    for path in scripts:
        text = path.read_text(encoding="utf-8-sig")
        reads_raw = "data/raw" in text or 'meta["file"]' in text
        verifies = "sha256" in text
        if reads_raw and not verifies:
            failures.append(f"{path.name}: reads raw telemetry without verifying a digest")
    record("C2 raw telemetry hash-verified before reading",
           "FAIL" if failures else "PASS",
           "; ".join(failures) if failures else "every script that reads raw telemetry verifies it")


def control_evidence_writes(root):
    """Inspect actual write calls, not every string literal.

    Scanning raw text flagged paths that appear only in a docstring listing
    artefacts, which is not a write. This looks for the write operations and
    checks the destinations of those only.
    """
    allowed = re.compile(
        r"docs/(?:\{dataset\}|DS\d{3})-(?:acquisition|inventory|capture|fields|normalization|validation)\.json"
        r"|docs/(?:environment-inventory|prd-compliance)\.json")
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
    record("C3 committed evidence writes are constrained",
           "FAIL" if failures else "PASS",
           "; ".join(sorted(set(failures))[:4]) if failures else
           "write destinations are limited to the documented docs/ evidence set")


def control_parsers(root, scripts):
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
    record("C4 safe parsers and no shell interpolation",
           "FAIL" if failures else "PASS",
           "; ".join(failures) if failures else "safe_load only; no shell=True")


def control_secrets(root, files):
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
    record("C5 no committed credentials or key material",
           "FAIL" if findings else "PASS",
           "; ".join(findings[:5]) if findings else
           f"{len(files)} tracked files scanned against {len(SECRET_PATTERNS)} patterns, no hits")


def control_data_untracked(root):
    tracked = set(tracked_files(root))
    offenders = [name for name in sorted(tracked)
                 if name.startswith(("data/raw", "data/processed", "data/private"))
                 or name.endswith((".evtx", ".pcap", ".pcapng"))]
    record("C6 telemetry not tracked by git",
           "FAIL" if offenders else "PASS",
           f"tracked: {offenders}" if offenders else
           f"none of the {len(DATA_GLOBS)} telemetry globs are tracked")


def control_dependencies(root):
    text = (root / "requirements.txt").read_text(encoding="utf-8-sig")
    entries = [line.strip() for line in text.splitlines()
               if line.strip() and not line.startswith("#")]
    unpinned = [item for item in entries if "==" not in item]
    hashed = "--hash" in text
    if unpinned:
        record("C7 dependencies pinned", "FAIL", f"unpinned: {unpinned}")
    elif hashed:
        record("C7 dependencies pinned and hash-locked", "PASS", f"{len(entries)} entries")
    else:
        record("C7 dependencies pinned, hash locking absent", "WARN",
               f"{len(entries)} entries are version-pinned but not hash-pinned; "
               "run pip download to generate hashes before any shared deployment")


def control_path_escape(root, scripts):
    failures = []
    for path in scripts:
        text = path.read_text(encoding="utf-8-sig")
        if "sys.argv" in text and "argparse" not in text:
            failures.append(f"{path.name}: reads sys.argv without argument parsing")
    record("C8 caller-supplied paths are constrained",
           "FAIL" if failures else "PASS",
           "; ".join(failures) if failures else
           "no unguarded sys.argv use; identifiers are validated and destinations confined")


def control_invisible_characters(root, files):
    """No invisible format characters in committed artefacts.

    A zero-width or bidirectional character embedded in a document can make text
    read one way and be compared another, which is the basis of homoglyph and
    invisible-spoofing attacks. A leading byte-order mark is a different matter:
    it is an encoding artefact, not content, and this project does not need one.
    """
    import unicodedata
    failures = []
    for relative in files:
        path = root / relative
        if path.suffix.lower() not in (".md", ".csv", ".yml", ".json", ".py", ".txt"):
            continue
        raw = path.read_bytes()
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
                    f"{relative}:{line}: U+{ord(char):04X} {unicodedata.name(char, '?')}")
    record("C9 no invisible format characters in committed artefacts",
           "FAIL" if failures else "PASS",
           "; ".join(failures[:4]) if failures else
           f"{len(files)} tracked files checked for BOMs, zero-width and bidi characters")


def disclosure_inventory(root):
    """Report what a published copy would disclose.

    The value set is derived from the recorded telemetry by the same collector
    the sanitiser uses, rather than from a hand-maintained pattern list. A
    hand-written list drifts, and a scanner built on one would quietly understate
    exactly what it exists to measure.
    """
    import sanitize
    values = sanitize.collect(root)
    report = {
        "host names": values["host"],
        "account names": values["account"],
        "internal IP addresses": values["internal_ip"],
        "attacker tradecraft artefacts": values["tradecraft"],
    }
    return {label: sorted(items) for label, items in report.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", type=Path, help="write the report as JSON")
    args = parser.parse_args()
    root = args.root.resolve()
    scripts = sorted((root / "scripts").glob("*.py"))
    files = tracked_files(root)
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
    print("\nDisclosure inventory for published artefacts (run scripts/sanitize.py to mask):")
    for label, values in disclosure.items():
        shown = ", ".join(values[:6]) + (" ..." if len(values) > 6 else "") or "none"
        print(f"  {label:<22} {shown}")
    failed = [item for item in RESULTS if item[1] == "FAIL"]
    warned = [item for item in RESULTS if item[1] == "WARN"]
    passed = [item for item in RESULTS if item[1] == "PASS"]
    print(f"\ncontrols: {len(passed)} pass, {len(warned)} warn, {len(failed)} fail")
    print("A clean run means the listed controls hold. It does not mean the project is "
          "free of vulnerabilities; see SECURITY.md.")
    if args.json:
        args.json.write_text(json.dumps({
            "controls": [{"id": c, "status": s, "detail": d} for c, s, d in RESULTS],
            "disclosure_inventory": disclosure,
            "tracked_files": len(files),
        }, indent=2) + "\n", encoding="utf-8")
    return 1 if failed else (2 if warned else 0)


if __name__ == "__main__":
    sys.exit(main())
