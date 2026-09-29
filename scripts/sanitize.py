"""Produce a publishable copy with sensitive values masked and evidence intact.

The point of this script is that a redacted copy must still be auditable. So it
masks values, not references:

- Masked: host names, account names, internal IP addresses, and attacker
  tradecraft strings. These come from the recorded telemetry, not from a
  hand-written list, so nothing is missed and nothing is invented.
- Preserved: every event UID of the form dataset:raw_sha256:line, the dataset
  digests, ATT&CK technique IDs, rule IDs, match counts, window matrices and
  every conclusion. The audit trail is the deliverable; masking it would destroy
  the work rather than protect it.

The mapping from pseudonym to real value is not stored. Each masked value is
written to a manifest as an HMAC-SHA256 keyed with a salt supplied by the
operator, so an authorised holder of the salt can confirm that
``ACCT-01`` in the published copy is the same account as the one in the
unredacted repository, while a reader of the published copy cannot recover it.

Originals are never modified. Output goes to a separate directory.

    python scripts/sanitize.py --out ../Cyberion-ThreatShield-public
    CYBERION_REDACTION_KEY=... python scripts/sanitize.py --verify out/
"""

import argparse
import csv
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_all as harness

ROOT = Path(__file__).resolve().parents[1]
PUBLISHABLE_SUFFIXES = {".md", ".csv", ".yml", ".json", ".txt"}
EXCLUDE_PREFIXES = ("references/", "data/", "coverage/baseline.json")
EXCLUDE_NAMES = {".gitignore", ".gitattributes", "requirements.txt"}
# Never rewrite these: they are evidence or configuration whose meaning depends
# on byte content, and none of them carry client-identifying values.
KEEP_EXACT = {
    "docs/DS001-inventory.json", "docs/DS002-inventory.json",
    "docs/DS001-capture.json", "docs/DS002-capture.json",
    "docs/DS001-acquisition.json", "docs/DS002-acquisition.json",
    "docs/DS001-normalization.json", "docs/DS002-normalization.json",
    "docs/DS001-validation.json", "docs/DS002-validation.json",
    "docs/DS001-fields.json", "docs/DS002-fields.json",
    "coverage/layer-v2.json", "coverage/baseline.json",
    "requirements.txt", ".gitattributes", ".gitignore",
}
NETWORK_FIELDS = ("SourceAddress", "DestAddress", "SourceIp", "DestinationIp",
                  "SourcePort", "DestinationPort")
ACCOUNT_FIELDS = ("SubjectUserName", "TargetUserName", "User")
# Attacker artefacts that some organisations will not want republished even
# though the dataset is public. Selected by inspecting the recorded script text.
TRADECRAFT = ("uoSWohnlCYlf=PFjN1Hpr2N7bafecwW/GboSMzg4=",
              "0]rX3Y4:()JchAKkR7Vg+[/Up92tmGQv")


def internal_ip(value):
    if not isinstance(value, str):
        return False
    parts = value.split(".")
    if len(parts) != 4 or not all(part.isdigit() for part in parts):
        return False
    octets = [int(part) for part in parts]
    if not all(0 <= octet <= 255 for octet in octets):
        return False
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    return octets[0] == 169 and octets[1] == 254


def collect(root):
    """Derive the sensitive value set from the recorded telemetry.

    The dataset identifiers are fixed here rather than supplied by a caller, and
    are still validated so that C1 holds uniformly across the scripts.
    """
    hosts, accounts, addresses = set(), set(), set()
    for dataset in ("DS001", "DS002"):
        if not re.fullmatch(r"DS\d{3}", dataset):
            raise ValueError(f"{dataset}: dataset ID must use the form DS001")
        capture = root / f"docs/{dataset}-capture.json"
        if capture.exists():
            hosts.update(json.loads(capture.read_text(encoding="utf-8")).get("hosts", {}))
    for path in sorted((root / "data/processed").glob("DS*.jsonl")):
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                event = json.loads(line)
                raw = event.get("raw") or {}
                hosts.add(event.get("host"))
                for field in ACCOUNT_FIELDS:
                    value = raw.get(field) or event.get("subject_user") or event.get("target_user")
                    if isinstance(value, str) and value not in ("-", "SYSTEM", "ANONYMOUS LOGON",
                                                                "LOCAL SERVICE", "NETWORK SERVICE"):
                        accounts.add(value)
                for field in NETWORK_FIELDS:
                    if internal_ip(raw.get(field)):
                        addresses.add(raw[field])
    hosts.discard(None)
    accounts.discard(None)
    addresses.discard(None)
    return {
        "host": sorted(hosts, key=lambda value: (-len(value), value)),
        "account": sorted(accounts, key=lambda value: (-len(value), value)),
        "internal_ip": sorted(addresses, key=lambda value: (-len(value), value)),
        "tradecraft": list(TRADECRAFT),
    }


def build_map(values, prefix):
    """Assign pseudonyms in a fully deterministic order.

    Sorting on length alone is not enough: equal-length values would fall back to
    set iteration order, which varies between runs because string hashing is
    randomised. The secondary sort on the value itself makes the manifest
    reproducible, and reproducible pseudonym assignment is what lets --verify
    mean anything.
    """
    mapping = {}
    for index, value in enumerate(values, 1):
        mapping[value] = f"{prefix}-{index:02d}"
    return mapping


def pseudonymise(root):
    values = collect(root)
    mapping = {}
    for category, items in values.items():
        prefix = {"host": "HOST", "account": "ACCT", "internal_ip": "IP",
                  "tradecraft": "ARTIFACT"}[category]
        ordered = sorted(items, key=lambda value: (-len(value), value))
        mapping.update(build_map(ordered, prefix))
    # Longest first so WORKSTATION6.theshire.local is masked before WORKSTATION6.
    ordered = sorted(mapping, key=lambda value: (-len(value), value))
    return mapping, ordered


def manifest_rows(mapping, key):
    rows = []
    for value, pseudonym in sorted(mapping.items(), key=lambda item: item[1]):
        digest = hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
        rows.append({"pseudonym": pseudonym, "hmac_sha256": digest,
                     "value_length": len(value)})
    return rows


def transform(text, ordered, mapping):
    for value in ordered:
        text = text.replace(value, mapping[value])
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--verify", type=Path,
                        help="re-derive a manifest from an output copy and compare")
    args = parser.parse_args()
    root = args.root.resolve()
    out = args.out.resolve()
    if out == root or root in out.parents and out.name == root.name:
        raise SystemExit("Refusing to write the sanitised copy over the repository.")
    key_material = os.environ.get("CYBERION_REDACTION_KEY")
    generated = False
    if not key_material:
        key_material = secrets.token_hex(32)
        generated = True
    key = key_material.encode("utf-8")

    mapping, ordered = pseudonymise(root)
    counts = {}
    for value in mapping.values():
        counts[value.split("-")[0]] = counts.get(value.split("-")[0], 0) + 1

    if args.verify:
        existing = args.verify / "redaction-manifest.csv"
        if not existing.exists():
            raise SystemExit(f"{existing} not found")
        previous = {row["pseudonym"]: row["hmac_sha256"]
                    for row in csv.DictReader(existing.open(encoding="utf-8"))}
        current = {row["pseudonym"]: row["hmac_sha256"] for row in manifest_rows(mapping, key)}
        if previous == current:
            print(f"verify OK: {len(current)} pseudonyms match the manifest")
            return 0
        print("verify FAILED: manifest does not match. The key or the values changed.",
              file=sys.stderr)
        return 1

    out.mkdir(parents=True, exist_ok=True)
    written = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if path.suffix.lower() not in PUBLISHABLE_SUFFIXES:
            continue
        if relative in KEEP_EXACT or relative in EXCLUDE_NAMES:
            continue
        if any(relative.startswith(prefix) for prefix in EXCLUDE_PREFIXES):
            continue
        if any(part in {".git", ".venv", "__pycache__", ".ipynb_checkpoints"} for part in path.parts):
            continue
        original = path.read_text(encoding="utf-8", errors="ignore")
        redacted = transform(original, ordered, mapping)
        destination = out / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(redacted, encoding="utf-8", newline="\n")
        written += 1

    manifest = out / "redaction-manifest.csv"
    with manifest.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["pseudonym", "hmac_sha256", "value_length"])
        writer.writeheader()
        writer.writerows(manifest_rows(mapping, key))
    readme = out / "REDACTION-NOTICE.md"
    readme.write_text(
        "# Redacted copy\n\n"
        "This copy masks host names, account names, internal IP addresses and two\n"
        "attacker tradecraft strings. Every event UID, dataset digest, ATT&CK technique\n"
        "ID, rule ID, match count and conclusion is preserved, so the audit trail can\n"
        "still be checked against the recordings.\n\n"
        "`redaction-manifest.csv` records an HMAC-SHA256 of each masked value, keyed with\n"
        "a salt held by the author. With that salt, a holder can confirm a pseudonym maps\n"
        "to the original value. Without it, the mapping cannot be recovered.\n\n"
        "The salt is not stored in this repository and is not recoverable from this copy.\n"
        "If the salt is lost, the redaction is permanent and one-way by design.\n",
        encoding="utf-8", newline="\n")

    print(f"masked values: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print(f"files written: {written} -> {out}")
    print(f"manifest: {manifest.name} ({len(mapping)} pseudonyms)")
    if generated:
        print("\nWARNING: CYBERION_REDACTION_KEY was not set, so a random salt was used.")
        print("Re-run with a known key to produce a copy you can later verify:")
        print("  set CYBERION_REDACTION_KEY and re-run, then scripts/sanitize.py --verify")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError) as error:
        sys.exit(f"Sanitisation stopped: {error}")
