"""Verify an acquisition archive, extract one member, and write docs/DSxxx-inventory.json.

Hardening over the original script:
- the dataset ID is validated, so it cannot be used to reach a path outside docs/;
- the member name must be a bare filename, not a path;
- the member's declared size is checked before extraction, so a compression bomb
  cannot exhaust memory after its digest has been accepted;
- the destination is confined to the archive's own directory;
- paths resolve from this file, not from the working directory.
"""

import argparse
import json
import re
from collections import Counter
from hashlib import sha256
from pathlib import Path
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
MAX_MEMBER_BYTES = 512 * 1024 * 1024


def safe_member(bundle, member):
    """Resolve a member name to a single flat entry, refusing paths and traversal."""
    if member in ("", ".", "..") or "/" in member or "\\" in member:
        raise ValueError("Member must be a bare file name, not a path.")
    names = bundle.namelist()
    matches = [name for name in names if name.rsplit("/", 1)[-1] == member]
    if len(matches) != 1:
        raise ValueError(f"Member {member!r} matched {len(matches)} archive entries.")
    name = matches[0]
    info = bundle.getinfo(name)
    if info.is_dir():
        raise ValueError(f"Member {member!r} is a directory.")
    if info.file_size > MAX_MEMBER_BYTES:
        raise ValueError(f"Member {member!r} declares {info.file_size} bytes, over the limit.")
    return name, info


def run(dataset, member, root):
    if not re.fullmatch(r"DS\d{3}", dataset):
        raise ValueError("Dataset ID must use the form DS001")
    meta = json.loads((root / f"docs/{dataset}-acquisition.json").read_text(encoding="utf-8-sig"))
    archive = (root / meta["archive"]).resolve()
    if not archive.is_file():
        raise ValueError(f"Acquisition archive is missing: {meta['archive']}")
    if sha256(archive.read_bytes()).hexdigest().upper() != meta["sha256"].upper():
        raise ValueError("Archive SHA-256 mismatch.")

    with ZipFile(archive) as bundle:
        name, info = safe_member(bundle, member)
        payload = bundle.read(name)

    if len(payload) != info.file_size:
        raise ValueError("Extracted size differs from the archive directory entry.")

    target = archive.with_name(member).resolve()
    if target.parent != archive.parent:
        raise ValueError("Destination is not beside the archive.")
    if target.exists():
        if target.read_bytes() != payload:
            raise ValueError("Existing file differs from archive; left unchanged.")
    else:
        target.write_bytes(payload)

    records = [
        json.loads(line)
        for line in payload.decode("utf-8-sig").splitlines()
        if line.strip()
    ]
    if not records:
        raise ValueError("Dataset contains no records.")

    report = {
        "dataset_id": dataset,
        "file": target.relative_to(root).as_posix(),
        "bytes": len(payload),
        "sha256": sha256(payload).hexdigest().upper(),
        "records": len(records),
    }
    for field in ("Channel", "SourceName", "ProviderName"):
        if any(field in record for record in records):
            counts = Counter(record.get(field) or "<missing>" for record in records)
            report[field] = dict(counts)

    (root / f"docs/{dataset}-inventory.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dataset", help="Acquisition ID, e.g. DS001")
    parser.add_argument("member", help="File name inside the archive, e.g. sample.json")
    args = parser.parse_args()
    try:
        summary = run(args.dataset, args.member, ROOT)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Inventory stopped: {error}\n")
    print(json.dumps(summary, indent=2))
