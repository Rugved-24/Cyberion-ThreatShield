import json
import sys
from collections import Counter
from hashlib import sha256
from pathlib import Path
from zipfile import ZipFile

dataset, member = sys.argv[1:]
meta = json.loads(
    Path(f"docs/{dataset}-acquisition.json").read_text(encoding="utf-8-sig")
)
archive = Path(meta["archive"])
if sha256(archive.read_bytes()).hexdigest().upper() != meta["sha256"]:
    raise ValueError("Archive SHA-256 mismatch.")

with ZipFile(archive) as bundle:
    payload = bundle.read(member)

target = archive.with_name(member)
if not target.exists():
    target.write_bytes(payload)
if target.read_bytes() != payload:
    raise ValueError("Existing file differs from archive; left unchanged.")

records = [
    json.loads(line)
    for line in payload.decode("utf-8-sig").splitlines()
    if line.strip()
]
if not records:
    raise ValueError("Dataset contains no records.")

report = {
    "dataset_id": dataset,
    "file": target.as_posix(),
    "bytes": len(payload),
    "sha256": sha256(payload).hexdigest().upper(),
    "records": len(records),
}
for field in ("Channel", "SourceName", "ProviderName"):
    if any(field in record for record in records):
        counts = Counter(record.get(field) or "<missing>" for record in records)
        report[field] = dict(counts)

summary = json.dumps(report, indent=2)
Path(f"docs/{dataset}-inventory.json").write_text(summary + "\n", encoding="utf-8")
print(summary)
