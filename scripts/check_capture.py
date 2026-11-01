"""Profile event-time fields in verified captures, writing docs/DSxxx-capture.json.

Hash verification happens before any record is read. This script writes a tracked
evidence file, so an unverified read here would let altered telemetry reach a
committed document. scripts/normalize_dataset.py already enforced this; this
script now does too.
"""

import json
import re
from hashlib import sha256
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATASETS = ("DS001", "DS002")
LOCAL_FIELDS = {"EventTime", "EventReceivedTime"}


def load_verified_inventory(dataset, root):
    """Resolve an inventory and prove the referenced file still matches its digest."""
    if not re.fullmatch(r"DS\d{3}", dataset):
        raise ValueError(f"{dataset}: dataset ID must use the form DS001")
    meta = json.loads((root / f"docs/{dataset}-inventory.json").read_text(encoding="utf-8-sig"))
    if meta.get("dataset_id") != dataset:
        raise ValueError(f"{dataset}: inventory dataset_id does not match the requested ID")
    path = (root / meta["file"]).resolve()
    if not path.is_relative_to(root / "data/raw"):
        raise ValueError(f"{dataset}: inventory file is not inside data/raw")
    if not path.is_file():
        raise ValueError(f"{dataset}: inventory references a missing file: {meta['file']}")
    digest = sha256(path.read_bytes()).hexdigest().upper()
    if digest != meta["sha256"].upper() or path.stat().st_size != meta["bytes"]:
        raise ValueError(f"{dataset}: raw file differs from the recorded SHA-256 or size")
    return meta, path


for dataset in DATASETS:
    meta, path = load_verified_inventory(dataset, ROOT)
    frame = pd.read_json(path, lines=True, convert_dates=False)
    sysmon = frame["SourceName"].eq("Microsoft-Windows-Sysmon")
    times = {}

    for field in ("@timestamp", "TimeCreated", "UtcTime", *sorted(LOCAL_FIELDS)):
        if field not in frame:
            continue
        values = frame[field].where(sysmon) if field == "UtcTime" else frame[field]
        if field in ("@timestamp", "TimeCreated"):
            explicit_zone = values.dropna().str.contains(r"(?:Z|[+-]\d{2}:\d{2})$")
            if not explicit_zone.all():
                raise ValueError(f"{dataset}/{field}: missing timezone.")
        times[field] = pd.to_datetime(
            values, format="ISO8601", utc=field not in LOCAL_FIELDS
        )

    report = {
        "dataset_id": dataset,
        "hosts": frame["Hostname"].value_counts().to_dict(),
        "ranges": {},
        "paired_differences_seconds": {},
        "note": "Ranges are per field; wall-clock differences do not establish timezones.",
        "verified_sha256": sha256(path.read_bytes()).hexdigest().upper(),
    }
    print(f"\n{dataset}\nHosts: {report['hosts']}")
    for field, values in times.items():
        valid = values.dropna()
        bounds = {
            "count": int(valid.size),
            "first": valid.min().isoformat(),
            "last": valid.max().isoformat(),
        }
        report["ranges"][field] = bounds
        print(f"{field}: {bounds}")
        if field == "UtcTime":
            continue

        baseline = times["UtcTime"]
        if field in LOCAL_FIELDS:
            baseline = baseline.dt.tz_localize(None)
        delta = (values - baseline).dt.total_seconds().where(sysmon)
        stats = delta.dropna().groupby(frame["Hostname"]).agg(
            ["count", "min", "median", "max"]
        ).round(3)
        label = f"{field} - UtcTime"
        if field in LOCAL_FIELDS:
            label += " (wall clock)"
        report["paired_differences_seconds"][label] = stats.to_dict("index")
        print(f"{label}:\n{stats.to_string()}")

    (ROOT / f"docs/{dataset}-capture.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
