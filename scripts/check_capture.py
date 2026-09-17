import json
from pathlib import Path

import pandas as pd

local_fields = {"EventTime", "EventReceivedTime"}
for dataset in ("DS001", "DS002"):
    meta = json.loads(Path(f"docs/{dataset}-inventory.json").read_text())
    frame = pd.read_json(meta["file"], lines=True, convert_dates=False)
    sysmon = frame["SourceName"].eq("Microsoft-Windows-Sysmon")
    times = {}

    for field in ("@timestamp", "TimeCreated", "UtcTime", *sorted(local_fields)):
        if field not in frame:
            continue
        values = frame[field].where(sysmon) if field == "UtcTime" else frame[field]
        if field in ("@timestamp", "TimeCreated"):
            explicit_zone = values.dropna().str.contains(r"(?:Z|[+-]\d{2}:\d{2})$")
            if not explicit_zone.all():
                raise ValueError(f"{dataset}/{field}: missing timezone.")
        times[field] = pd.to_datetime(
            values, format="ISO8601", utc=field not in local_fields
        )

    report = {
        "dataset_id": dataset,
        "hosts": frame["Hostname"].value_counts().to_dict(),
        "ranges": {},
        "paired_differences_seconds": {},
        "note": "Ranges are per field; wall-clock differences do not establish timezones.",
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
        if field in local_fields:
            baseline = baseline.dt.tz_localize(None)
        delta = (values - baseline).dt.total_seconds().where(sysmon)
        stats = delta.dropna().groupby(frame["Hostname"]).agg(
            ["count", "min", "median", "max"]
        ).round(3)
        label = f"{field} - UtcTime"
        if field in local_fields:
            label += " (wall clock)"
        report["paired_differences_seconds"][label] = stats.to_dict("index")
        print(f"{label}:\n{stats.to_string()}")

    Path(f"docs/{dataset}-capture.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
