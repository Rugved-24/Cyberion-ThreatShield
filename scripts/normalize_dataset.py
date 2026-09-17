"""Normalize verified JSONL captures using docs/field_mapping.md v1."""

import argparse
import json
import re
from collections import Counter
from datetime import UTC, datetime
from hashlib import sha256
from io import StringIO
from pathlib import Path

SYSMON = "Microsoft-Windows-Sysmon"
SECURITY = "Microsoft-Windows-Security-Auditing"
POWERSHELL = "Microsoft-Windows-PowerShell"
TIME_FIELDS = ("@timestamp", "TimeCreated", "UtcTime", "EventTime", "EventReceivedTime")
MAPPINGS = {
    (SYSMON, None): {
        "image": "Image", "process_id": "ProcessId",
        "process_guid": "ProcessGuid", "user": "User",
    },
    (SYSMON, 1): {
        "command_line": "CommandLine", "parent_image": "ParentImage",
        "parent_process_id": "ParentProcessId", "parent_process_guid": "ParentProcessGuid",
    },
    (SYSMON, 10): {
        "source_process_guid": "SourceProcessGUID", "target_process_guid": "TargetProcessGUID",
    },
    (SYSMON, 3): {"source_ip": "SourceIp", "destination_ip": "DestinationIp"},
    (SECURITY, None): {"subject_user": "SubjectUserName", "target_user": "TargetUserName"},
    (SECURITY, 4688): {
        "image": "NewProcessName", "process_id": "NewProcessId",
        "command_line": "CommandLine", "parent_image": "ParentProcessName",
        "parent_process_id": "ProcessId",
    },
    (POWERSHELL, 4103): {"context_info": "ContextInfo", "payload": "Payload"},
    (POWERSHELL, 4104): {
        "script_block_id": "ScriptBlockId", "script_block_text": "ScriptBlockText",
    },
}
OPTIONAL_FIELDS = sorted({field for mapping in MAPPINGS.values() for field in mapping})


class TimestampError(ValueError):
    """A Sysmon timestamp could not be interpreted under the documented policy."""


def value(row, field, kind=str, required=False):
    item = row.get(field)
    if item in (None, "", "-"):
        if required:
            raise ValueError(f"{field}: required value missing")
        return None
    if type(item) is not kind:
        raise ValueError(f"{field}: expected {kind.__name__}, got {type(item).__name__}")
    return item


def normalize(row):
    if not isinstance(row, dict):
        raise ValueError("Event must be a JSON object")
    provider = value(row, "SourceName", required=True)
    event_id = value(row, "EventID", int, required=True)
    channel = value(row, "Channel", required=True)
    result = dict.fromkeys(OPTIONAL_FIELDS)
    result.update(
        provider=provider, event_id=event_id,
        channel="Security" if channel == "security" else channel,
        host=value(row, "Hostname", required=True),
        record_number=value(row, "RecordNumber", int),
        timestamps_original={key: row[key] for key in TIME_FIELDS if key in row},
        timestamp_utc=None, timestamp_basis="unresolved", raw=row,
    )
    if provider == SYSMON:
        try:
            stamp = value(row, "UtcTime", required=True)
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)?", stamp):
                raise ValueError("Expected UTC date and time, with at most six fractional digits")
            instant = datetime.fromisoformat(stamp)
            if instant.tzinfo is None:
                instant = instant.replace(tzinfo=UTC)
            result.update(timestamp_utc=instant.isoformat(), timestamp_basis="sysmon_utc")
        except ValueError as error:
            raise TimestampError(f"UtcTime: {error}") from error
    for key in ((provider, None), (provider, event_id)):
        for output, source in MAPPINGS.get(key, {}).items():
            result[output] = value(row, source)
    return result


def json_object(pairs):
    """Reject duplicate keys instead of silently losing an original value."""
    result = {}
    for key, item in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = item
    return result


def reject_constant(item):
    raise ValueError(f"Invalid JSON constant: {item}")


def run(dataset, root):
    if not re.fullmatch(r"DS\d{3}", dataset):
        raise ValueError("Dataset ID must use the form DS001")
    root = root.resolve()
    meta = json.loads((root / f"docs/{dataset}-inventory.json").read_text(encoding="utf-8-sig"))
    path = (root / meta["file"]).resolve()
    if meta["dataset_id"] != dataset or not path.is_relative_to(root / "data/raw"):
        raise ValueError("Inventory ID or raw-file location is invalid")
    raw = path.read_bytes()
    digest = sha256(raw).hexdigest().upper()
    if digest != meta["sha256"].upper() or len(raw) != meta["bytes"]:
        raise ValueError("Raw file differs from the recorded SHA-256 or size")
    source_file = path.relative_to(root).as_posix()
    rows, errors, content_counts = [], [], Counter()
    blank_lines = input_records = timestamp_errors = 0
    for number, line in enumerate(StringIO(raw.decode("utf-8-sig"), newline=None), 1):
        if not line.strip():
            blank_lines += 1
            continue
        input_records += 1
        try:
            event = json.loads(line, object_pairs_hook=json_object, parse_constant=reject_constant)
            result = normalize(event)
            result.update(
                dataset_id=dataset, source_file=source_file, raw_sha256=digest,
                record_locator=number, event_uid=f"{dataset}:{digest}:{number}",
            )
            canonical = json.dumps(event, sort_keys=True, ensure_ascii=False, allow_nan=False)
            content_counts[sha256(canonical.encode("utf-8")).hexdigest()] += 1
            rows.append(result)
        except (ValueError, OverflowError) as error:
            timestamp_errors += isinstance(error, TimestampError)
            errors.append({"record_locator": number, "error": str(error)})
    unique_ids = len({row["event_uid"] for row in rows})
    passed = not errors and input_records == meta["records"] and unique_ids == len(rows)
    output = root / f"data/processed/{dataset}.jsonl"
    report = {
        "dataset_id": dataset, "status": "PASS" if passed else "FAIL",
        "source_file": source_file, "raw_sha256": digest,
        "normalizer_sha256": sha256(Path(__file__).read_bytes()).hexdigest().upper(),
        "expected_records": meta["records"], "input_records": input_records,
        "blank_lines": blank_lines, "normalized_records": len(rows),
        "unique_event_uids": unique_ids,
        "duplicate_content_extra_records": sum(count - 1 for count in content_counts.values()),
        "timestamp_utc_records": sum(row["timestamp_utc"] is not None for row in rows),
        "timestamp_unresolved_records": sum(row["timestamp_basis"] == "unresolved" for row in rows),
        "timestamp_errors": timestamp_errors, "rejected_records": len(errors), "errors": errors,
        "providers": dict(Counter(row["provider"] for row in rows)),
        "output_file": output.relative_to(root).as_posix(), "output_written": False,
    }
    if passed:
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(".jsonl.tmp")
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as stream:
                for row in rows:
                    stream.write(json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n")
            temporary.replace(output)
        finally:
            temporary.unlink(missing_ok=True)
        report["output_written"] = True
        report["output_sha256"] = sha256(output.read_bytes()).hexdigest().upper()
    report_path = root / f"docs/{dataset}-normalization.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        f"{dataset}: {report['status']}; input={input_records}; normalized={len(rows)}; "
        f"UTC={report['timestamp_utc_records']}; unresolved={report['timestamp_unresolved_records']}; "
        f"rejected={len(errors)}; duplicates={report['duplicate_content_extra_records']}"
    )
    if not passed:
        raise ValueError(f"See {report_path.name}; any previous output was left unchanged")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("datasets", nargs="+", help="Inventory IDs, e.g. DS001 DS002")
    args = parser.parse_args()
    try:
        for dataset in args.datasets:
            run(dataset, Path(__file__).resolve().parents[1])
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Normalization stopped: {error}\n")
