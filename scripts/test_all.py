"""Validate and replay every Sigma rule against the normalized telemetry.

One harness for the whole rule set. It performs, for each rule under rules/:

1. a pySigma syntax check via `sigma check`;
2. a replay of the rule's detection logic against data/processed/DS*.jsonl,
   which only happens after the processed file's SHA-256 is matched against
   the SHA-256 recorded by scripts/normalize_dataset.py;
3. a benign-comparison count, using the rule's own anchor selection, so the
   near-miss volume behind a match count is always visible;
4. the declared-negative assertion, from x-evidence.negative_event_uids;
5. for correlation rules, the window-boundary matrix declared in
   x-correlation.window_tests, evaluated by the single correlate() helper.

Supported condition grammar (deliberately small and explicit):

    condition: <name> | <name> and <name> | <name> or <name> | not <name>

Parentheses, `| count`, `| near`, `| all` and field-reference conditions are
not supported and raise, so an unreplayable rule fails closed instead of
silently matching nothing.

A selection is a mapping of field name to one or more matchers. A field name
may carry the modifiers endswith, startswith, contains, re, exists, and the
quantifier all. String modifiers other than `re` are compared case
insensitively, because Sysmon records image paths with inconsistent casing.
An absent, null, empty or "-" field never matches.

A correlation rule keeps an ordinary Sigma `condition` so that the rule stays
valid Sigma, and carries the real pairing in the x-correlation block:

    x-correlation:
      join_field: process_guid -> parent_process_guid
      scope: same dataset, exact host string, non-null event times only
      window_seconds: 30
      window_tests: [{window_seconds: 0.6, expect: match}, ...]

Results are written to detections/test-results.csv, one row per rule.
"""

import argparse
import csv
import json
import re
import subprocess
import sys
from datetime import datetime
from hashlib import sha256
from pathlib import Path

import pandas as pd

RULES = "rules"
RESULTS = "detections/test-results.csv"

FIELDS = {
    "EventID": "event_id",
    "Provider": "provider",
    "SourceName": "provider",
    "Channel": "channel",
    "Hostname": "host",
    "Host": "host",
    "Image": "image",
    "CommandLine": "command_line",
    "ParentImage": "parent_image",
    "ProcessGuid": "process_guid",
    "ParentProcessGuid": "parent_process_guid",
    "ProcessId": "process_id",
    "User": "user",
    "SourceProcessGUID": "source_process_guid",
    "TargetProcessGUID": "target_process_guid",
    "SourceIp": "source_ip",
    "DestinationIp": "destination_ip",
    "ScriptBlockId": "script_block_id",
    "ScriptBlockText": "script_block_text",
    "ContextInfo": "context_info",
    "Payload": "payload",
    "SourceImage": "SourceImage",
    "TargetImage": "TargetImage",
    "GrantedAccess": "GrantedAccess",
    "CallTrace": "CallTrace",
    "QueryName": "QueryName",
    "QueryStatus": "QueryStatus",
    "ServiceName": "ServiceName",
    "ServiceFileName": "ServiceFileName",
    "ServiceStartType": "ServiceStartType",
    "ServiceAccount": "ServiceAccount",
    "LogonType": "LogonType",
    "TargetUserName": "target_user",
    "SubjectUserName": "subject_user",
    "ShareName": "ShareName",
    "RelativeTargetName": "RelativeTargetName",
    "TargetObject": "TargetObject",
    "DestinationPort": "DestinationPort",
}
QUANTIFIERS = {"all": lambda items: all(items), "any": lambda items: any(items)}
OPERATORS = {
    "endswith": lambda value, needle: value.lower().endswith(needle.lower()),
    "startswith": lambda value, needle: value.lower().startswith(needle.lower()),
    "contains": lambda value, needle: needle.lower() in value.lower(),
    "re": lambda value, pattern: re.search(pattern, value) is not None,
    "exists": lambda value, _: value not in (None, "", "-"),
}
ANCHOR = ("EventID", "Provider", "SourceName", "Channel")
NUMERIC = {"LogonType", "ServiceStartType", "DestinationPort"}


class RuleError(ValueError):
    """A rule cannot be replayed under the supported grammar."""


def text(value):
    return "" if value is None else str(value)


def present(value):
    return value not in (None, "", "-")


def load_yaml(path):
    try:
        import yaml
    except ModuleNotFoundError as error:
        raise RuleError("PyYAML is required to read rules") from error
    return yaml.safe_load(path.read_text(encoding="utf-8-sig"))


def load_datasets(root):
    frames = {}
    for path in sorted((root / "data/processed").glob("DS*.jsonl")):
        dataset = path.stem
        report_path = root / f"docs/{dataset}-normalization.json"
        if not report_path.exists():
            raise RuleError(f"{dataset}: missing {report_path.name}; run normalize_dataset.py")
        report = json.loads(report_path.read_text(encoding="utf-8-sig"))
        if report.get("status") != "PASS":
            raise RuleError(f"{dataset}: normalization status is not PASS")
        digest = sha256(path.read_bytes()).hexdigest().upper()
        if digest != report["output_sha256"].upper():
            raise RuleError(f"{dataset}: processed SHA-256 differs from the normalization report")
        frame = pd.read_json(path, lines=True, convert_dates=False)
        frame["timestamp_instant"] = frame["timestamp_utc"].map(parse_instant)
        for field in sorted(set(FIELDS.values()) - set(frame.columns)):
            frame[field] = [event.get(field) for event in frame["raw"]]
            if field in NUMERIC:
                frame[field] = frame[field].map(coerce_number)
        frames[dataset] = frame
    if not frames:
        raise RuleError("no processed datasets found; run normalize_dataset.py first")
    return frames


def parse_instant(value):
    if not present(value) or not isinstance(value, str):
        return None
    return datetime.fromisoformat(value)


def coerce_number(value):
    """SIEMs index numeric-looking log fields as numbers, so rules write them
    as numbers. The original string is always still available in raw."""
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value):
        return int(value)
    return value


def split_name(field):
    parts = field.split("|")
    name, modifiers = parts[0], parts[1:]
    quantifier = next((item for item in modifiers if item in QUANTIFIERS), "any")
    operators = [item for item in modifiers if item in OPERATORS]
    unknown = [item for item in modifiers if item not in set(QUANTIFIERS) | set(OPERATORS)]
    if unknown:
        raise RuleError(f"{field}: unsupported modifier(s) {unknown}")
    if len(operators) > 1:
        raise RuleError(f"{field}: at most one string operator is supported")
    if name not in FIELDS:
        raise RuleError(f"{field}: field is not in the documented mapping")
    return name, operators[0] if operators else None, quantifier


def match_field(series, field, matchers):
    name, operator, quantifier = split_name(field)
    column = series[FIELDS[name]]
    values = matchers if isinstance(matchers, list) else [matchers]
    if operator is None:
        filled = column.map(present)
        results = [filled & (column == value) for value in values]
    else:
        apply = OPERATORS[operator]
        results = [column.map(lambda cell, needle=item: present(cell) and apply(text(cell), needle))
                   for item in values]
        if operator == "exists":
            results = [column.map(present) for _ in values]
    stacked = results[0]
    for result in results[1:]:
        stacked = stacked | result if quantifier == "any" else stacked & result
    return stacked


def selection_mask(frame, selection):
    if not isinstance(selection, dict) or not selection:
        raise RuleError("a selection must be a non-empty mapping")
    mask = pd.Series(True, index=frame.index)
    for field, matchers in selection.items():
        mask &= match_field(frame, field, matchers)
    return mask


def parse_condition(condition):
    tokens = re.findall(r"\(|\)|\bnot\b|\band\b|\bor\b|[A-Za-z_][A-Za-z0-9_]*", str(condition))
    if any(token in {"(", ")"} for token in tokens):
        raise RuleError("parentheses are not supported in conditions")
    return tokens


def evaluate(frame, condition, detections):
    tokens = parse_condition(condition)
    if not tokens:
        raise RuleError("empty condition")
    result, joiner, negate = None, None, False
    for token in tokens:
        if token in {"and", "or"}:
            if result is None:
                raise RuleError(f"condition {condition!r} starts with an operator")
            joiner = token
        elif token == "not":
            negate = True
        else:
            if token not in detections:
                raise RuleError(f"{token}: condition references an undefined selection")
            mask = selection_mask(frame, detections[token])
            term = ~mask if negate else mask
            if result is None:
                result = term
            elif joiner == "and":
                result &= term
            else:
                result |= term
            joiner, negate = None, False
    if result is None or joiner is not None or negate:
        raise RuleError(f"condition {condition!r} is incomplete")
    return result


def evaluate_named(frame, name, detections):
    if name not in detections:
        raise RuleError(f"{name}: undefined selection")
    return selection_mask(frame, detections[name])


def correlate(frame, parent, child, window_seconds, join=("process_guid", "parent_process_guid"),
              same_host=True, same_dataset=True):
    """Single parent/child pairing helper used by every correlation rule.

    Only rows with a resolved event time participate, only the exact host
    string matches, and only a GUID join is used: DS002 has no ordinary
    Sysmon ProcessId, and hexadecimal and decimal PID strings cannot be
    joined. The window is measured from the parent event to the child event.
    """
    pairs = []
    parents = frame[parent & frame["timestamp_instant"].notna()]
    children = frame[child & frame["timestamp_instant"].notna()]
    lookup = {}
    for _, kid in children.iterrows():
        key = (kid[join[1]], kid["host"] if same_host else None, kid["dataset_id"] if same_dataset else None)
        lookup.setdefault(key, []).append(kid)
    for _, mom in parents.iterrows():
        key = (mom[join[0]], mom["host"] if same_host else None, mom["dataset_id"] if same_dataset else None)
        for kid in lookup.get(key, []):
            delay = (kid["timestamp_instant"] - mom["timestamp_instant"]).total_seconds()
            if 0 <= delay <= window_seconds:
                pairs.append((mom, kid, delay))
    return pairs


def sigma_check(root, rule_paths):
    executable = root / ".venv/Scripts/sigma.exe"
    if not executable.exists():
        executable = Path(sys.executable).parent / "sigma.exe"
    if not executable.exists():
        return "skipped: sigma executable not found"
    result = subprocess.run(
        [str(executable), "check", "--fail-on-issues", *[str(path) for path in rule_paths]],
        cwd=root, capture_output=True, text=True,
    )
    if result.returncode == 0:
        return "PASS"
    detail = (result.stdout + result.stderr).strip().splitlines()
    return "FAIL: " + " | ".join(detail[:6])


def uids(frame):
    return [str(item) for item in frame["event_uid"]]


def anchor_mask(frame, detections):
    """The telemetry scope shared by every selection, used to count near misses."""
    anchor = {field: matchers for name, selection in detections.items() if isinstance(selection, dict)
              for field, matchers in selection.items() if field in ANCHOR}
    if not anchor:
        return pd.Series(False, index=frame.index)
    return selection_mask(frame, anchor)


def run_rule(rule_path, root, frames, check):
    rule = load_yaml(rule_path)
    for required in ("title", "id", "detection", "x-attack", "x-evidence", "x-benign-review"):
        if required not in rule:
            raise RuleError(f"{required} is required")
    detections = rule["detection"]
    for name, selection in detections.items():
        if name == "condition" or name.startswith("filter"):
            continue
        if not isinstance(selection, dict):
            raise RuleError(f"{name}: selection must be a mapping")
    condition = detections["condition"]
    evidence = rule["x-evidence"]
    expected = list(evidence.get("expected_event_uids") or [])
    negatives = list(evidence.get("negative_event_uids") or [])
    row = {
        "rule_id": str(rule["id"]),
        "title": rule["title"],
        "rule_file": rule_path.relative_to(root).as_posix(),
        "techniques": ",".join(rule["x-attack"].get("techniques", [])),
        "level": rule.get("level", ""),
        "sigma_check": check,
        "status": "",
        "datasets": "",
        "matches": 0,
        "event_uids": "",
        "expected_hits": f"{len(expected)}/{len(expected)}" if expected else "0/0",
        "benign_matches": 0,
        "benign_uids": "",
        "declared_negatives": len(negatives),
        "negatives_held": "0/0" if negatives else "0/0",
        "window_seconds": "",
        "window_tests": "",
        "notes": "",
    }
    if not frames:
        row.update(status="NO DATA", notes="no processed telemetry available")
        return row
    all_matches, all_benign = [], []
    if "x-correlation" in rule:
        spec = rule["x-correlation"]
        window = float(spec["window_seconds"])
        row["window_seconds"] = window
        tests = []
        for dataset, frame in frames.items():
            parent = evaluate_named(frame, spec["parent"], detections)
            child = evaluate_named(frame, spec["child"], detections)
            pairs = correlate(frame, parent, child, window)
            tests.extend((mom, kid, delay) for mom, kid, delay in pairs)
        for test in spec.get("window_tests", []):
            trial = float(test["window_seconds"])
            observed = correlate_any(frames, spec, detections, trial)
            want = str(test.get("expect", "match"))
            got = "match" if observed else "no match"
            tests_result = "ok" if got == want else "MISMATCH"
            row["window_tests"] += ("" if not row["window_tests"] else ";") + f"{trial}s={got}/{want}:{tests_result}"
        if row["window_tests"] and "MISMATCH" in row["window_tests"]:
            row["status"] = "FAIL"
            row["notes"] = "window-boundary matrix mismatch"
            return row
        all_matches = tests
        parents = [pair[0] for pair in tests]
        children = [pair[1] for pair in tests]
        row["matches"] = len(tests)
        row["datasets"] = ",".join(sorted({item["dataset_id"] for item in parents + children})) or ""
        row["event_uids"] = ";".join(f"{mom['event_uid']}>{kid['event_uid']}" for mom, kid, _ in tests)
    else:
        for dataset, frame in frames.items():
            mask = evaluate(frame, condition, detections)
            hits = frame[mask]
            all_matches.extend(hits.to_dict("records"))
            anchor = anchor_mask(frame, detections)
            near = frame[anchor & ~mask]
            all_benign.extend(near.to_dict("records"))
        row["matches"] = len(all_matches)
        row["datasets"] = ",".join(sorted({item["dataset_id"] for item in all_matches})) or ""
        row["event_uids"] = ";".join(str(item["event_uid"]) for item in all_matches)
        row["benign_matches"] = len(all_benign)
        row["benign_uids"] = ";".join(str(item["event_uid"]) for item in all_benign[:20])
    hit_uids = set()
    for item in all_matches:
        if isinstance(item, tuple):
            hit_uids.update((item[0]["event_uid"], item[1]["event_uid"]))
        else:
            hit_uids.add(item["event_uid"])
    expected_hits = sum(1 for value in expected if value in hit_uids)
    row["expected_hits"] = f"{expected_hits}/{len(expected)}"
    held = sum(1 for value in negatives if value not in hit_uids)
    row["negatives_held"] = f"{held}/{len(negatives)}"
    if expected and expected_hits != len(expected):
        row["status"] = "FAIL"
        row["notes"] = "declared evidence line did not match"
    elif negatives and held != len(negatives):
        row["status"] = "FAIL"
        row["notes"] = "declared negative matched"
    elif check.startswith("FAIL"):
        row["status"] = "FAIL"
        row["notes"] = "sigma check failed"
    else:
        row["status"] = "PASS"
        if not negatives:
            row["notes"] = "no declared negatives; benign review pending"
    return row


def correlate_any(frames, spec, detections, window):
    for frame in frames.values():
        parent = evaluate_named(frame, spec["parent"], detections)
        child = evaluate_named(frame, spec["child"], detections)
        if correlate(frame, parent, child, window):
            return True
    return False


def rule_paths(root):
    paths = [path for path in sorted((root / RULES).rglob("*.yml"))
             if not path.name.startswith("_") and path.name != "sigma.yml"]
    if not paths:
        raise RuleError(f"no rules found under {RULES}/")
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--skip-syntax", action="store_true", help="skip the sigma check step")
    parser.add_argument("--rule", action="append", help="limit replay to a rule id or title substring")
    args = parser.parse_args()
    root = args.root.resolve()
    paths = rule_paths(root)
    if args.rule:
        paths = [path for path in paths
                 if any(needle in path.name or needle in path.read_text(encoding="utf-8-sig")
                        for needle in args.rule)]
        if not paths:
            raise RuleError("no rule matched the --rule filter")
    check = "skipped" if args.skip_syntax else sigma_check(root, paths)
    frames = load_datasets(root)
    rows = []
    for path in paths:
        try:
            rows.append(run_rule(path, root, frames, check))
        except (RuleError, OSError, ValueError, KeyError) as error:
            rows.append({
                "rule_id": path.stem, "title": path.stem,
                "rule_file": path.relative_to(root).as_posix(), "techniques": "", "level": "",
                "sigma_check": check, "status": "ERROR", "datasets": "", "matches": 0,
                "event_uids": "", "expected_hits": "0/0", "benign_matches": 0, "benign_uids": "",
                "declared_negatives": 0, "negatives_held": "0/0", "window_seconds": "",
                "window_tests": "", "notes": f"{type(error).__name__}: {error}",
            })
    results = root / RESULTS
    results.parent.mkdir(parents=True, exist_ok=True)
    fields = ["rule_id", "title", "rule_file", "techniques", "level", "sigma_check", "status",
              "datasets", "matches", "event_uids", "expected_hits", "benign_matches", "benign_uids",
              "declared_negatives", "negatives_held", "window_seconds", "window_tests", "notes"]
    with results.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    width = max(len(row["rule_id"]) for row in rows)
    for row in rows:
        print(f"{row['rule_id']:<{width}}  {row['status']:<7} matches={row['matches']:<3} "
              f"evidence={row['expected_hits']:<5} negatives={row['negatives_held']:<5} "
              f"benign={row['benign_matches']:<4} {row['notes']}")
    failures = [row for row in rows if row["status"] not in {"PASS", "NO DATA"}]
    print(f"\nrules={len(rows)} pass={len(rows) - len(failures)} fail={len(failures)} "
          f"sigma_check={check.splitlines()[0] if check else 'skipped'}")
    print(f"results: {results.relative_to(root).as_posix()}")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuleError, ValueError, KeyError) as error:
        sys.exit(f"Rule testing stopped: {error}")
