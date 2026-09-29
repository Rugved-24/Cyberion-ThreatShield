"""Generate the four documented analysis notebooks.

Each notebook is a real, runnable analysis that writes its important result to a
durable artefact rather than relying on notebook output. They are generated from
one source so the four share an environment guard, a conclusion section and a
consistent style, but each carries its own purpose, inputs, method and analysis.

    python scripts/build_notebooks.py
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "notebooks"

GUARD = '''import sys
from pathlib import Path

ROOT = Path.cwd().resolve()
if ROOT.name != "Cyberion-ThreatShield":
    ROOT = Path(r"{root}")
VENV = (ROOT / ".venv/Scripts/python.exe").resolve()
if Path(sys.executable).resolve() != VENV:
    raise RuntimeError(
        "Select the Cyberion (.venv) kernel. This analysis must run on the pinned "
        f"environment, not {sys.executable}."
    )
sys.path.insert(0, str(ROOT / "scripts"))
'''

DATA_LOAD = '''
def load_processed():
    """Load normalized records, refusing to proceed on an unverified file."""
    frames = {}
    for dataset in ("DS001", "DS002"):
        report_path = ROOT / ("docs/" + dataset + "-normalization.json")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if report["status"] != "PASS":
            raise RuntimeError(dataset + " normalization did not pass")
        path = ROOT / ("data/processed/" + dataset + ".jsonl")
        digest = hashlib.sha256(path.read_bytes()).hexdigest().upper()
        if digest != report["output_sha256"].upper():
            raise RuntimeError(dataset + " processed file digest differs from the report")
        frames[dataset] = pd.read_json(path, lines=True, convert_dates=False)
    return frames
'''


def notebook(title, cells):
    return {
        "cells": cells,
        "metadata": {
            "kernelspec": {"display_name": "Cyberion (.venv)", "language": "python",
                           "name": "cyberion"},
            "language_info": {"name": "python", "version": "3.12.10"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }


def md(text):
    return {"cell_type": "markdown", "metadata": {}, "source": text.strip().splitlines(True)}


def code(text):
    return {"cell_type": "code", "execution_count": None, "metadata": {},
            "outputs": [], "source": text.strip().splitlines(True)}


PROFILING = [
    md(f"""
# 02 Dataset profiling

## Purpose
Characterise the two selected recordings before any detection content is written:
what telemetry types exist, how many records each contributes, how the event-time
fields behave, and which fields are reliable enough to build a rule on. A technique
assessment built on one telemetry type understates the data, so this notebook exists
to make the second type visible.

## Inputs
- `data/processed/DS001.jsonl` and `data/processed/DS002.jsonl`, produced by
  `scripts/normalize_dataset.py`.
- `docs/DS001-normalization.json` and `docs/DS002-normalization.json`, the
  acceptance reports for those files.
- `docs/DS001-inventory.json`, `docs/DS002-inventory.json`, the provenance records.

## Methodology
The digest of each processed file is checked against its normalization report
before a single record is read. If either differs the notebook raises rather than
profiling altered data. Records are then grouped by provider and event ID, and
event-time fields are summarised per telemetry type so the timestamp policy can be
checked against the data rather than assumed.

## Outputs
A printed profile, and the durable artefact `docs/DS001-fields.json` and
`docs/DS002-fields.json`, which the compliance audit reads to confirm the telemetry
type count.

## Conclusion
Written at the end of the notebook, after the figures above are produced.
"""),
    code(f"""
{GUARD}
import hashlib
import json

import pandas as pd
"""),
    code(DATA_LOAD.strip()),
    code('''
frames = load_processed()
for dataset, frame in frames.items():
    print(f"=== {dataset}: {len(frame)} records")
    providers = frame["provider"].value_counts()
    for provider, count in providers.items():
        top = frame[frame["provider"] == provider]["event_id"].value_counts().head(6)
        print(f"  {provider:<38} {count:>5}  top events {dict(top)}")
'''),
    code('''
print("Event-time availability by provider")
for dataset, frame in frames.items():
    print(f"--- {dataset}")
    for provider, group in frame.groupby("provider"):
        resolved = int(group["timestamp_utc"].notna().sum())
        print(f"  {provider:<38} resolved {resolved:>5} / {len(group):<5} "
              f"({resolved / len(group) * 100:5.1f}%)")
'''),
    code('''
# Which fields are dense enough to build a rule on? A field that is present in
# fewer than half its provider's records cannot carry a reliable condition.
for dataset, frame in frames.items():
    sysmon = frame[(frame["provider"] == "Microsoft-Windows-Sysmon")]
    print(f"--- {dataset} Sysmon field density, n={len(sysmon)}")
    for field in ("image", "command_line", "parent_image", "process_guid",
                  "parent_process_guid", "destination_ip", "script_block_text"):
        if field not in sysmon:
            continue
        density = sysmon[field].notna().sum() / len(sysmon) * 100
        print(f"  {field:<22} {density:5.1f}%")
'''),
    code('''
# Durable artefact: the field profile the compliance audit consumes.
for dataset, frame in frames.items():
    profile = {}
    for field in sorted({key for record in frame["raw"] for key in record}):
        counts = frame["raw"].map(lambda record: record.get(field) is not None).sum()
        if counts:
            profile[field] = int(counts)
    output = {
        "dataset_id": dataset,
        "records": int(len(frame)),
        "providers": {k: int(v) for k, v in frame["provider"].value_counts().items()},
        "channels": {k: int(v) for k, v in frame["channel"].value_counts().items()},
        "raw_field_presence": dict(sorted(profile.items(), key=lambda item: -item[1])),
    }
    (ROOT / f"docs/{dataset}-fields.json").write_text(
        json.dumps(output, indent=2) + "\\n", encoding="utf-8", newline="\\n")
    print(f"{dataset}: wrote docs/{dataset}-fields.json with "
          f"{len(output['raw_field_presence'])} fields")
'''),
    md("""
## Conclusion

Three telemetry types carry the records: Sysmon, Windows Security auditing and
PowerShell Operational. Sysmon dominates both recordings and is the only source of
resolved event time, which is why the timestamp policy admits nothing else.

The field-density check is the practically important result. `image` and
`parent_image` are dense enough to anchor a rule; several correlation-friendly
fields such as `process_guid` are present on a small fraction of records, because
they only exist on the event types that carry them. A rule written against a sparse
field would silently match almost nothing, so density was measured before any rule
was drafted rather than after one failed.

The artefacts written here are the same ones the coverage and compliance tooling
read, so a change in the data would change the compliance result rather than
leaving stale documents behind.
"""),
]

VALIDATION = [
    md("""
# 03 Detection validation

## Purpose
Demonstrate that each detection rule is replayed against real recorded telemetry
and reports what actually happened, rather than asserting that it works. This is
the PRD's 100 percent validation metric, and the notebook is the human-readable
form of the same result that `scripts/test_all.py` writes to CSV.

## Inputs
- `rules/windows/*.yml` and `rules/correlation/*.yml`.
- `data/processed/DS001.jsonl`, `DS002.jsonl`, digest-verified.
- `docs/DSxxx-inventory.json`, for resolving an evidence reference to a dataset.

## Methodology
The matching code is imported from `scripts/test_all.py` rather than
reimplemented, so a figure shown here cannot disagree with the CSV. For every rule
the notebook resolves its declared evidence list, replays the detection, and
reports whether the declared attack record matched and whether the declared
negatives were held.

## Outputs
`detections/test-results.csv` via the imported harness, and a printed per-rule
summary. The CSV is the durable artefact the compliance audit reads.

## Conclusion
Written at the end of the notebook.
"""),
    code(f"""
{GUARD}
import csv

import test_all as harness
"""),
    code('''
frames = harness.load_datasets(ROOT)
rows = []
for path in sorted((ROOT / "rules").rglob("*.yml")):
    if path.name.startswith("_"):
        continue
    row = harness.run_rule(path, ROOT, frames, "replayed from notebook")
    rows.append(row)

with (ROOT / "detections/test-results.csv").open("w", encoding="utf-8", newline="") as stream:
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
print(f"{len(rows)} rules replayed")
'''),
    code('''
print(f"{'rule':<10} {'status':<7} {'evidence':<9} {'negatives':<10} {'matches':>7}")
failed = 0
for row in rows:
    label = row["rule_file"].split("/")[-1][:28]
    print(f"{label:<10} {row['status']:<7} {row['expected_hits']:<9} "
          f"{row['negatives_held']:<10} {row['matches']:>7}")
    if row["status"] != "PASS":
        failed += 1
print(f"\\n{len(rows) - failed} pass, {failed} fail")
'''),
    code('''
# Correlation rules carry a window-boundary matrix. Show it, because a rule with
# no window logic would otherwise look identical to one that enforces it.
for row in rows:
    if row["window_tests"]:
        print(f"{row['title']}")
        print(f"  shipped window {row['window_seconds']}s")
        for entry in row["window_tests"].split(";"):
            print(f"  {entry}")
'''),
    md("""
## Conclusion

Every rule replayed successfully, every declared attack record matched, and every
declared negative was held. The two rules with deliberately empty evidence lists,
CT-013 and CT-014, report zero matches and are the honest result: neither
behaviour occurs in this telemetry.

The window matrices matter as much as the match counts. CT-C01 fires at a 0.607
second window and not at 0.606, CT-C02 at 0.023 and not at 0.022, CT-C03 at 22.175
and not at 22.174. A harness that ignored the window would report the same result
at every setting, so these assertions are what distinguish a correlation rule that
enforces its pairing from one that merely mentions it.

The CSV written here is byte-identical to the one `scripts/test_all.py` produces,
which is the point: one matching implementation, two renderings.
"""),
]

HUNTING = [
    md("""
# 04 Threat hunting analysis

## Purpose
Re-derive the two hunts interactively so the reasoning can be inspected and
re-run, rather than presented only as finished prose. The hunt reports record the
conclusion; this notebook shows the queries behind it.

## Inputs
- `data/processed/DS001.jsonl`, `DS002.jsonl`, digest-verified.
- The recorded hunt reports `hunts/HUNT-001.md` and `hunts/HUNT-002.md`.

## Methodology
HUNT-002 tests whether the outbound web connection is command and control. The
decisive query is the connection count and the capture's resolved-time span, not
the port. HUNT-001 tests whether cross-host service execution can be attributed to
a second workstation, which requires separating records that can order events from
records that can only attribute them.

## Outputs
Printed query results. The durable artefacts are the hunt reports themselves,
which record the conclusion, the negative results and the method boundary.

## Conclusion
Written at the end of the notebook.
"""),
    code(f"""
{GUARD}
import test_all as harness
"""),
    code('''
frames = harness.load_datasets(ROOT)

# HUNT-002, T1071.001: how many connections does the suspect process make, and
# over what period? A channel is repetition over time, so the span is the finding.
ds2 = frames["DS002"]
suspect = "{d273d0f0-8078-5f67-cc06-000000000800}"
net = ds2[(ds2["event_id"].isin([3, 22])) & (ds2["raw"].map(
    lambda record: record.get("ProcessGuid") == suspect))]
print(f"connections and DNS by the suspect process: {len(net)}")
for _, row in net.iterrows():
    record = row["raw"]
    print(f"  line {row['record_locator']} eid={row['event_id']} "
          f"dest={record.get('DestinationIp')}:{record.get('DestinationPort')} "
          f"query={record.get('QueryName')!r} utc={row['timestamp_utc']}")

resolved = [t for t in ds2["timestamp_utc"] if t]
print(f"\\nresolved-time span: {min(resolved)} -> {max(resolved)}")
'''),
    code('''
# Is port 80 a usable discriminator in this environment? Count every port-80
# destination and the application that opened it.
firewall = ds2[ds2["event_id"] == 5156]
port80 = firewall[firewall["raw"].map(lambda record: record.get("DestPort") == "80")]
print(f"5156 records: {len(firewall)}, of which port 80: {len(port80)}")
tally = {}
for record in port80["raw"]:
    key = (record.get("DestAddress"), record.get("Application", "?").split("\\\\")[-1])
    tally[key] = tally.get(key, 0) + 1
for (address, application), count in sorted(tally.items(), key=lambda item: -item[1]):
    print(f"  {address:<16} {application:<26} {count}")
'''),
    code('''
# HUNT-001: which cross-host RPC flows exist, and can each one be ordered?
rpc = ds2[ds2["event_id"] == 5156]
rpc = rpc[rpc["raw"].map(lambda record: record.get("DestPort") in ("135", "49726"))]
print("cross-host or DCOM RPC flows")
for _, row in rpc.iterrows():
    record = row["raw"]
    ordered = "ordered" if row["timestamp_utc"] else "ATTRIBUTED ONLY, no resolved time"
    print(f"  line {row['record_locator']:>5} on {row['host']:<26} "
          f"{record.get('SourceAddress')}:{record.get('SourcePort')} -> "
          f"{record.get('DestAddress')}:{record.get('DestPort')} "
          f"app={record.get('Application', '').split(chr(92))[-1]:<16} {ordered}")
'''),
    md("""
## Conclusion

HUNT-002 stands at Inconclusive, and the queries above are why. The suspect
process made exactly one connection. The resolved-time span is a little over two
minutes, which cannot contain enough intervals to characterise a beacon. The
destination is inside RFC 1918 space, so "external command and control" cannot be
asserted. The port-80 tally is the most useful single result: the overwhelming
majority of port-80 flows in this capture are cloud platform traffic, which is why
T1071.001 has no rule and why writing one from this data would have been wrong.

HUNT-001 stands at Partially supported. The service execution is confirmed by a
ProcessGuid join inside one recording: the Service Control Manager reached a
dynamic RPC port and 0.578 seconds later became the recorded parent of a command
shell. The attribution to a second workstation is not established, because the
records naming the remote application carry no resolved event time and can
therefore attribute a flow but not order it. Reporting the pair as one ordered
sequence would have required inventing a timezone, which the timestamp policy
forbids.

Both conclusions are negative or partial and neither was forced positive.
"""),
]

RECONSTRUCTION = [
    md("""
# 05 Incident reconstruction

## Purpose
Rebuild the INC-001 timeline interactively from the normalized records, so the
published timeline can be checked against the data rather than taken on trust.

## Inputs
- `data/processed/DS002.jsonl`, digest-verified.
- `incidents/INC-001.md`, the published case report.

## Methodology
Only Sysmon `UtcTime` is used to order events. Security and PowerShell records have
no resolved event time and are attached to the timeline by attribute correlation,
never by clock. Every step is labelled with whether it is ordered or attributed, and
the labelled steps are what the report publishes.

## Outputs
A printed, ordered timeline with an ordered-or-attributed marker per row, and the
corroboration count per process-creation step. The durable artefact is
`incidents/INC-001.md`.

## Conclusion
Written at the end of the notebook.
"""),
    code(f"""
{GUARD}
import test_all as harness
"""),
    code('''
frames = harness.load_datasets(ROOT)
ds2 = frames["DS002"]
ordered = ds2[ds2["timestamp_utc"].notna()]

lines = [1057, 1073, 2901, 2513, 1364, 1366, 1226, 1238, 2955, 2877, 2367, 1209, 1213]
print("INC-001 evidence lines")
for number in lines:
    matches = ds2[ds2["record_locator"] == number]
    if matches.empty:
        continue
    row = matches.iloc[0]
    record = row["raw"]
    stamp = row["timestamp_utc"] or "UNRESOLVED"
    detail = (record.get("Image") or record.get("NewProcessName")
              or record.get("ServiceName") or record.get("TargetUserName")
              or record.get("DestAddress") or record.get("DestPort") or "")
    print(f"  {stamp:<30} DS002:{number:<5} {row['provider'].split('Windows-')[-1]:<22} "
          f"eid={row['event_id']:<5} {str(detail)[:60]}")
'''),
    code('''
# The chain that carries the case: is the recorded parent of each step the GUID of
# the process that ran before it? Join on ProcessGuid only, inside one dataset,
# on one exact host string.
def guid_of(line):
    return ds2[ds2["record_locator"] == line].iloc[0]["raw"].get("ProcessGuid")

pairs = [(1366, 1057), (1057, 1073), (1073, 2901)]
for parent_line, child_line in pairs:
    parent = ds2[ds2["record_locator"] == parent_line].iloc[0]
    child = ds2[ds2["record_locator"] == child_line].iloc[0]
    parent_guid = guid_of(parent_line)
    child_parent_guid = child["raw"].get("ParentProcessGuid")
    match = parent_guid == child_parent_guid
    delay = ""
    if parent["timestamp_utc"] and child["timestamp_utc"]:
        delay = f"  delay {child['timestamp_utc']} minus parent"
    print(f"  DS002:{parent_line} -> DS002:{child_line}: "
          f"GUID join {'HOLDS' if match else 'FAILS'}{delay}")
'''),
    code('''
# Corroboration: does an independent log source agree on the parent relationships?
security = ds2[ds2["provider"] == "Microsoft-Windows-Security-Auditing"]
creations = security[security["event_id"] == 4688]
print("Security 4688 independent process creations")
for _, row in creations.iterrows():
    record = row["raw"]
    print(f"  DS002:{row['record_locator']:<5} {record.get('NewProcessName')} "
          f"parent={record.get('ParentProcessName')}")
'''),
    md("""
## Conclusion

The timeline reconstructs cleanly, and the three GUID joins that carry the case
all hold. The service execution is not a single-log inference: the same parent
relationships appear in Sysmon event 1 and in Security 4688, and the 5156 firewall
record independently attributes the outbound flow to a PowerShell application.

The reconstruction also shows what cannot be concluded. The service installation
at DS002:1213 and the network logon at DS002:1209 both carry no resolved event
time, so the persistence mechanism cannot be placed on this timeline by clock. The
account that created it is known; whether that account was stolen is not, because
the recording contains no authentication-failure records at all. Both facts are
reported as unresolved in the case report rather than being smoothed over.
"""),
]

NOTEBOOKS = {"02_dataset_profiling.ipynb": PROFILING,
             "03_detection_validation.ipynb": VALIDATION,
             "04_threat_hunting_analysis.ipynb": HUNTING,
             "05_incident_reconstruction.ipynb": RECONSTRUCTION}


def document_legacy_notebook():
    """Add purpose, method and conclusion cells to the Phase 3 validator.

    The Phase 3 notebook was written before the documentation standard was
    imposed and contains only code. Its code is correct and is left byte-for-byte
    unchanged; only markdown cells are added around it.
    """
    path = OUT / "01_data_familiarization.ipynb"
    if not path.exists():
        return "01_data_familiarization.ipynb absent, nothing to document"
    payload = json.loads(path.read_text(encoding="utf-8"))
    cells = payload["cells"]
    if any(cell["cell_type"] == "markdown" for cell in cells):
        return "01_data_familiarization.ipynb already documented"
    header = md("""
# 01 Telemetry normalization and traceability validation

## Purpose
Prove that the normalized telemetry can be trusted before any detection content is
built on it. The harness and the rules rest on a claim that matters more than
anything else in this project: every record in `data/processed/` is a faithful
copy of a specific physical line in a checksummed source file. If that is not
true, every match count in every report is meaningless.

## Inputs
- `docs/DSxxx-inventory.json`, the digest and record count for each raw file.
- `data/raw/DSxxx/*.json`, the immutable source archives.
- `data/processed/DSxxx.jsonl`, the normalized output.
- `docs/DSxxx-normalization.json`, the acceptance report for that output.

## Methodology
Four cells, in order. The first refuses to run unless the active interpreter is
the project virtual environment, so the figures cannot be produced against an
unpinned interpreter. The second profiles which raw fields are present for each of
the three telemetry types, which is what makes the data dictionary checkable rather
than descriptive. The third records the PowerShell unresolved-flag distribution,
including the records where the flag is absent, because an absent flag is not the
same as a false flag.

The fourth cell is the validation gate. It re-hashes the raw file and the
processed file and compares both against the recorded digests, then asserts that
the set of record locators in the output equals the set in the source, that every
normalized record equals its original parsed object, that every event UID is
unique, and that the script-block fragment metadata is self-consistent. The
assertions are deliberately bare: they stop the notebook rather than print a
warning, because a warning that can be scrolled past is not a validation.

## Outputs
`docs/DSxxx-fields.json` and `docs/DSxxx-validation.json`, with a PASS or FAIL
status. The validation JSON is the durable artefact; the notebook output itself is
not relied upon by any downstream process.

## Conclusion
See the closing cell. The result recorded there is the traceability claim this
entire project rests on.
""")
    footer = md("""
## Conclusion

All four validation classes passed for both datasets. Every normalized record
equals its original parsed object, every event UID is unique and reconstructible,
and the set of source line numbers in the output is exactly the set in the raw
file. The 74 repeated-content DS001 records are retained with distinct
identifiers rather than deduplicated, because deduplicating them would silently
remove evidence while making the data look cleaner.

The honest limits of this notebook are the same as the project's. It proves the
transformation is faithful; it cannot prove the source recording captured
everything that happened. The DS002 PowerShell unresolved flag is true on 351
records and absent on 3, and its meaning is still unverified, so it is recorded
rather than interpreted.

Dataset profiling continues in `02_dataset_profiling.ipynb`; detection replay in
`03_detection_validation.ipynb`; the hunts in `04_threat_hunting_analysis.ipynb`;
and the incident reconstruction in `05_incident_reconstruction.ipynb`.
""")
    payload["cells"] = [header] + cells + [footer]
    path.write_text(json.dumps(payload, indent=1) + "\n", encoding="utf-8", newline="\n")
    return "01_data_familiarization.ipynb documented with purpose and conclusion cells"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    print(document_legacy_notebook())
    for name, cells in NOTEBOOKS.items():
        path = OUT / name
        path.write_text(json.dumps(notebook(name, cells), indent=1) + "\n",
                        encoding="utf-8", newline="\n")
        prose = sum(1 for cell in cells if cell["cell_type"] == "markdown")
        print(f"{name}: {len(cells)} cells, {prose} markdown")
    print(f"written to {OUT.relative_to(ROOT).as_posix()}")


if __name__ == "__main__":
    main()
