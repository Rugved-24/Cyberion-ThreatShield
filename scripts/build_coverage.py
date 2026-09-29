"""Generate the Phase 6 ATT&CK coverage layer from recorded test evidence.

Reads three recorded artefacts and nothing else:

- detections/test-results.csv, produced by scripts/test_all.py.
- detections/tuning-results.csv, produced by scripts/tune.py.
- the rules themselves, for the technique mapping and scope statements.

Writes coverage/layer-v2.json in ATT&CK Navigator layer format 4.5, matching
the structure of the frozen Phase 4 baseline. coverage/baseline.json is never
written by this script; its SHA-256 is re-read and recorded in the v2 layer so
that the pre-implementation position stays auditable next to the result.

Scoring is mechanical, so a status cannot be inflated by prose:

  Covered (2)          at least one rule matched its declared attack evidence
                       AND at least one tuning case for that technique shows the
                       tuned rule with zero residual benign matches.
  Partially Covered (1) at least one rule matched its declared attack evidence,
                       with no measured benign result available.
  Not Covered (0)      no rule matched declared attack evidence.

An empty declared evidence list can never produce Covered or Partially
Covered, which is what keeps CT-013 and CT-014 at zero.
"""

import argparse
import csv
import json
import sys
from hashlib import sha256
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_all as harness

ASSESSMENT_DATE = "2026-09-29"
STIX_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
            "6cda5ad8462c79e14fbb872f4e09059b18e0cfc4/enterprise-attack/"
            "enterprise-attack-19.2.json")
STIX_SHA256 = "DC1639CAA5501D720E280CF1CBD8FBE009884A0C9B3E6E9ED9D0C25166C3D8F4"
COLORS = {0: "#f4cccc", 1: "#fff2cc", 2: "#d9ead3"}
LABELS = {0: "Not Covered", 1: "Partially Covered", 2: "Covered"}

# technique id, name, ATT&CK 19.2 object version, tactics, Phase 4 evidence state
TECHNIQUES = [
    ("T1218.005", "Mshta", "3.0", ["Stealth"], "Candidate evidence"),
    ("T1059.001", "PowerShell", "1.5", ["Execution"], "Candidate evidence"),
    ("T1569.002", "Service Execution", "1.3", ["Execution"], "Candidate evidence"),
    ("T1033", "System Owner/User Discovery", "1.6", ["Discovery"], "Candidate evidence"),
    ("T1059.003", "Windows Command Shell", "1.5", ["Execution"], "Mapping review"),
    ("T1059.005", "Visual Basic", "1.5", ["Execution"], "Mapping review"),
    ("T1518.001", "Security Software Discovery", "1.5", ["Discovery"], "Mapping review"),
    ("T1027.010", "Command Obfuscation", "2.0", ["Stealth"], "Mapping review"),
    ("T1140", "Deobfuscate/Decode Files or Information", "2.0", ["Stealth"],
     "Added in Phase 6"),
    ("T1685", "Disable or Modify Tools", "1.0", ["Defense Impairment"], "Mapping review"),
    ("T1021.002", "SMB/Windows Admin Shares", "1.3", ["Lateral Movement"],
     "Needs corroboration"),
    ("T1047", "Windows Management Instrumentation", "1.6", ["Execution"],
     "Needs corroboration"),
    ("T1053.005", "Scheduled Task", "1.8",
     ["Execution", "Persistence", "Privilege Escalation"], "Needs corroboration"),
    ("T1543.003", "Windows Service", "1.6", ["Persistence", "Privilege Escalation"],
     "Needs corroboration"),
    ("T1547.001", "Registry Run Keys / Startup Folder", "2.1",
     ["Persistence", "Privilege Escalation"], "Evidence gap"),
    ("T1003.001", "LSASS Memory", "1.5", ["Credential Access"], "Needs corroboration"),
    ("T1110.003", "Password Spraying", "1.8", ["Credential Access"], "Evidence gap"),
    ("T1078", "Valid Accounts", "3.0",
     ["Stealth", "Persistence", "Privilege Escalation", "Initial Access"],
     "Needs corroboration"),
    ("T1105", "Ingress Tool Transfer", "2.6", ["Command and Control"],
     "Needs corroboration"),
    ("T1071.001", "Web Protocols", "1.5", ["Command and Control"], "Needs corroboration"),
    ("T1486", "Data Encrypted for Impact", "1.5", ["Impact"], "Evidence gap"),
]

GAPS = {
    "T1547.001": (
        "No registry record in DS002 writes a CurrentVersion\\Run or RunOnce target; the "
        "reviewed registry events cover Internet Settings, Delivery Optimization and "
        "notification keys only. The only 'Startup' text in the capture is unrelated. "
        "Minimal new dataset: a Sysmon-instrumented capture with event 13 writes to "
        "HKLM\\...\\CurrentVersion\\Run plus the resulting execution of the written "
        "value. Minimum acceptance: one labelled run-key write and one process creation "
        "whose parent or command line references the written value."
    ),
    "T1110.003": (
        "Neither capture contains Security 4625, so there is no authentication-failure "
        "series at all, and the recordings are too short to characterise a spray. "
        "Minimal new dataset: an authentication log spanning at least one hour with "
        "Security 4625, covering one spray against ten or more distinct accounts, plus "
        "a matched benign set of ordinary user password typos."
    ),
    "T1486": (
        "No labelled encryption-for-impact sequence exists. Generic file operations in "
        "Sysmon event 11 are not evidence of encryption, and this project's name is not "
        "evidence either. Minimal new dataset: a documented safe-emulation recording "
        "showing the rename or overwrite pattern against known file types together with "
        "the process that performed it."
    ),
    "T1047": (
        "DS002 records three WMI 5857 provider-start events and one WmiPrvSE.exe process "
        "creation, which is provider startup rather than an adversary WMI operation. No "
        "rule was written because a WmiPrvSE rule would match ordinary Windows on every "
        "host. Minimal new dataset: a WMI-Activity 5858 or 5861 operation record with an "
        "attributable process, or a child process created through WMI."
    ),
    "T1053.005": (
        "The only Task Scheduler record in DS002 is event 129, a task deletion, so there "
        "is no task creation or action definition to build on. Minimal new dataset: "
        "Security 4698 or 4702 with the task XML action and a Sysmon 1 process creation "
        "for the task binary, plus a benign scheduled-task baseline."
    ),
    "T1071.001": (
        "Deliberately left without a rule. T1071.001 is the reserved gap for HUNT-002, "
        "which must run before any rule is written so that the hypothesis is recorded "
        "independently of the detection. The evidence is DS002:1073 creating the process, "
        "DS002:2513 connecting it to 10.10.10.5:80, and DS002:1827 for the script. See "
        "hunts/HUNT-002.md."
    ),
}


def read_rows(path):
    if not path.exists():
        raise SystemExit(f"missing {path}; run the producing script first")
    return list(csv.DictReader(path.open(encoding="utf-8")))


def rule_index(root):
    index = {}
    for path in sorted((root / "rules").rglob("*.yml")):
        if path.name.startswith("_"):
            continue
        rule = harness.load_yaml(path)
        index[str(rule["id"])] = {
            "path": path.relative_to(root).as_posix(),
            "title": rule["title"],
            "techniques": rule["x-attack"]["techniques"],
            "level": rule["level"],
            "rationale": " ".join(rule["x-severity"]["rationale"].split()),
            "expected": rule["x-evidence"]["expected_event_uids"] or [],
            "negatives": rule["x-evidence"]["negative_event_uids"] or [],
            "benign_note": " ".join(rule["x-benign-review"]["note"].split()),
            "benign_status": rule["x-benign-review"]["status"],
        }
    return index


def write_matrix(root, layer, summary, baseline_sha):
    counts = {label: sum(1 for item in layer["techniques"] if item["score"] == score)
              for score, label in LABELS.items()}
    lines = [
        "# Cyberion ThreatShield: tested coverage matrix (Phase 6)",
        "",
        "Generated by `scripts/build_coverage.py` from `detections/test-results.csv` and",
        "`detections/tuning-results.csv`. Do not hand-edit; edit the rules and re-run.",
        f"Assessment date: {ASSESSMENT_DATE} UTC. Framework: MITRE ATT&CK 19.2.",
        "",
        f"**Covered {counts['Covered']} · Partially Covered {counts['Partially Covered']} · "
        f"Not Covered {counts['Not Covered']} · {len(layer['techniques'])} technique IDs.**",
        "",
        "## Scoring contract",
        "",
        "| Score | Label | Mechanical condition |",
        "| --- | --- | --- |",
        "| 2 | Covered | A rule matched its declared attack evidence **and** a tuning case "
        "shows the tuned rule with zero residual benign matches. |",
        "| 1 | Partially Covered | A rule matched its declared attack evidence, but no "
        "measured benign comparison exists for that technique. |",
        "| 0 | Not Covered | No rule matched declared attack evidence, or no rule exists. |",
        "",
        "A rule with an empty declared evidence list can never score 1 or 2. That is why",
        "CT-013 and CT-014 stay at 0 even though both were authored, tuned and tested.",
        "",
        "## Matrix",
        "",
        "| Technique | ATT&CK 19.2 version | Tactics (taxonomy) | Status | Rules | Severities |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for identifier, name, score, names in summary:
        entry = next(item for item in layer["techniques"] if item["techniqueID"] == identifier)
        meta = {item["name"]: item["value"] for item in entry["metadata"]}
        lines.append(
            f"| [{identifier} - {name}](https://attack.mitre.org/versions/v19/techniques/"
            f"{identifier.replace('.', '/')}) | {meta['Object version']} | "
            f"{meta['Tactics (taxonomy)']} | {LABELS[score]} | {names} | "
            f"{meta['Rule severities']} |"
        )
    lines += [
        "",
        "## Evidence gaps and the minimum dataset needed",
        "",
    ]
    for identifier in GAPS:
        entry = next(item for item in layer["techniques"] if item["techniqueID"] == identifier)
        if entry["score"] != 0:
            continue
        lines.append(f"### {identifier}")
        lines.append("")
        lines.append(GAPS[identifier])
        lines.append("")
    lines += [
        "## Baseline and provenance",
        "",
        "- Phase 4 baseline: `coverage/baseline.json`, frozen, SHA-256 "
        f"`{baseline_sha}`.",
        "- It records 20 technique IDs, all Not Covered, before any rule was authored. It is",
        "  retained unmodified so the before and after positions are comparable.",
        "- T1140 was added in Phase 6; it is Stealth, object version 2.0, no sub-techniques,",
        "  last modified 12 May 2026 in v19.2.",
        "- Pinned STIX source: " + STIX_URL,
        f"- STIX SHA-256: `{STIX_SHA256}`.",
        "- Navigator layer: `coverage/layer-v2.json`, format 4.5, attack domain 19.",
        "",
        "## What this matrix does not claim",
        "",
        "- Tactic labels are ATT&CK taxonomy. They do not assert that the objective occurred",
        "  in these captures.",
        "- An unlisted technique is unassessed. 12 of the technique's sub-techniques and the",
        "  rest of the ATT&CK matrix are out of scope for this engagement.",
        "- Partially Covered does not mean the technique is detected in a client environment.",
        "  It means a rule matched real attack telemetry here and its false-positive rate is",
        "  unmeasured, because the recordings contain no separately collected clean",
        "  environment. See `evidence/tuning/benign-baseline.json` for exactly what was used.",
        "- The two tuned rules that now match nothing were tuned against benign activity,",
        "  which is a precision result and not a detection result.",
        "",
    ]
    path = root / "coverage/matrix-v2.md"
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return path.relative_to(root).as_posix()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    results = {row["rule_id"]: row for row in read_rows(root / "detections/test-results.csv")}
    tuning = {row["id"]: row for row in read_rows(root / "detections/tuning-results.csv")}
    rules = rule_index(root)
    tuned = {case["rule"]: case for case in tuning.values()}
    by_technique = {}
    for identifier, entry in rules.items():
        row = results.get(identifier)
        if row is None:
            raise SystemExit(f"{identifier} has no test result row")
        case = tuned.get(entry["path"])
        attack_hits = int(row["expected_hits"].split("/")[0])
        for technique in entry["techniques"]:
            by_technique.setdefault(technique, []).append(
                {"rule": entry, "result": row, "attack_hits": attack_hits,
                 "negatives_held": row["negatives_held"],
                 "measured_benign": case is not None and int(case["after_benign"]) == 0}
            )
    techniques, summary = [], []
    for identifier, name, version, tactics, state in TECHNIQUES:
        entries = by_technique.get(identifier, [])
        with_evidence = [item for item in entries if item["attack_hits"] > 0]
        measured = [item for item in with_evidence if item["measured_benign"]]
        if measured:
            score, basis = 2, ("rule matched declared attack evidence and a tuning case "
                               "shows zero residual benign matches")
        elif with_evidence:
            score, basis = 1, ("rule matched declared attack evidence; no measured benign "
                               "comparison exists for this technique")
        else:
            score, basis = 0, ("no rule matched declared attack evidence"
                               if entries else "no rule authored for this technique")
        names = ", ".join(item["rule"]["title"].split(" - ")[0] for item in entries) or "None"
        levels = ", ".join(sorted({item["rule"]["level"] for item in entries})) or "n/a"
        if score == 0 and identifier in GAPS:
            comment = f"Not Covered. {GAPS[identifier]}"
        elif entries:
            detail = []
            for item in entries:
                hit = item["result"]["expected_hits"]
                detail.append(f"{item['rule']['title'].split(' - ')[0]} evidence {hit}, "
                              f"negatives {item['negatives_held']}")
            comment = f"{LABELS[score]}. Basis: {basis}. " + "; ".join(detail) + "."
        else:
            comment = f"Not Covered. {basis}. Recorded as an evidence gap with the "\
                      f"minimum dataset needed; no rule was manufactured for it."
        techniques.append({
            "techniqueID": identifier,
            "enabled": True,
            "score": score,
            "color": COLORS[score],
            "comment": comment,
            "metadata": [
                {"name": "Coverage status", "value": LABELS[score]},
                {"name": "Evidence state", "value": state},
                {"name": "Tactics (taxonomy)", "value": ", ".join(tactics)},
                {"name": "Object version", "value": version},
                {"name": "Supporting rules", "value": names},
                {"name": "Rule severities", "value": levels},
                {"name": "Scored from", "value": basis},
            ],
        })
        summary.append((identifier, name, score, names))
    baseline = root / "coverage/baseline.json"
    baseline_sha = sha256(baseline.read_bytes()).hexdigest().upper()
    counts = {label: sum(1 for item in techniques if item["score"] == score)
              for score, label in LABELS.items()}
    layer = {
        "name": "Cyberion ThreatShield - Phase 6 tested coverage",
        "versions": {"attack": "19", "navigator": "5.3.2", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            f"{len(techniques)} technique IDs scored from recorded replay results, not "
            f"from intent. Covered {counts['Covered']}, Partially Covered "
            f"{counts['Partially Covered']}, Not Covered {counts['Not Covered']}. A "
            "Partially Covered entry has a rule that matched real attack telemetry but "
            "no measured benign comparison, because the recordings contain no separately "
            "collected clean environment. Associated tactics are ATT&CK taxonomy and do "
            "not assert that the objective occurred in these captures."
        ),
        "filters": {"platforms": ["Windows"]},
        "layout": {"layout": "side", "showID": True, "showName": True,
                   "showAggregateScores": False, "expandedSubtechniques": "annotated"},
        "sorting": 0,
        "hideDisabled": False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "techniques": techniques,
        "gradient": {"colors": ["#f4cccc", "#fff2cc", "#d9ead3"], "minValue": 0, "maxValue": 2},
        "legendItems": [{"label": f"{LABELS[0]} (assessed)", "color": COLORS[0]},
                        {"label": LABELS[1], "color": COLORS[1]},
                        {"label": LABELS[2], "color": COLORS[2]}],
        "metadata": [
            {"name": "ATT&CK release", "value": "19.2"},
            {"name": "Assessment date (UTC)", "value": ASSESSMENT_DATE},
            {"name": "Pinned STIX URL", "value": STIX_URL},
            {"name": "STIX SHA-256", "value": STIX_SHA256},
            {"name": "Distinct assessed technique IDs", "value": str(len(techniques))},
            {"name": "Rules authored", "value": str(len(rules))},
            {"name": "Rules with matched attack evidence", "value": str(sum(
                1 for entry in rules.values() if entry["expected"]))},
            {"name": "Rules with no attacker instance in telemetry", "value": str(sum(
                1 for entry in rules.values() if not entry["expected"]))},
            {"name": "Phase 4 baseline file", "value": "coverage/baseline.json"},
            {"name": "Phase 4 baseline SHA-256", "value": baseline_sha},
            {"name": "Baseline is frozen", "value": "Yes; this script never writes it"},
            {"name": "Scoring source", "value": "detections/test-results.csv and "
                                                "detections/tuning-results.csv"},
            {"name": "Benign baseline", "value": "evidence/tuning/benign-baseline.json; "
                                                  "attributed background activity inside "
                                                  "the attack recordings, not a clean "
                                                  "environment"},
        ],
    }
    output = root / "coverage/layer-v2.json"
    output.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8", newline="\n")
    write_matrix(root, layer, summary, baseline_sha)
    for identifier, name, score, names in summary:
        print(f"{identifier:<11} v{score}  {LABELS[score]:<19} {name[:38]:<38} {names}")
    print(f"\nCovered={counts['Covered']} Partially={counts['Partially Covered']} "
          f"NotCovered={counts['Not Covered']} total={len(techniques)}")
    print(f"baseline.json SHA-256 {baseline_sha} (frozen)")
    print(f"written: {output.relative_to(root).as_posix()}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, harness.RuleError) as error:
        sys.exit(f"Coverage build stopped: {error}")
