"""Measure false-positive tuning with before and after replay for three rules.

One script produces every tuning artefact, so the numbers in
evidence/tuning/*.md are generated rather than typed:

- detections/tuning-results.csv, one row per tuning case.
- evidence/tuning/benign-baseline.json, the comparison population used.
- evidence/tuning/CT-0xx-false-positive.md, the narrative record referenced by
  the corresponding rule's references block.

The matching code is imported from scripts/test_all.py, so a tuning figure and a
rule test figure can never disagree about what a condition means.

The comparison population is not a separately collected clean recording. It is
the set of records inside DS001 and DS002 that can be attributed to ordinary
Windows or vendor activity from fields that are present in the record itself,
for example an LSASS handle opened by the logon session manager, a SYSVOL read
by a machine account, or a logon by a machine account. That is weaker than a
purpose-built benign baseline and the limitation is recorded in every generated
document; it is used because it is real, attributable telemetry rather than
invented data.
"""

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_all as harness

DS1 = "25AA24B5F631F19AC23F64DB116C23E632295FB5F59040E966FA47E7758B2A32"
DS2 = "968C4B699F7239D106577B2B8E206EDFAF812F193A60E663966258AF67A56ACC"
U1 = f"DS001:{DS1}"
U2 = f"DS002:{DS2}"

BENIGN_BASELINE = {
    "purpose": "Comparison population for false-positive tuning.",
    "status": "attributable background activity inside the recorded attack datasets",
    "not_a_clean_baseline": (
        "These recordings are adversary-emulation captures. The records listed here were "
        "attributed to ordinary Windows or vendor activity using fields present in the "
        "record itself. They are not a separately collected clean environment, they are "
        "not exhaustive, and they are not a substitute for one. A client deployment must "
        "collect its own baseline before relying on any false-positive rate in this file."
    ),
    "benign_groups": [
        {
            "group": "logon_session_manager_lsass_access",
            "attribution": (
                "Sysmon event 10 handles to lsass.exe opened by svchost.exe whose call "
                "trace resolves to lsm.dll, the logon session manager, or sysmain.dll, the "
                "memory compression driver. Both run on every sign-in and under memory "
                "pressure."
            ),
            "event_uids": [f"{U2}:{line}" for line in (2466, 2467, 3108, 4276, 4278, 4332, 4333)],
        },
        {
            "group": "domain_controller_sysvol_replication",
            "attribution": (
                "Security 5140 and 5145 share events on the SYSVOL administrative share "
                "by the machine account MORDORDC$ for gpt.ini group policy template "
                "files. This is ordinary Group Policy replication on a domain controller."
            ),
            "event_uids": [f"{U2}:{line}" for line in (728, 729, 730)],
        },
        {
            "group": "machine_account_network_logons",
            "attribution": (
                "Security 4624 logons of type 3 by the machine account MORDORDC$ on the "
                "domain controller MORDORDC.theshire.local. Machine logons dominate type 3 "
                "on any busy domain controller. These records are on a different host "
                "from the attack evidence and the two host names are deliberately not "
                "merged; the comparison is valid because the rule logic is host agnostic, "
                "and it is stated this way so that no same-host relationship is implied."
            ),
            "event_uids": [f"{U2}:{line}" for line in (289, 700, 703, 709, 726, 3199)],
        },
        {
            "group": "click_to_run_office_updater",
            "attribution": (
                "Sysmon event 1 creation of OfficeC2RClient.exe under the Click-to-Run "
                "shared folder, parented by svchost.exe, following a recorded scheduled "
                "task registration. Vendor update activity."
            ),
            "event_uids": [f"{U2}:363", f"{U2}:359"],
        },
    ],
}

CASES = [
    {
        "id": "CT-012",
        "title": "Network logon by a named user account",
        "rule": "rules/windows/auth_network_logon_interactive_account.yml",
        "before": {
            "selection_type": {
                "EventID": 4624,
                "Provider": "Microsoft-Windows-Security-Auditing",
                "LogonType": 3,
            },
            "condition": "selection_type",
        },
        "change": (
            "Added a filter excluding target accounts whose name ends with the "
            "machine-account marker, and a required check that the account name is "
            "present at all."
        ),
        "tradeoff": (
            "Any attack that authenticates as a machine account is now invisible to this "
            "rule. That is an accepted loss: machine-account authentication is dominated "
            "by domain replication and service traffic, so keeping those matches would "
            "mean giving up the signal entirely. The residual risk is real and is why the "
            "playbook asks the analyst to confirm the account owner rather than to trust "
            "the alert on its own."
        ),
        "benign_group": "machine_account_network_logons",
        "attack_uids": [f"{U2}:1209"],
        "attack_lines": "DS002:1209",
        "observations": [
            "Before: the logon type alone also matched the domain controller's own "
            "machine-account logons, which are the majority of type 3 activity there.",
            "After: only the named account remains, and the type 3 logons for the "
            "machine account are no longer reported.",
            "The benign and the malicious matches are on two different recorded hosts, "
            "MORDORDC.theshire.local and WORKSTATION6.theshire.local. The host names are "
            "not merged, so this is a comparison of rule logic across two hosts rather "
            "than a same-host before and after, and it is described that way in the "
            "generated record.",
        ],
    },
    {
        "id": "CT-013",
        "title": "Process access to LSASS by a non-system caller",
        "rule": "rules/windows/sysmon_process_access_lsass_memory.yml",
        "before": {
            "selection_target": {
                "EventID": 10,
                "Provider": "Microsoft-Windows-Sysmon",
                "TargetImage|endswith": "\\lsass.exe",
            },
            "condition": "selection_target",
        },
        "change": (
            "Added two exclusions on the recorded call trace: the logon session manager "
            "module lsm.dll and the memory compression driver sysmain.dll."
        ),
        "tradeoff": (
            "A malicious process that injected code into lsm.dll or sysmain.dll would be "
            "suppressed, because the exclusion matches the module in the trace rather "
            "than the identity of the caller. A production deployment should allow-list "
            "by signed binary path instead. The rule now matches nothing in this "
            "telemetry, so it is retained as an untested candidate and T1003.001 is left "
            "at Not Covered rather than being claimed as detected."
        ),
        "benign_group": "logon_session_manager_lsass_access",
        "attack_uids": [],
        "attack_lines": "none; no attacker instance of this behaviour is present",
        "observations": [
            "Before: every match was ordinary Windows activity, so the untuned rule had "
            "a false-positive rate of one hundred per cent in this telemetry.",
            "After: the rule is silent here. That is a precision improvement, not a "
            "detection success, and the two are recorded separately on purpose.",
            "The access rights in the excluded records were query-information and "
            "memory-read handles consistent with the attributed Windows callers, which "
            "is the reason for the exclusion and not the process name alone.",
        ],
    },
    {
        "id": "CT-014",
        "title": "Admin or service share access by a user account",
        "rule": "rules/windows/file_share_admin_share_remote_service_access.yml",
        "before": {
            "selection_event": {
                "EventID": [5140, 5145],
                "Provider": "Microsoft-Windows-Security-Auditing",
            },
            "condition": "selection_event",
        },
        "change": (
            "Added a filter excluding machine accounts and a filter excluding group "
            "policy template files, which are the only objects read on the domain "
            "controller SYSVOL share in this recording."
        ),
        "tradeoff": (
            "The two filters are narrow and specific to this recording's share layout. "
            "An environment where backups run under a named service account, or where a "
            "different policy file set is replicated, would need both filters revisited. "
            "The rule matches nothing in this telemetry and must not be read as evidence "
            "that lateral movement is covered."
        ),
        "benign_group": "domain_controller_sysvol_replication",
        "attack_uids": [],
        "attack_lines": "none; no attacker instance of remote service execution is present",
        "observations": [
            "Before: all three matches were domain controller SYSVOL replication by a "
            "machine account for group policy templates.",
            "After: the rule is silent on this recording.",
            "The source dataset directory name refers to a PsExec-style lateral movement "
            "scenario, but no record in the capture shows remote service execution, and "
            "a directory name is not evidence. This is recorded so that the absence is "
            "explicit rather than assumed.",
        ],
    },
]


def replay(frames, detection, condition):
    hits = []
    for dataset, frame in frames.items():
        mask = harness.evaluate(frame, condition, detection)
        hits.extend(frame[mask].to_dict("records"))
    return hits


def classify(hits, case):
    attack = set(case["attack_uids"])
    matched = {item["event_uid"] for item in hits}
    return (sorted(matched & attack), sorted(matched - attack))


def run_case(case, root, frames):
    before_hits = replay(frames, case["before"], case["before"]["condition"])
    after_rule = harness.load_yaml(root / case["rule"])
    after_detection = after_rule["detection"]
    after_hits = replay(frames, after_detection, after_detection["condition"])
    before_attack, before_benign = classify(before_hits, case)
    after_attack, after_benign = classify(after_hits, case)
    lost = sorted(set(before_attack) - set(after_attack))
    group = next(item for item in BENIGN_BASELINE["benign_groups"]
                 if item["group"] == case["benign_group"])
    expected_benign = set(group["event_uids"])
    return {
        "id": case["id"],
        "title": case["title"],
        "rule": case["rule"],
        "before_matches": len(before_hits),
        "before_benign": len(before_benign),
        "before_attack": len(before_attack),
        "after_matches": len(after_hits),
        "after_benign": len(after_benign),
        "after_attack": len(after_attack),
        "known_benign_suppressed": len(expected_benign & {item["event_uid"] for item in before_hits}),
        "known_benign_remaining": len(expected_benign & {item["event_uid"] for item in after_hits}),
        "attack_matches_lost": len(lost),
        "attack_uids_remaining": ";".join(after_attack) or "none",
        "residual_benign_uids": ";".join(after_benign[:20]) or "none",
        "status": "PASS" if not lost and not after_benign else "REVIEW",
    }


def write_markdown(case, result, root):
    lines = [
        f"# {case['id']} false-positive tuning record",
        "",
        f"Behaviour: {case['title']}",
        f"Shipped rule: `{case['rule']}`",
        "Generated by `scripts/tune.py`. Do not edit the figures by hand.",
        "",
        "## Observed false positives",
        "",
        result["before_benign"] and
        f"The untuned logic produced {result['before_matches']} matches, of which "
        f"{result['before_benign']} were attributed benign activity and "
        f"{result['before_attack']} were the expected attack evidence." or
        "The untuned logic produced no matches in this telemetry.",
        "",
        "## Change made",
        "",
        case["change"],
        "",
        "## Before and after",
        "",
        "| Measure | Before | After |",
        "| --- | --- | --- |",
        f"| Total matches | {result['before_matches']} | {result['after_matches']} |",
        f"| Attributed benign matches | {result['before_benign']} | {result['after_benign']} |",
        f"| Expected attack matches | {result['before_attack']} | {result['after_attack']} |",
        f"| Known benign group suppressed | {result['known_benign_suppressed']} | "
        f"{result['known_benign_remaining']} |",
        "",
        "## Attack evidence that must survive the change",
        "",
        f"Declared evidence: {case['attack_lines']}.",
        f"Attack matches retained after tuning: {result['after_attack']} "
        f"({result['attack_uids_remaining']}).",
        f"Attack matches lost by the change: {result['attack_matches_lost']}.",
        "",
        "## Trade-off accepted",
        "",
        case["tradeoff"],
        "",
        "## Observations",
        "",
        *[f"- {item}" for item in case["observations"]],
        "",
        "## Comparison population",
        "",
        BENIGN_BASELINE["not_a_clean_baseline"],
        "",
    ]
    path = root / f"evidence/tuning/{case['id']}-false-positive.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return path.relative_to(root).as_posix()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    frames = harness.load_datasets(root)
    results = []
    for case in CASES:
        result = run_case(case, root, frames)
        result["record"] = write_markdown(case, result, root)
        results.append(result)
    baseline_path = root / "evidence/tuning/benign-baseline.json"
    baseline_path.write_text(json.dumps(BENIGN_BASELINE, indent=2) + "\n", encoding="utf-8", newline="\n")
    results_path = root / "detections/tuning-results.csv"
    fields = ["id", "title", "rule", "before_matches", "before_benign", "before_attack",
              "after_matches", "after_benign", "after_attack", "known_benign_suppressed",
              "known_benign_remaining", "attack_matches_lost", "attack_uids_remaining",
              "residual_benign_uids", "status", "record"]
    with results_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)
    for result in results:
        print(f"{result['id']}  {result['status']:<6} "
              f"before={result['before_matches']} (benign {result['before_benign']}, "
              f"attack {result['before_attack']})  "
              f"after={result['after_matches']} (benign {result['after_benign']}, "
              f"attack {result['after_attack']})  lost={result['attack_matches_lost']}")
    review = [item for item in results if item["status"] != "PASS"]
    print(f"\ncases={len(results)} pass={len(results) - len(review)} review={len(review)}")
    print(f"results: {results_path.relative_to(root).as_posix()}")
    return 1 if review else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, harness.RuleError, ValueError, KeyError) as error:
        sys.exit(f"Tuning stopped: {error}")
