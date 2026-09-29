# Purple-team exercise plan

PRD section 11 optional enhancement. This plan is written, not executed: the host
has no hypervisor, so no isolated lab VM could be created. See
`docs/environment-gaps.md`.

The plan exists because the coverage matrix says which techniques are **not**
covered, and only an exercise can tell you whether a detection works against an
operator who knows it exists. A rule validated only against its own author's
dataset has not met an adversary.

## 1. Preconditions

None of this may be run on a daily-use machine. The engagement instruction and
this plan both require an isolated environment.

| Requirement | Detail |
| --- | --- |
| Host | Windows 11 or Server, hardware virtualization enabled |
| Guest | One Windows evaluation VM, fully patched, snapshot before each test |
| Sysmon | Installed in the guest with a documented configuration, including event 1, 3, 7, 10, 11, 12, 13, 22 |
| Audit policy | Security auditing enabled for process creation, logon, service installation and share access |
| PowerShell | Script block logging enabled, and its enablement **verified** before the exercise |
| Red team tooling | Atomic Red Team |
| Network | An isolated virtual switch, or a lab segment with no route to production |

Verification before the first test: confirm a 4104 record appears for a benign
script, and confirm 4625 failures are recorded. A rule cannot be declared failed
if the telemetry to observe it was never collected.

## 2. Scope, chosen deliberately

Only tests that are **safe, produce useful defensive telemetry, and are reversible
by deleting the VM**. The engagement instruction forbids destructive,
credential-stealing or persistence-heavy tests merely to satisfy a number.

| Test intent | ATT&CK | Why it is in scope | Safety note |
| --- | --- | --- | --- |
| Registry run key write | T1547.001 | Closes a documented evidence gap | Reversible; delete the key afterwards |
| Windows service with a script image path | T1543.003 | Existing rule CT-011, currently untested against a true positive beyond the recording | Delete the service afterwards |
| Scheduled task creation | T1053.005 | Closes a gap; currently only a task-deletion event exists in the data | Delete the task afterwards |
| WMI process creation | T1047 | Closes a gap; only provider-start events exist today | Reversible |
| Encoded PowerShell download and execute | T1105, T1027.010, T1140 | Exercises CT-002, CT-008, CT-009 against a live operator | Use an inert payload, never real malware |
| Service-to-shell chain | T1569.002 | Exercises CT-C02 with a real activation rather than a recording | Delete the service |
| Credential memory access | T1003.001 | Exercises CT-013, which currently matches only benign activity | Use a read-only access request; do not dump |
| Controlled local account spray | T1110.003 | Closes a gap; no 4625 exists in the current data | Use invented local accounts only, never domain accounts |
| Beacon simulation to a lab sink | T1071.001 | Closes the gap left inconclusive by HUNT-002 | Point at a lab sink, never a real host |
| Lab encryption marker | T1486 | Closes a gap | A marker file in a lab directory only, never real data |

Explicitly out of scope: credential theft against real accounts, destructive
payloads, persistence on anything outside the VM, and any test whose telemetry
would be indistinguishable from a real intrusion on a production network.

## 3. Exercise loop

Per test:

1. Snapshot the VM. Record the snapshot identifier.
2. Record the expected ATT&CK technique and the detection rules expected to fire.
3. Execute exactly one test. Record the test identifier and the command used.
4. **Do not assume the rule fired.** Collect the telemetry, then run
   `scripts/test_all.py` against the collected records and record the actual match
   count and event references.
5. Classify the outcome as one of: detected with no analyst action needed;
   detected but ambiguous; not detected.
6. Record the gap. A test that produces no telemetry teaches you about the
   telemetry configuration; a test that produces telemetry nobody detected teaches
   you about the rules.
7. Restore the snapshot.

The critical discipline is step 4. Running Atomic Red Team is not validation. A
test that executed and a rule that fired are separate facts, and only the second
one is a detection result.

## 4. Measurement

| Metric | Definition | Target |
| --- | --- | --- |
| Detection rate | Tests where the expected rule matched recorded telemetry | Baseline on first run; no target is claimed before data exists |
| Telemetry completeness | Tests that produced the telemetry the rule requires | 100% |
| False-positive rate | Benign administrative activity matching any rule | Measured, not assumed; requires a benign baseline |
| Analytic value | Whether the alert would change an analyst's next action | Assessed per test |

No target is set for the detection rate in advance. Setting one before the first
exercise would be inventing a benchmark.

## 5. Updating the deliverables

After an exercise, and only from recorded results:

- Add the collected records as a new dataset with full provenance, following
  `docs/datasets.md`. Locally generated telemetry is labelled as locally
  generated and is never presented as public incident data.
- Re-run `scripts/test_all.py`, `scripts/tune.py` and `scripts/build_coverage.py`.
  The coverage matrix will move on its own; do not edit it by hand.
- Re-run `scripts/prd_compliance.py` to confirm the change did not break a
  requirement.
- Record the result in `PROGRESS.md` and update `docs/prd-compliance-report.md`.

A technique moves from Not Covered only when a rule matches recorded attack
evidence, exactly as for the existing telemetry. Generating the telemetry
locally does not relax that rule; it satisfies it.

## 6. What this plan cannot achieve

It cannot establish a false-positive rate. That requires a benign recording of
ordinary activity, which is a separate exercise, and it is the single change that
would move the most techniques from Partially Covered to Covered.
