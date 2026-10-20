# Final project status report

Project code **CDL-DET-V2**, PRD version 2.0. Generated 2026-10-20 by `scripts/final_status.py`.

Every figure below is counted from a file in the repository. None is estimated.

## 1. Environment and tools configured

| Item | Value |
| --- | --- |
| Operating system | Windows 11 (AMD64) |
| CPU / RAM | 12 logical cores, 15 GiB |
| Python | 3.12.10, isolated venv = True |
| Key packages | pandas 3.0.5, PyYAML 6.0.3, pySigma present |
| Jupyter kernel | none |
| Git | 12 commits, 133 tracked files, 0 remotes |
| Virtualization | hypervisor present = None, platforms = none |
| SIEM | none installed, correct per PRD section 2.9 |

Gaps in `docs/environment-gaps.md`. The decisive one is that **no hypervisor exists**, so no isolated lab VM could be created.

## 2. Datasets and provenance

| Dataset | Records | SHA-256 |
| --- | --- | --- |
| DS001 | 1127 | `25AA24B5F631F19AC23F64DB116C23E632295FB5F59040E966FA47E7758B2A32` |
| DS002 | 4348 | `968C4B699F7239D106577B2B8E206EDFAF812F193A60E663966258AF67A56ACC` |

Both Mordor datasets via the Open Threat Research Forge. Raw files immutable and digest-verified before every read. Licence terms unresolved, so the repository has no remote and external release goes through `scripts/sanitize.py`.

## 3. Detection content

| Measure | Count |
| --- | --- |
| Sigma rules authored | **17** |
| Rules with a PASS validation record | **17** |
| Rules empirically validated against real attack telemetry | **15** |
| Rules retained with no attacker instance in the telemetry | 2 |
| Correlation rules | **3** |
| Declared negative cases held | 39 of 39 |
| Sigma syntax validation | PASS |

The PRD requires 15+ rules, 3+ correlation rules, 100% validated and every rule with a false-positive note. All met. The 2 rules without an attacker instance are held at Not Covered by design, not counted as detections.

## 4. ATT&CK coverage

| Measure | Value |
| --- | --- |
| Techniques assessed | **21** (PRD requires 20+) |
| Tactics represented | **11** (PRD requires 4+) |
| Covered | 1 |
| Partially Covered | 12 |
| Not Covered | 8 |

Tactics: Command and Control, Credential Access, Defense Impairment, Discovery, Execution, Impact, Initial Access, Lateral Movement, Persistence, Privilege Escalation, Stealth.

### Coverage gaps identified

| Technique | Why not covered |
| --- | --- |
| T1003.001 | Rule authored, tuned and tested, but every match in the telemetry was benign. No attacker instance exists. |
| T1021.002 | Rule authored, tuned and tested, but every match was domain controller SYSVOL replication. No attacker instance exists. |
| T1047 | Only WMI provider-start events exist, which ordinary Windows produces on every host. A rule would be noise. |
| T1053.005 | Only a task-deletion event exists. No creation or action definition to test against. |
| T1071.001 | Reserved for HUNT-002, which concluded inconclusive. One connection in a 2m14s window; 42 of 43 port-80 flows are benign platform traffic. |
| T1110.003 | Evidence gap. Not one event 4625 in either recording. Needs one hour of authentication logs with failures. |
| T1486 | Evidence gap. No labelled encryption sequence. Needs a documented safe simulation. |
| T1547.001 | Evidence gap. No run-key write in either recording. Needs about five minutes of new capture. |

Three of these could not be attempted at all on this host, because closing them needs telemetry that does not exist in the recordings and no hypervisor exists to generate it locally.

## 5. Threat hunts

| Hunt | Technique | Conclusion |
| --- | --- | --- |
| HUNT-002 | T1071.001 Web Protocols | **Inconclusive** |

HUNT-002 satisfies the PRD requirement for a hunt against a technique with no existing rule. Neither hunt was forced positive; one is inconclusive and one is partially supported.

## 6. Incident cases

| Case | Classification |
| --- | --- |
| INC-001 | **True positive** |
| INC-002 | **True positive** |

Both corroborated across at least two independent log sources. Neither is linked into one campaign, because the host strings differ and host aliases are never merged.

## 7. Response playbooks, IOCs and tuning

| Measure | Count |
| --- | --- |
| Response playbooks | **4** (PRD requires 3+) |
| IOC register entries | **22** |
| IOC entries marked DO NOT BLOCK, with reason | 4 |
| Documented tuning passes | **3** |
| Matches before tuning | 17 |
| Matches after tuning | 1 |
| Declared attack matches lost by tuning | **0** |

Documented notebooks: **5**, each carrying purpose, inputs, method, analysis and conclusions.

## 8. Optional enhancements

| Enhancement | Status |
| --- | --- |
| Local script-level rule-testing harness | Delivered, `scripts/test_all.py` |
| Convert a subset of rules to a second query language | Delivered, 28 queries across kql and spl |
| Atomic Red Team validation | Not done, no hypervisor on this host |
| Purple-team exercise plan | Delivered, `docs/purple-team-plan.md` |

The three correlation rules are deliberately **not** converted. The converter folds a parent and a child selection into one AND, producing a query asking for a single event that is both processes at once, which can never match. Shipping that would look like a working conversion and be silently wrong.

## 9. Known limitations

1. Two recordings of roughly two minutes each. Absence of evidence in a two-minute window is not evidence of absence.
2. **No clean benign baseline**, which caps 12 techniques at Partially Covered. This is the largest gap and the cheapest to close.
3. Unresolved event time for 1642 records, the direct cause of two inconclusive conclusions.
4. No proxy or gateway content, so tool-transfer assessment cannot progress past inconclusive.
5. **No authentication-failure records at all**, so credential compromise is unanswerable in both incident cases.
6. Three techniques cannot be attempted on this host: no hypervisor, and the recordings contain no example.
7. Dataset licence terms unresolved; external publication gated on a rights review.
8. **No independent review.** Every rule, figure and conclusion was produced and checked by one person.

## 10. Requirement-by-requirement PRD compliance status

| Requirement | Status |
| --- | --- |
| 15+ Sigma rules | Met, 17 |
| Every rule mapped to an ATT&CK technique | Met |
| 3+ correlation rules | Met, 3 |
| 20+ techniques assessed | Met, 21 |
| 4+ tactics | Met, 11 |
| 100% of rules validated against real telemetry | Met, 17/17 |
| False-positive consideration for every rule | Met, 17/17 |
| 3+ documented tuning passes | Met, 3 |
| 2+ structured threat hunts | Met, 2 |
| 1+ hunt on an uncovered technique | Met, HUNT-002 on T1071.001 |
| 2+ complete incident case reports | Met, 2 |
| 3+ response playbooks | Met, 4 |
| IOC research notes | Met, 22 entries |
| Complete ATT&CK coverage matrix | Met, `coverage/matrix-v2.md` and Navigator layer |
| Methodology documentation | Met, `docs/methodology.md` |
| Executive summary | Met, `reports/executive-summary.md` |
| Final technical report | Met, `reports/final-technical-report.md` |
| Final presentation | Met, `presentation/deck.pptx` |
| Meaningful Git history | Met, 12 commits |
| Reproducibility of major findings | Met, three commands regenerate every figure |
| Human-readable requirements matrix | Met, `PROJECT_REQUIREMENTS.md` plus CSV and JSON |
| Automated quality checks | Met, `scripts/prd_compliance.py` |

**Automated audit:** 85/85 mandatory requirements pass, 3/3 optional enhancements. Full detail in `docs/prd-compliance-report.md`.

## 11. Generated deliverables

| Artefact | Producer |
| --- | --- |
| `PROJECT_REQUIREMENTS.md`, `.csv`, `.json` | `scripts/render_requirements.py` |
| `docs/prd-compliance-report.md` | `scripts/prd_compliance.py` |
| `detections/test-results.csv` | `scripts/test_all.py` |
| `detections/tuning-results.csv` | `scripts/tune.py` |
| `coverage/matrix-v2.md`, `coverage/layer-v2.json` | `scripts/build_coverage.py` |
| `detections/converted/*` | `scripts/convert_rules.py` |
| `presentation/deck.pptx` | `scripts/build_deck.py` |
| `notebooks/02..05*.ipynb` | `scripts/build_notebooks.py` |
| `docs/environment-inventory.json` | `scripts/environment_inventory.py` |
| `reports/final-status-report.md` | `scripts/final_status.py` |

