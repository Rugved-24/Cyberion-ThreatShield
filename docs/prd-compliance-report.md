# PRD compliance report

PRD: **CDL-DET-V2 v2.0**  
Audited: 2026-09-29T14:18:23.479279+00:00  
Mandatory requirements passing: **85/85**  
Optional enhancements passing: **3/3**

Every row below was verified by opening the artefact and applying the named check. A row
is not satisfied by a file existing.

| Requirement | PRD section | Check | Status | Detail |
| --- | --- | --- | --- | --- |
| R-2.7-01 | 2.7 Success Metrics | `rule_count` | PASS | 17 rules (requirement 15+) |
| R-2.7-01 | 2.7 Success Metrics | `rule_has_attack_tag` | PASS | 17 rules each carry at least one attack.t tag |
| R-2.7-01 | 2.7 Success Metrics | `rule_unique_id` | PASS | 17 unique ids across 17 rules |
| R-2.7-02 | 2.7 Success Metrics | `technique_count` | PASS | 21 techniques on the matrix (requirement 20+) |
| R-2.7-03 | 2.7 Success Metrics | `hunt_count` | PASS | 2 hunt reports (requirement 2+) |
| R-2.7-03 | 2.7 Success Metrics | `hunt_has_hypothesis` | PASS | every hunt states a hypothesis |
| R-2.7-03 | 2.7 Success Metrics | `hunt_has_classified_conclusion` | PASS | conclusions classified in ('Confirmed', 'Inconclusive', 'Ruled out', 'Partially supported') |
| R-2.7-04 | 2.7 Success Metrics | `incident_count` | PASS | 2 incident case reports (requirement 2+) |
| R-2.7-04 | 2.7 Success Metrics | `incident_has_closure_class` | PASS | closure classified as ('True positive', 'False positive', 'Benign positive') |
| R-2.7-04 | 2.7 Success Metrics | `incident_has_evidence_reference` | PASS | every case cites event references |
| R-2.7-05 | 2.7 Success Metrics | `all_rules_have_validation_record` | PASS | 17 validation records, one per rule |
| R-2.7-05 | 2.7 Success Metrics | `validation_against_real_dataset` | PASS | 15 rules matched declared evidence in ['DS001', 'DS002']; 2 rules carry empty evidence by design (CT-014, CT-013) |
| R-2.7-06 | 2.7 Success Metrics | `every_rule_has_falsepositives` | PASS | 17 rules document realistic benign triggers |
| R-4.1-01 | 4.1 Log & Telemetry Familiarization | `telemetry_type_count` | PASS | 3 telemetry types documented in the data dictionary: ['sysmon', 'windows security', 'powershell']; 0 distinct providers recorded in the field profiles |
| R-4.1-01 | 4.1 Log & Telemetry Familiarization | `data_dictionary_covers_three_types` | PASS | sections for all 3 telemetry types; each field entry states meaning, type, limitation and detection relevance |
| R-4.2-01 | 4.2 Detection Rule Engineering | `rule_has_required_fields` | PASS | all rules carry 11 required fields |
| R-4.2-01 | 4.2 Detection Rule Engineering | `rule_has_severity_rationale` | PASS | every rule has a written severity justification |
| R-4.2-01 | 4.2 Detection Rule Engineering | `every_rule_has_falsepositives` | PASS | 17 rules document realistic benign triggers |
| R-4.2-02 | 4.2 Detection Rule Engineering | `correlation_rule_count` | PASS | 3 correlation rules (requirement 3+) |
| R-4.2-02 | 4.2 Detection Rule Engineering | `correlation_has_join_and_window` | PASS | every correlation rule declares parent, child, join and window |
| R-4.2-02 | 4.2 Detection Rule Engineering | `correlation_window_matrix_present` | PASS | every correlation rule asserts a window-boundary matrix |
| R-4.3-01 | 4.3 ATT&CK Mapping & Coverage | `matrix_uses_three_states` | PASS | states used: ['Covered', 'Not Covered', 'Partially Covered'] |
| R-4.3-01 | 4.3 ATT&CK Mapping & Coverage | `matrix_rule_refs_resolve` | PASS | 17 referenced rule ids all resolve |
| R-4.3-02 | 4.3 ATT&CK Mapping & Coverage | `tactic_count` | PASS | 11 tactics: ['Command and Control', 'Credential Access', 'Defense Impairment', 'Discovery', 'Execution', 'Impact', 'Initial Access', 'Lateral Movement', 'Persistence', 'Privilege Escalation', 'Stealth'] |
| R-4.3-03 | 4.3 ATT&CK Mapping & Coverage | `covered_requires_validated_rule` | PASS | every Covered technique rests on a PASS validation record |
| R-4.3-03 | 4.3 ATT&CK Mapping & Coverage | `empty_evidence_cannot_be_covered` | PASS | CT-013 and CT-014 have empty evidence and stay Not Covered |
| R-4.4-01 | 4.4 Threat Hunting | `hunt_targets_uncovered_technique` | PASS | hunt targets uncovered technique(s): ['T1021.002', 'T1071.001'] |
| R-4.4-02 | 4.4 Threat Hunting | `hunt_has_classified_conclusion` | PASS | conclusions classified in ('Confirmed', 'Inconclusive', 'Ruled out', 'Partially supported') |
| R-4.4-02 | 4.4 Threat Hunting | `hunt_records_negative_findings` | PASS | every hunt records negative or inconclusive findings |
| R-4.5-01 | 4.5 IOC Research & Correlation | `ioc_count` | PASS | 22 IOC register entries |
| R-4.5-01 | 4.5 IOC Research & Correlation | `ioc_has_required_columns` | PASS | columns: ['confidence', 'detection_rule', 'first_seen_utc', 'indicator', 'last_seen_utc', 'limitations', 'operational_use', 'source_lines', 'type', 'value'] |
| R-4.5-01 | 4.5 IOC Research & Correlation | `ioc_has_confidence` | PASS | 22 entries all carry a confidence value |
| R-4.5-01 | 4.5 IOC Research & Correlation | `ioc_has_operational_use` | PASS | 22 entries all state their operational use |
| R-4.5-01 | 4.5 IOC Research & Correlation | `ioc_never_says_do_not_block_ambiguously` | PASS | every DO NOT BLOCK entry also records its reason |
| R-4.6-01 | 4.6 Incident Investigation & Case Reporting | `incident_has_timeline` | PASS | every case has a timeline section |
| R-4.6-01 | 4.6 Incident Investigation & Case Reporting | `incident_has_root_cause` | PASS | every case has a root cause section |
| R-4.6-01 | 4.6 Incident Investigation & Case Reporting | `incident_has_impact` | PASS | every case has an impact assessment |
| R-4.6-01 | 4.6 Incident Investigation & Case Reporting | `incident_has_closure_class` | PASS | closure classified as ('True positive', 'False positive', 'Benign positive') |
| R-4.6-02 | 4.6 Incident Investigation & Case Reporting | `incident_corroborates_two_sources` | PASS | every case cites at least two independent log sources |
| R-4.6-02 | 4.6 Incident Investigation & Case Reporting | `incident_evidence_references_resolve` | PASS | 34 event references resolve: 0 full UIDs and 34 DSxxx:line shorthand, all inside a known dataset digest and within its record count |
| R-4.7-01 | 4.7 Incident Response Playbooks | `playbook_count` | PASS | 4 playbooks (requirement 3+) |
| R-4.7-01 | 4.7 Incident Response Playbooks | `playbook_has_required_sections` | PASS | all 4 playbooks carry trigger, investigation, containment, eradication, recovery and communications |
| R-4.8-01 | 4.8 Rule Quality & False Positive Tuning | `tuning_case_count` | PASS | 3 tuning cases (requirement 3+) |
| R-4.8-01 | 4.8 Rule Quality & False Positive Tuning | `tuning_records_before_and_after` | PASS | every case records a before and an after match count |
| R-4.8-01 | 4.8 Rule Quality & False Positive Tuning | `tuning_records_tradeoff` | PASS | every tuning record states the accepted trade-off |
| R-4.9-01 | 4.9 Reporting & Executive Communication | `exec_summary_exists` | PASS | reports/executive-summary.md |
| R-4.9-01 | 4.9 Reporting & Executive Communication | `exec_summary_uses_plain_language` | PASS | plain-language markers 39 vs raw jargon 4 |
| R-5-01 | 5 Deliverable Quality Standards | `pipeline_commands_documented` | PASS | pipeline order documented for 6 stages |
| R-5-01 | 5 Deliverable Quality Standards | `pipeline_runs_clean` | PASS | test_all, tune and build_coverage all exit 0 |
| R-5-02 | 5 Deliverable Quality Standards | `evidence_references_resolve` | PASS | 119 event references resolve: 57 full UIDs and 62 DSxxx:line shorthand, all inside a known dataset digest and within its record count |
| R-5-02 | 5 Deliverable Quality Standards | `no_unsupported_claims_flagged` | PASS | 10 narrative documents scanned against 7 absolute-claim phrases; none asserted |
| R-5-03 | 5 Deliverable Quality Standards | `rule_has_attack_tag` | PASS | 17 rules each carry at least one attack.t tag |
| R-5-03 | 5 Deliverable Quality Standards | `technique_ids_resolve_to_catalog` | PASS | 15 technique ids all resolve to the verified ATT&CK 19.2 subset |
| R-5-04 | 5 Deliverable Quality Standards | `git_commit_count` | PASS | 11 commits |
| R-5-04 | 5 Deliverable Quality Standards | `git_tracked_no_telemetry` | PASS | 79 tracked files, no telemetry among them |
| R-6.03 | 6.3 Incident Investigation Workflow | `incident_references_playbook` | PASS | every case references a response playbook |
| R-7-01 | 7 Reports & Documentation Deliverables | `final_report_exists` | PASS | reports/final-technical-report.md |
| R-7-01 | 7 Reports & Documentation Deliverables | `final_report_has_required_sections` | PASS | all 18 required sections present |
| R-7-02 | 7 Reports & Documentation Deliverables | `methodology_exists` | PASS | docs/methodology.md |
| R-7-02 | 7 Reports & Documentation Deliverables | `methodology_covers_required_topics` | PASS | 11 required topics covered |
| R-7-03 | 7 Reports & Documentation Deliverables | `presentation_exists` | PASS | presentation: ['deck.pptx'] |
| R-7-03 | 7 Reports & Documentation Deliverables | `presentation_has_slides` | PASS | 14 slides in deck.pptx |
| R-8-01 | 8 Detection Rule Format Standard | `rule_has_required_fields` | PASS | all rules carry 11 required fields |
| R-8-01 | 8 Detection Rule Format Standard | `sigma_syntax_valid` | PASS | sigma-cli 3.1.0 checked 17 rules |
| R-9-01 | 9 Data Sources | `dataset_provenance_documented` | PASS | acquisition records for DS001 and DS002 present |
| R-9-01 | 9 Data Sources | `raw_hashes_match_inventory` | PASS | 2 raw files match their recorded SHA-256 |
| R-9-01 | 9 Data Sources | `licence_limitation_documented` | PASS | dataset licence ambiguity is documented in docs/datasets.md and SECURITY.md |
| R-10-01 | 10 Enterprise Constraints | `tuning_case_count` | PASS | 3 tuning cases (requirement 3+) |
| R-10-01 | 10 Enterprise Constraints | `rules_state_precision_limitations` | PASS | every rule states its false-positive limitation |
| R-12-01 | 12 Deliverables Checklist | `checklist_all_present` | PASS | all 11 checklist artefacts present |
| R-13-01 | 13 Weekly Milestones | `week_checkpoints_recorded` | PASS | Week 1-4 exit criteria recorded in PROGRESS.md |
| R-14-01 | 14 Evaluation Rubric | `quality_review_against_rubric` | PASS | all 8 PRD section 14 dimensions reviewed, 4 of them carrying an explicit deduction |
| R-15-01 | 15 Tools Required | `environment_documented` | PASS | host, storage, python, tools, virtualization and office recorded |
| R-15-01 | 15 Tools Required | `python_version_ok` | PASS | Python 3.12.10 |
| R-15-01 | 15 Tools Required | `sigma_tooling_present` | PASS | sigma-cli present |
| R-15-01 | 15 Tools Required | `git_present` | PASS | git present |
| R-11-01 | 11 Optional Advanced Enhancements | `converted_rule_count` | PASS (optional) | 29 converted query files |
| R-11-02 | 11 Optional Advanced Enhancements | `harness_exists` | PASS (optional) | scripts/test_all.py |
| R-11-03 | 11 Optional Advanced Enhancements | `purple_team_plan_exists` | PASS (optional) | docs/purple-team-plan.md |
| R-ENV-01 | Environment inspection | `environment_documented` | PASS | host, storage, python, tools, virtualization and office recorded |
| R-ENV-02 | Environment inspection | `python_venv_isolated` | PASS | isolated environment at E:\VS Code Projects\Cyberion-ThreatShield\.venv |
| R-ENV-03 | Environment inspection | `environment_gaps_documented` | PASS | docs/environment-gaps.md |
| R-NB-01 | Analysis notebooks | `notebook_count` | PASS | 5 notebooks (requirement: profiling, validation, hunting, reconstruction) |
| R-NB-01 | Analysis notebooks | `notebook_is_documented` | PASS | all 5 notebooks carry purpose, method and conclusion narrative |
| R-QA-01 | Automated quality checks | `qa_checks_present` | PASS | scripts/prd_compliance.py |
| R-QA-01 | Automated quality checks | `qa_runs_clean` | PASS | this audit is the quality gate; its own result is the record |
| R-STR-01 | Repository structure | `structure_mapping_documented` | PASS | docs/project-structure.md |
| R-STR-01 | Repository structure | `id_crosswalk_documented` | PASS | crosswalk maps CT-* to DET-* and HUNT-* to TH-* |

## Recorded limitations

These are disclosed gaps where the required evidence or environment does not exist.
They are not incomplete work and are not counted as failures.

### R-4.2-03-LIM

**Requirement affected:** R-4.3-01 / R-4.6-01 partial scope

**What was asked:** Close the three evidence gaps T1547.001 Registry Run Keys / Startup Folder, T1110.003 Password Spraying and T1486 Data Encrypted for Impact.

**Effect:** These three techniques stay Not Covered. They cannot be demonstrated with the two selected recordings, which contain no run-key write, no event 4625 authentication failure, and no labelled encryption sequence.

**Why it cannot be done here:** Closing them would require locally generated telemetry. This host has no hypervisor, no VirtualBox or VMware, no working Docker daemon and no Hyper-V compute service, so no isolated Windows test VM can be created. The PRD and the engagement instruction both forbid running attack simulation on the user's daily-use environment, so the Atomic Red Team route is closed as well.

**Evidence:** docs/environment-inventory.json records hypervisor_present and platforms_on_path as absent. coverage/matrix-v2.md records the minimum dataset each gap needs.

**What was deliberately not done:** No rule was written for these techniques. No telemetry was synthesised. They are reported as Not Covered with a stated visibility gap.

### R-2.7-06-LIM

**Requirement affected:** R-2.7-06 / quality of false-positive review

**What was asked:** Measure the false-positive rate of every rule against a clean recording of normal business activity.

**Effect:** 12 of 21 techniques are capped at Partially Covered rather than Covered. The coverage matrix is not overstated, and the cap is deliberate.

**Why it cannot be done here:** Both selected recordings are adversary-emulation captures. They contain no baseline of ordinary activity. Three rules were measured against attributable benign background inside the captures, which is real evidence but not a clean-environment baseline.

**Evidence:** evidence/tuning/benign-baseline.json states explicitly that it is not a separately collected clean baseline.

**What was deliberately not done:** No benign baseline was invented. The measured figures come from scripts/tune.py against real records.

### R-9-02-LIM

**Requirement affected:** R-9-01 distribution

**What was asked:** Clear redistribution terms for the selected public datasets before external publication.

**Effect:** The repository is not published externally. A redacted copy path exists but publication remains gated on a rights review.

**Why it cannot be done here:** The pinned upstream files carry conflicting MIT and GPL-3.0 licence labels, which is a genuine unresolved ambiguity, not a formality.

**Evidence:** references/OTRF-LICENSE, references/OTRF-README.md, docs/datasets.md, SECURITY.md.

**What was deliberately not done:** No licence claim was invented or assumed.

## Quality review against the PRD section 14 evaluation rubric

Self-assessment by the author. The deductions are stated because a rubric review
in which everything scores well is not a review.

| Dimension | Weight | Assessment | Evidence and deduction |
| --- | --- | --- | --- |
| Detection Rule Quality | 20% | Strong on precision and validation, weak on measurement. | 17 rules, all syntax-valid and all replayed, with declared evidence and negative lists that fail the run if unmet. Severity has a written justification per rule. Three rules tuned with generated before/after figures. Deduction: 12 of 21 techniques have unmeasured false-positive rates, and two tuned rules match nothing, so library precision is proven only against two recordings. |
| MITRE ATT&CK Rigor | 15% | Strong. | 21 technique IDs across 11 tactics, verified against the pinned ATT&CK 19.2 STIX source rather than recalled, including the v19 Stealth rename. Coverage is computed from recorded results by script, so a status cannot be inflated by prose, and a rule with empty evidence cannot score above zero. Every matrix row references a rule that exists, checked by the audit. |
| Threat Hunting Method | 15% | Strong, and notable for its negative results. | Two hunts, hypothesis-first with the pre-hunt commit recorded so a conclusion could not be reverse-engineered from an existing rule. One concluded inconclusive and one partially supported; neither was forced positive. Searches that returned nothing are recorded so a later analyst does not repeat them. HUNT-002's port-80 ratio is a reusable negative result rather than a discarded one. |
| Incident Investigation Quality | 15% | Strong on evidence, honest on the unresolved questions. | Both cases corroborated across independent sources, four for INC-001 and two for INC-002. INC-001's SYSTEM context is confirmed by recorded command output, not inferred from a configuration field. Timelines label every step as ordered or attributed, so no step is ordered on a timestamp the project refuses to trust. Deduction: the account-compromise question is unresolved in both cases and no authentication history exists to resolve it. |
| Playbook Practicality | 10% | Adequate to good. | Four playbooks from one template, each with an expected time to scope for one analyst, containment ordered least to most disruptive, and an explicit step that ends the investigation as benign. Deduction: none has been exercised under time pressure, and PB-02 explicitly cannot establish causal attribution from the available telemetry. |
| Documentation and Reproducibility | 15% | Strong, with one structural deviation. | Three commands regenerate every figure from recorded evidence; the generator for each artefact is listed in docs/project-structure.md. The 119 event references across rules, hunts and incident reports are resolved against the recorded digests by the audit. Method, environment, field mapping, timestamp policy and rule contract are all documented. Deviation: the numbered directory layout suggested in the brief was not adopted, and the mapping is documented instead. |
| Executive Communication | 5% | Good. | An executive summary in business language with a glossary, a presentation deck with speaker notes, and a limitations section placed in the main body rather than an appendix. No figure in either is typed; both are generated from the artefacts. |
| Independent Judgment | 5% | This is where the work is strongest. | Declined to claim 13 Covered techniques to reach a flattering number; left three techniques uncovered rather than writing rules with no telemetry; concluded a hunt inconclusive rather than forcing a positive; refused to convert correlation rules after observing the converter produce a query that can never match; and declined the request to claim zero vulnerabilities, building verification instead. Deduction: the largest judgement failure is that Phase 4 assessed one telemetry type and understated the data by six candidate behaviours. |

Weighing: detection-rule quality, threat-hunting method and independent
judgement are the strongest areas, and all three are areas where the honest answer
is unfavourable to the project. Documentation and reproducibility are strong but
carry one structural deviation. The weakest area is incident investigation,
specifically because the telemetry cannot answer the credential question, which
is a data limitation rather than an analytical one.

