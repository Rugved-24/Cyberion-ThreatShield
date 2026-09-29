"""The PRD requirement matrix, as data.

One record per requirement extracted from Cyberion Defense Labs PRD CDL-DET-V2
version 2.0. scripts/prd_compliance.py reads this, checks each requirement
against a real artefact, and refuses to accept a filename that does not exist.

Fields:

  id           stable requirement identifier, used by every compliance report
  prd          the PRD section the requirement comes from
  text         the requirement, in PRD terminology
  kind         countable | artefact | process
  target       the number the PRD asks for, or None
  artefacts    files that must exist and be non-trivial
  verify       named checks prd_compliance.py must run, not merely a file test
  optional     True for PRD section 11 stretch goals, which never gate completion

`text` is quoted or closely paraphrased from the PRD. Where this project
legitimately cannot satisfy a requirement, the `limitation` field records why,
and the compliance report marks it PARTIAL or BLOCKED rather than PASS. No
requirement may be marked PASS on the strength of a file existing.
"""

PRD_ID = "CDL-DET-V2"
PRD_VERSION = "2.0"

# PRD section 14 evaluation rubric, with an honest self-assessment. The weight
# column is the PRD's. The assessment is the author's own and is deliberately
# not all-positive, because a rubric review in which everything scores well is
# not a review.
QUALITY_REVIEW = [
    dict(dimension="Detection Rule Quality", weight="20%",
         assessment="Strong on precision and validation, weak on measurement.",
         evidence="17 rules, all syntax-valid and all replayed, with declared evidence and "
                  "negative lists that fail the run if unmet. Severity has a written "
                  "justification per rule. Three rules tuned with generated before/after "
                  "figures. Deduction: 12 of 21 techniques have unmeasured false-positive "
                  "rates, and two tuned rules match nothing, so library precision is proven "
                  "only against two recordings."),
    dict(dimension="MITRE ATT&CK Rigor", weight="15%",
         assessment="Strong.",
         evidence="21 technique IDs across 11 tactics, verified against the pinned ATT&CK 19.2 "
                  "STIX source rather than recalled, including the v19 Stealth rename. "
                  "Coverage is computed from recorded results by script, so a status cannot be "
                  "inflated by prose, and a rule with empty evidence cannot score above zero. "
                  "Every matrix row references a rule that exists, checked by the audit."),
    dict(dimension="Threat Hunting Method", weight="15%",
         assessment="Strong, and notable for its negative results.",
         evidence="Two hunts, hypothesis-first with the pre-hunt commit recorded so a "
                  "conclusion could not be reverse-engineered from an existing rule. One "
                  "concluded inconclusive and one partially supported; neither was forced "
                  "positive. Searches that returned nothing are recorded so a later analyst "
                  "does not repeat them. HUNT-002's port-80 ratio is a reusable negative "
                  "result rather than a discarded one."),
    dict(dimension="Incident Investigation Quality", weight="15%",
         assessment="Strong on evidence, honest on the unresolved questions.",
         evidence="Both cases corroborated across independent sources, four for INC-001 and two "
                  "for INC-002. INC-001's SYSTEM context is confirmed by recorded command "
                  "output, not inferred from a configuration field. Timelines label every step "
                  "as ordered or attributed, so no step is ordered on a timestamp the project "
                  "refuses to trust. Deduction: the account-compromise question is unresolved "
                  "in both cases and no authentication history exists to resolve it."),
    dict(dimension="Playbook Practicality", weight="10%",
         assessment="Adequate to good.",
         evidence="Four playbooks from one template, each with an expected time to scope for "
                  "one analyst, containment ordered least to most disruptive, and an explicit "
                  "step that ends the investigation as benign. Deduction: none has been "
                  "exercised under time pressure, and PB-02 explicitly cannot establish "
                  "causal attribution from the available telemetry."),
    dict(dimension="Documentation and Reproducibility", weight="15%",
         assessment="Strong, with one structural deviation.",
         evidence="Three commands regenerate every figure from recorded evidence; the generator "
                  "for each artefact is listed in docs/project-structure.md. The 119 event "
                  "references across rules, hunts and incident reports are resolved against "
                  "the recorded digests by the audit. Method, environment, field mapping, "
                  "timestamp policy and rule contract are all documented. Deviation: the "
                  "numbered directory layout suggested in the brief was not adopted, and the "
                  "mapping is documented instead."),
    dict(dimension="Executive Communication", weight="5%",
         assessment="Good.",
         evidence="An executive summary in business language with a glossary, a presentation "
                  "deck with speaker notes, and a limitations section placed in the main body "
                  "rather than an appendix. No figure in either is typed; both are generated "
                  "from the artefacts."),
    dict(dimension="Independent Judgment", weight="5%",
         assessment="This is where the work is strongest.",
         evidence="Declined to claim 13 Covered techniques to reach a flattering number; left "
                  "three techniques uncovered rather than writing rules with no telemetry; "
                  "concluded a hunt inconclusive rather than forcing a positive; refused to "
                  "convert correlation rules after observing the converter produce a query "
                  "that can never match; and declined the request to claim zero vulnerabilities, "
                  "building verification instead. Deduction: the largest judgement failure is "
                  "that Phase 4 assessed one telemetry type and understated the data by six "
                  "candidate behaviours."),
]

REQUIREMENTS = [
    # ---------------------------------------------------------------- section 2.7
    dict(id="R-2.7-01", prd="2.7 Success Metrics", kind="countable", target=15,
         text="15+ Sigma rules, each mapped to a MITRE ATT&CK technique ID",
         artefacts=["rules/windows", "rules/correlation"],
         verify=["rule_count", "rule_has_attack_tag", "rule_unique_id"]),
    dict(id="R-2.7-02", prd="2.7 Success Metrics", kind="countable", target=20,
         text="At least 20 techniques assessed and placed on the coverage matrix",
         artefacts=["coverage/matrix-v2.md", "coverage/layer-v2.json"],
         verify=["technique_count"]),
    dict(id="R-2.7-03", prd="2.7 Success Metrics", kind="countable", target=2,
         text="Threat hunts completed, each with a documented hypothesis and outcome",
         artefacts=["hunts"],
         verify=["hunt_count", "hunt_has_hypothesis", "hunt_has_classified_conclusion"]),
    dict(id="R-2.7-04", prd="2.7 Success Metrics", kind="countable", target=2,
         text="Incident case reports completed, full lifecycle from detection to closure",
         artefacts=["incidents"],
         verify=["incident_count", "incident_has_closure_class",
                 "incident_has_evidence_reference"]),
    dict(id="R-2.7-05", prd="2.7 Success Metrics", kind="countable", target=1,
         text="Rules validated against real attack telemetry: 100% of submitted rules "
              "tested against actual log data, not assumed to work",
         artefacts=["detections/test-results.csv"],
         verify=["all_rules_have_validation_record", "validation_against_real_dataset"]),
    dict(id="R-2.7-06", prd="2.7 Success Metrics", kind="countable", target=1,
         text="False positive review documented: every rule includes a documented "
              "false-positive consideration",
         artefacts=["rules"],
         verify=["every_rule_has_falsepositives"]),
    dict(id="R-4.1-01", prd="4.1 Log & Telemetry Familiarization", kind="countable", target=3,
         text="At least three log/telemetry source types from the datasets, with a data "
              "dictionary describing the fields and their detection meaning",
         artefacts=["docs/data_dictionary.md", "docs/DS001-fields.json", "docs/DS002-fields.json"],
         verify=["telemetry_type_count", "data_dictionary_covers_three_types"]),
    dict(id="R-4.2-01", prd="4.2 Detection Rule Engineering", kind="artefact",
         text="Every rule documents the ATT&CK technique ID, the logic and field "
              "conditions, a severity rating with justification, and a false-positive discussion",
         artefacts=["rules", "docs/rules.md"],
         verify=["rule_has_required_fields", "rule_has_severity_rationale",
                 "every_rule_has_falsepositives"]),
    dict(id="R-4.2-02", prd="4.2 Detection Rule Engineering", kind="countable", target=3,
         text="At least 3 correlation-style rules that depend on a sequence or combination "
              "of events, not a single log line",
         artefacts=["rules/correlation"],
         verify=["correlation_rule_count", "correlation_has_join_and_window",
                 "correlation_window_matrix_present"]),
    dict(id="R-4.3-01", prd="4.3 ATT&CK Mapping & Coverage", kind="artefact",
         text="Coverage matrix marking each technique Covered, Partially Covered or Not "
              "Covered, with the supporting rule ID referenced",
         artefacts=["coverage/matrix-v2.md", "coverage/layer-v2.json"],
         verify=["matrix_uses_three_states", "matrix_rule_refs_resolve"]),
    dict(id="R-4.3-02", prd="4.3 ATT&CK Mapping & Coverage", kind="countable", target=4,
         text="Cover techniques across at least 4 different tactics",
         artefacts=["coverage/matrix-v2.md"],
         verify=["tactic_count"]),
    dict(id="R-4.3-03", prd="4.3 ATT&CK Mapping & Coverage", kind="process",
         text="A technique must not be marked Covered merely because a rule carries a "
              "related ATT&CK tag; coverage must rest on tested detection logic and evidence",
         artefacts=["coverage/matrix-v2.json", "detections/test-results.csv"],
         verify=["covered_requires_validated_rule", "empty_evidence_cannot_be_covered"]),
    dict(id="R-4.4-01", prd="4.4 Threat Hunting", kind="countable", target=1,
         text="At least one hunt investigates an ATT&CK technique not already covered by "
              "an existing detection rule",
         artefacts=["hunts/HUNT-002.md"],
         verify=["hunt_targets_uncovered_technique"]),
    dict(id="R-4.4-02", prd="4.4 Threat Hunting", kind="process",
         text="Hunt conclusions classified Confirmed, Inconclusive or Ruled Out; a negative "
              "result is valid if supported by evidence and no hunt is forced positive",
         artefacts=["hunts"],
         verify=["hunt_has_classified_conclusion", "hunt_records_negative_findings"]),
    dict(id="R-4.5-01", prd="4.5 IOC Research & Correlation", kind="artefact",
         text="IOC register with indicator, type, source event, timestamp, context, "
              "ATT&CK relationship, confidence, external enrichment and operational use",
         artefacts=["ioc/watchlist.csv"],
         verify=["ioc_count", "ioc_has_required_columns", "ioc_has_confidence",
                 "ioc_has_operational_use", "ioc_never_says_do_not_block_ambiguously"]),
    dict(id="R-4.6-01", prd="4.6 Incident Investigation & Case Reporting", kind="artefact",
         text="Each case report includes timeline from raw log evidence, root cause, "
              "ATT&CK techniques, impact assessment and a justified closure classification",
         artefacts=["incidents"],
         verify=["incident_has_timeline", "incident_has_root_cause", "incident_has_impact",
                 "incident_has_closure_class"]),
    dict(id="R-4.6-02", prd="4.6 Incident Investigation & Case Reporting", kind="process",
         text="Confirm findings using corroborating evidence from at least two sources "
              "where possible; every significant statement traces to evidence",
         artefacts=["incidents"],
         verify=["incident_corroborates_two_sources", "incident_evidence_references_resolve"]),
    dict(id="R-4.7-01", prd="4.7 Incident Response Playbooks", kind="countable", target=3,
         text="Playbooks for at least 3 scenarios, each with trigger conditions, "
              "investigation, containment, eradication/recovery and stakeholder communications",
         artefacts=["playbooks"],
         verify=["playbook_count", "playbook_has_required_sections"]),
    dict(id="R-4.8-01", prd="4.8 Rule Quality & False Positive Tuning", kind="countable", target=3,
         text="For at least 3 rules, document a tuning pass: observed false-positive "
              "scenario, logic change, and the trade-off accepted",
         artefacts=["evidence/tuning", "detections/tuning-results.csv"],
         verify=["tuning_case_count", "tuning_records_before_and_after",
                 "tuning_records_tradeoff"]),
    dict(id="R-4.9-01", prd="4.9 Reporting & Executive Communication", kind="artefact",
         text="Executive summary translating technical findings into business-relevant "
              "language for a non-technical stakeholder",
         artefacts=["reports/executive-summary.md"],
         verify=["exec_summary_exists", "exec_summary_uses_plain_language"]),
    dict(id="R-5-01", prd="5 Deliverable Quality Standards", kind="process",
         text="Reproducibility: every rule and hunt finding reproducible against the stated "
              "dataset by another analyst following the written method",
         artefacts=["docs/environment.md", "docs/rules.md", "README.md"],
         verify=["pipeline_commands_documented", "pipeline_runs_clean"]),
    dict(id="R-5-02", prd="5 Deliverable Quality Standards", kind="process",
         text="Evidence-based claims: every conclusion cites the specific log evidence supporting it",
         artefacts=["rules", "hunts", "incidents"],
         verify=["evidence_references_resolve", "no_unsupported_claims_flagged"]),
    dict(id="R-5-03", prd="5 Deliverable Quality Standards", kind="process",
         text="Framework alignment: all detections and findings mapped to current specific "
              "ATT&CK technique IDs, not vague tactic-level labels",
         artefacts=["rules", "coverage"],
         verify=["rule_has_attack_tag", "technique_ids_resolve_to_catalog"]),
    dict(id="R-5-04", prd="5 Deliverable Quality Standards", kind="process",
         text="Version control: all rules and reports tracked in a version-controlled "
              "repository with meaningful commit history",
         artefacts=[".git"],
         verify=["git_commit_count", "git_tracked_no_telemetry"]),
    dict(id="R-6.03", prd="6.3 Incident Investigation Workflow", kind="process",
         text="Map each stage of the timeline to a MITRE ATT&CK technique and document a "
              "recommended containment/response approach referencing the relevant playbook",
         artefacts=["incidents"],
         verify=["incident_references_playbook"]),
    dict(id="R-7-01", prd="7 Reports & Documentation Deliverables", kind="artefact",
         text="Final technical report integrating the project with stable IDs and filenames",
         artefacts=["reports/final-technical-report.md"],
         verify=["final_report_exists", "final_report_has_required_sections"]),
    dict(id="R-7-02", prd="7 Reports & Documentation Deliverables", kind="artefact",
         text="Methodology document describing datasets used and how telemetry was obtained",
         artefacts=["docs/methodology.md", "docs/datasets.md", "docs/field_mapping.md",
                    "docs/timestamp_policy.md"],
         verify=["methodology_exists", "methodology_covers_required_topics"]),
    dict(id="R-7-03", prd="7 Reports & Documentation Deliverables", kind="artefact",
         text="Final presentation summarising coverage improvements and key findings",
         artefacts=["presentation/deck.pptx"],
         verify=["presentation_exists", "presentation_has_slides"]),
    dict(id="R-8-01", prd="8 Detection Rule Format Standard", kind="artefact",
         text="Each rule includes title, id, status, description, references, ATT&CK tags, "
              "logsource, selection/condition logic, falsepositives and level",
         artefacts=["rules"],
         verify=["rule_has_required_fields", "sigma_syntax_valid"]),
    dict(id="R-9-01", prd="9 Data Sources", kind="process",
         text="Use real publicly documented security datasets; do not invent logs or "
              "incidents, and label any locally generated telemetry as such",
         artefacts=["docs/datasets.md", "docs/DS001-acquisition.json", "docs/DS002-acquisition.json",
                    "references/OTRF-LICENSE"],
         verify=["dataset_provenance_documented", "raw_hashes_match_inventory",
                 "licence_limitation_documented"]),
    dict(id="R-10-01", prd="10 Enterprise Constraints", kind="process",
         text="Rules must be precise enough for a high-volume environment; do not maximise "
              "alert volume",
         artefacts=["evidence/tuning", "SECURITY.md"],
         verify=["tuning_case_count", "rules_state_precision_limitations"]),
    dict(id="R-12-01", prd="12 Deliverables Checklist", kind="artefact",
         text="All nine Section 12 deliverables complete: rule library, coverage matrix, "
              "hunt reports, incident reports, playbooks, IOC notes, executive summary, "
              "methodology, presentation",
         artefacts=["rules", "coverage/matrix-v2.md", "hunts", "incidents", "playbooks",
                    "ioc/watchlist.csv", "reports/executive-summary.md",
                    "reports/final-technical-report.md", "presentation/deck.pptx"],
         verify=["checklist_all_present"]),
    dict(id="R-13-01", prd="13 Weekly Milestones", kind="process",
         text="Four-week delivery structure with Week 1 data familiarization, Week 2 rule "
              "engineering, Week 3 hunting and incidents, Week 4 finalization, treated as "
              "checkpoints",
         artefacts=["PROGRESS.md"],
         verify=["week_checkpoints_recorded"]),
    dict(id="R-14-01", prd="14 Evaluation Rubric", kind="process",
         text="Quality review against detection-rule quality, ATT&CK rigor, threat-hunting "
              "method, incident quality, playbook practicality, documentation and "
              "reproducibility, executive communication and independent judgement",
         artefacts=["docs/prd-compliance-report.md"],
         verify=["quality_review_against_rubric"]),
    dict(id="R-15-01", prd="15 Tools Required", kind="process",
         text="Python 3.11+ with pandas and Jupyter, Sigma tooling, Git, ATT&CK Navigator "
              "reference, all in a reproducible pinned environment",
         artefacts=["requirements.txt", "docs/environment-inventory.json", "docs/environment.md"],
         verify=["environment_documented", "python_version_ok", "sigma_tooling_present",
                 "git_present"]),
    # ---------------------------------------------------------------- section 11, optional
    dict(id="R-11-01", prd="11 Optional Advanced Enhancements", kind="artefact", optional=True,
         text="Convert a subset of Sigma rules to a second query language to demonstrate "
              "backend portability",
         artefacts=["detections/converted"],
         verify=["converted_rule_count"]),
    dict(id="R-11-02", prd="11 Optional Advanced Enhancements", kind="artefact", optional=True,
         text="Build a small script-level rule-testing harness that runs Sigma rules against "
              "sample logs locally",
         artefacts=["scripts/test_all.py"],
         verify=["harness_exists"]),
    dict(id="R-11-03", prd="11 Optional Advanced Enhancements", kind="artefact", optional=True,
         text="Draft a purple-team exercise plan pairing detections with the attack "
              "techniques used to validate them",
         artefacts=["docs/purple-team-plan.md"],
         verify=["purple_team_plan_exists"]),
    # ------------------------------------------------- environment inspection
    dict(id="R-ENV-01", prd="Environment inspection", kind="process",
         text="Determine OS, architecture, CPU, RAM, storage, Python versions, Git, IDE, "
              "PowerShell, virtualization, spreadsheet and presentation software, Jupyter, "
              "and establish the minimum required environment",
         artefacts=["docs/environment-inventory.json", "docs/environment.md"],
         verify=["environment_documented"]),
    dict(id="R-ENV-02", prd="Environment inspection", kind="process",
         text="Use a dedicated isolated Python virtual environment rather than modifying "
              "the global environment",
         artefacts=["docs/environment-inventory.json"],
         verify=["python_venv_isolated"]),
    dict(id="R-ENV-03", prd="Environment inspection", kind="process",
         text="Determine what components are missing and establish the minimum required "
              "environment; do not install software that is already correctly installed",
         artefacts=["docs/environment-inventory.json", "docs/environment-gaps.md"],
         verify=["environment_gaps_documented"]),
    dict(id="R-NB-01", prd="Analysis notebooks", kind="artefact",
         text="Reusable notebooks for dataset profiling, detection validation, threat "
              "hunting and incident reconstruction, each documenting purpose, inputs, "
              "methodology, analysis, outputs and conclusions, with important results saved "
              "to durable artefacts",
         artefacts=["notebooks"],
         verify=["notebook_count", "notebook_is_documented"]),
    dict(id="R-QA-01", prd="Automated quality checks", kind="artefact",
         text="Lightweight local validation scripts checking required rule fields, unique "
              "IDs, ATT&CK tags, coverage-matrix rule references, validation records, "
              "false-positive documentation, incident evidence, playbook sections, and that "
              "every Covered technique references a validated rule",
         artefacts=["scripts/prd_compliance.py"],
         verify=["qa_checks_present", "qa_runs_clean"]),
    dict(id="R-STR-01", prd="Repository structure", kind="artefact",
         text="Professional repository structure with consistent filenames and unique IDs",
         artefacts=["docs/project-structure.md", "PROJECT_REQUIREMENTS.md"],
         verify=["structure_mapping_documented", "id_crosswalk_documented"]),
]

# Requirements this environment cannot legitimately satisfy, with the reason.
LIMITATIONS = [
    dict(
        id="R-4.2-03-LIM",
        requirement="R-4.3-01 / R-4.6-01 partial scope",
        text="Close the three evidence gaps T1547.001 Registry Run Keys / Startup Folder, "
             "T1110.003 Password Spraying and T1486 Data Encrypted for Impact.",
        effect="These three techniques stay Not Covered. They cannot be demonstrated with "
               "the two selected recordings, which contain no run-key write, no event 4625 "
               "authentication failure, and no labelled encryption sequence.",
        reason="Closing them would require locally generated telemetry. This host has no "
               "hypervisor, no VirtualBox or VMware, no working Docker daemon and no "
               "Hyper-V compute service, so no isolated Windows test VM can be created. "
               "The PRD and the engagement instruction both forbid running attack "
               "simulation on the user's daily-use environment, so the Atomic Red Team "
               "route is closed as well.",
        evidence="docs/environment-inventory.json records hypervisor_present and "
                 "platforms_on_path as absent. coverage/matrix-v2.md records the minimum "
                 "dataset each gap needs.",
        not_fabricated="No rule was written for these techniques. No telemetry was "
                       "synthesised. They are reported as Not Covered with a stated "
                       "visibility gap.",
    ),
    dict(
        id="R-2.7-06-LIM",
        requirement="R-2.7-06 / quality of false-positive review",
        text="Measure the false-positive rate of every rule against a clean recording of "
             "normal business activity.",
        effect="12 of 21 techniques are capped at Partially Covered rather than Covered. "
               "The coverage matrix is not overstated, and the cap is deliberate.",
        reason="Both selected recordings are adversary-emulation captures. They contain "
               "no baseline of ordinary activity. Three rules were measured against "
               "attributable benign background inside the captures, which is real evidence "
               "but not a clean-environment baseline.",
        evidence="evidence/tuning/benign-baseline.json states explicitly that it is not a "
                 "separately collected clean baseline.",
        not_fabricated="No benign baseline was invented. The measured figures come from "
                       "scripts/tune.py against real records.",
    ),
    dict(
        id="R-9-02-LIM",
        requirement="R-9-01 distribution",
        text="Clear redistribution terms for the selected public datasets before external "
             "publication.",
        effect="The repository is not published externally. A redacted copy path exists but "
               "publication remains gated on a rights review.",
        reason="The pinned upstream files carry conflicting MIT and GPL-3.0 licence "
               "labels, which is a genuine unresolved ambiguity, not a formality.",
        evidence="references/OTRF-LICENSE, references/OTRF-README.md, "
                 "docs/datasets.md, SECURITY.md.",
        not_fabricated="No licence claim was invented or assumed.",
    ),
]
