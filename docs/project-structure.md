# Repository structure and identifier crosswalk

The engagement instruction suggests a numbered layout. This project uses a flat,
descriptive layout instead. This document records the mapping, the identifier
crosswalk, and why the deviation was made, so that a reviewer following the
suggested structure can find every artefact without guessing.

## Why the numbered layout was not adopted

The suggested layout was introduced in the brief after the repository had already
been built, verified and committed. Renaming at that point would have required
rewriting every cross-reference in 17 Sigma rules, both hunt reports, both
incident reports, the coverage matrix, the generated layer, the tuning records and
the test-result CSV, and would have invalidated the event-reference trail that
the whole evidence contract depends on. That is a large, risky change with no
analytical gain, so the mapping is documented instead and the identifiers are
cross-walked below.

If a numbered layout is required for submission, it can be produced mechanically
from the current tree with a scripted move plus a reference rewrite, and the
pipeline re-run to confirm nothing broke. It should not be done by hand.

## Directory mapping

| Suggested | Actual | Notes |
| --- | --- | --- |
| `01_Data/raw` | `data/raw/` | Immutable source archives, git-ignored. Verified by SHA-256 before every read. |
| `01_Data/processed` | `data/processed/` | Normalized JSONL, git-ignored, hash-verified by the harness. |
| `01_Data/data_dictionary` | `docs/data_dictionary.md` | Plus generated `docs/DS001-fields.json` and `docs/DS002-fields.json`. |
| `02_Detection_Rules/sigma` | `rules/windows/`, `rules/correlation/` | Split by rule shape so correlation rules are identifiable without opening them. `rules/_template.yml` is the single skeleton. |
| `02_Detection_Rules/rule_test_results` | `detections/test-results.csv`, `detections/tuning-results.csv`, `detections/converted/` | Generated. Never hand-edited. |
| `03_MITRE_ATT&CK` | `coverage/` | `assessment.md` and `baseline.json` are the frozen Phase 4 position; `matrix-v2.md` and `layer-v2.json` are the generated tested position. |
| `04_Threat_Hunts/TH-001` | `hunts/HUNT-001.md` | One file per hunt rather than a directory per hunt; a hunt is a single document, so a directory would add a level without adding information. |
| `04_Threat_Hunts/TH-002` | `hunts/HUNT-002.md` | |
| `05_Incident_Cases/INC-001` | `incidents/INC-001.md` | Same reasoning. |
| `05_Incident_Cases/INC-002` | `incidents/INC-002.md` | |
| `06_IR_Playbooks` | `playbooks/` | `_template.md` plus four playbooks. |
| `07_IOC_Research` | `ioc/watchlist.csv` | |
| `08_Notebooks` | `notebooks/` | |
| `09_Reports` | `reports/` | `executive-summary.md` and `final-technical-report.md`. |
| `10_Presentation` | `presentation/` | `deck.pptx` and the speaker-note outline. |
| `PROJECT_REQUIREMENTS.md` | `PROJECT_REQUIREMENTS.md` | Rendered from `scripts/requirements_matrix.py`. |
| requirements | `requirements.txt`, `requirements-dev.txt` | |
| validation scripts | `scripts/` | 8 scripts. See `docs/rules.md` and `SECURITY.md`. |

## Identifier crosswalk

The brief suggests `DET-001`, `TH-001`, `INC-001`, `PB-001` and IOC identifiers.
This project uses `CT-`, `HUNT-`, `INC-`, `PB-` and CSV rows keyed by indicator.
`CT-` was chosen deliberately: it reads as "Cyberion ThreatShield" and, more
importantly, it was fixed before any rule was written, so every reference written
since then is consistent. The mapping is one-to-one and lossless.

| Suggested scheme | This project | Count | Example |
| --- | --- | --- | --- |
| `DET-001` | `CT-001` | 14 single-event rules, `CT-001` to `CT-014` | `CT-001` Mshta inline VBScript |
| `DET-015` (correlation) | `CT-C01` | 3 correlation rules | `CT-C02` service shell to encoded PowerShell |
| `TH-001` | `HUNT-001` | 2 hunts | `HUNT-002` T1071.001 web protocols |
| `INC-001` | `INC-001` | 2 cases | Identical, no mapping needed. |
| `PB-001` | `PB-01` | 4 playbooks | `PB-01` service-based execution |
| `IOC-001` | row 1 of `ioc/watchlist.csv` | 22 entries | Indicator is the key, not a synthetic ID, so an indicator can be matched by value. |

Rules also carry a stable UUID in the standard Sigma `id` field, which is the
identifier a SIEM would record. `CT-001` is `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b4401`.

## How a rule ID maps to the Sigma UUID

| Label | Sigma id |
| --- | --- |
| CT-001 | `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b4401` |
| CT-002 | `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b4402` |
| CT-003 | `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b4403` |
| CT-004 | `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b4404` |
| CT-005 | `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b4405` |
| CT-006 | `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b4406` |
| CT-007 | `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b4407` |
| CT-008 | `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b4408` |
| CT-009 | `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b4409` |
| CT-010 | `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b440a` |
| CT-011 | `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b440b` |
| CT-012 | `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b440c` |
| CT-013 | `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b440d` |
| CT-014 | `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b440e` |
| CT-C01 | `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b4501` |
| CT-C02 | `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b4502` |
| CT-C03 | `9c1a4d20-1b7e-4f3c-8a51-0d6f2e1b4503` |

## Where generated artefacts must not be hand-edited

These are produced by a script and will be overwritten. Editing them by hand
breaks the correspondence between the evidence and the claim.

| Artefact | Produced by |
| --- | --- |
| `detections/test-results.csv` | `scripts/test_all.py` |
| `detections/tuning-results.csv` | `scripts/tune.py` |
| `coverage/matrix-v2.md`, `coverage/layer-v2.json` | `scripts/build_coverage.py` |
| `evidence/tuning/*-false-positive.md` | `scripts/tune.py` |
| `evidence/tuning/benign-baseline.json` | `scripts/tune.py` |
| `docs/DSxxx-inventory.json` | `scripts/inventory_dataset.py` |
| `docs/DSxxx-capture.json` | `scripts/check_capture.py` |
| `docs/DSxxx-normalization.json` | `scripts/normalize_dataset.py` |
| `docs/DSxxx-fields.json`, `docs/DSxxx-validation.json` | `notebooks/01_data_familiarization.ipynb` |
| `docs/environment-inventory.json` | `scripts/environment_inventory.py` |
| `docs/prd-compliance-report.md` | `scripts/prd_compliance.py` |
| `PROJECT_REQUIREMENTS.md` | `scripts/render_requirements.py` |
| `reports/final-status-report.md` | `scripts/final_status.py` |

`coverage/baseline.json` and `coverage/assessment.md` are frozen: they record the
Phase 4 position before any rule existed, and no script writes them.
