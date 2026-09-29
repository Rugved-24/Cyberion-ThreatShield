# Cyberion ThreatShield

An independent detection-engineering and threat-hunting project using public
security telemetry in a simulated client scenario.

Deliverables: Sigma detection rules tested against real telemetry, an ATT&CK
coverage matrix, hypothesis-driven threat hunts, incident case reports, IOC
research, and written response playbooks.

## Current state

Phases 0-6 complete. All product-requirements deliverables are present.

| Deliverable | Target | Delivered |
| --- | --- | --- |
| Sigma rules, replayed against real telemetry | 15+ | 17 |
| Correlation rules | 3 | 3 |
| ATT&CK techniques assessed | 20+ | 21 |
| Techniques Covered / Partially / Not Covered | — | 1 / 12 / 8 |
| Threat hunts | 2+ | 2 |
| Incident case reports | 2+ | 2 |
| Response playbooks | 3+ | 4 |
| False-positive tuning records | 3 | 3 |
| IOC watchlist entries | — | 22 |

## Where to start

| If you want to… | Read |
| --- | --- |
| Understand the project in one page | `reports/executive-summary.md` |
| Write or modify a detection rule | `docs/rules.md`, then `rules/_template.yml` |
| See what is detected and what is not | `coverage/matrix-v2.md` |
| See the rule test results | `detections/test-results.csv` |
| Re-run everything | `docs/environment.md` |
| Understand a specific finding | `hunts/`, `incidents/` |
| Respond to an alert at 3am | `playbooks/` |

## Layout

```
rules/          Sigma rules; _template.yml is the only shape, windows/ and correlation/
scripts/        inventory, capture profiling, normalization, test harness, tuning, coverage
docs/           scope, methodology, environment, field mapping, rules contract, evidence JSON
coverage/       assessment.md + baseline.json (Phase 4, frozen) and matrix-v2.md + layer-v2.json
hunts/          HUNT-001 and HUNT-002, hypothesis first, negative results recorded
incidents/      INC-001 and INC-002, full timeline and closure classification
ioc/            watchlist.csv, every entry traced to a source record
playbooks/      _template.md plus four response playbooks
reports/        executive summary in business language
presentation/   final deck outline with speaker notes
detections/     generated: test-results.csv and tuning-results.csv
evidence/       ground_truth, tests, tuning records and the benign baseline
data/           raw (immutable, gitignored), processed, private
```

## The four rules that govern this project

1. **Raw data is immutable.** Every processing step verifies SHA-256 before it
   runs and fails closed on a mismatch.
2. **Only Sysmon event time is UTC.** Everything else stays explicitly unresolved.
   No timezone is ever inferred to make a timeline work.
3. **No coverage claim without a replay.** A technique is Covered only when a rule
   matched real attack telemetry *and* a measured benign comparison exists. The
   coverage matrix is generated from recorded results, so it cannot be inflated by
   prose.
4. **No host aliases are merged.** `WORKSTATION5` and
   `WORKSTATION5.theshire.local` stay separate, and no conclusion in this
   repository depends on them being the same machine.

## Status and next step

`PROGRESS.md`. Environment: `docs/environment.md`. Dependencies:
`requirements.txt`. Rule contract: `docs/rules.md`.
