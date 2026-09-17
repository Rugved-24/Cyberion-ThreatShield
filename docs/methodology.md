# Working Method

## Data
Record source URLs, usage terms, acquisition dates, and SHA-256 hashes.
Preserve raw files; write transformations to data/processed.
Document fields and normalize timestamps to UTC while retaining originals.
Keep source-file and record references for every derived finding.

## Detections
Select observable attacker behavior and verify its ATT&CK mapping.
Check Sigma syntax, then replay the logic against documented telemetry.
Record rule version, dataset hash, commands, match counts, and record IDs.
Review matches and benign triggers; syntax validity alone is insufficient.
Validate correlation ordering, grouping, and time windows explicitly.
Synthetic test fixtures supplement real telemetry rather than replace it.

## Hunts and Investigations
Record each hunt hypothesis and coverage status before running queries.
Preserve the method and evidence, including negative or inconclusive results.
Corroborate incident findings across sources where available.
Separate observed facts, inferred root cause, and unresolved uncertainty.
Document timelines, impact, response recommendations, and closure rationale.

## IOCs and Tuning
Trace indicators to source records and dated intelligence references.
Record confidence, limitations, and intended detection or watchlist use.
For tuning, preserve observed benign matches and compare before/after results.
Recheck known attack matches and document accepted trade-offs.

## Reproduction and Review
Use requirements.txt to reproduce the recorded Windows environment.
Keep evidence references aligned across rules, coverage, and reports.
Review sensitive content and dataset terms before publication.
Record actual validation results and the next checkpoint in PROGRESS.md.
