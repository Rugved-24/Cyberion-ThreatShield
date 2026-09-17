# Dataset Register

Provider: Open Threat Research Forge (OTRF).
Scenario contributor: Roberto Rodriguez (@Cyb3rWard0g).

## Recordings
- DS001: Mshta VBScript Execute PowerShell; 1,127 events.
- DS002: Empire Invoke PsExec; 4,348 events.

Scenario documentation:
- DS001: https://securitydatasets.com/notebooks/atomic/windows/defense_evasion/SDWIN-201022025808.html
- DS002: https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-190518210652.html

For each ID, docs/DSxxx-acquisition.json records the pinned download URL,
acquisition time, archive size and SHA-256. docs/DSxxx-inventory.json records
the extracted file, size, SHA-256, event count and channel/provider counts.

Both recordings contain attack-emulation telemetry. Event-level benign
labels have not been established. Per-field ranges are recorded in docs/DS001-capture.json and
docs/DS002-capture.json. See docs/timestamp_policy.md for limitations.

## Source coverage
Sysmon, Windows Security auditing and PowerShell Operational are present.
DS002 Security/security casing will be normalized in derived data only.
Classic Windows PowerShell remains distinct from PowerShell Operational.

## Attribution and usage terms
Pinned upstream files are retained in references/OTRF-LICENSE and
references/OTRF-README.md. The pinned files confirm conflicting MIT/GPL-3.0 labels.
Raw telemetry remains local; redistribution terms require review.

## Benign comparison plan
Collect a separate, documented local baseline of read-only PowerShell
inventory commands and ordinary application launches. Record activity,
start/end times and source-event references in data/private.
Background events in attack recordings are not automatically benign.
Count tuning cases only after observing and confirming genuine benign matches.

## Correlation candidates
Inspect DS001 for parent/child process relationships and DS002 for related
remote-service and process events. Verify timestamps, hosts and identity
fields before correlating. Keep the two recordings separate.
Additional datasets will be selected when specific evidence gaps emerge.
