# Timestamp and Host Policy

Evidence: docs/DS001-capture.json and docs/DS002-capture.json.

## Findings
- DS001: @timestamp and TimeCreated precede Sysmon UtcTime by
  14,399.489-14,400 seconds across 892 paired records. Cause unresolved.
- DS002: @timestamp minus Sysmon UtcTime ranges from -0.494 to
  +3.921 seconds. Its exact collection/export semantics remain unverified.
- DS002 EventTime and EventReceivedTime lack timezone information.
  Their approximate four-hour clock difference does not establish a timezone.
- WORKSTATION6 and WORKSTATION6.theshire.local remain separate identities
  until an alias mapping is supported by evidence.

## Phase 3 rules
- Preserve original timestamp strings, hostnames and record locations.
- Use Sysmon UtcTime as the Sysmon event-time field, interpreted as UTC.
- Keep non-Sysmon event-time UTC unresolved pending source-specific validation.
- Retain encoded @timestamp separately; do not apply automatic hour shifts.
- CreationUtcTime and PreviousCreationUtcTime describe file metadata.
- Validate recording, host identity and timestamp basis before time-window joins.
