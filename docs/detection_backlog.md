# Detection Backlog

Status: candidates identified; Sigma implementation and rule testing pending.
ATT&CK references reviewed: 2026-09-17.
Evidence references use dataset ID and original physical line number.
Resolve source files and hashes through docs/DS001-inventory.json.

| ID | Candidate | Type | ATT&CK | Evidence |
| --- | --- | --- | --- | --- |
| CT-001 | Mshta executes inline VBScript | Single event | T1218.005 | DS001:275 |
| CT-C01 | Mshta launches PowerShell | Correlation | T1218.005, T1059.001 | DS001:275, DS001:398 |

## CT-001

Priority: first implementation.
Source: Microsoft-Windows-Sysmon, EventID 1.
Proposed logic: Image ends with \mshta.exe and CommandLine contains vbscript:.
Use case-insensitive comparisons.
Required fields: Image, CommandLine, EventID and provider.
Validation: match DS001:275; test casing, missing fields and unrelated processes.
Benign review: investigate approved automation using inline VBScript.
Scope: inline VBScript invocation; broader Mshta behavior remains unassessed.

## CT-C01

Source: two Sysmon process-creation events within the same recording.
Join: same host and parent ProcessGuid equals child ParentProcessGuid.
Require the parent image to be mshta.exe and child image to be powershell.exe.
Observed evidence: WORKSTATION5; parent line 275, child line 398.
Observed delay: 0.607 seconds using Sysmon UTC event times.
Correlation window: pending selection and validation.
Validation: correct pair, wrong host, wrong GUID, reversed order and window boundaries.

## Limitations and Next Work

Candidates do not count as tested detections or completed technique coverage.
No confirmed benign comparison matches have been evaluated.
Next: assess at least 20 ATT&CK techniques and record evidence gaps.
Complete the Phase 4 review before implementing the first Sigma rule.

References:
- https://attack.mitre.org/techniques/T1218/005/
- https://attack.mitre.org/techniques/T1059/001/

## DS002 Candidates

Source: Microsoft-Windows-Sysmon, EventID 1.
Resolve DS002 evidence through docs/DS002-inventory.json.
All entries remain candidates pending implementation and testing.

| ID | Candidate | Type | ATT&CK | DS002 lines |
| --- | --- | --- | --- | --- |
| CT-002 | Encoded PowerShell invocation | Single event | T1059.001 | 1073 |
| CT-003 | Service-launched command shell | Single event | T1569.002 | 1057 |
| CT-004 | PowerShell launches whoami | Single event | T1033 | 2901 |
| CT-C02 | Service-launched shell creates encoded PowerShell | Correlation | T1569.002, T1059.001 | 1057, 1073 |
| CT-C03 | Encoded PowerShell launches whoami | Correlation | T1059.001, T1033 | 1073, 2901 |

### Proposed Conditions

- CT-002: powershell.exe with an encoded-command argument; observed switch: -enc.
- CT-003: cmd.exe with ParentImage ending in \services.exe.
- CT-004: whoami.exe with ParentImage ending in \powershell.exe.
- CT-C02: CT-003 process creates the CT-002 process.
- CT-C03: CT-002 process creates the CT-004 process.
- Compare image names and argument switches case-insensitively.
- Test argument boundaries and supported switch variants before finalizing CT-002.

### Correlation Evidence and Validation

Both pairs share the exact host WORKSTATION6.theshire.local.
Parent ProcessGuid matches child ParentProcessGuid in each pair.
Observed delays: CT-C02 = 0.023 seconds; CT-C03 = 22.175 seconds.
The services.exe relationship is recorded in the cmd.exe event's ParentImage.
Rule windows remain undecided; observed delays are sample measurements.
Require matching dataset, host and GUID, plus validated event ordering.
Test mismatched GUIDs, missing fields, reversed order and window boundaries.
Approved automation and administration require benign comparison testing.

### Evidence Limits

Security events at lines 1209 and 1213 share host and logon ID 0x2990d17.
Their UTC event timestamps remain unresolved; temporal correlation is blocked.
The observed share-access records concern SYSVOL policy files.
Those share records alone do not establish attacker lateral movement.
Ordinary process names and command switches alone do not establish malicious intent.
No completed detection coverage is claimed.

References:
- https://attack.mitre.org/techniques/T1059/001/
- https://attack.mitre.org/techniques/T1569/002/
- https://attack.mitre.org/techniques/T1033/
