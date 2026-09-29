# Detection Backlog

Status: **superseded by the implemented rule library.** The seven candidates below
were recorded in Phase 4 and all seven were implemented and replayed. Six further
candidates were added in Phase 5 from the same telemetry; see the Phase 5 section
at the end of this file. For the current state, read `detections/test-results.csv`
and `coverage/matrix-v2.md`.
ATT&CK references reviewed: 2026-09-17, re-checked against 19.2 on 2026-09-29.
Evidence references use dataset ID and original physical line number.
Resolve source files and hashes through docs/DS001-inventory.json.

| ID | Candidate | Type | ATT&CK | Evidence | Outcome |
| --- | --- | --- | --- | --- | --- |
| CT-001 | Mshta executes inline VBScript | Single event | T1218.005, T1059.005 | DS001:275 | Implemented, replayed |
| CT-002 | Encoded PowerShell invocation | Single event | T1059.001 | DS002:1073 | Implemented, replayed |
| CT-003 | Service-launched command shell | Single event | T1569.002 | DS002:1057 | Implemented, replayed |
| CT-004 | PowerShell launches whoami | Single event | T1033 | DS002:2901 | Implemented, replayed |
| CT-C01 | Mshta launches PowerShell | Correlation | T1218.005, T1059.001 | DS001:275, DS001:398 | Implemented, window matrix asserted |
| CT-C02 | Service-launched shell creates encoded PowerShell | Correlation | T1569.002, T1059.001 | DS002:1057, DS002:1073 | Implemented, window matrix asserted |
| CT-C03 | Encoded PowerShell launches whoami | Correlation | T1059.001, T1033 | DS002:1073, DS002:2901 | Implemented, window matrix asserted |

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

---

## Phase 5 additions: candidates found in the recorded script content

Phase 4 assessed the process-creation records and missed most of the attack chain,
because the chain is recorded in the PowerShell script block rather than in process
creation. Reviewing `DS002:1827` statically produced six further candidates, all of
which were implemented and replayed. This is recorded because the Phase 4 gap is
itself a lesson: a technique assessment based on one telemetry type will understate
what the data contains.

| ID | Candidate | Type | ATT&CK | Evidence | Outcome |
| --- | --- | --- | --- | --- | --- |
| CT-005 | Command shell used to launch PowerShell in the background | Single event | T1059.003 | DS002:1057 | Implemented, replayed |
| CT-006 | Script block disabling ScriptBlock logging | Single event | T1685 | DS002:1827 | Implemented, replayed |
| CT-007 | Script block forcing the AMSI failure flag | Single event | T1685 | DS002:1827 | Implemented, replayed |
| CT-008 | Decoding an embedded payload and executing it in memory | Single event | T1027.010, T1140 | DS002:1827 | Implemented, replayed |
| CT-009 | Web download using the default network credentials | Single event | T1105 | DS002:1827 | Implemented, replayed |
| CT-010 | PowerShell enumerating the Sysmon service | Single event | T1518.001 | DS001:398 | Implemented, replayed |
| CT-011 | Service installed with a PowerShell image path | Single event | T1543.003 | DS002:1213 | Implemented, replayed |
| CT-012 | Network logon by a named user account | Single event | T1078 | DS002:1209 | Implemented, replayed, tuned |
| CT-013 | Process access to LSASS by a non-system caller | Single event | T1003.001 | none; 7 benign records | Implemented, tuned, **no attacker instance** |
| CT-014 | Admin or service share access by a user account | Single event | T1021.002 | none; 3 benign records | Implemented, tuned, **no attacker instance** |

### Notes on the six new candidates

- **CT-005 and CT-003 observe the same process creation** but test different
  behaviour: the parentage that establishes the service context, and the
  non-interactive dispatch pattern that establishes concealment. They are not
  duplicates and are rated differently.
- **CT-006 and CT-007 read the same script block** but test independent control
  bypasses that can be deployed separately, and an analyst needs to know which
  control was targeted.
- **CT-008 required a regex, not a substring.** The recorded script obfuscates the
  decode function name as `FroMBASe64StrinG`, so a case-sensitive substring test
  for `FromBase64String` would not have fired. The `(?i)` prefix is load-bearing.
- **CT-013 and CT-014 are retained with deliberately empty evidence lists.** They
  were written because a client asking about those techniques needs something to
  point at, and both were tuned against real benign activity. Neither can score
  above Not Covered, and the coverage builder refuses to promote them.

### T1140 added in Phase 6

T1140 Deobfuscate/Decode Files or Information was not in the Phase 4 assessment and
was added when CT-008 was written. Verified in ATT&CK 19.2: tactic **Stealth**,
object version 2.0, no sub-techniques, last modified 12 May 2026.

## Candidates deliberately not created

| Technique | Reason no candidate exists |
| --- | --- |
| T1071.001 Web Protocols | Reserved for HUNT-002 so the hypothesis is recorded independently of any rule. HUNT-002 concluded inconclusive; see `hunts/HUNT-002.md`. |
| T1047 WMI | Only provider-start events and one `WmiPrvSE.exe` creation exist. A rule would match ordinary Windows on every host. |
| T1053.005 Scheduled Task | The only Task Scheduler record in DS002 is event 129, a task deletion. No creation or action definition exists. |
| T1547.001 Run Keys / Startup Folder | No `CurrentVersion\Run` target in any registry event. Evidence gap; minimum dataset specified in `coverage/matrix-v2.md`. |
| T1110.003 Password Spraying | No event 4625 in either dataset. Evidence gap; minimum dataset specified in `coverage/matrix-v2.md`. |
| T1486 Data Encrypted for Impact | No labelled encryption sequence. Evidence gap; minimum dataset specified in `coverage/matrix-v2.md`. |
