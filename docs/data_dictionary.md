# Data Dictionary

Scope: observed DS001 and DS002 exports.
Complete field counts and observed types: DS001-fields.json and DS002-fields.json.
Counts describe populated fields, not detection coverage.

## Source coverage

| SourceName | DS001 | DS002 |
| --- | ---: | ---: |
| Microsoft-Windows-Sysmon | 892 | 2941 |
| Microsoft-Windows-Security-Auditing | 232 | 599 |
| Microsoft-Windows-PowerShell | 0 | 354 |

Other providers remain part of each dataset.
The Security channel also contains events from other providers.
Classic Windows PowerShell remains distinct from PowerShell Operational.

## Common fields

| Raw field | Observed type | Meaning or limitation |
| --- | --- | --- |
| EventID | integer | Event type; interpret with provider |
| SourceName, Channel | string | Provider and event channel |
| Hostname | string | Event host; aliases remain unverified |
| RecordNumber | integer | DS002 only; not globally unique |
| @timestamp, TimeCreated | string | Encoded timestamps; see timestamp_policy.md |
| EventTime, EventReceivedTime | string | DS002 timestamps without timezone |
| Keywords, Task | string/integer | Types differ between captures; retain originals |

## Sysmon

| Raw field | Type | Meaning or limitation |
| --- | --- | --- |
| UtcTime | string | UTC event time |
| ProcessGuid, Image, ProcessId | string | Process identity; ProcessId absent from DS002 |
| CommandLine, ParentImage, ParentCommandLine | string | Process-creation context |
| ParentProcessGuid, ParentProcessId | string | Parent process identity |
| SourceProcessGUID, TargetProcessGUID | string | Separate process-access roles |
| SourceImage, TargetImage | string | Images for those separate roles |
| SourceIp, DestinationIp | string | Network endpoints; present in DS002 |
| CreationUtcTime, PreviousCreationUtcTime | string | File timestamps, not event timestamps |

## Windows Security auditing

| Raw field | Type | Meaning or limitation |
| --- | --- | --- |
| NewProcessId, NewProcessName | string | New process in event 4688 |
| ProcessId, ParentProcessName | string | Creator process in event 4688 |
| CommandLine | string | Command line in event 4688 |
| SubjectUserName, TargetUserName | string | Distinct account roles; do not merge |
| ProcessID | string | Distinct exported key; mapping pending event-specific review |

## PowerShell Operational

| Raw field | Type | Meaning or limitation |
| --- | --- | --- |
| ContextInfo, Payload | string | Present on 350 event-4103 records |
| ScriptBlockText, ScriptBlockId | string | Script text and identifier on one event 4104 |
| MessageNumber, MessageTotal | string | Fragment metadata; observed values 1 and 1 |
| ERROR_EVT_UNRESOLVED | boolean | True on 351 records; absent on 3; meaning unresolved |

The 4104 record is RecordNumber 6870 and declares one of one fragments.
This does not prove successful execution or capture-wide completeness.
Preserve structured payloads and flags without treating flagged records as unusable.
ExecutionProcessID is not a substitute for an absent monitored-process PID.

## Fields used by detection rules outside the normalized schema

Phase 3 normalized a fixed set of outputs. Phase 5 rules legitimately need fields
that were never normalized, because the behaviours they detect are recorded in
events the original mapping did not cover. Rather than re-run normalization and
invalidate the Phase 3 evidence, the test harness reads these fields from the
preserved original object, which is exactly why `raw` is retained in every record.

| Sigma field | Raw field | Source and event | Used by | Note |
| --- | --- | --- | --- | --- |
| `SourceImage` | SourceImage | Sysmon 10 | context only | Process holding the handle, not the target |
| `TargetImage` | TargetImage | Sysmon 10 | CT-013 | Compared against `lsass.exe` |
| `GrantedAccess` | GrantedAccess | Sysmon 10 | context only | Hex string such as `0x1000`; **not** used as a rule condition, because the same value has different meaning per request type |
| `CallTrace` | CallTrace | Sysmon 10 | CT-013 | Module list behind the handle; the basis for the `lsm.dll` and `sysmain.dll` exclusions |
| `QueryName` | QueryName | Sysmon 22 | HUNT-002 | `localhost` and a host name in this data; no real domain is resolved |
| `ServiceName` | ServiceName | Security 4697 | CT-011 | Generic value; the rule keys on the image path, not the name |
| `ServiceFileName` | ServiceFileName | Security 4697 | CT-011 | The decisive field: the registered binary path |
| `ServiceStartType` | ServiceStartType | Security 4697 | context only | String, not integer, in the raw export |
| `ServiceAccount` | ServiceAccount | Security 4697 | context only | `LocalSystem` in the observed registration |
| `LogonType` | LogonType | Security 4624 | CT-012 | **Stored as a string** `"3"`; the harness coerces numeric-looking values to integers at load time so rules can be written portably as `LogonType: 3` |
| `TargetUserName` | TargetUserName | Security 4624 | CT-012 | Present on all 4624 records; machine accounts end with `$` |
| `SubjectUserName` | SubjectUserName | Security 4624, 4697, 5140, 5145 | CT-014 | Distinct account role from `TargetUserName`; do not merge |
| `ShareName` | ShareName | Security 5140, 5145 | CT-014 | `\\*\SYSVOL` in this data |
| `RelativeTargetName` | RelativeTargetName | Security 5145 | CT-014 | Object accessed; `gpt.ini` drives the policy-file exclusion |
| `DestinationPort` | DestinationPort | Sysmon 3 | HUNT-002 | Integer in the raw export |
| `TargetObject` | TargetObject | Sysmon 12, 13, 14 | evidence gap review | Searched for `CurrentVersion\Run` targets; **none exist**, which is why T1547.001 is an evidence gap |

Two rules of interpretation apply to all of the above:

- These fields are read from `raw`, so they are only available where the original
  event carried them. A rule written against one of them will not fire on a host
  that does not collect that event type, and the rules say so in their `x-scope`
  excluded field.
- Numeric-looking values are compared as numbers. `ServiceStartType` and
  `LogonType` are strings in the export, and a rule author writing `3` should not
  have to know that. The coercion happens in the harness only; the original value
  is still in `raw`.
