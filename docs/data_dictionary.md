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
