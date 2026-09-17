# Field Mapping v1

Apply mappings by exact SourceName and, where specified, EventID.
Preserve every input event and its complete original object in raw.
Raw field names are case-sensitive.

## Common mappings

| Output | Origin or conversion | Type / requirement |
| --- | --- | --- |
| dataset_id | Inventory dataset_id | string, required |
| source_file | Inventory file; project-relative path | string, required |
| raw_sha256 | Verified source-file SHA-256, uppercase | string, required |
| record_locator | Physical source line, starting at 1 | integer, required |
| event_uid | dataset_id:raw_sha256:record_locator | string, required |
| provider | SourceName, unchanged | string, required |
| channel | Channel; map security to Security | string, required |
| host | Hostname, unchanged | string, required |
| event_id | EventID; require integer, reject boolean | integer, required |
| record_number | RecordNumber | integer, optional |
| timestamps_original | Available @timestamp, TimeCreated, UtcTime, EventTime, EventReceivedTime | object, required |
| timestamp_utc | Sysmon UtcTime parsed as UTC; otherwise null | string, optional |
| timestamp_basis | sysmon_utc or unresolved | string, required |
| raw | Entire original event object | object, required |

Do not infer timezone shifts or merge short hostnames with domain-qualified names.
File creation timestamps must not populate timestamp_utc.
See timestamp_policy.md for known discrepancies.

## Source-specific mappings

All outputs below are optional strings unless explicitly stated otherwise.

| Output | Sysmon | Security auditing | PowerShell Operational |
| --- | --- | --- | --- |
| image | Image | NewProcessName, event 4688 | null |
| process_id | ProcessId | NewProcessId, event 4688 | null |
| process_guid | ProcessGuid | null | null |
| command_line | CommandLine, event 1 | CommandLine, event 4688 | null |
| parent_image | ParentImage, event 1 | ParentProcessName, event 4688 | null |
| parent_process_id | ParentProcessId, event 1 | ProcessId, event 4688 | null |
| parent_process_guid | ParentProcessGuid, event 1 | null | null |
| user | User | null | null |
| subject_user | null | SubjectUserName | null |
| target_user | null | TargetUserName | null |
| source_process_guid | SourceProcessGUID, event 10 | null | null |
| target_process_guid | TargetProcessGUID, event 10 | null | null |
| source_ip | SourceIp, event 3 | null | null |
| destination_ip | DestinationIp, event 3 | null | null |
| script_block_id | null | null | ScriptBlockId, event 4104 |
| script_block_text | null | null | ScriptBlockText, event 4104 |
| context_info | null | null | ContextInfo, event 4103 |
| payload | null | null | Payload, event 4103 |

Keep PID strings unchanged initially; hexadecimal and decimal forms cannot
be joined directly. Keep remaining source-specific fields in raw.
Missing, null, empty-string and "-" optional values map to null.
Retain meaningful false and zero values. Never replace missing fields by guessing.

## Validation gate

- Verify raw hashes before processing; never modify source files.
- Account for 1127 DS001 and 4348 DS002 records, including other providers.
- Retain physical line numbers; count blank lines separately.
- Report malformed records or invalid mapped types; do not silently drop them.
- Require unique event_uid values; report duplicate content without deleting it.
- Check normalized examples against their original lines for all three sources.
- Report timestamp nulls and failures separately; unresolved times remain null.
- Verify script-block grouping and fragment metadata before reconstruction.
- Write derived records under data/processed and validation reports under docs.
