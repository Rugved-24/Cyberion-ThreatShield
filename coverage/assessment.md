# Cyberion ThreatShield: Initial ATT&CK Assessment

Assessment date: 2026-09-18 UTC. Phase 4; scoped Windows telemetry assessment.

**20 distinct active technique IDs; 11 associated tactics; 20 Not Covered; 0 tested detections.**
The evidence states are 4 candidate evidence, 5 mapping review, 8 needs corroboration, 3 evidence gap.
These evidence states describe investigation readiness, not detection coverage.

## Framework and evidence provenance

- Framework: MITRE Enterprise ATT&CK **19.2**; [release history](https://attack.mitre.org/resources/versions/) and [v19 website](https://attack.mitre.org/versions/v19/).
- Immutable [STIX source](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/6cda5ad8462c79e14fbb872f4e09059b18e0cfc4/enterprise-attack/enterprise-attack-19.2.json); repository revision `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4`.
- Source SHA-256: `DC1639CAA5501D720E280CF1CBD8FBE009884A0C9B3E6E9ED9D0C25166C3D8F4`.
- Technique names, memberships and object versions were checked against that source; all selected IDs are active and not deprecated.
- Navigator format: [layer 4.5](https://github.com/mitre-attack/attack-navigator/blob/v5.3.2/layers/spec/v4.5/layerformat.md). `versions.attack` selects the v19 domain; metadata pins the exact 19.2 content used here.
- In v19, Mshta is under Stealth. Do not copy the older Defense Evasion labels from dataset directory names or substitute obsolete IDs to satisfy a validator.
- `DS001:275` means physical line 275 in the original DS001 JSONL file. Resolve files through `docs/DS001-inventory.json` and `docs/DS002-inventory.json`; reconstruct a full event UID as `dataset_id:raw_sha256:line`.
- DS001 raw SHA-256: `25AA24B5F631F19AC23F64DB116C23E632295FB5F59040E966FA47E7758B2A32`.
- DS002 raw SHA-256: `968C4B699F7239D106577B2B8E206EDFAF812F193A60E663966258AF67A56ACC`.
- Review used public copies matching those hashes. Your prior validation traced all 5,475 normalized records to original lines.

## Status contract and scope

- **Not Covered (score 0):** no defensible tested detection for the stated behavior. Every entry starts here.
- **Partially Covered (score 1):** some variants or required telemetry are supported, with documented material limitations and evidence.
- **Covered (score 2):** the explicitly scoped behavior has reproducible real-data detection tests; limitations are stated.

This is a baseline for the selected environment and techniques, not enterprise-wide coverage. Tactic memberships below are ATT&CK taxonomy: they do not prove those objectives occurred in these captures. An unlisted technique is unassessed. Multiple memberships and related rules do not multiply distinct technique coverage. No parent/sub-technique pair is double-counted in these 20 entries.

Candidate evidence means a corresponding entry exists in `docs/detection_backlog.md`. Mapping review means visible behavior needs mapping/scope review before a candidate is assigned. Needs corroboration means relevant telemetry or leads exist but do not establish the behavior sufficiently. Evidence gap means a usable labeled example has not been established. Background activity remains unlabeled unless independently validated.

## Matrix

All rows have coverage status **Not Covered**. Candidate IDs below refer to plans, not implemented Sigma rules.

| Technique and object version | ATT&CK tactic(s) | Evidence state | Current candidate IDs |
| --- | --- | --- | --- |
| [T1218.005 - Mshta](https://attack.mitre.org/versions/v19/techniques/T1218/005) (v3.0) | Stealth | Candidate evidence | CT-001, CT-C01 |
| [T1059.001 - PowerShell](https://attack.mitre.org/versions/v19/techniques/T1059/001) (v1.5) | Execution | Candidate evidence | CT-002, CT-C01, CT-C02, CT-C03 |
| [T1569.002 - Service Execution](https://attack.mitre.org/versions/v19/techniques/T1569/002) (v1.3) | Execution | Candidate evidence | CT-003, CT-C02 |
| [T1033 - System Owner/User Discovery](https://attack.mitre.org/versions/v19/techniques/T1033) (v1.6) | Discovery | Candidate evidence | CT-004, CT-C03 |
| [T1059.003 - Windows Command Shell](https://attack.mitre.org/versions/v19/techniques/T1059/003) (v1.5) | Execution | Mapping review | None assigned |
| [T1059.005 - Visual Basic](https://attack.mitre.org/versions/v19/techniques/T1059/005) (v1.5) | Execution | Mapping review | None assigned |
| [T1518.001 - Security Software Discovery](https://attack.mitre.org/versions/v19/techniques/T1518/001) (v1.5) | Discovery | Mapping review | None assigned |
| [T1027.010 - Command Obfuscation](https://attack.mitre.org/versions/v19/techniques/T1027/010) (v2.0) | Stealth | Mapping review | None assigned |
| [T1685 - Disable or Modify Tools](https://attack.mitre.org/versions/v19/techniques/T1685) (v1.0) | Defense Impairment | Mapping review | None assigned |
| [T1021.002 - SMB/Windows Admin Shares](https://attack.mitre.org/versions/v19/techniques/T1021/002) (v1.3) | Lateral Movement | Needs corroboration | None assigned |
| [T1047 - Windows Management Instrumentation](https://attack.mitre.org/versions/v19/techniques/T1047) (v1.6) | Execution | Needs corroboration | None assigned |
| [T1053.005 - Scheduled Task](https://attack.mitre.org/versions/v19/techniques/T1053/005) (v1.8) | Execution; Persistence; Privilege Escalation | Needs corroboration | None assigned |
| [T1543.003 - Windows Service](https://attack.mitre.org/versions/v19/techniques/T1543/003) (v1.6) | Persistence; Privilege Escalation | Needs corroboration | None assigned |
| [T1547.001 - Registry Run Keys / Startup Folder](https://attack.mitre.org/versions/v19/techniques/T1547/001) (v2.1) | Persistence; Privilege Escalation | Evidence gap | None assigned |
| [T1003.001 - LSASS Memory](https://attack.mitre.org/versions/v19/techniques/T1003/001) (v1.5) | Credential Access | Needs corroboration | None assigned |
| [T1110.003 - Password Spraying](https://attack.mitre.org/versions/v19/techniques/T1110/003) (v1.8) | Credential Access | Evidence gap | None assigned |
| [T1078 - Valid Accounts](https://attack.mitre.org/versions/v19/techniques/T1078) (v3.0) | Stealth; Persistence; Privilege Escalation; Initial Access | Needs corroboration | None assigned |
| [T1105 - Ingress Tool Transfer](https://attack.mitre.org/versions/v19/techniques/T1105) (v2.6) | Command and Control | Needs corroboration | None assigned |
| [T1071.001 - Web Protocols](https://attack.mitre.org/versions/v19/techniques/T1071/001) (v1.5) | Command and Control | Needs corroboration | None assigned |
| [T1486 - Data Encrypted for Impact](https://attack.mitre.org/versions/v19/techniques/T1486) (v1.5) | Impact | Evidence gap | None assigned |

## Per-technique evidence and next actions

### T1218.005 - Mshta

- Required telemetry: Process creation with image, command line and process/parent GUIDs.
- Available evidence: [DS001:275](../docs/DS001-inventory.json) records inline VBScript in mshta.exe; [DS001:398](../docs/DS001-inventory.json) is its GUID-linked PowerShell child.
- Limitation: Only this inline-VBScript variant is represented; no rule has passed replay or benign testing.
- Next action: Implement CT-001 first and retain CT-C01 for correlation development.

### T1059.001 - PowerShell

- Required telemetry: PowerShell process creation and, for content inspection, script-block/module logging.
- Available evidence: [DS001:398](../docs/DS001-inventory.json) launches PowerShell; [DS002:1073](../docs/DS002-inventory.json) has an encoded-command switch; [DS002:1827](../docs/DS002-inventory.json) retains script text.
- Limitation: A command or script record does not establish that every embedded operation succeeded.
- Next action: Implement bounded argument matching and test ordinary administrative invocations.

### T1569.002 - Service Execution

- Required telemetry: Process parent/child context; service-installation records for corroboration.
- Available evidence: [DS002:1057](../docs/DS002-inventory.json) has services.exe as cmd.exe's parent; line 1073 is its PowerShell child; line 1213 registers Updater.
- Limitation: The registration event's UTC time is unresolved. ParentImage alone does not establish malicious intent.
- Next action: Test the Sysmon-scoped candidate; defer temporal joins to Security events.

### T1033 - System Owner/User Discovery

- Required telemetry: Process creation with image, command line and parent identity.
- Available evidence: [DS002:2901](../docs/DS002-inventory.json) records whoami.exe as a child of the PowerShell process at line 1073.
- Limitation: The process launch does not preserve its output; whoami also supports legitimate administration.
- Next action: Use parent context and collect a confirmed benign comparison before claiming useful detection.

### T1059.003 - Windows Command Shell

- Required telemetry: Command-shell process creation and command-line content.
- Available evidence: [DS002:1057](../docs/DS002-inventory.json) records cmd.exe /C starting PowerShell.
- Limitation: CT-003 currently maps Service Execution; a Command Shell mapping has not yet been assigned.
- Next action: Review adding this mapping to CT-003; do not manufacture a duplicate rule to raise the rule count.

### T1059.005 - Visual Basic

- Required telemetry: Interpreter/host process command line and corroborating script or child-process evidence.
- Available evidence: [DS001:275](../docs/DS001-inventory.json) contains inline VBScript and line 398 records the resulting PowerShell child.
- Limitation: The existing CT-001 mapping is Mshta; broader Visual Basic execution variants remain unassessed.
- Next action: Review whether the scoped CT-001 behavior warrants an additional mapping.

### T1518.001 - Security Software Discovery

- Required telemetry: Process or script text naming a security product/service.
- Available evidence: [DS001:398](../docs/DS001-inventory.json) contains Get-Service sysmon.
- Limitation: The query is visible; its result and operator intent are not established by this event alone.
- Next action: Evaluate a security-service discovery candidate and an authorized inventory comparison.

### T1027.010 - Command Obfuscation

- Required telemetry: Full command/script content, including encoded arguments, with reproducible static inspection.
- Available evidence: [DS002:1073](../docs/DS002-inventory.json) contains -enc and a long encoded argument; line 1827 retains mixed-case and concatenated script text.
- Limitation: Encoding also has legitimate uses. CT-002 currently maps PowerShell only.
- Next action: Document encoding/obfuscation evidence and scope before extending CT-002's mapping.

### T1685 - Disable or Modify Tools

- Required telemetry: Script content or security-control changes with enough context to identify the attempted impairment.
- Available evidence: [DS002:1827](../docs/DS002-inventory.json) contains script text attempting logging-setting and AMSI-related field changes.
- Limitation: Static content supports a proposed impairment attempt, not successful impairment. Rendering-flag meaning remains unresolved.
- Next action: Review the script statically and select the appropriate v19.2 parent/sub-technique scope before adding a rule.

### T1021.002 - SMB/Windows Admin Shares

- Required telemetry: SMB/admin-share activity linked to authenticated sessions and remote execution.
- Available evidence: [DS002:728-730](../docs/DS002-inventory.json) are SYSVOL policy-file share events; lines 1364-1370 contain RPC-related connection leads.
- Limitation: Neither the PsExec scenario label nor SYSVOL access proves an attacker SMB/admin-share sequence.
- Next action: Acquire or identify a coherent admin-share scenario and validate its identity/time joins.

### T1047 - Windows Management Instrumentation

- Required telemetry: WMI operation context and attributable process execution or remote-management activity.
- Available evidence: [DS002:2451](../docs/DS002-inventory.json), 4216 and 4219 are WMI provider-start events; line 2469 launches WmiPrvSE.exe.
- Limitation: Provider startup and the executable name do not establish adversary WMI execution.
- Next action: Find operation/child-process evidence or acquire a labeled WMI execution recording.

### T1053.005 - Scheduled Task

- Required telemetry: Task registration/modification or task definition plus attributable action execution.
- Available evidence: [DS002:359](../docs/DS002-inventory.json) launches an Office-named scheduled task; line 363 records OfficeC2RClient.exe.
- Limitation: These records do not establish attacker task creation or persistence and are not assigned a benign label.
- Next action: Collect task-definition/change evidence and documented legitimate task comparisons.

### T1543.003 - Windows Service

- Required telemetry: Service creation/change, binary path, account and start configuration, with execution/context.
- Available evidence: [DS002:1213](../docs/DS002-inventory.json) installs Updater with a PowerShell-containing service command; process leads occur at 1057 and 1073.
- Limitation: Service creation is observed; persistence or privilege-escalation objectives are unproven. Security UTC is unresolved.
- Next action: Assess service-creation scope separately from CT-003's execution signal and validate legitimate installers.

### T1547.001 - Registry Run Keys / Startup Folder

- Required telemetry: Run-key writes or Startup-folder changes, plus later execution and a documented positive case.
- Available evidence: Sysmon registry/file telemetry exists, but the reviewed registry events have no CurrentVersion\Run target.
- Limitation: Startup-folder persistence has not been established; these short captures cannot establish absence generally.
- Next action: Acquire an attributed persistence recording with both modification and resulting execution.

### T1003.001 - LSASS Memory

- Required telemetry: LSASS process-access details with source identity, access mask/call trace and corroborating activity.
- Available evidence: [DS002:2466](../docs/DS002-inventory.json), 2467, 3108, 4276, 4278, 4332 and 4333 are LSASS accesses from svchost.exe.
- Limitation: Access alone does not prove credential dumping; process names alone do not establish legitimacy either.
- Next action: Review source provenance, access details and surrounding events; obtain confirmed positive/benign examples.

### T1110.003 - Password Spraying

- Required telemetry: A sufficient-duration authentication series containing failures across users and source context.
- Available evidence: Neither capture contains Security-Auditing event 4625; no labeled spraying sequence is established.
- Limitation: Successful logons and short capture duration cannot establish password spraying or its absence.
- Next action: Acquire an authentication-failure dataset with controlled spraying and legitimate failed-login comparisons.

### T1078 - Valid Accounts

- Required telemetry: Authentication records plus account ownership, authorization and relevant activity context.
- Available evidence: [DS002:1209](../docs/DS002-inventory.json) records a network logon as pgustavo; line 1213 shares its host and logon ID.
- Limitation: Account use is recorded; credential compromise and applicable adversary objectives need corroboration.
- Next action: Establish the account's authorized use and resolve temporal semantics before wider session correlation.

### T1105 - Ingress Tool Transfer

- Required telemetry: Transfer command plus network, response, file or memory evidence supporting transferred content.
- Available evidence: [DS002:1827](../docs/DS002-inventory.json) contains retrieval-related script content; line 2513 records PowerShell connecting to 10.10.10.5:80.
- Limitation: A script and connection do not demonstrate a completed tool transfer or identify the returned content.
- Next action: Seek corroborating transfer artifacts or a dataset with request/response and resulting content evidence.

### T1071.001 - Web Protocols

- Required telemetry: Process-linked connections and web-protocol/session content or context supporting a C2 assessment.
- Available evidence: [DS002:2513](../docs/DS002-inventory.json) is a connection to 10.10.10.5:80 from the process GUID created at 1073; script context is at 1827.
- Limitation: Port 80 is not proof of HTTP or C2. A single connection does not establish beaconing. Script UTC is unresolved.
- Next action: Reserve for HUNT-002; assess C2 versus one-off retrieval using static script review and process/network evidence.

### T1486 - Data Encrypted for Impact

- Required telemetry: Labeled file-change effects and process context sufficient to demonstrate encryption for impact.
- Available evidence: File-related Sysmon events exist, but no confirmed encryption-for-impact sequence has been identified.
- Limitation: Generic file operations and this project's name do not establish ransomware activity.
- Next action: Acquire a documented safe-emulation recording with known file effects if this gap is selected for implementation.

## First five priorities

Priority reflects telemetry availability, scenario relevance, analyst value and testing feasibility. Correlations remain scheduled for their build phase; this ranking does not authorize skipping prerequisite rule tests.

| Rank | Candidate | Observed behavior | Justification and validation need |
| --- | --- | --- | --- |
| 1 | CT-001 | Mshta runs inline VBScript | Complete process fields and a specific behavior in DS001; high relevance and a small first implementation. Test casing, missing fields, unrelated processes and approved automation. |
| 2 | CT-002 | PowerShell uses an encoded-command argument | Full process/command evidence in DS002; useful investigation signal. Test argument boundaries and variants; encoding alone is insufficient to classify intent. |
| 3 | CT-003 | A service launches cmd.exe | Parent context exists without relying on unresolved Security timestamps; useful service-abuse lead. Legitimate service wrappers need comparison before judging alert quality. |
| 4 | CT-C01 | Mshta creates PowerShell | Both Sysmon records, same host and exact GUID linkage exist; observed delay is 0.607 seconds. Adds context after the base rule; validate joins, ordering and window boundaries. |
| 5 | CT-C02 | Service-launched shell creates encoded PowerShell | Exact Sysmon GUID linkage exists; observed delay is 0.023 seconds. Adds service context to CT-002/003; validate unrelated/benign chains and choose a defensible window. |

CT-004 and CT-C03 remain in the backlog. The seven current candidates do not satisfy the final requirement for 15 tested detections. Add candidates only for distinct useful behavior with reproducible evidence; do not split equivalent logic merely to increase counts.

## Reserved HUNT-002 gap

- **Technique:** T1071.001 - Web Protocols. Current status: Not Covered. No existing backlog rule evaluates network/C2 behavior.
- **Hypothesis:** the web-oriented activity of the DS002 encoded PowerShell process supports a command-and-control interpretation. Alternatives include a one-off staging download, authorized administration, or insufficient telemetry to distinguish them.
- **Usable starting evidence:** DS002:1073 (process creation), DS002:2513 (matching process GUID, connection to 10.10.10.5:80), and DS002:1827 (script context).
- **Method boundary:** use static script review and log analysis. Scope GUID joins to recording and exact host; preserve UTC uncertainty on script records. Do not infer HTTP solely from the port, merge unverified host aliases, or infer periodic beaconing from one connection.
- **Possible outcome:** supported, rejected or inconclusive hypothesis, with the evidence and limits recorded. A hunt result does not automatically become a tested detection.
- **Before the hunt:** commit this baseline and record that commit in `hunts/HUNT-002.md`. No commit hash is claimed here. If a validated rule covers the target before the hunt, select and document another gap first.
- **Baseline file:** `coverage/baseline.json`; SHA-256 `0545961215106A38AAF5D8B4A497C5207765A7B839E9A098BD84849BFC5E03BD`.

## Data and validation constraints

All three core telemetry types are available across the recordings, but availability is event/field specific. DS001 has no PowerShell Operational records. DS002 has no ordinary Sysmon ProcessId field; use validated GUID joins. Non-Sysmon event-time UTC remains unresolved (235 DS001 and 1,407 DS002 records). Preserve the 74 repeated-content DS001 records and their separate source-line IDs.

The next data priorities are a documented benign comparison, coherent authentication-failure evidence for spraying, and an attributed persistence recording. Network response/content evidence would improve the reserved hunt. Local benign collection must establish what was actually recorded; ordinary commands do not guarantee every required audit source is enabled.

For this baseline, technique IDs/versions/tactics, all cited line locators, distinct counts and candidate references were checked. The JSON is generated to Navigator's published layer format; interactive import is a separate local check. Load `coverage/baseline.json` in Navigator, verify the name/domain and Not Covered legend, and retain an export with the project. Tactic columns may repeat a technique; the file contains 20 distinct technique IDs.

Once local files and the Navigator view are checked, record the Phase 4 checkpoint. Phase 5 begins with CT-001, including real-data replay and explicit validation results.
