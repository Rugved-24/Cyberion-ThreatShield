# HUNT-001: Remote service execution between WORKSTATION5 and WORKSTATION6

- Techniques under test: **T1021.002 SMB/Windows Admin Shares** and **T1569.002
  Service Execution** (ATT&CK 19.2, object versions 1.3 and 1.3)
- Coverage status at the time of the hunt: **Not Covered** for both
- Rule coverage at the time of the hunt: CT-003 and CT-014 were authored but neither
  had produced a detection. T1071.001 in HUNT-002 is the qualifying hunt against a
  technique with no rule at all; this hunt is run because the source scenario is
  named for remote execution and the coverage matrix showed nothing.
- Pre-hunt commit: **`e873dc9`** ("Generate tested ATT&CK coverage layer and matrix
  from replay evidence")
- Pre-hunt matrix: `coverage/matrix-v2.md`
- Hunt date: 2026-09-29
- Method boundary: log analysis and GUID joins only. No remote execution was
  attempted against any host.

## 1. Hypothesis

A remote execution or lateral movement sequence occurred between the two
workstations in DS002, in which a process on `WORKSTATION5.theshire.local` caused
a service on `WORKSTATION6.theshire.local` to execute a command shell.

Stated so that it can be refuted: **if the service execution on WORKSTATION6 was
locally initiated, then no cross-host RPC activation of that service should appear
in the recording, and the cross-host RPC records that do exist should be
unrelated in time and process identity.**

### Alternative explanations considered in advance

1. Ordinary domain and management traffic between the two workstations, since both
   are members of the same domain and both appear in the same capture.
2. A locally initiated service execution on WORKSTATION6, with the cross-host RPC
   records belonging to unrelated activity.
3. Cross-host traffic that is real but cannot be causally linked to the service
   execution, because the required records have no resolved event time.

## 2. Method and evidence

All RPC-related records in DS002 were enumerated from three fields: destination
port, the recorded application, and the source address. Destination ports 135, the
DCOM endpoint mapper, and 49726, a dynamic RPC port, were used as the starting
set because those are the ports a Service Control Manager activation traverses.

### 2.1 Cross-host RPC inventory

| Line | Source | Host name on the record | Flow | Application | Resolved UTC |
| --- | --- | --- | --- | --- | --- |
| DS002:1206 | Security 5156 | WORKSTATION6.theshire.local | 172.18.39.5:56607 to 172.18.39.6:135 | svchost.exe | unresolved |
| DS002:1207 | Security 5156 | WORKSTATION6.theshire.local | 172.18.39.5:56608 to 172.18.39.6:49726 | services.exe | unresolved |
| DS002:1229 | Security 5156 | WORKSTATION5.theshire.local | 172.18.39.5:56607 to 172.18.39.6:135 | powershell.exe | unresolved |
| DS002:1232 | Security 5156 | WORKSTATION5.theshire.local | 172.18.39.5:56608 to 172.18.39.6:49726 | powershell.exe | unresolved |
| DS002:1364 | Sysmon 3 | WORKSTATION6.theshire.local | to 172.18.39.6:135 | svchost.exe | 16:16:56.010 |
| DS002:1366 | Sysmon 3 | WORKSTATION6.theshire.local | to 172.18.39.6:49726 | services.exe | 16:16:56.019 |
| DS002:1367 | Sysmon 3 | WORKSTATION5.theshire.local | to 172.18.39.6:135 | powershell.exe | 16:16:58.794 |
| DS002:1370 | Sysmon 3 | WORKSTATION5.theshire.local | to 172.18.39.6:49726 | powershell.exe | 16:16:58.803 |

172.18.39.5 is the address recorded for `WORKSTATION5.theshire.local` and
172.18.39.6 for `WORKSTATION6.theshire.local` in the same records. The two host
names are distinct strings and are not merged with the bare `WORKSTATION6` or with
DS001's `WORKSTATION5`.

The same two source ports, 56607 and 56608, appear in the records held on both
hosts, which is the expected shape of a flow logged at both ends.

### 2.2 The GUID join that holds

The decisive observation is a **ProcessGuid equality join inside one dataset on
one exact host string**, which is the only join method this project permits.

| Record | Line | Process GUID | UTC |
| --- | --- | --- | --- |
| services.exe network connection | DS002:1366 | `{d273d0f0-e865-5f64-0b00-000000000800}` | 16:16:56.019 |
| cmd.exe process creation, `ParentProcessGuid` | DS002:1057 | `{d273d0f0-e865-5f64-0b00-000000000800}` | 16:16:56.597 |

The recorded parent of the command shell is the very process that had just
connected to the dynamic RPC port, **0.578 seconds earlier**. A second, independent
host of evidence agrees: Security 4688 at DS002:1226 records `cmd.exe` with parent
`services.exe` on the same host.

The full chain on WORKSTATION6, every link GUID-joined, all times Sysmon `UtcTime`:

| Step | Line | Process | Parent | UTC |
| --- | --- | --- | --- | --- |
| RPC endpoint contacted | DS002:1364 | svchost.exe | — | 16:16:56.010 |
| Service Control Manager reaches dynamic RPC port | DS002:1366 | services.exe | — | 16:16:56.019 |
| Command shell created | DS002:1057 | cmd.exe | services.exe | 16:16:56.597 |
| Concealed PowerShell created | DS002:1073 | powershell.exe | cmd.exe | 16:16:56.620 |
| Account discovery | DS002:2901 | whoami.exe | powershell.exe | 16:17:18.795 |
| Retrieval to an internal address | DS002:2513 | powershell.exe | — | 16:17:01.152 |

### 2.3 Where the causal claim fails

The hypothesis that a process on WORKSTATION5 **caused** the service execution on
WORKSTATION6 is **not established**, and the reason is specific and checkable.

The Security 5156 records carry no resolved event time. Their `EventTime` fields
read 12:16:56 while their `@timestamp` fields read 16:16:58.210 to 16:16:58.224Z.
The project's timestamp policy forbids inferring a timezone to force an ordering,
and the four-hour difference between the two fields is exactly the unresolved
discrepancy that policy exists to prevent being papered over. These records are
therefore used for **attribution of the application and the flow**, never for
**ordering**.

With ordering restricted to Sysmon `UtcTime`, the two cross-host RPC episodes fall
on either side of the service execution:

- 16:16:56.010 and 16:16:56.019, RPC on WORKSTATION6 by `svchost.exe` and
  `services.exe`, **0.578 seconds before** the command shell. No record in the
  capture identifies a remote source for this episode.
- 16:16:58.79, RPC from `WORKSTATION5.theshire.local` by `powershell.exe`, which
  **2.2 seconds after** the service execution. A remote source is identified here.

The episode with an identified remote source is the **later** one. The episode that
precedes the service execution has no identified remote source. The hypothesis is
therefore neither confirmed nor refuted on attribution: the records are consistent
with remote activation and also consistent with a local trigger whose remote origin
was not captured.

### 2.4 What was ruled out

- **Not administrative share access.** All three Security 5140 and 5145 records in
  DS002 (lines 728, 729, 730) are on host `MORDORDC.theshire.local`, are performed
  by the machine account `MORDORDC$`, and read the SYSVOL `gpt.ini` group policy
  templates. This is domain controller Group Policy replication. It is not lateral
  movement and it is not on either workstation.
- **Not credential use on WORKSTATION5.** DS001's host string is `WORKSTATION5`
  with no domain, and the acting account there is `wardog`. DS002's
  `WORKSTATION5.theshire.local` is a different host string. The two are not merged
  and no account relationship between them is claimed.
- **Not the source of the WORKSTATION6 activity by process identity.** The
  PowerShell process on `WORKSTATION5.theshire.local` has GUID
  `{b34bc01c-7dfc-5f67-de11-000000000400}`. The PowerShell process on
  `WORKSTATION6.theshire.local` has GUID `{d273d0f0-8078-5f67-cc06-000000000800}`.
  They are unrelated identifiers on unrelated hosts.

## 3. Findings

1. A Service Control Manager process on WORKSTATION6 connected to a dynamic RPC
   port and became, 0.578 seconds later by GUID join, the recorded parent of a
   command shell. A second log source, Security 4688, records the same parent-child
   relationship. The service execution itself is confirmed.
2. The service was registered as a service with a PowerShell binary path running as
   LocalSystem (DS002:1213, Security 4697). The registration record has no resolved
   event time, so the association between the registration and the execution rests
   on identical command text rather than on a timestamp.
3. Cross-host RPC traffic between the two workstations is present and
   cross-attributed, but the episode that precedes the service execution has no
   identified remote source, and the episode with an identified remote source
   follows it by 2.2 seconds.
4. No SMB or administrative share access between the two workstations exists in the
   capture.

## 4. Conclusion

**Partially supported.** The remote service execution pattern on WORKSTATION6 is
confirmed. The **lateral movement attribution to WORKSTATION5 is inconclusive**, and
it is recorded as inconclusive rather than upgraded, because the only records that
identify a remote process lack resolved event times.

Both techniques therefore keep their honest status on the matrix:

- **T1569.002 Service Execution: Partially Covered**, via CT-003 and CT-C02, which
  matched the confirmed execution.
- **T1021.002 SMB/Windows Admin Shares: Not Covered.** The hypothesis named SMB and
  admin shares, and the capture contains no attacker instance of either. CT-014 was
  authored, tuned against real benign activity and tested; it matched nothing. That
  is a precision result, not a detection, and the technique stays at zero.

### 4.1 What would close the lateral movement gap

- A capture that includes Security 5156 with a trustworthy event time, or the
  equivalent network telemetry, so that the two RPC episodes can be ordered.
- Service Control Manager operational events, event 7045 in the System log, which
  would date the service installation to the same clock as the process events.
- A longer capture covering the authentication that preceded the RPC, so that the
  account used to activate the service can be identified rather than inferred.

### 4.2 Hand-off

The confirmed service execution is carried into `incidents/INC-001.md`. The
unresolved attribution is carried forward as an open question in that report rather
than being closed here, and it is the reason the incident's root-cause section
distinguishes what is known from what is not.

## 5. Negative results recorded

- No event 4625 exists in either dataset, so no failed authentication could be used
  to test whether the service activation was preceded by credential guessing.
- No event 7045 exists in either dataset, so the service installation cannot be
  dated on the System channel.
- No Sysmon event 3 or 22 record in DS002 shows either workstation connecting to
  the other for administrative share access; the only cross-host flows are the RPC
  pairs listed in section 2.1.
- No SMB, named pipe or `ADMIN$` artefact was found in any record.
