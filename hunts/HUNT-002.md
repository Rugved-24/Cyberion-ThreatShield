# HUNT-002: Web-protocol command and control from the encoded PowerShell process

- Technique under test: **T1071.001 Web Protocols** (ATT&CK 19.2, object version 1.5)
- Coverage status at the time of the hunt: **Not Covered**
- Rule coverage at the time of the hunt: **none**. No rule existed for T1071.001, and
  none was written before the hunt, so the hypothesis could not be biased by an
  existing rule.
- Pre-hunt baseline commit: **`a85ce34`** ("Record ATT&CK coverage baseline and
  detection backlog")
- Pre-hunt baseline file: `coverage/baseline.json`, SHA-256
  `0545961215106A38AAF5D8B4A497C5207765A7B839E9A098BD84849BFC5E03BD`
- Hunt date: 2026-09-29
- Analyst role: Detection Engineer / Threat Hunter, single analyst
- Method boundary: static script review and log analysis only. No traffic was
  generated, replayed or re-requested.

## 1. Hypothesis

The PowerShell process created on WORKSTATION6 at 16:16:56.620 UTC is
command-and-controlled over a web protocol, and the connection observed to
10.10.10.5 on port 80 is that command-and-control channel rather than a single
retrieval.

The hypothesis is stated in the falsifiable form that the analysis must be able to
refute: **if the activity is a one-off staging download, then the capture should
show a single retrieval and no repeating pattern, and no evidence of an ongoing
session.**

### Alternative explanations considered in advance

1. A one-off retrieval of a second-stage payload, with no persistent channel.
2. Authorised administrative or deployment activity using a download.
3. Insufficient telemetry to distinguish any of the above, because the capture is
   short and contains no response content.

## 2. Starting evidence

| Reference | What it shows |
| --- | --- |
| DS002:1073 | PowerShell process creation, encoded-command switch, Sysmon event 1, 16:16:56.620 UTC |
| DS002:2513 | Network connection from that process to 10.10.10.5:80, Sysmon event 3, 16:17:01.152 UTC |
| DS002:1827 | The PowerShell script block, event 4104, which contains the download logic |
| DS002:2367 | Windows Filtering Platform record, Security 5156, naming the same destination and a PowerShell application path |

The process identity link between 1073 and 2513 is a **ProcessGuid equality on the
same dataset and the same exact host string**, not a process identifier join:
DS002 has no ordinary Sysmon `ProcessId`, and hexadecimal and decimal process
identifiers cannot be joined. The PowerShell process GUID is
`{d273d0f0-8078-5f67-cc06-000000000800}` and it is identical in both records.

## 3. Analysis performed

### 3.1 Static review of the script block

DS002:1827 is a single PowerShell script block. Read literally, it performs, in
order: a check of the PowerShell version, a write of the ScriptBlockLogging
policy values to zero, a set of the AMSI initialisation-failure field, a
`WebClient` construction that attaches the process default web proxy and the
default network credential cache, a user-agent string, a base64-decoded server
address, a fixed request path `/news.php`, a fixed cookie, an RC4 key schedule
and a call to `Invoke-Expression` on the decoded result.

The embedded address is stored as a base64 string that decodes, as UTF-16LE, to
`http://10.10.10.5`. This is a direct, checkable observation and not an
interpretation: the decoded value matches the destination address recorded in
DS002:2513.

Two properties of the script matter for the hypothesis:

- The download is a **single** `DownloadData` call followed by a single
  `Invoke-Expression`. There is no loop, no sleep-and-repeat, and no timer in the
  captured text.
- The tool is a **stager**: its purpose is to obtain and run further instructions.
  That is consistent with command and control, but a capability to receive
  instructions is not an observation of an established channel.

### 3.2 Connection frequency, which is the decisive test

Every Sysmon event 3 and event 22 record in DS002 was enumerated. Connections from
the PowerShell process GUID `{d273d0f0-8078-5f67-cc06-000000000800}`:

| Line | Type | Destination | UTC |
| --- | --- | --- | --- |
| DS002:2513 | Sysmon 3 | 10.10.10.5:80 | 16:17:01.152 |
| DS002:2625 | Sysmon 22 DNS | query name `localhost` | 16:17:02.160 |

**There is exactly one connection to 10.10.10.5 in the entire recording.** No
second connection, no interval, no jitter pattern, and no repeat.

The capture window matters as much as the count. The records in DS002 that carry a
resolved event time span **16:16:06.470 to 16:18:20.199 UTC, about 2 minutes and
14 seconds**. A beacon is defined by repetition over time. Two minutes and fourteen
seconds of data cannot distinguish a 60-second beacon with jitter from a single
request, because at most two intervals could have been observed and one of them
falls outside the window.

### 3.3 Is port 80 a useful discriminator? A negative result worth recording

Port 80 was tested as a candidate signal and **rejected as a discriminator**. All 83
Security 5156 records in DS002 were grouped by destination port and destination
address:

| Destination port 80 destination | Records | Application |
| --- | --- | --- |
| 168.63.129.16 | 39 | windowsazureguestagent.exe, waappagent.exe, wasecagentprov.exe |
| 169.254.169.254 | 3 | windowsazureguestagent.exe |
| 10.10.10.5 | 1 | powershell.exe |

Forty-two of the 43 port-80 connections in this recording are ordinary Azure
platform traffic: the guest agent talking to the Azure wire server and to the
instance metadata service. A rule of the form "connection to port 80" would have
produced 43 alerts, of which 42 were benign. This is recorded as a negative result
because it is the single most useful thing this hunt produced for rule authors, and
it is the reason T1071.001 has no rule.

### 3.4 Independent corroboration of the connection

The connection is attested by **two independent log sources**:

| Source | Line | Host | Content |
| --- | --- | --- | --- |
| Sysmon event 3 | DS002:2513 | WORKSTATION6.theshire.local | destination 10.10.10.5:80, process GUID as above, 16:17:01.152 UTC |
| Security 5156 | DS002:2367 | WORKSTATION6.theshire.local | source 172.18.39.6:63854 to 10.10.10.5:80, application `\device\harddiskvolume2\windows\system32\windowspowershell\v1.0\powershell.exe` |

The 5156 record names the initiating application as `powershell.exe` and matches
the destination address and port exactly. This is corroboration by attribute
(host string, destination, application path), **not** a join: the 5156 record
carries `ProcessId` 4312 in decimal, DS002 has no Sysmon `ProcessId`, and the
project's timestamp policy forbids inferring a timezone to force an ordering that
the records do not support.

The 5156 record's own `EventTime` reads 12:17:01 while its `@timestamp` reads
16:17:02.941Z, a four-hour difference. That difference is recorded as an
unresolved local-versus-UTC rendering discrepancy and was **not** used to place the
event in the sequence. Ordering rests only on Sysmon `UtcTime`.

### 3.5 What is absent

- No HTTP request line, header, user-agent or response body is present in any
  captured record. The user-agent string exists only inside the script text.
- No packet capture, proxy log or web gateway log is present.
- No DNS resolution for any domain name by this process; the only DNS query is for
  `localhost`. The destination was used as a literal address.
- No second-stage script text is present. The `Invoke-Expression` result was not
  captured, so what was retrieved is unknown.
- The destination 10.10.10.5 is inside RFC 1918 private space. It is not an
  internet-routable address, so "external command and control" cannot be asserted.

## 4. Findings

1. A PowerShell process with a concealed encoded command retrieved content from an
   internal address on port 80 and evaluated it in memory. This is confirmed by
   two independent sources and by static script content.
2. The retrieval to 10.10.10.5 occurred **once**. No repeating pattern exists in the
   recording.
3. The available time base for ordering is 2 minutes 14 seconds, which is
   structurally insufficient to characterise beaconing.
4. Port 80 is a poor discriminator in this environment: 42 of 43 port-80
   connections are Azure platform traffic.
5. The destination is a private address, so the activity is not external command
   and control as the term is normally applied.

## 5. Conclusion

**Inconclusive** for T1071.001 Web Protocols as a command-and-control channel.

The tool-transfer interpretation is **supported** and is already covered by CT-009
and scored Partially Covered. The command-and-control interpretation is **plausible
but not established**, and the single-connection count is the reason it is not
upgraded to confirmed. A stager is built to receive further instructions, but this
capture shows one retrieval and no session.

This is a negative result in the honest sense: the hypothesis was neither confirmed
nor refuted, and the reason it could not be resolved is recorded together with the
data that would resolve it.

### 5.1 What would settle it

- A capture of at least several hours from the same instrumentation, which would
  expose a repeating interval if one exists.
- Proxy, web gateway or packet capture content for the destination, which would
  show the request shape and the response body.
- The second-stage script text, which would show whether the payload is a beacon
  configuration or a further stager.
- DNS or NetFlow history for the destination across other hosts, which would show
  whether the address is a shared staging server or a dedicated one.

### 5.2 Consequence for detection content

T1071.001 stays **Not Covered** on `coverage/matrix-v2.md`, with CT-001 style
content deliberately withheld. No rule was written for it, because a rule at this
point would have to key on something this capture cannot support: a repetition
pattern that does not exist in the data, or a port and address pair that is
environment-specific. The honest engineering action is to leave the gap visible
and to state what telemetry would close it.

## 6. Method notes and negative results

- The hypothesis, the alternatives and the pre-hunt commit were recorded **before**
  the analysis, at `a85ce34`, precisely so that the conclusion could not be
  reverse-engineered from a rule that already existed.
- The 176 records with host `WORKSTATION6` in DS002 were **not** merged with the
  2906 records for `WORKSTATION6.theshire.local`. No host alias was merged
  anywhere in this hunt, so no conclusion here depends on an unverified hostname
  identity.
- The PowerShell process on `WORKSTATION5.theshire.local` (GUID
  `{b34bc01c-7dfc-5f67-de11-000000000400}`) that resolved
  `WORKSTATION6.theshire.local` by DNS and connected to 172.18.39.6 on ports 135 and
  49726 at 16:16:58.794 and 16:16:58.803 is a **different process on a different
  host** and was excluded from this hunt. It is examined in HUNT-001, where the
  relationship between the two hosts matters.
- Searches that returned nothing, recorded so the next analyst does not repeat them:
  no Sysmon event 11 file event coincides with the connection time; no event 3
  record from this process targets any address other than 10.10.10.5; no event 22
  DNS record for this process resolves a real name.
