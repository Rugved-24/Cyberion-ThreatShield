# PB-04: Suspected command and control or tool retrieval over the web

| Field | Value |
| --- | --- |
| Playbook ID | PB-04 |
| Version | 1.0 |
| Owner | Detection Engineering |
| Last reviewed | 2026-09-29 |
| Applies to | CT-009, and any process-linked outbound connection from an interpreter or script host |
| Expected time to scope | 45-60 minutes for one analyst |
| Escalates to | Incident Response lead, immediately, if a repeating interval is found or if transferred content is recovered |

## 1. Before you start

**What you need:** process creation telemetry, network connection telemetry with
the initiating process identified, and **proxy, gateway or packet capture content
if it exists**. That last item is the difference between scoping this and guessing.

**Rules this playbook depends on.**

| Rule | Status | Consequence for this playbook |
| --- | --- | --- |
| CT-009 PowerShell web download using the default network credentials | Partially Covered | Confirms the transfer pattern in script text. It does not confirm what was transferred, and it does not tell you whether a channel exists. |
| CT-002 PowerShell with an encoded command | Partially Covered | Identifies which process to follow, since the command line is not readable. |
| T1071.001 Web Protocols | **Not Covered** | There is deliberately no rule. See section 1.1. |

**What this playbook does not cover.** There is no rule for web-based command and
control, and the reason is a finding rather than an omission. In this project's
hunt, **42 of the 43 port-80 connections in the recording were ordinary Azure
platform traffic**: the guest agent talking to the platform wire server and the
instance metadata service. A rule keyed on port 80 would have produced a 98 per
cent false-positive rate. A rule keyed on a repetition interval cannot be written
from a capture 2 minutes 14 seconds long. Both are recorded in
`hunts/HUNT-002.md`.

### 1.1 Read this before you write a C2 rule

Do not write a C2 detection from a single connection. Before any rule is proposed,
answer all four of these:

1. How many connections to the destination exist, and over what period?
2. Is the interval regular, and does it survive jitter?
3. Do you have response content, or only the request side?
4. Is the destination external, or inside your own address space?

If question 1 returns one connection, you do not have a beacon and you cannot write
a beacon rule. If question 4 returns an internal address, you do not have external
command and control, and the more likely readings are an internal staging server, a
proxy, or a lab address.

## 2. Trigger conditions

- **Escalate immediately:** a repeating connection interval from one process, with
  jitter consistent across at least ten intervals.
- **Escalate immediately:** a script host connects to a web port using the default
  network credential cache. That is CT-009, and it is a credential exposure
  question as well as a transfer question.
- **Escalate immediately:** transferred content is recovered and it is executable,
  or it decodes to a script.
- **Work as an investigation:** a single connection from an interpreter to a web
  port. This is the HUNT-002 case, and the correct outcome is usually a recorded
  inconclusive, not an escalation.

## 3. Investigation steps

| # | Action | How to check | Record |
| --- | --- | --- | --- |
| 1 | Identify the process, not the address | Follow the process GUID from the connection record back to its creation record, on one exact host string. | The process GUID, image, full command line, parent process and user. |
| 2 | Read the command line | If an encoded command is present, the real command is not readable. Note that, and go to the script block instead. | Whether the command line is readable, and what it shows if it is. |
| 3 | Read the script | PowerShell 4104 for the same host. Look for a download call, a credential cache, a decoding routine and an in-memory execution call. | Which of the four behaviours are present, by source line. Do not paste the script into a ticket. |
| 4 | Enumerate **all** connections from that process | Every event 3 and event 22 record for the process GUID, in order, with destinations and times. | The full list, and the total count. |
| 5 | Compute the intervals | If there is more than one connection, the interval between each. | Every interval. If there is one connection, record that there are no intervals. |
| 6 | Establish the capture's time base | The earliest and latest resolved event time in the whole recording. | The span, in seconds, and the count of records that carry a resolved time. |
| 7 | **Decide the beacon question at step 6** | Compare the number of observed intervals against the span. One connection in 2 minutes cannot characterise a beacon. | Your conclusion and the arithmetic behind it. |
| 8 | Check the destination's address space | Is it external, RFC 1918, or link-local metadata? | The classification, with the address. |
| 9 | Get a second source for the flow | Firewall or proxy records for the same flow. Use them to attribute the application, not to order the events, unless they carry a usable time. | Whether a second source agrees, and whether it has a usable time. |
| 10 | Search proxy or gateway content | Request the request line, headers and response body for the destination. If none exists, record that as the blocker. | Whether content was available. This is the single most valuable missing artefact. |
| 11 | Look for the transferred content | Second-stage script text, files written after the transfer, or the decoded payload in the script's own logic. | What was found, or that nothing was found. |
| 12 | Check for credential exposure | If the script attached the default network credential cache, determine whether the proxy and server would have required authentication. | Whether credentials could have been presented, as possible or confirmed. |
| 13 | Check the script's own loop | Read for a sleep, a timer or a repeated request in the script text. A stager without a loop in the text is a one-shot retriever. | Whether a loop exists in the captured text. |
| 14 | Check the estate baseline for the port | Count connections to that port across all hosts. If most are vendor traffic, the port is not a usable discriminator and you must say so. | The ratio, as evidence. |
| 15 | **Stop here and record inconclusive** | If there is one connection, no response content and no repetition, record the hypothesis as inconclusive, state what would resolve it, and do not escalate. | The inconclusive record and the data that would change it. |

### 3.1 Interpretation guide

| Observation | Most likely meaning | Alternative to rule out |
| --- | --- | --- |
| One connection, no response content, capture under an hour | Insufficient evidence for a channel | A genuine beacon whose interval is longer than the capture |
| Repeating interval with consistent jitter | Beaconing | A scheduled task or updater on the same interval; check for a matching schedule |
| Connection to an RFC 1918 address on a web port | Internal staging, a proxy, or a lab address | An internal C2 relay, which is a real and serious possibility |
| Connection to link-local `169.254.169.254` | Cloud instance metadata, from a platform agent | Cloud credential theft, if the requesting process is unexpected |
| Script downloads and evaluates in memory, no loop | One-shot retrieval of a further stage | A stager that received a longer sleep interval from its configuration |
| Default network credential cache attached to a web request | Credential exposure risk | Nothing; treat as possible exposure until the authentication requirement is known |
| Destination resolves by DNS rather than literal address | Normal for most tooling | Domain-generation or fast-flux behaviour, which needs many resolutions, not one |

### 3.2 Decision point

**Escalate as command and control** only when a repeating interval is measured over
a span that could contain several intervals, **and** the destination is external, or
is internal with a reason to be internal that is documented.

**Escalate as tool retrieval** when transferred content is recovered, or when the
script's logic and the single transfer together make a first-stage loader clear.
This is the HUNT-002 outcome for T1105.

**Record as inconclusive** in every other case, including the single-connection
case. Record what would resolve it. An inconclusive record with a clear list of
missing data is more useful to the next analyst than an escalation built on one
port number.

## 4. Containment

1. **Block the destination** at the proxy or firewall, scoped to the process and
   host where possible. Do not block the port estate-wide on the strength of one
   connection; step 14 exists because that would break the platform.
2. **Isolate the host** only if there is a second indicator, such as a recovered
   payload or a control-bypass rule hit. One unexplained connection is not a reason
   to take a host out of service.
3. **Capture memory** before isolation if a PowerShell process may still hold the
   decoded payload. The payload may exist only in memory.
4. If the destination is internal, identify its owner before blocking. It may be a
   legitimate service that the script is abusing.

## 5. Eradication

1. Remove any file or scheduled task the retrieved content created.
2. Hunt the estate for the destination address and, if recovered, for the cookie or
   key values from `ioc/watchlist.csv`. Those are the indicators that survive an
   address change.
3. Search for the same script block text or its decoded form across all hosts.
4. If credentials may have been presented, treat it as a credential incident and
   cross-reference PB-03.

## 6. Recovery

1. Re-enable and verify any logging the script disabled. A stager that disables
   script block logging will leave no record of the second stage.
2. Block the destination at the proxy permanently while the investigation runs.
3. Increase retention on the affected hosts. The second stage is often only
   available in short retention windows.
4. Monitor for 30 days with CT-002, CT-008 and CT-009 enabled, and with the
   destination on the watchlist.

## 7. Stakeholder communications

| Point | When | Audience | Must contain | Must not contain |
| --- | --- | --- | --- | --- |
| Initial notification | Within 1 hour, only on escalation criteria met | IT lead, Incident Response, Network Operations | The process, the destination and its address class, the number of connections and the capture span | "Command and control is confirmed" unless step 7's arithmetic supports a repeating interval |
| Containment confirmation | Within 2 hours | Same | What was blocked and at what layer, whether the host was isolated and why or why not, and the credential exposure assessment | Any claim about data that was or was not transferred; nothing in this playbook can support one |
| Closure | Within 5 business days | IT lead, compliance if credentials were exposed | The conclusion, the evidence for it, the interval arithmetic, the credential assessment, and the specific telemetry that was missing | A statement that the host is clean, given that the capture is minutes long |

## 8. Post-incident actions

1. If a repeating interval was found, this is the first opportunity in this project
   to write a T1071.001 rule. Write it against the measured interval, record the
   measurement, and test it. Do not reuse a threshold from a different environment.
2. Record the port-80 benign ratio as a standing note for rule authors. It is the
   kind of number that prevents a whole class of bad rules.
3. If no proxy or gateway content exists anywhere in the environment, raise it as a
   collection gap. Without it, this playbook's step 10 can never succeed and C2
   assessment stays permanently inconclusive.
4. Update `hunts/HUNT-002.md`'s conclusion if new evidence arrives, and record the
   date. A hunt conclusion is not permanent.

## 9. Change log

| Version | Date | Change | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-09-29 | Initial version, derived from `hunts/HUNT-002.md` and CT-009 | Detection Engineering |
