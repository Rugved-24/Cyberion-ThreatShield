# PB-02: Suspected lateral movement via remote services

| Field | Value |
| --- | --- |
| Playbook ID | PB-02 |
| Version | 1.0 |
| Owner | Detection Engineering |
| Last reviewed | 2026-09-29 |
| Applies to | HUNT-001 findings, CT-014, CT-003 on a non-originating host, CT-C02 where the parent is a service on a second host |
| Expected time to scope | 45-60 minutes for one analyst |
| Escalates to | Incident Response lead and Network Operations, immediately, on a confirmed cross-host flow with a service or shell as the receiving application |

## 1. Before you start

**What you need:** read access to process creation, network connection, firewall
and authentication telemetry, and the ability to resolve which address belongs to
which host.

**Rules this playbook depends on.**

| Rule | Status | Consequence for this playbook |
| --- | --- | --- |
| CT-014 admin or service share access by a user account | **Not Covered** | It was authored, tuned and tested, and it matches **nothing** in the available telemetry because every share record present was benign. A hit would be interesting; a miss proves nothing. Do not rely on it. |
| CT-003 command shell created by the Service Control Manager | Partially Covered | Usable on the receiving host. |
| CT-C02 service-launched shell creating encoded PowerShell | Partially Covered | Usable on the receiving host, and the strongest single signal in this playbook. |

**What this playbook does not cover.** This playbook cannot establish **causation**
between a source host and a remote execution on a target host using the telemetry
in this project. The reason is specific and worth understanding before you start:
the firewall records that identify the remote application carry no resolved event
time, so they can attribute a flow but cannot order it. If you force an ordering by
assuming a timezone, you will produce a confident and wrong timeline. Use the
method in step 6 instead, and report attribution as unresolved when it is
unresolved.

## 2. Trigger conditions

- **Escalate immediately:** a cross-host flow to destination port 135 followed by a
  connection to a dynamic RPC port, where the receiving application is
  `services.exe` or `svchost.exe` and the initiating application is a shell or
  PowerShell.
- **Escalate immediately:** CT-C02 fires on a host that is not the one where the
  intrusion is believed to have started.
- **Work as an investigation:** CT-014 fires, understanding that it has never
  produced a detection.
- **Escalate immediately:** a process on host A opens a handle to `lsass.exe` on
  host B over RPC. That is credential access across hosts and is not covered by any
  rule in this library.

## 3. Investigation steps

| # | Action | How to check | Record |
| --- | --- | --- | --- |
| 1 | Establish both host identities | Take both host strings exactly as recorded. Map each to its address from the same records. Do not merge host aliases. | Both host strings and both addresses, and whether the log uses two spellings for either host. |
| 2 | Enumerate the cross-host flows | Group network records by source address, destination address and destination port. Start with port 135 and the dynamic ports that follow it. | Every flow, both directions, with the application recorded on each side. |
| 3 | Check for repeated connections | Count flows per pair. One flow is not a pattern; a lateral movement sequence normally shows several. | The count, and the interval if there is more than one. |
| 4 | Read the receiving application | Firewall records name the application that owns the socket. `services.exe` receiving a dynamic RPC connection is the Service Control Manager being activated. | The receiving application and the source port. |
| 5 | Read the initiating application | The same flow recorded at the other end names the process that opened it. | The initiating application path. |
| 6 | Build the orderable sequence | Use only records with a resolved event time. Records without one are used for attribution, never for order. Mark every step in your timeline as ordered or attributed. | The sequence, with each step labelled ordered or attributed. |
| 7 | Look for the activation on the target | On the target host, find the service's process, then walk up the process GUID chain to whatever it launched. | The chain with one source line per link. |
| 8 | Test the same-host alternative | If no cross-host flow precedes the target's execution, look for a local trigger: a logon, a scheduled task, a management agent, or an interactive session. | What local trigger you found, or that you found none. |
| 9 | Check the authentication that preceded it | Type 3 and type 10 logons for the account, and failed logons. | Whether 4625 exists at all on the estate. If it does not, say so; this project has no 4625 in either dataset. |
| 10 | Check the service registration | Security 4697 or System 7045 on the target, for the service name and image path. | Whether the event exists and what time it carries. |
| 11 | **Stop here if it is a management agent** | If the initiating application is a known management or deployment agent and the activity matches its schedule, record the agent and the schedule. | The agent, its owner, and the change or schedule reference. |
| 12 | Scope the estate | Repeat steps 2 to 4 for all host pairs over 30 days. | Number of distinct source and target hosts. |

### 3.1 Interpretation guide

| Observation | Most likely meaning | Alternative to rule out |
| --- | --- | --- |
| Source port 135 to target, then a dynamic port, receiving application `services.exe` | Service activation over DCOM | Scheduled task or management agent performing a remote action; check the owner and the schedule |
| Cross-host RPC with a **PowerShell** initiating application | Remote execution or remote reconnaissance | An administrator running a remote command; check the account and whether a change record exists |
| Machine account reading `SYSVOL` `gpt.ini` on a domain controller | Group Policy replication | Nothing. It is benign and must be excluded, not investigated. |
| Machine account type 3 logons in volume | Domain replication and service traffic | Nothing. This is the majority of type 3 activity on any busy domain controller. |
| Cross-host flow to a host where no process chain follows | A failed or unrelated connection | Part of a sequence whose later steps fall outside the capture window |

### 3.2 Decision point

**Escalate** if the receiving application on the target is `services.exe` or a
service, **and** the target then shows a process chain attributable to that service,
**and** a cross-host flow to it exists in the window. The orderability of the flow
is **not** required for escalation.

**Report as unattributed** if the escalation conditions hold but no cross-host flow
can be placed before the target's execution. Say "remote activation is consistent
with the evidence and the responsible source is not established". Do not name a
source host you cannot order.

**Close as benign** only for the specific benign patterns in the interpretation
guide, such as domain controller SYSVOL replication or machine-account logons.

## 4. Containment

1. **Isolate the target host first.** The target is where code is running; the
   source may already be clean or may not exist.
2. **Preserve the source host.** Do not isolate or wipe the apparent source until
   its memory is captured; it holds the tooling that performed the movement.
3. **Capture memory on both hosts** if tooling exists, before isolation.
4. **Block the administrative share path** at the network layer for the affected
   pair only. A blanket SMB block will break the domain.
5. Record the isolation time to the second, so the two timelines can be compared
   afterwards.

## 5. Eradication

1. Remove the service or scheduled task on the target that was activated remotely.
2. **Do not delete the source host's tooling before you have captured it.** It is
   the primary evidence for how movement occurred.
3. Search the estate for the same service name and image path on every host. This
   is CT-011.
4. Search for administrative share access by user accounts. Understand that CT-014
   has produced no detection, so this search is manual until that changes.
5. Hunt for the account used, across all hosts, and reset it. Cross-reference
   PB-03.

## 6. Recovery

1. Rebuild the target from a known good image. A host that was activated remotely
   had its service interface used; assume local tampering.
2. Reset the account that performed the activation, and any account that
   authenticates to the target.
3. Review whether the source host is still required in the estate. If it is a
   workstation acting as a pivot, that is an architecture finding.
4. Monitor both hosts for 30 days with CT-003, CT-011 and CT-C02 enabled.

## 7. Stakeholder communications

| Point | When | Audience | Must contain | Must not contain |
| --- | --- | --- | --- | --- |
| Initial notification | Within 1 hour | IT lead, Incident Response, Network Operations, the owner of the source host if it is a workstation | Both hosts, that remote service execution on the target is confirmed, and that the source is not yet established | The name of a source host as the attacker or the origin; "the attacker moved from X" |
| Containment confirmation | Within 2 hours | Same | Which host was isolated, what evidence was preserved, and that the source remains unattributed | Any claim that the pair is clean, or that only the target is affected |
| Closure | Within 5 business days | Service owners, IT lead, and the security architecture owner | The ordered sequence, clearly separating ordered steps from attributed ones, the account actions taken, and the reason attribution is or is not established | A causal story built from records that have no usable time |

## 8. Post-incident actions

1. Record the exact telemetry that would have made attribution possible: firewall
   records with a usable event time, or System 7045, or DCOM activation auditing.
   This is a collection request, not a rule request.
2. If CT-014 matched nothing, say so in the coverage matrix. It stays Not Covered
   until a capture containing real remote service execution exists to test against.
3. Consider a correlation rule joining a cross-host flow to a service activation on
   one host. It cannot be written or tested with the current data, and that fact
   should be recorded rather than worked around.
4. If the source is a workstation, raise the lateral movement architecture with the
   security owner. That is a bigger finding than the incident.

## 9. Change log

| Version | Date | Change | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-09-29 | Initial version, derived from `hunts/HUNT-001.md` and CT-014 tuning | Detection Engineering |
