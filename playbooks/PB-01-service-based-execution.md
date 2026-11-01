# PB-01: Service-based execution and persistence on a Windows host

| Field | Value |
| --- | --- |
| Playbook ID | PB-01 |
| Version | 1.0 |
| Owner | Detection Engineering |
| Last reviewed | 2026-09-29 |
| Applies to | CT-011, CT-003, CT-005, CT-C02 |
| Expected time to scope | 30-45 minutes for one analyst, assuming telemetry is present |
| Escalates to | Incident Response lead, immediately, if step 2.1 confirms a service image path is a command interpreter |

## 1. Before you start

**What you need:** the host name **exactly as the log records it**, the alert
time, and read access to process creation, service and script telemetry.

**Rules this playbook depends on.**

| Rule | Status | Consequence for this playbook |
| --- | --- | --- |
| CT-011 service installed with a PowerShell image path | Partially Covered | A hit is meaningful. A miss does not prove no such service exists, because 4697 may not be collected. |
| CT-003 command shell created by the Service Control Manager | Partially Covered | Same. |
| CT-005 command shell used as a background PowerShell dispatcher | Partially Covered | Same. |
| CT-C02 correlation of CT-003 to an encoded PowerShell child | Partially Covered | This is the highest-value combination and the reason to work the case. |

**What this playbook does not cover.** It does not cover remote activation of the
service from another host. The correlation between a service installation and the
service's execution is **not** testable in this project's telemetry because the
service installation record carries no resolved event time. If you need to prove
remote activation, you need System event 7045 or firewall records with a usable
time, and you should say so rather than assuming adjacency.

## 2. Trigger conditions

- **Escalate immediately:** CT-011 fires with a service account of `LocalSystem`,
  `LocalService` or `NetworkService`, or with a demand start type.
- **Escalate immediately:** CT-C02 fires. The service and the concealed execution
  are in the same window.
- **Work as an investigation:** CT-003 or CT-005 fires alone.
- **Escalate immediately, out of band:** any alert containing a script block that
  references ScriptBlock logging or the AMSI failure flag. This is CT-006 or
  CT-007 and it is a deliberate action against a control; do not work it at low
  priority.

## 3. Investigation steps

| # | Action | How to check | Record |
| --- | --- | --- | --- |
| 1 | Fix the host identity | Copy the host string from the alert. Do not shorten it or add a domain suffix. If the log holds both `HOST` and `HOST.domain`, treat them as two hosts until proven otherwise. | The exact host string, and any other spelling seen in the same period. |
| 2 | Read the service record | Security 4697: `ServiceName`, `ServiceFileName`, `ServiceStartType`, `ServiceAccount`, `SubjectUserName`. | All five fields verbatim. `ServiceFileName` is the decisive one. |
| 3 | Decide whether the service is legitimate | A real service has a program path, usually signed, usually under Program Files or the system directory. A service whose path resolves `cmd`, `powershell`, `wscript`, `mshta`, `rundll32` with a script, or a base64-looking argument, is not a service. | Your decision and the one field that drove it. |
| 4 | Reconstruct the process chain | Walk **up** from the service: find the process creation whose `ParentProcessGuid` equals the service's process GUID, and repeat. Join on the process GUID within one dataset and one exact host string. Do not join on process identifiers: hexadecimal and decimal forms cannot be compared. | An ordered chain with one source line per link and the delay between each pair. |
| 5 | Confirm with a second source | Look for Security 4688 records covering the same process creations. If 4688 agrees on the parent relationships, the chain is corroborated. | Whether 4688 agreed, and the lines that agreed. |
| 6 | Read the script, if one was logged | PowerShell 4104 for the same host. Do not execute, deobfuscate on a production jump host, or paste it into a ticket in full. Extract only the indicators you need. | The technique behaviours present: control bypass, decoding, download, in-memory execution. Reference the line, not the text. |
| 7 | Check whether the operator blinded the host | Look for ScriptBlock logging changes and AMSI manipulation in the 4104 record, and for the state of the ScriptBlockLogging policy key. | Whether logging was disabled, and whether you can still see this host's PowerShell at all. |
| 8 | Establish the account context | `SubjectUserName` on the 4697 and 4688 records. Then look for a type 3 network logon for that account (CT-012). | The account, and whether a logon record exists at all. |
| 9 | **Stop here if it is benign** | If step 3 shows a legitimate vendor service, record the vendor, the change record, and add the image path to the allow list. Do not continue. | The allow-list entry and the change reference. |
| 10 | Scope the estate | Run CT-011 and CT-003 across all hosts for the last 30 days. | Host count, not event count. |
| 11 | Check for the retrieved content | Identify the destination of any connection from the service's child processes, and search proxy or firewall logs for it. | The destinations found, and whether response content was available. |

### 3.1 Interpretation guide

| Observation | Most likely meaning | Alternative to rule out |
| --- | --- | --- |
| Service image path is `%COMSPEC% /C start /b ...` | Remote or local service execution through a dispatcher | A legacy installer that genuinely wraps a batch script; check the vendor and the change record |
| Service account is `LocalSystem` and start type is demand | Execution outside any user session, on demand | A monitoring or backup agent; these legitimately run as SYSTEM |
| `cmd.exe` parented by `services.exe`, then PowerShell with an encoded argument | Confirmed service-based execution of concealed script | None plausible; treat as true positive |
| A 4104 record that disables logging **and** tampers with AMSI | Deliberate evidence destruction and inspection bypass | Lab or detection-engineering tooling; handle by host exclusion, not by weakening the rule |
| No 4104 records at all for the host | Either the host never ran PowerShell, or its logging is off | Check whether script block logging is enabled before concluding anything |

### 3.2 Decision point

**Benign** only if step 3 identifies a known vendor service with a real program
path, a change record, and no concealed execution in step 4. In that case allow
list the image path and close.

**Escalate** in every other case. A service whose image path is a command
interpreter has no benign form that also produces a concealed PowerShell child, so
the presence of both is a true positive by construction.

## 4. Containment

1. **Capture volatile memory first, if the tooling exists.** A PowerShell process
   running as SYSTEM may still hold the retrieved second stage in memory. This is
   the one step where delay destroys evidence.
2. **Record the service configuration** with `sc qc <name>` and the full registry
   key before changing anything.
3. **Isolate the host** from the network. Do not power it off; a shutdown destroys
   the memory image and the volatile process list.
4. **Do not stop the service yet.** A stopped service may be restarted by a parent
   orchestrator, and stopping it changes the service's last-start evidence.
5. If the service must be stopped to stop active execution, stop it and record the
   time to the minute.

## 5. Eradication

1. Delete the service, recording the exact command and its output.
2. Search the estate for services whose `ServiceFileName` references
   `powershell`, `cmd`, `wscript`, `mshta` or `certutil`. This is CT-011, unmodified.
3. Search for services running as `LocalSystem` with a demand start type and a path
   outside Program Files.
4. Search for any remaining process whose parent is `services.exe`.
5. Hunt for the account's activity across all hosts before assuming the blast
   radius is one machine.

## 6. Recovery

1. Re-enable PowerShell script block logging and **verify** that 4104 records are
   arriving. The attacker disabled this; assume it is still off.
2. Verify AMSI is functioning by confirming the initialisation-failure field is
   false, using a benign script.
3. Rebuild the host from a known good image or restore point. Do not clean in
   place: the attacker controlled the host as SYSTEM.
4. Rotate any credential whose material could have been read by the executed
   script. Cross-reference PB-03.
5. Monitor the rebuilt host for 14 days with CT-002, CT-006, CT-007 and CT-C02
   enabled.

## 7. Stakeholder communications

| Point | When | Audience | Must contain | Must not contain |
| --- | --- | --- | --- | --- |
| Initial notification | Within 1 hour of escalation | Service owner, IT lead, Incident Response | Host, time, what was observed, that execution as a privileged account is confirmed, and that scope is currently one host | Any claim that data was stolen; any attribution to a named actor |
| Containment confirmation | Within 2 hours of isolation | Same, plus the service owner | What was isolated, what was preserved, the service name and account, and the credential reset decision | A root cause that has not been verified; the contents of any recovered script |
| Closure | Within 5 business days | Service owner, IT lead, compliance if data access is in scope | Confirmed timeline with source references, what was and was not determined, detection changes made, and the collection gaps that were found | An assurance that the host is clean without stating the limits of what was checked |

## 8. Post-incident actions

1. Add the confirmed technique to the ATT&CK coverage matrix with a rule reference.
   A "Covered" entry requires a tested rule **and** a benign comparison.
2. If CT-011 or CT-003 produced a false positive, record it in
   `evidence/tuning/` with before and after counts. Do not simply add an exclusion.
3. Record whether 4697 and 7045 are collected across the estate. If not, that is
   the finding, and it outranks any individual rule.
4. Note explicitly what was **not** determined. In this project's own cases that
   always included whether the account was compromised and whether the retrieval
   returned anything usable.

## 9. Change log

| Version | Date | Change | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-09-29 | Initial version, derived from INC-001 and `hunts/HUNT-001.md` | Detection Engineering |
