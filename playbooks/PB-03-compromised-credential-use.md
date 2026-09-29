# PB-03: Compromised or misused credential

| Field | Value |
| --- | --- |
| Playbook ID | PB-03 |
| Version | 1.0 |
| Owner | Detection Engineering |
| Last reviewed | 2026-09-29 |
| Applies to | CT-012, and any case where a logon, service installation or execution is attributed to a named user account |
| Expected time to scope | 30 minutes for one analyst, plus whatever the identity team needs for the reset |
| Escalates to | Identity and Access Management, immediately, for any account used in a privileged or service context |

## 1. Before you start

**What you need:** authentication telemetry including **failed** logons, the
account's owner from the identity directory, and the privilege context the account
acted in.

**Rules this playbook depends on.**

| Rule | Status | Consequence for this playbook |
| --- | --- | --- |
| CT-012 network logon by a named user account | **Covered** | This is the only technique in the library scored Covered: the rule matched its declared malicious record and its tuning case shows zero residual benign matches. A hit is worth working and a miss is meaningful for type 3 named-account logons. |

**What this playbook does not cover.** This playbook cannot tell you whether an
account was **compromised**, and that limitation is not a defect in the rule, it is
a property of the question. In this project's own telemetry there are **zero**
event 4625 records across both datasets and only eight 4624 records in total, so
there is no authentication history to reason about at all. If failed-logon
collection is missing on your estate, the first output of this playbook is a
collection request, not a conclusion.

## 2. Trigger conditions

- **Escalate immediately:** CT-012 fires for an account that is a domain
  administrator, a service account, or an account with local administrator rights.
- **Escalate immediately:** an account is the subject user on a service
  installation, or the initiator of a process running as `LocalSystem`.
- **Work as an investigation:** CT-012 fires for an ordinary named account.
- **Escalate out of band:** the account is simultaneously the subject of a
  credential dumping alert. Cross-reference PB-01 and the LSASS discussion in
  `coverage/matrix-v2.md`.

## 3. Investigation steps

| # | Action | How to check | Record |
| --- | --- | --- | --- |
| 1 | Establish whether 4625 is collected at all | Query for any failed logon on the host over the last 30 days. | A count. Zero means the collection gap, and you must say so rather than reporting "no failed logons". |
| 2 | Establish the account's owner and privilege | Identity directory: owner, role, privilege, whether it is a service account, and its last password change. | The owner, the privilege level, and whether the account is human or machine. |
| 3 | Build the account's activity list | All logons for the account over at least 30 days: type, source address, host, and count by day. | The list, and any day whose volume departs from the account's own baseline. |
| 4 | Find the privilege transition | Look for the account acting in a privileged context: a service installation, a process running as SYSTEM, or a logon to a server. | The event and the privilege it acquired. |
| 5 | Separate operator from adversary | If this is a lab, adversary-emulation or penetration test, check the engagement calendar **before** classifying anything. An emulation account is not a compromised account. | The engagement reference, or "no engagement reference found". |
| 6 | Check the source addresses | Are the logon sources consistent with where the user works? | The source addresses, and the answer to whether they are consistent. |
| 7 | Check for the account as a target | Failed logons for the account, from any source, if step 1 permits. | The failures, or a statement that they cannot be retrieved. |
| 8 | **Stop here if the account is an operator's** | If step 5 identifies an engagement account and step 4's activity matches the recorded technique for that engagement, classify as expected activity and record the engagement reference. Do not reset the credential. | The classification and the reference. |
| 9 | Decide the credential action | If the account is not explained by step 5 or 8, treat the credential as compromised. | Your decision and the evidence for it. |
| 10 | Reset, then hunt | Reset per step 9, then search every host for activity by the account since the earliest unexplained logon. | The reset time and the scope of the resulting search. |

### 3.1 Interpretation guide

| Observation | Most likely meaning | Alternative to rule out |
| --- | --- | --- |
| Six type 3 logons for a machine account ending in `$` | Domain replication and service traffic | Nothing. Benign, and the reason CT-012 excludes machine accounts. |
| One type 3 logon for a named account, followed by a service installation | The account was used to create persistence | The account is an emulation or test account; check step 5 |
| Type 3 logon at an unusual hour from an unfamiliar address | Possible credential use | VPN, remote worker or a lab jump host; confirm the address against the user's normal pattern |
| Volume of type 3 logons far above the account's own baseline | Automated or scripted use | A scheduled task, backup agent or monitoring probe owned by that account |
| Account is the subject user on a 4697 for a service running as `LocalSystem` | Privilege escalation through the account | Vendor installer; check the image path against PB-01 step 3 |

### 3.2 Decision point

**Treat as compromised** if the account's activity is not explained by a documented
engagement, a named service function, or a known administrative pattern, **and** it
acquired privilege it does not normally hold.

**Classify as expected** only with a written reference: an engagement ticket, a
change record, or a documented service function. "It is probably the operator" is
not a reference and must not be recorded as a closure.

**Report as unresolved** if 4625 is not collected and there is no documentation.
This is a legitimate outcome. In this project's INC-001 and INC-002 the credential
question was left open for exactly this reason, and that was the correct result.

## 4. Containment

1. **Reset the credential** before investigating further, if there is any doubt.
   A reset is cheap; a continued foothold is not.
2. **Revoke active sessions and tokens** at the same time as the reset, otherwise
   the old session survives.
3. **Do not disable the account** as a first step if it is a service account; a
   disabled service account can break a business process and generate a second
   incident. Identify what depends on it first.
4. For a privileged account, escalate to the identity team immediately rather than
   handling the reset yourself.

## 5. Eradication

1. Hunt the account's activity across the estate from the earliest unexplained
   logon to the reset time. Use the time range, not just the host.
2. Remove anything the account created: services, scheduled tasks, files, registry
   keys. Use PB-01 for services.
3. Check whether the account's credentials could have been presented elsewhere, in
   particular to a proxy or a web service. This is the specific risk in
   `incidents/INC-001.md`, where the executed script attached the default network
   credential cache to a web request.
4. Confirm no other account shares the same password. This is a common finding and
   it turns a single incident into an estate-wide one.

## 6. Recovery

1. Confirm the new credential works and the old one does not, by checking for a
   failed logon with the old value if the estate records them.
2. Force a re-enrolment for any privileged account that may have been exposed to a
   web service.
3. Review the account's standing privilege. If the incident occurred because an
   ordinary account could reach a privileged context, that is the fix.
4. Monitor the account for 30 days with CT-012 enabled.

## 7. Stakeholder communications

| Point | When | Audience | Must contain | Must not contain |
| --- | --- | --- | --- | --- |
| Initial notification | Within 1 hour, for a privileged account | Identity and Access Management, IT lead, Incident Response | The account, the privilege it acquired, and that a reset is in progress | "The account is compromised" unless step 9 was completed; the user's name before the identity team has been notified |
| Containment confirmation | Within 2 hours | Same | The reset time, session revocation, and the scope of the hunt that follows | A statement that the account is safe; a promise that no data was accessed |
| Closure | Within 5 business days | IT lead, compliance if the account is privileged or regulated | Whether compromise was confirmed or left unresolved, the evidence for that statement, the standing privilege finding, and whether other accounts share the credential | A classification of "benign" based on an absence of failed logons when 4625 is not collected |

## 8. Post-incident actions

1. If 4625 is not collected anywhere in the estate, raise it as a coverage gap with
   a named owner. Password spraying, T1110.003, cannot be assessed at all without
   it, and it is one of the three evidence gaps recorded in
   `coverage/matrix-v2.md`.
2. Review whether any account can create a service that runs as `LocalSystem`. That
   is the specific path that made this a privilege escalation in INC-001.
3. Add the observed account pattern to the tuning record if CT-012 produced a false
   positive, with before and after counts.
4. Record the credential question's answer, including "unresolved", in the incident
   report. Do not leave it implied.

## 9. Change log

| Version | Date | Change | Author |
| --- | --- | --- | --- |
| 1.0 | 2026-09-29 | Initial version, derived from INC-001, INC-002 and CT-012 tuning | Detection Engineering |
