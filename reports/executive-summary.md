# Executive Summary: Cyberion ThreatShield Detection Engineering Engagement

**Prepared for:** non-technical stakeholders
**Date:** 2026-09-29
**Scope:** detection content, threat hunting and incident analysis over two public
adversary-emulation telemetry recordings
**Status:** all engagement deliverables complete

---

## 1. The one-paragraph version

We tested whether our security monitoring would actually catch a real attacker,
using recorded evidence of two genuine intrusions rather than a tabletop exercise.
We wrote 17 alarm rules, ran every one of them against the recorded evidence, and
confirmed 15 of them fire on real attacker activity and do not fire on the
ordinary background activity that surrounded it. We then investigated both
intrusions from beginning to end and confirmed both were real. The most important
finding is not what we caught, but what we could **not** prove: for 12 of the 21
attack techniques we assessed, we can confirm our alarms work, but we cannot yet
measure how often they would trouble your staff with false alarms, because we have
no clean reference recording of normal business activity to measure against. That is
a data-collection task, not a writing task, and it is the single highest-value next
step.

## 2. Why this work was done

The business problem is not that we lack alarms. It is that nobody can say what our
alarms cover. Before this engagement, if a manager asked "would we notice if an
attacker stole credentials from a server?", the honest answer required someone to
re-read rule files scattered across configuration by hand. There was no shared
picture of our blind spots, and no record of whether any given alarm had ever been
tested against a real attack.

This engagement produced that picture, and it is now version-controlled, so it can
be re-run and compared rather than remembered.

## 3. What we produced

| Deliverable | Delivered | Notes |
| --- | --- | --- |
| Detection rules (Sigma format) | **17** | All syntax-validated and replayed against real recorded attacks. 15 confirmed firing on attacker activity; 2 deliberately retained despite matching nothing. 3 are multi-event correlation rules. |
| ATT&CK techniques assessed | **21** | Assessed, mapped and placed on a coverage matrix with supporting rule references. |
| Techniques confirmed covered | **1** | Only where we have both a tested rule and a measured false-positive result. |
| Threat hunts | **2** | Both hypothesis-driven. One produced a confirmed negative result; one produced a confirmed positive. |
| Incident case reports | **2** | Both closed as true positives, with full timelines and evidence citations. |
| Response playbooks | **4** | Written for use under time pressure by a single analyst. |
| False-positive tuning records | **3** | With before-and-after numbers, not opinions. |
| Indicator watchlist | **22 entries** | Each traced to a source record, including entries marked **do not block**. |

## 4. What we found

**Both recorded intrusions were real, and both were confirmed by more than one
independent log source.** This matters more than it sounds. A single log can be
misread; two independent systems recording the same event make a confident
conclusion possible.

- **Incident 1.** On one workstation, a Windows "service" was registered whose
  entire purpose was to run a hidden command. When the operating system started
  that service, it ran with the highest local privileges, with nobody logged in. It
  launched a script that deliberately switched off two of the very monitoring tools
  that would have recorded it, then downloaded and ran further code from a server on
  the internal network. The command log even captured the attacker checking which
  account it was running as, and the answer was "system" — so this is confirmed,
  not assumed.
- **Incident 2.** On a second workstation, a standard Windows component was used to
  run a small script that opened an interactive administrator-style session, then
  immediately checked whether our monitoring sensor was running. The session was
  deliberately left open.

**The most valuable finding is a negative one.** Our hunt tested whether the second
incident's outbound connection to a web server was an attacker command channel. The
answer is **we cannot tell, and here is exactly why**: there was only one
connection, and the recording covers about two minutes. A "command and control
channel" is defined by repetition over time, and two minutes cannot show repetition.
Along the way we found that 42 of the 43 web connections in the recording were
ordinary cloud platform traffic, which means a naive "alert on web traffic" rule
would have been wrong 98 per cent of the time. Reporting that honestly is more
valuable than shipping a rule that looks impressive and floods the team.

## 5. Coverage: what we can and cannot claim

| Status | Count | What it means in plain terms |
| --- | --- | --- |
| Covered | 1 | A tested alarm that fires on a real attack **and** was measured against real ordinary activity with no false alarms. |
| Partially covered | 12 | A tested alarm that fires on a real attack, but whose false-alarm rate is unmeasured. |
| Not covered | 8 | No confirmed detection. In three cases this is a genuine evidence gap in our data, and we have specified exactly what data is needed. |

We deliberately resisted scoring these higher. Claiming "covered" without a measured
false-alarm rate is precisely the habit this engagement was created to eliminate,
and it would have been easy and wrong to do so.

## 6. The four things we recommend

1. **Collect a clean reference recording of normal activity.** This is the single
   highest-value action. It converts 12 techniques from "works, unmeasured" to
   "works and measured", and it is the prerequisite for ever claiming a detection is
   safe to deploy. It requires no new tooling.
2. **Close three specific evidence gaps.** Each needs a short, targeted recording
   rather than a new platform: startup persistence (about 5 minutes of recording),
   password spraying (one hour of authentication logs, including failed sign-ins),
   and file-encrypting ransomware (a documented safe simulation). Details are in
   `coverage/matrix-v2.md`.
3. **Enable the logging we discovered we were missing.** Two findings came from this:
   one workstation had **no** PowerShell script logging at all, and **neither**
   recording contained a single failed sign-in. Without failed sign-ins, credential
   attacks are invisible. This is a configuration change with a large payoff.
4. **Deploy the 15 confirmed rules, with the caveats attached.** They are portable
   across security platforms, documented so a new analyst can pick them up, and
   reproducible by re-running one command. The caveats matter: they have not been
   measured against your environment's false-alarm rate, and two of them
   (`T1003.001` credential memory access, `T1021.002` remote file shares) currently
   match nothing and are retained only to flag the gap.

## 7. Honest limitations

We want these visible rather than buried, because the value of this work depends on
its claims being trustworthy.

- **The evidence is two short recordings**, roughly two minutes each, from a
  controlled lab. They are real telemetry, but they are not your environment and
  they are not long enough to describe normal background activity.
- **One technique is fully covered.** Twelve are confirmed working but unmeasured.
  We consider that a truthful and useful position, not a failure.
- **The largest unresolved question is whether an account was stolen.** In both
  incidents the acting user account is known, but neither recording contains any
  authentication history, so we cannot say whether a person was tricked or an
  account was misused. This is a collection gap, and it affects both incidents.
- **Two machines may be the same machine and we did not assume they are.** The
  recordings name one of them two different ways. We kept them separate, which is
  why the two incidents are reported as two cases rather than one campaign.
- **The dataset carries unclear licensing terms** and the raw records stay local.
  Nothing here should be published externally without a rights review.
- **Nothing was deployed and nothing was automated.** No systems were changed, no
  alerts were fired at anyone, and no response was executed. This was analysis and
  content production, which is what was commissioned.

## 8. Reproducibility

Every number in this summary can be regenerated from the recorded evidence by
another analyst using three commands and `requirements.txt`. Rule test results,
tuning before-and-after figures, and the coverage matrix are all generated from the
recorded results rather than typed by hand, so the coverage claim and the underlying
evidence cannot drift apart. The pre-engagement baseline is retained unmodified
alongside the final position, with its checksum, so the change can be audited.

## 9. Appendix: glossary

| Term | Meaning |
| --- | --- |
| Detection rule | A written instruction that turns log data into an alert. Written here in an open, vendor-neutral format (Sigma). |
| Replay | Running a rule against recorded data to prove it fires when it should. |
| False positive | An alert caused by legitimate activity. The main practical cost of detection engineering. |
| Correlation rule | A rule that requires two events in sequence, not one. |
| MITRE ATT&CK | The public catalogue of attacker techniques that this work is mapped against. Version 19.2. |
| Coverage matrix | The table showing, technique by technique, whether we can detect it. |
| T1078, T1105 etc. | ATT&CK's identifiers for individual techniques. |
| IOC / indicator | An observable artefact, such as an address or file name, that may indicate an attack. |
| Playbook | A written procedure for responding to a type of incident under time pressure. |
| Volatile memory | A running system's in-memory state. It can hold an attacker's code and is lost at shutdown. |
| True positive | A confirmed real attack, as opposed to a false alarm. |
