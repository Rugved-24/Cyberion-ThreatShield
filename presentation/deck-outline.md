# Final presentation outline: Cyberion ThreatShield

Format: 14 slides, 20-minute delivery plus 10 minutes questions. Speaker notes
belong under each slide. Every figure on every slide is reproducible from the
repository; the source artefact is named on the slide so a question can be answered
without hunting for it.

The narrative is deliberately **before → work → evidence → honesty → ask**. The
"honesty" section is the part that makes the rest credible and must not be cut for
time.

---

## Slide 1 — Title

**Cyberion ThreatShield: what we can detect, what we cannot, and what to fix first**

- Detection engineering and threat hunting engagement
- Date, author role, repository reference
- Speaker note: set expectations. This is an assessment of our own monitoring,
  not a description of a breach. Two real recorded intrusions were used as the
  test material.

## Slide 2 — The question we were asked

**"If an attacker came in tomorrow, would we notice — and could we prove it?"**

Three bullets:

- The previous position: alarms existed but were undocumented, untested and
  unmapped. Nobody could answer without re-reading configuration by hand.
- The business cost: blind spots are invisible until an incident exposes them.
- What "done" looks like: a documented, tested, mapped library, plus a repeatable
  hunting method and a written response.

Speaker note: this slide exists so the audience knows the deliverable is evidence,
not volume.

## Slide 3 — What we used as evidence

**Two public adversary-emulation recordings. Real telemetry, not invented.**

| Recording | Host | Process-creation records | Total records |
| --- | --- | --- | --- |
| DS001 | `WORKSTATION5` | 3 | 1,127 |
| DS002 | `WORKSTATION6.theshire.local` | 6 | 4,348 |

- Three telemetry types: Sysmon, Windows Security auditing, PowerShell script and
  module logging.
- Every record traceable to a source line and checksummed.
- Speaker note: state the constraint early. Three process records on a host is very
  few. It shapes every result that follows, and the audience should hear that from
  us rather than find it in the appendix.

## Slide 4 — The method in one picture

Five steps, each with a named artefact:

1. **Baseline** — 21 ATT&CK techniques assessed, all scored Not Covered. *(coverage/baseline.json)*
2. **Build** — one template, one shared test harness, no per-rule scripts. *(rules/, scripts/test_all.py)*
3. **Replay** — every rule run against real attack telemetry. *(detections/test-results.csv)*
4. **Tune** — three false-positive cases with before-and-after numbers. *(evidence/tuning/)*
5. **Score** — coverage derived mechanically from the recorded results. *(coverage/matrix-v2.json)*

Speaker note: the key claim is step 5. Coverage is computed from test output, not
asserted in prose, so it cannot drift from the evidence.

## Slide 5 — Deliverables at a glance

| Deliverable | Target | Delivered |
| --- | --- | --- |
| Sigma rules | 15+ | **17** (15 confirmed, 2 gap-retaining) |
| Techniques assessed | 20+ | **21** |
| Threat hunts | 2+ | **2** |
| Incident case reports | 2+ | **2** (both true positive) |
| Response playbooks | 3+ | **4** |
| Tuning records | 3 | **3** |
| IOC watchlist | — | **22 entries** |

Speaker note: 2 of the 17 rules match nothing on purpose. Say so here rather than
letting it be discovered later.

## Slide 6 — Coverage: the honest version

**Covered 1 · Partially Covered 12 · Not Covered 8**

- **Covered** = tested rule that fires on a real attack **and** measured against
  real ordinary activity with zero false alarms.
- **Partially Covered** = fires on a real attack; false-alarm rate unmeasured.
- **Not Covered** = no confirmed detection.

Visual: the Navigator layer, three colours.

Speaker note: this is the slide that builds or destroys credibility. One Covered is
a low number and it is the correct number. The reason is on the next slide.

## Slide 7 — Why only one technique is fully covered

**We refuse to score a detection "covered" without a measured false-alarm rate.**

- The recordings contain no clean reference of normal business activity.
- Rule authors routinely assume their rule is precise. On a high-volume estate
  that assumption becomes alert fatigue.
- We could have claimed 13 Covered. That would have been wrong and unauditable.

Speaker note: if challenged on the low number, this is the answer. We traded a
flattering number for one an auditor could verify.

## Slide 8 — Incident 1: confirmed true positive

**A "service" whose only job was to run a hidden command, running as SYSTEM.**

Timeline in four steps, each with a time and a source line:

| Time (UTC) | What happened | Evidence |
| --- | --- | --- |
| 16:16:56.019 | Service Control Manager reaches a dynamic RPC port | DS002:1366 |
| 16:16:56.597 | Command shell created by that service | DS002:1057, DS002:1226 |
| 16:16:56.620 | Concealed PowerShell with an encoded payload | DS002:1073, DS002:1238 |
| 16:17:18.795 | Account check — log records the answer: `nt authority\system` | DS002:2901, DS002:2877 |

- Corroborated by **four independent log sources**.
- The script disabled its own logging and inspection controls first.

Speaker note: "the log recorded the attacker's own answer" is the line that lands.
It is the difference between confirmed and inferred.

## Slide 9 — Incident 2: confirmed true positive

**A signed Windows component used as a loader, then an open administrator session.**

| Time (UTC) | What happened | Evidence |
| --- | --- | --- |
| 06:57:59.855 | `mshta.exe` with an inline VBScript URL | DS001:275, DS001:4 |
| 06:58:00.462 | PowerShell created, session deliberately left open (`-noexit`) | DS001:398, DS001:30 |
| 06:58:00.462 | Immediate check of whether our sensor is running | DS001:398 |

- Same parent-child chain recorded by two independent process logs.
- No persistence, no escalation — and still a true positive.

Speaker note: contrast with slide 8. Small, patient intrusion versus fast,
privileged one. Both needed different rules.

## Slide 10 — The hunt that found the most by proving nothing

**Was the outbound web connection command and control? Inconclusive — and here is
the arithmetic.**

- Exactly **one** connection to the destination.
- Recording covers **2 minutes 14 seconds**. A beacon is defined by repetition;
  two minutes cannot show it.
- No response content, no second-stage script text.
- Destination is a **private internal address**, so "external C2" cannot be claimed.

**The negative result that shaped every future rule:** of 43 connections to port 80
in the recording, **42 were ordinary cloud platform traffic**. A "alert on web
traffic" rule would have been wrong 98% of the time.

Speaker note: this is the strongest slide in the deck for a technical audience and
the best demonstration of method for a non-technical one. We stopped rather than
shipped a plausible rule.

## Slide 11 — Three rules that failed the false-positive test

| Rule | Before | After | What we did |
| --- | --- | --- | --- |
| CT-012 named-account network logon | 7 matches (6 false) | 1 match, 0 false | Excluded machine accounts. **This is the one Covered technique.** |
| CT-013 LSASS memory access | 7 matches (7 false) | 0 matches | Excluded two Windows components by call trace. |
| CT-014 remote file share access | 3 matches (3 false) | 0 matches | Excluded machine accounts and policy files. |

- Every match in the last two rows was ordinary Windows or vendor activity.
- Tuning them to silence is a **precision** result, not a detection. Both techniques
  stay Not Covered.
- Accepted trade-offs are recorded in writing, including what each change now misses.

Speaker note: the middle and bottom rows are the ones to dwell on. We are showing
our own rules failing, and the fix being to admit we cannot detect it yet.

## Slide 12 — What we deliberately did not build

| Technique | Why no rule | Minimum data needed |
| --- | --- | --- |
| T1071.001 Web Protocols | One connection in 2m14s; 42 of 43 port-80 flows are benign platform traffic | Longer capture plus proxy or gateway content |
| T1547.001 Startup persistence | No run-key write anywhere in the recordings | ~5 min capture with a run-key write and the resulting execution |
| T1110.003 Password spraying | **Zero** failed sign-ins in either recording | 1 hour of authentication logs including 4625 |
| T1486 Ransomware for impact | No labelled encryption sequence | Documented safe simulation with known file effects |

Speaker note: "we did not build a rule to hit a number" is the sentence to say
out loud. It is the difference between an audit-ready library and a spreadsheet.

## Slide 13 — Collection gaps we found, which matter more than any rule

1. **One workstation had no PowerShell script logging at all.** A rule needing
   script text could not have been written for that host.
2. **Neither recording contains a single failed sign-in.** Credential attacks are
   invisible without them.
3. **No service-install events with usable timestamps**, so the persistence
   mechanism cannot be placed on a timeline.
4. **No proxy or web gateway content**, so tool-transfer assessment can never be
   more than inconclusive.

Speaker note: these are configuration findings, not content findings. They are also
the cheapest to fix.

## Slide 14 — What we are asking for

| # | Ask | Cost | Unlocks |
| --- | --- | --- | --- |
| 1 | Record a clean baseline of normal activity | Analyst time, no new tools | 12 techniques from unmeasured to measured |
| 2 | Enable PowerShell script logging and failed sign-in collection everywhere | Configuration | Credential and script visibility |
| 3 | Deploy the 15 confirmed rules, with caveats attached | Analyst time | Immediate coverage on 12 techniques |
| 4 | Collect three short targeted recordings | Analyst time, ~1 hour total | Closes 3 named gaps |
| 5 | Add proxy or gateway logging | Existing platform config | Makes tool-transfer assessment possible at all |

Closing line: **we would rather hand over one verified detection and three named
gaps than fifteen detections and no idea which of them work.**

---

## Speaker preparation: questions to expect

| Likely question | Answer |
| --- | --- |
| "Only 1 of 21 covered — is that bad?" | The baseline was 0 of 21 with no test evidence at all. 13 techniques now have rules proven against real attacks. The remaining gap is measurement, not capability. |
| "Can we deploy these rules tomorrow?" | The 15 confirmed ones, yes, with the stated caveats. Run them in alert-only mode for two weeks and compare volume against the current baseline before routing them to an on-call queue. |
| "Was any real data breached?" | Cannot be determined, and we say so. The recordings are lab captures. Within them, no evidence of data access was found, and the capture length means absence of evidence proves nothing. |
| "Why not just use an off-the-shelf ruleset?" | Because it would arrive untested against our data, with no evidence trail, and we would not know its false-alarm rate. The method is the deliverable, not just the rules. |
| "Which is the biggest risk?" | Credential compromise, because it is the one question neither incident could answer, and because failed sign-in logging is missing everywhere. |
| "How do we know the numbers are real?" | Three commands regenerate every figure from the recorded evidence. The pre-engagement baseline is retained unmodified with its checksum. See the reproducibility slide in `reports/executive-summary.md` section 8. |
