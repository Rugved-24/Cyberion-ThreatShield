# PB-XX: <playbook title>

> Template. Copy this file, rename it to `PB-NN-<slug>.yml`-style name
> `PB-NN-<slug>.md`, and replace every `<...>` placeholder. Delete this
> instruction block and the "Template" row from the change log.
>
> Design constraints that apply to every playbook in this directory:
> assume one analyst on shift with no second pair of hands, assume the alert may
> be a false positive, and assume the analyst has not seen the host before.
> Every step must be executable in the order written, and every step must say
> what to record.

| Field | Value |
| --- | --- |
| Playbook ID | PB-XX |
| Version | 1.0 |
| Owner | Detection Engineering |
| Last reviewed | YYYY-MM-DD |
| Applies to | <the alert, rule ID or technique that opens this playbook> |
| Expected time to scope | <realistic minutes for one analyst> |
| Escalates to | <role or team, and the condition that triggers it> |

## 1. Before you start

**What you need:** host name exactly as the log records it, the alert time, and
read access to the platform's process, script and network telemetry.

**Rules this playbook depends on.** List the rule IDs and state, for each, whether
it is Partially Covered or Covered, because an analyst needs to know whether a
negative result means anything.

**What this playbook does not cover.** State the gaps explicitly so that a
responder does not assume coverage that does not exist.

## 2. Trigger conditions

List the specific alerts, rule IDs or hunt outcomes that open this playbook, and
the severity at which it is escalated rather than worked.

## 3. Investigation steps

Numbered, ordered, and each with a **Record:** line naming exactly what to write
down. Include at least one step that can end the investigation as a false positive,
so that the playbook is not a script for escalation.

| # | Action | How to check | Record |
| --- | --- | --- | --- |
| 1 | | | |

### 3.1 Interpretation guide

A small table of observation to meaning, so the analyst does not have to re-derive
the reasoning. Include the ambiguous cases, not just the obvious ones.

| Observation | Most likely meaning | Alternative to rule out |
| --- | --- | --- |

### 3.2 Decision point

State the explicit condition that separates "benign" from "escalate", so the
decision is auditable rather than a judgement call.

## 4. Containment

Ordered, with the least disruptive option first and an explicit note on what is
lost by each irreversible step. Preserve evidence before acting wherever possible.

## 5. Eradication

What to remove, and the estate-wide search to run for the same technique.

## 6. Recovery

How to return the host to a known good state, and how to verify that the controls
the attacker disabled are working again.

## 7. Stakeholder communications

Three fixed points with a time, an audience and a specific content list:
initial notification, containment confirmation, and closure. Include what must
**not** be said at each point, such as unconfirmed attribution.

## 8. Post-incident actions

Detection gaps revealed, tuning required, and which artefacts must be updated.

## 9. Change log

| Version | Date | Change | Author |
| --- | --- | --- | --- |
