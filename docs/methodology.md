# Methodology

How this engagement was performed, from dataset selection to final reporting. An
analyst who has not spoken to the author should be able to reproduce every figure
in the reports by following this document and the repository.

Terminology follows the Cyberion Defense Labs PRD CDL-DET-V2 version 2.0.

---

## 1. Objectives

Establish whether a detection-engineering and threat-hunting practice can be
built and evidenced from real public telemetry, and produce the work product a
detection engineer or threat hunter would produce day to day: detection content,
coverage assessment, structured hunts, incident cases, response procedures and
business-facing reporting. No software product, service or platform was built.

## 2. Scope and exclusions

In scope: analysis of publicly documented security telemetry; Sigma rule authoring
mapped to MITRE ATT&CK; structured hypothesis-driven hunting; incident case
reporting; response playbook authoring; IOC research; coverage assessment;
executive reporting.

Explicitly out of scope, per PRD section 2.9: building or hosting any application,
backend or database; standing up a live SIEM; automated response execution;
production client log access. None was built. The Python in this repository is
analysis tooling, not a product, and none of it is a deliverable in itself.

## 3. Tools and environment

Python 3.12.10 in a dedicated virtual environment, pandas for data handling,
JupyterLab for documented analysis, `sigma-cli` 3.1.0 and pySigma for rule
authoring and syntax validation, and Git for version control. The environment was
inspected before use and the observed values are recorded in
`docs/environment-inventory.json`; gaps are recorded in
`docs/environment-gaps.md`. The full pinned dependency set is `requirements.txt`,
with QA and reporting tooling separated into `requirements-dev.txt`.

No SIEM was installed. PRD section 2.9 permits a local Elastic or OpenSearch
instance only as a query aid, and the PRD's own success metric requires rules to be
tested against real log data, which the local replay harness does more
reproducibly than a console query.

## 4. Dataset selection

Selection criterion: the dataset must contain enough *recorded* attacker behaviour
to support real detection engineering, and must be documented well enough that
provenance can be stated.

Two Mordor datasets distributed by the Open Threat Research Forge were selected:

| Dataset | Scenario label | Records | SHA-256 |
| --- | --- | --- | --- |
| DS001 | mshta VBScript executing PowerShell | 1127 | `25AA24B5F631F19AC23F64DB116C23E632295FB5F59040E966FA47E7758B2A32` |
| DS002 | Empire PsExec DCOM/tcp/svcctl | 4348 | `968C4B699F7239D106577B2B8E206EDFAF812F193A60E663966258AF67A56ACC` |

Dataset selection was an iterative decision, not a first choice. DS001 and DS002
were acquired first because their scenario labels name specific techniques. Phase 4
then assessed techniques from the process-creation records in both and found only
seven candidate behaviours, because the attack chain in DS002 is recorded in the
PowerShell script block rather than in process creation. Re-reading the recorded
script text produced six further candidate behaviours and two more techniques.
This is recorded as a methodology lesson rather than hidden: a technique assessment
based on a single telemetry type understates what the data contains.

Criteria explicitly *not* used for selection: a scenario directory name is not
evidence. The DS002 label names a lateral-movement technique that the capture does
not actually contain, and the project reports that discrepancy rather than
inheriting the label's claim.

## 5. Telemetry acquisition and provenance

For each dataset: the archive's SHA-256 was verified against the recorded
acquisition record before extraction, the extracted member's digest was recorded
in `docs/DSxxx-inventory.json`, and the raw file is treated as immutable from that
point. `docs/DS001-acquisition.json` and `docs/DS002-acquisition.json` hold the
source URL, acquisition date and digest. Raw files are never modified and are
excluded from version control.

Licence terms are unresolved. The pinned upstream files carry conflicting MIT and
GPL-3.0 labels. This is recorded in `docs/datasets.md` and `SECURITY.md`, and it
is the reason the repository has no configured remote: external publication goes
through `scripts/sanitize.py`, which masks identifying values while preserving
every evidence reference.

## 6. Data preparation

Four stages, each of which verifies the previous stage's output hash and fails
closed on a mismatch.

1. **Inventory.** Verify the archive digest, extract one member, record its digest,
   byte size and record count. `scripts/inventory_dataset.py`.
2. **Capture profiling.** Profile every timestamp field and reject records whose
   `@timestamp` or `TimeCreated` lack an explicit timezone.
   `scripts/check_capture.py`.
3. **Normalization.** Map fields per `docs/field_mapping.md`, parse only Sysmon
   `UtcTime` into `timestamp_utc`, retain the original event object in `raw`, and
   assign each record an `event_uid` of `dataset_id:raw_sha256:record_locator`.
   `scripts/normalize_dataset.py`. All-or-nothing: output is written only when
   every record is accepted and every UID is unique.
4. **Field profiling and traceability validation.** Profiler and validator in
   `notebooks/01_data_familiarization.ipynb`.

Result: 5475 records normalized, zero rejected, every record traceable to a
physical source line.

## 7. Field interpretation and the data dictionary

`docs/data_dictionary.md` documents every field used, its type, its meaning from
a detection standpoint, and its limitations. Three telemetry types are covered:
Sysmon, Windows Security auditing, and PowerShell Operational.

Two interpretation rules govern everything downstream:

- **Field names are case-sensitive.** `ProcessID` is not `ProcessId`.
  `Channel: security` and `Channel: Security` both occur in DS002 and mean
  different things.
- **A missing field is never guessed.** Absent, null, empty and `-` map to null.
  Meaningful false and zero values are retained.

Numeric-looking fields are compared as numbers in the replay harness because SIEMs
index them that way, while the original string remains in `raw`.

## 8. Timestamp policy

`docs/timestamp_policy.md`. Only Sysmon `UtcTime` is treated as event-time UTC.
Everything else is explicitly `unresolved` and is never converted.

This is the single most consequential methodological decision in the project. In
DS002 the Security `EventTime` reads four hours behind its own `@timestamp`. The
offset was **not** resolved to any timezone, because doing so would manufacture an
ordering the data does not support. The consequence is stated rather than hidden:
235 DS001 and 1407 DS002 records have no event time, which is the direct cause of
the two inconclusive conclusions in the hunt reports and of the inability to
correlate the service installation to its execution.

## 9. Detection-engineering methodology

For each rule: select an observable behaviour, confirm the ATT&CK mapping against
version 19.2, write the rule from the template, and declare the evidence.

Behaviour selection required a defensible reason for every field and condition,
not a keyword search. Where a single log line was insufficient to express the
behaviour, a correlation rule was used instead and the pairing is expressed as a
GUID join, never as a process-identifier join, because DS002 has no ordinary Sysmon
`ProcessId` and hexadecimal and decimal identifiers cannot be compared.

Correlation windows are set well above the observed delay. The three shipped
windows are 5 s, 5 s and 30 s against observed delays of 0.607 s, 0.023 s and
22.175 s, so that normal scheduling jitter does not suppress a real detection. The
observed values are retained only as window-matrix assertions.

## 10. Sigma validation methodology

Validation is split into four kinds and all four are recorded per rule:

1. **Syntax.** `sigma check --fail-on-issues` treats warnings as failures.
2. **Structural.** Required fields, a unique UUID, at least one `attack.t` tag, a
   logsource matching the field structure, and a written severity justification.
3. **Logical.** The condition must be expressible in the documented replay grammar.
   Anything outside it raises and rejects the rule rather than silently matching
   nothing. Five failure modes are tested deliberately: parentheses, undefined
   selection, two string operators on one field, a field-reference condition, and
   a trailing operator.
4. **Empirical.** Replay against the recorded telemetry, with a declared evidence
   list and a declared negative list. A rule whose declared evidence does not match
   **fails**. A rule whose declared negative matches **fails**.

A rule is not called validated because its YAML parses. `scripts/test_all.py`
produces `detections/test-results.csv` with per-rule match counts, event UIDs,
held negatives, residual benign volume and, for correlation rules, the
window-boundary matrix result.

## 11. ATT&CK mapping methodology

Mappings are verified against the pinned Enterprise ATT&CK 19.2 STIX source
recorded in `coverage/baseline.json`, not from memory and not from the dataset
directory names. In version 19 the Defense Evasion tactic is split; Mshta
T1218.005 sits under **Stealth**, and this project uses the current name.

A rule carries its techniques in `x-attack.techniques`. Coverage is then *derived*
by `scripts/build_coverage.py` from recorded test results, never asserted in prose:
Covered requires a matched declared attack evidence **and** a measured benign
result; Partially Covered requires matched attack evidence with no measured benign
comparison; otherwise Not Covered. A rule with a deliberately empty evidence list
therefore cannot score above 0, which is what holds CT-013 and CT-014 at Not
Covered.

## 12. Threat-hunting methodology

Hypothesis first, coverage status recorded before analysis, and the commit
recorded so the conclusion cannot be reverse-engineered from an existing rule.
HUNT-002's pre-hunt commit is `a85ce34`.

Every hunt states the hypothesis in falsifiable form, lists the alternative
explanations considered in advance, gives the data scope, records the queries and
their results, and classifies the conclusion as Confirmed, Partially supported,
Inconclusive or Ruled out. Negative results are recorded as findings, including
searches that returned nothing, so a later analyst does not repeat them.

No hunt outcome was forced positive. One concluded Partially supported and one
concluded Inconclusive.

## 13. IOC enrichment

Indicators are read from the recorded telemetry rather than recalled from
public reporting, and each is traced to its source records. `ioc/watchlist.csv`
records type, source lines, confidence, intended operational use and limitations.

Two disciplines apply. First, source facts are separated from interpretation: a
value observed in a log is a fact; what it means is an inference. Second,
enrichment is used conservatively. No campaign or actor attribution is asserted
because the public write-up evidence for this dataset does not support one.
The register deliberately includes indicators marked **DO NOT BLOCK** with the
reason, because a watchlist that cannot distinguish a malicious address from
Azure platform traffic is worse than no watchlist.

## 14. Incident investigation methodology

Findings from detections or hunts are carried through evidence collection,
timeline reconstruction, technique mapping, root cause, impact, response
recommendation and closure classification.

Findings are corroborated across independent log sources wherever the data
allows, and this is stated per case: INC-001 is corroborated by four, INC-002 by
two. Observed fact, inferred root cause and unresolved uncertainty are kept in
separate sections, because the unresolved items are the ones that change the
response. Closure is justified against evidence rather than asserted.

## 15. False-positive tuning methodology

Three rules were tuned. For each: the original logic is preserved, the observed
benign scenario is identified from the record, the change is explained, the
before and after counts are **generated** by `scripts/tune.py` rather than typed,
and the accepted trade-off is written down.

The harness imports its matching code from `scripts/test_all.py`, so a tuning
figure and a rule test figure cannot disagree about what a condition means.
A tuning case fails if the change loses a declared attack match or leaves a
residual benign match.

Critically, tuning to silence is not the goal. CT-013 and CT-014 were tuned to zero
matches because every match they produced was benign, and both techniques
therefore remain **Not Covered**. A precision improvement is not a detection, and
the two are reported separately.

## 16. Evidence handling

Every conclusion cites a specific record. References appear in two documented
forms: the full `event_uid` of `dataset:raw_sha256:line` in machine-readable
files, and the `DSxxx:line` shorthand in prose tables. `scripts/prd_compliance.py`
resolves **both** forms against the recorded inventory and fails if any reference
names an unknown dataset digest or a line outside that dataset's record count.

Host aliases are never merged. `WORKSTATION5` and `WORKSTATION5.theshire.local`
remain distinct, and no conclusion in this repository depends on them being the
same machine.

## 17. Reproducibility

`requirements.txt` pins the environment. `docs/environment.md` gives the exact
command sequence in pipeline order. Every figure in every report is generated
from recorded evidence by a named script, and the generator is listed per artefact
in `docs/project-structure.md`. Re-running the pipeline either reproduces the
recorded state exactly or fails.

The pre-implementation coverage position is retained unmodified
(`coverage/baseline.json`, SHA-256 recorded in the generated layer) so the before
and after can be compared and the change audited.

## 18. Ethical and authorization considerations

- The recordings are public adversary-emulation datasets. No live client
  environment was accessed.
- **No attack simulation was executed.** The host has no hypervisor, so no
  isolated lab VM could be created, and running simulation on the user's
  daily-use environment is prohibited by the engagement instruction. Three
  techniques are consequently reported as Not Covered rather than demonstrated
  with invented telemetry.
- No destructive, credential-stealing or persistence-heavy technique was run, and
  none would have been run to satisfy a numerical requirement.
- The recordings contain no personal data beyond synthetic account names present
  in a lab environment. Those names, host names and internal addresses are masked
  in any published copy.

## 19. Limitations

Stated in full in `PROGRESS.md` and in each report. In summary: two recordings of
about two minutes each; no clean benign baseline, which caps 12 of 21 techniques
at Partially Covered; unresolved event times for 1642 records; no proxy or
gateway content, which makes tool-transfer assessment permanently inconclusive
without new collection; no authentication-failure records at all; and unresolved
dataset licence terms.

## 20. Original working principles

The ten-line working method this project began with, retained verbatim as the
baseline these sections formalise.

### Data
Record source URLs, usage terms, acquisition dates, and SHA-256 hashes.
Preserve raw files; write transformations to data/processed.
Document fields and normalize timestamps to UTC while retaining originals.
Keep source-file and record references for every derived finding.

### Detections
Select observable attacker behavior and verify its ATT&CK mapping.
Check Sigma syntax, then replay the logic against documented telemetry.
Record rule version, dataset hash, commands, match counts, and record IDs.
Review matches and benign triggers; syntax validity alone is insufficient.
Validate correlation ordering, grouping, and time windows explicitly.
Synthetic test fixtures supplement real telemetry rather than replace it.

### Hunts and Investigations
Record each hunt hypothesis and coverage status before running queries.
Preserve the method and evidence, including negative or inconclusive results.
Corroborate incident findings across sources where available.
Separate observed facts, inferred root cause, and unresolved uncertainty.
Document timelines, impact, response recommendations, and closure rationale.

### IOCs and Tuning
Trace indicators to source records and dated intelligence references.
Record confidence, limitations, and intended detection or watchlist use.
For tuning, preserve observed benign matches and compare before/after results.
Recheck known attack matches and document accepted trade-offs.

### Reproduction and Review
Use requirements.txt to reproduce the recorded Windows environment.
Keep evidence references aligned across rules, coverage, and reports.
Review sensitive content and dataset terms before publication.
Record actual validation results and the next checkpoint in PROGRESS.md.
