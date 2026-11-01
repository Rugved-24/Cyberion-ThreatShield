# Security posture

This project is a detection-engineering and threat-hunting repository. It builds
no service, opens no port, deploys nothing, and holds no production access. Its
entire value depends on the evidence it cites being genuine and unaltered.

## The honest position

**This project cannot be made immune to cyber attacks, and it does not have zero
vulnerabilities.** No software artefact can. Anyone asserting otherwise is
describing a control set, not immunity, and repeating the claim here would
contradict the purpose of this repository.

What can be done, and what this project does do:

1. State the threat model explicitly, including who the attacker is.
2. Assert the specific invariants that matter for *this* repository, in code,
   and fail the build when one breaks.
3. Report what remains unfixed rather than rounding it down.
4. Make a redacted copy publishable without breaking the audit trail.

Run the controls yourself:

```powershell
.\.venv\Scripts\python.exe scripts\security_review.py
```

Exit codes: `0` all controls pass, `1` at least one control failed, `2` at least
one control warned. A warning is not a pass, and the script says so.

## Threat model

| Actor | Capability | In scope | Notes |
| --- | --- | --- | --- |
| **Malicious contributor** — anyone who can open a pull request against this repository | Edit any tracked file, including rules and scripts | **Yes** | The rules are executed by the harness. A malicious regex or a poisoned rule is the realistic route into this codebase. |
| **Supply chain** — a compromised or substituted Python package | Arbitrary code at install time, before any control runs | **Yes** | Mitigated only partially. See residual risk R1. |
| **Local user on the analyst workstation** | Read the working tree, including raw telemetry | Partly | The raw recordings are not committed, but they are on disk in `data/`. |
| **Accidental corruption** | Alter a telemetry file or an evidence document | **Yes** | This is the most likely real-world failure and the one the project has hardened against hardest. |
| **Network attacker** | Reach a running service | **No** | There is no service, listener or network-exposed component. Nothing to attack remotely. |
| **Attacker in the recorded data** | Appear in the telemetry as script content | **Yes** | Rule conditions are matched against attacker-controlled strings. |

The last row is the one people forget. In this project the log content is written
by the adversary. Every rule is a predicate evaluated against hostile input, and
the harness itself must never be tricked into treating that input as a command.

## Controls asserted in code

| ID | Control | Current state |
| --- | --- | --- |
| C1 | Dataset identifiers are validated before being used to build a filesystem path | PASS |
| C2 | Every script that reads raw telemetry verifies its SHA-256 **before** reading | PASS |
| C3 | Committed evidence writes are restricted to the documented `docs/DSxxx-*.json` set | PASS |
| C4 | YAML parsed with `safe_load` only; no `shell=True` anywhere | PASS |
| C5 | No credentials, tokens or key material committed | PASS, 75 tracked files scanned |
| C6 | Telemetry directories and binary event files are not tracked by git | PASS |
| C7 | Dependencies are version-pinned | **WARN** — pinned but not hash-pinned, see R1 |
| C8 | Caller-supplied paths and archive members are confined to their permitted directory | PASS |
| C9 | No byte-order marks, zero-width or bidirectional characters in committed artefacts | PASS |

### Defects found and fixed

These were real, were introduced or inherited during the work, and are now fixed.

| Defect | Why it mattered | Fix |
| --- | --- | --- |
| `check_capture.py` read raw telemetry **without verifying its digest**, then wrote a tracked evidence file from it | The single most serious issue found. Altered telemetry could reach a committed evidence document unverified, which breaks the project's core contract that every finding cites verified evidence | Digest verified before the first record is read; the verified digest is now recorded in the output |
| `inventory_dataset.py` built a path from an unvalidated `sys.argv` value | A crafted dataset ID could reach outside `docs/`. Local-only, but it contradicted a control the project already enforced elsewhere | Identifier validated against `DS\d{3}` |
| `inventory_dataset.py` extracted an arbitrary archive member with no size limit | A compression bomb could exhaust memory after its digest was accepted | Member must be a bare file name, declared size checked before extraction, destination confined |
| `scripts/` relied on the working directory | Behaviour depended on where the script was invoked from | Paths resolve from the script location |
| Byte-order marks in 13 committed files, three introduced by rewrites during this work | Inconsistent encoding; a BOM in a text file defeats naive byte-level matching, which is how this was detected | `scripts/normalize_text.py`, plus control C9 to prevent recurrence |

## Residual risk

Stated plainly, because a risk register with nothing in it is not a risk register.

| ID | Risk | Severity | Why it is not fixed here | Action to close it |
| --- | --- | --- | --- | --- |
| R1 | **Dependency substitution.** `requirements.txt` pins 104 versions but not their content hashes | Medium | Generating hashes requires downloading every artifact from PyPI, which needs network access this environment does not have | `pip download -r requirements.txt -d hashes/` then `pip install --require-hashes -r requirements.txt` |
| R2 | **Hostile rule content.** Rule files are data evaluated by the harness; a catastrophic-backtracking regex in a rule would hang it | Low | A rule is reviewed code, and this project's rules are its own output. ReDoS hardening would add a dependency and slow every replay | Bound the evaluation, or treat `rules/` as code and require review. Note it in the contribution path |
| R3 | **Raw telemetry on disk.** `data/raw/` holds the full recordings in clear text | Low, environmental | Out of scope: the recordings are the evidence and must be local to be analysable | Full-disk or container encryption on the analyst workstation |
| R4 | **Redaction is one-way by design.** If the redaction salt is lost, the mapping cannot be recovered | Low, by design | Reversible redaction is defeated by anyone holding the output | Store the salt in a password manager, not in the repository |
| R5 | **No independent review.** Every rule, figure and conclusion was produced and checked by the same person | Medium, process | A single-analyst engagement | Peer review of at least the Covered technique and the two incident closures |
| R6 | **Redacted copies can drift.** A sanitised copy is a snapshot; the repository can move afterwards | Low | Inherent to copying | Record the source commit in the redacted copy. Not yet implemented |

## Publishing a redacted copy

The recordings are public datasets with unresolved licence terms
(`references/OTRF-LICENSE` carries conflicting MIT and GPL-3.0 labels), and the
written reports contain host names, account names and internal addresses from the
lab network. Both are reasons to publish a redacted copy rather than the
repository.

```powershell
$env:CYBERION_REDACTION_KEY = "<a long random value>"
.\.venv\Scripts\python.exe scripts\sanitize.py --out ..\Cyberion-ThreatShield-public
.\.venv\Scripts\python.exe scripts\sanitize.py --out unused --verify ..\Cyberion-ThreatShield-public
```

Verified behaviour of the current implementation:

- 27 values masked: 5 host names, 12 account names, 8 internal addresses, 2
  attacker tradecraft strings. The list is derived from the recorded telemetry,
  not hand-maintained, so it cannot drift out of date.
- 0 residual sensitive values in the output, checked against 24 values read back
  from the recordings.
- **All 52 event UIDs preserved**, and with them every rule, match count,
  conclusion, ATT&CK technique ID and timeline. The audit trail survives
  redaction, which is the point: an audit that cannot verify its citations is
  worth nothing.
- The pseudonym-to-value mapping is not written anywhere. `redaction-manifest.csv`
  holds HMAC-SHA256 values keyed with the salt, so a holder of the salt can
  confirm a mapping and a reader of the copy cannot recover it.
- `--verify` returns 0 for the correct key and 1 for any other.

**Do not commit the redaction salt.** It is read from the environment and is never
written to disk. If `CYBERION_REDACTION_KEY` is unset a random salt is generated
and the script says so loudly, because a copy produced that way can never be
verified later.

## What is deliberately not claimed

- Not "zero vulnerabilities". See the residual risk table.
- Not "secure" or "hardened" in the sense of an audited product. No external
  review, penetration test or certification has been performed.
- Not "the coverage numbers are safe". Twelve of twenty-one techniques are
  Partially Covered precisely because their false-alarm rate is unmeasured. A
  clean security review of the repository does not change that, and the two must
  not be confused.

## Reporting a problem

If you believe you have found a defect in this repository, report it to the
project owner with the file, the line, and the reproduction. If the defect affects
evidence integrity — an altered telemetry file, an unverifiable citation, a
coverage number that does not follow from the recorded results — that is the
highest-priority class and should be treated as such rather than as a bug.
