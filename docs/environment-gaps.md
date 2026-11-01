# Environment inspection and gaps

Observed host inventory: `docs/environment-inventory.json`, captured by
`scripts/environment_inventory.py`. Nothing in this document is assumed; the
figures are read from that file.

## Observed host

| Item | Observed value | PRD expectation | Status |
| --- | --- | --- | --- |
| Operating system | Windows 11, AMD64 | Modern Windows | Meets |
| Logical CPU cores | 12 | Not specified | Meets |
| RAM | 15 GiB | Not specified | Meets |
| Storage | C:, D: and E: volumes recorded in the JSON | Not specified | Meets |
| Python | 3.12.10 in `E:\VS Code Projects\Cyberion-ThreatShield\.venv` | 3.11+ | Meets |
| Environment isolation | `sys.prefix != sys.base_prefix`, confirmed | Dedicated isolated environment | Meets |
| Git | Present, 12 commits, **no remote configured** | Version control mandatory | Meets, with a note |
| PowerShell | Windows PowerShell 5.1 present. `pwsh` 7 **not** installed | PowerShell 7 recommended | Gap G1, not required |
| Jupyter kernel | `cyberion` registered during this engagement, alongside `python3` | Jupyter for analysis | Meets |
| sigma-cli | Present at `.venv\Scripts\sigma.exe`, version 3.1.0 | Sigma tooling | Meets |
| Spreadsheet software | Excel installed | Excel or LibreOffice Calc | Meets, not required for any deliverable |
| Presentation software | PowerPoint installed | PowerPoint or equivalent | Meets |
| Browser | Chrome and Edge present on PATH, not invoked | Modern browser | Meets |
| Virtualization | **No hypervisor detected. No VirtualBox, VMware or Hyper-V tooling. Docker CLI present but the daemon is not running. `vmcompute` present but stopped.** | Lab VM optional | **Gap G2, decisive** |
| SIEM | None installed | Explicitly out of scope | Correctly absent |

## What was installed, and what was deliberately not

Installed during this engagement, because the work needed them:

- The project virtual environment and the pinned dependency set in
  `requirements.txt`.
- The `cyberion` Jupyter kernel. It was **missing** when the environment was
  first inspected and the notebook's own guard cell would have refused to run.
  This is a genuine gap that was closed rather than assumed away.

Not installed, on purpose:

- **No SIEM.** The PRD places a live platform out of scope and permits a local
  Elastic or OpenSearch instance only as a query aid. Nothing in the deliverables
  needs one: every rule is replayed through `scripts/test_all.py` against the
  recorded telemetry, which is more reproducible than a console query and is
  itself one of the PRD's optional stretch goals.
- **No additional Python packages.** `requirements.txt` is a pinned environment,
  not a wish list. `matplotlib`, `openpyxl` and `requests` are present only
  because the upstream Windows freeze included them; the deliverables do not
  depend on them and nothing was added for appearance.

## Gap G1: PowerShell 7 is not installed

The PRD recommends PowerShell 7. Windows PowerShell 5.1 is what is present and
it is sufficient: the entire pipeline is driven by `.venv\Scripts\python.exe`
invocations and does not rely on any PowerShell 7 feature. Recorded as a
deviation from the recommendation, not a requirement failure.

## Gap G2: no isolated test laboratory, and this is decisive

This host has **no working virtualization**. There is no hypervisor, no
VirtualBox, no VMware, no enabled Hyper-V compute service, and the Docker daemon
is not running.

Two consequences follow, and they are the reason three techniques are reported
as Not Covered rather than tested:

1. **A Windows test VM cannot be created**, so Atomic Red Team cannot be executed
   against a Sysmon-instrumented isolated machine.
2. The PRD and the engagement instruction both forbid running attack simulation
   on the user's daily-use environment. That route is therefore closed on
   instruction even though no technical barrier was tested for it.

The three affected techniques are T1547.001 Registry Run Keys / Startup Folder,
T1110.003 Password Spraying and T1486 Data Encrypted for Impact. Neither selected
recording contains an example of any of them: no run-key registry write, no event
4625 authentication failure, and no labelled encryption sequence.

**What was not done:** no rule was written for these techniques, no telemetry was
synthesised, and no result was estimated. The minimum dataset each gap needs is
specified in `coverage/matrix-v2.md` so the gap can be closed on a host that has
a hypervisor.

**What would close it:** a host with any hypervisor, one isolated Windows
evaluation VM, Sysmon, and a short Atomic Red Team selection. The instruction
not to run destructive, credential-stealing or persistence-heavy tests is
respected: a run-key write, a controlled spray of invented local accounts and a
safe-emulation encryption marker would each be sufficient, and none of those
require a destructive payload.

## Note on Git remotes

The repository has no configured remote. This is deliberate: the raw telemetry is
third-party material with unresolved licence terms, and the engagement instruction
prohibits uploading proprietary or restricted telemetry. Publishing is instead
handled by `scripts/sanitize.py`, which produces a redacted copy for external
release. See `SECURITY.md` and `docs/datasets.md`.

## Reproducing the inspection

```powershell
.\.venv\Scripts\python.exe scripts\environment_inventory.py
```

The script is safe to re-run. It locates GUI executables such as browsers by
presence only and never invokes them, because `msedge --version` does not reliably
return on Windows and would otherwise hang the inventory.
