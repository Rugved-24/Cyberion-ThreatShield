# Environment

Platform: Windows, PowerShell 5.1
Python: 3.12.10, project-local .venv
Git: 2.55.0.windows.4

Validated packages:
- sigma-cli 3.1.0
- pandas 3.0.5
- jupyterlab 4.6.3
- pytest 9.1.1

Checks passed: pip dependency consistency, pandas/PyYAML/pySigma
imports, Sigma startup, and JupyterLab version output.

requirements.txt records the installed Windows dependency set.

## Reproducing the environment

`requirements.txt` is a fully pinned Windows dependency set. The commands below are
the ones that produced the recorded environment. Run them from the repository root.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Do not run the pipeline with a system Python. Every script resolves the repository
root from its own file location, so the working directory does not matter, but the
interpreter does.

## Jupyter kernel

The notebook enforces its own kernel. Register it once after creating the venv:

```powershell
.\.venv\Scripts\python.exe -m ipykernel install --user --name cyberion `
  --display-name "Cyberion (.venv)"
```

`notebooks/01_data_familiarization.ipynb` raises at cell 0 if the running
interpreter is not `.venv\Scripts\python.exe`. That check is intentional: a
notebook run against a different interpreter can silently produce different
aggregate figures.

## Pipeline order

Each step verifies the previous step's output hash, so the order matters and a
re-run either reproduces the recorded state exactly or fails.

```powershell
# 1. Verify the recorded archive hash and extract, writing docs/DSxxx-inventory.json
.\.venv\Scripts\python.exe scripts\inventory_dataset.py DS001 cmd_mshta_vbscript_execute_psh.zip
.\.venv\Scripts\python.exe scripts\inventory_dataset.py DS002 empire_psexec_dcerpc_tcp_svcctl.zip

# 2. Profile event times, writing docs/DSxxx-capture.json
.\.venv\Scripts\python.exe scripts\check_capture.py

# 3. Normalize and trace, writing data/processed/DSxxx.jsonl and docs/DSxxx-normalization.json
.\.venv\Scripts\python.exe scripts\normalize_dataset.py DS001 DS002

# 4. Field profile and traceability validation, via the notebook
#    writes docs/DSxxx-fields.json and docs/DSxxx-validation.json

# 5. Detection content
.\.venv\Scripts\python.exe scripts\test_all.py
.\.venv\Scripts\python.exe scripts\tune.py
.\.venv\Scripts\python.exe scripts\build_coverage.py
```

`inventory_dataset.py` is the one script that uses working-directory-relative paths
rather than resolving from `__file__`. Run it from the repository root.

## Exit codes

| Script | Non-zero exit means |
| --- | --- |
| `inventory_dataset.py` | Archive hash or size differs from the recorded acquisition record |
| `normalize_dataset.py` | Any record rejected, record count mismatch, or duplicate event UIDs. The previous output file is left unchanged. |
| `test_all.py` | Any rule failed: declared evidence missed, declared negative matched, `sigma check` failed, or a correlation window matrix mismatched |
| `tune.py` | A tuning case lost a declared attack match, or the tuned rule left a residual benign match |
| `build_coverage.py` | A rule has no row in the test results, or a required input artefact is missing |

Each failure is intended to stop the pipeline. A harness that continued past a hash
mismatch would produce confident and wrong output, which is the specific failure
mode this project is built to avoid.

## Direct invocation without activation

All commands use the interpreter path directly, so no `Activate.ps1` call is needed
and no execution-policy change is required.
