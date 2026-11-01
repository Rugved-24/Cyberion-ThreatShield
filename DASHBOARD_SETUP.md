# Cyberion ThreatShield dashboard (optional enhancement)

This adds a local, read-only Streamlit dashboard. It does not replace any required project deliverable, change Sigma rules, or act as a live SIEM.

## Install on Windows

Run these commands from the repository root (`E:\VS Code Projects\Cyberion-ThreatShield`):

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dashboard.txt
.\.venv\Scripts\python.exe -m streamlit run dashboard\app.py
```

Streamlit should open a local browser tab. If it does not, open the `Local URL` printed in the terminal (usually `http://localhost:8501`). Keep the terminal open while using the dashboard; press `Ctrl+C` to stop it.

## Files read

- `detections/test-results.csv`
- `detections/tuning-results.csv`
- `coverage/matrix-v2.md`
- `hunts/HUNT-*.md`
- `incidents/INC-*.md`
- `ioc/watchlist.csv` (aggregate counts only; indicator values are not displayed)

The dashboard deliberately avoids showing event UIDs, hostnames, account names, or IOC values in its summary views. Source reports and data still remain in the repository, so do not publish the project without reviewing and sanitizing them first.

## Important interpretation notes

- A passing validation status is not the same as proof of production detection effectiveness.
- ATT&CK coverage is read from the generated matrix; current coverage is 1 Covered, 12 Partially Covered, and 8 Not Covered.
- Tuning examples are not treated as a global false-positive rate.
- This is a static analysis dashboard, not real-time telemetry ingestion, a SIEM, or automated response.

## Troubleshooting

- If Streamlit is missing, rerun the `pip install` command above.
- If the dashboard reports missing files, confirm the terminal's working directory is the repository root and that the existing project output files are present.
- If charts do not refresh after regenerating CSV/Markdown outputs, use the Refresh dashboard data button under **About & Limitations**, or restart Streamlit.
