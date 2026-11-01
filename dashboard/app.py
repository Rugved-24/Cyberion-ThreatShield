from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st

APP_DIR = Path(__file__).resolve().parent
ROOT = APP_DIR.parent
TEST_RESULTS = ROOT / "detections" / "test-results.csv"
TUNING_RESULTS = ROOT / "detections" / "tuning-results.csv"
COVERAGE_MATRIX = ROOT / "coverage" / "matrix-v2.md"
IOC_FILE = ROOT / "ioc" / "watchlist.csv"
HUNTS_DIR = ROOT / "hunts"
INCIDENTS_DIR = ROOT / "incidents"

st.set_page_config(
    page_title="Cyberion ThreatShield | Detection Engineering",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .block-container {padding-top: 1.5rem; padding-bottom: 2rem; max-width: 1500px;}
      .hero {padding: 1.25rem 1.4rem; border: 1px solid rgba(120,140,170,.35);
             border-radius: 16px; margin-bottom: 1rem;
             background: linear-gradient(115deg, rgba(25,45,70,.65), rgba(18,25,40,.35));}
      .hero h1 {margin: 0 0 .3rem 0; font-size: 2rem;}
      .muted {color: #9ca9bb; font-size: .92rem;}
      div[data-testid="stMetric"] {border: 1px solid rgba(120,140,170,.28); padding: .8rem 1rem; border-radius: 12px;}
    </style>
    """,
    unsafe_allow_html=True,
)


def read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path, keep_default_na=False)
    except (OSError, UnicodeError, pd.errors.ParserError) as exc:
        st.warning(f"Could not read {path.relative_to(ROOT)}: {exc}")
        return pd.DataFrame()


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8") if path.exists() else ""
    except (OSError, UnicodeError):
        return ""


def parse_coverage(markdown: str) -> pd.DataFrame:
    rows: list[dict[str, str]] = []
    for line in markdown.splitlines():
        if not line.startswith("| [T"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 6:
            continue
        first = re.match(r"\[([^]]+)\]", cells[0])
        label = first.group(1) if first else cells[0]
        match = re.match(r"(T\d{4}(?:\.\d{3})?)\s*-\s*(.+)", label)
        if not match:
            continue
        rows.append(
            {
                "Technique ID": match.group(1),
                "Technique": match.group(2),
                "ATT&CK version": cells[1],
                "Tactics": cells[2],
                "Coverage": cells[3],
                "Rules": cells[4],
                "Severity": cells[5],
            }
        )
    return pd.DataFrame(rows)


def parse_metadata(markdown: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in markdown.splitlines():
        match = re.match(r"\|\s*([^|]+?)\s*\|\s*(.*?)\s*\|\s*$", line)
        if match and match.group(1).strip().lower() not in {"field", "---"}:
            key, value = match.group(1).strip(), match.group(2).strip()
            value = re.sub(r"`([^`]*)`", r"\1", value)
            value = re.sub(r"\*\*(.*?)\*\*", r"\1", value)
            result[key] = value
    return result


def extract_section(markdown: str, heading: str, max_chars: int = 850) -> str:
    lines = markdown.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(rf"^##\s+.*{re.escape(heading)}", line, flags=re.I):
            start = i + 1
            break
    if start is None:
        return ""
    collected: list[str] = []
    for line in lines[start:]:
        if line.startswith("## "):
            break
        if line.strip():
            cleaned = re.sub(r"`([^`]*)`", r"\1", line.strip())
            cleaned = re.sub(r"\*\*(.*?)\*\*", r"\1", cleaned)
            cleaned = re.sub(r"[*_#]", "", cleaned)
            collected.append(cleaned)
    return " ".join(collected)[:max_chars]


@st.cache_data(show_spinner=False)
def load_data() -> dict[str, Any]:
    test = read_csv(TEST_RESULTS)
    tuning = read_csv(TUNING_RESULTS)
    matrix = parse_coverage(read_text(COVERAGE_MATRIX))
    iocs = read_csv(IOC_FILE)

    if not test.empty:
        for col in ["matches", "benign_matches", "declared_negatives"]:
            if col in test:
                test[col] = pd.to_numeric(test[col], errors="coerce").fillna(0).astype(int)
    if not tuning.empty:
        for col in ["before_matches", "before_benign", "before_attack", "after_matches", "after_benign", "after_attack"]:
            if col in tuning:
                tuning[col] = pd.to_numeric(tuning[col], errors="coerce").fillna(0).astype(int)
    return {"test": test, "tuning": tuning, "coverage": matrix, "iocs": iocs}


def show_missing(required: list[Path]) -> bool:
    missing = [str(path.relative_to(ROOT)) for path in required if not path.exists()]
    if missing:
        st.error("Some project outputs were not found. Run the dashboard from the project repository root or restore these files: " + ", ".join(missing))
        return True
    return False


data = load_data()
test_df: pd.DataFrame = data["test"]
tuning_df: pd.DataFrame = data["tuning"]
coverage_df: pd.DataFrame = data["coverage"]
ioc_df: pd.DataFrame = data["iocs"]

with st.sidebar:
    st.markdown("## 🛡️ ThreatShield")
    st.caption("Detection engineering workspace")
    page = st.radio(
        "Navigation",
        ["Overview", "ATT&CK Coverage", "Detection Rules", "Hunts & Incidents", "Tuning & IOCs", "About & Limitations"],
        label_visibility="collapsed",
    )
    st.divider()
    st.caption("Local, read-only dashboard · CDL-DET-V2")

st.markdown(
    '<div class="hero"><h1>Cyberion ThreatShield</h1>'
    '<div class="muted">Detection engineering · ATT&CK coverage · Threat hunting · Incident evidence</div></div>',
    unsafe_allow_html=True,
)

if page == "Overview":
    if show_missing([TEST_RESULTS, COVERAGE_MATRIX]):
        st.stop()
    rules_total = len(test_df)
    validated = 0
    if not test_df.empty and {"sigma_check", "status"}.issubset(test_df.columns):
        validated = int(((test_df["sigma_check"].str.upper() == "PASS") & (test_df["status"].str.upper() == "PASS")).sum())
    matched = int((test_df["matches"] > 0).sum()) if "matches" in test_df else 0
    cov_counts = coverage_df["Coverage"].value_counts() if not coverage_df.empty else pd.Series(dtype=int)
    covered = int(cov_counts.get("Covered", 0))
    partial = int(cov_counts.get("Partially Covered", 0))
    not_covered = int(cov_counts.get("Not Covered", 0))
    hunts_count = len(list(HUNTS_DIR.glob("HUNT-*.md"))) if HUNTS_DIR.exists() else 0
    incidents_count = len(list(INCIDENTS_DIR.glob("INC-*.md"))) if INCIDENTS_DIR.exists() else 0

    a, b, c, d = st.columns(4)
    a.metric("Detection rules", rules_total, help="Rows in detections/test-results.csv")
    b.metric("Rules passing checks", f"{validated}/{rules_total}", help="Both Sigma validation and project test status are PASS")
    c.metric("Rules with matches", f"{matched}/{rules_total}", help="At least one match in the current test-results.csv; not a measure of production effectiveness")
    d.metric("ATT&CK techniques", len(coverage_df))

    st.subheader("Coverage posture")
    left, right = st.columns([1, 1.2])
    with left:
        if not coverage_df.empty:
            order = ["Covered", "Partially Covered", "Not Covered"]
            counts = coverage_df["Coverage"].value_counts().reindex(order, fill_value=0).rename_axis("Status").reset_index(name="Techniques")
            fig = px.bar(counts, x="Status", y="Techniques", color="Status", text="Techniques", title="ATT&CK coverage by status")
            fig.update_layout(showlegend=False, margin=dict(l=10, r=10, t=55, b=10), height=330)
            st.plotly_chart(fig, width="stretch")
    with right:
        st.markdown("#### Coverage summary")
        c1, c2, c3 = st.columns(3)
        c1.metric("Covered", covered)
        c2.metric("Partial", partial)
        c3.metric("Not covered", not_covered)
        st.info("Coverage labels are taken from the tested coverage matrix. A rule passing validation does not by itself prove that an ATT&CK technique is fully covered.")
        st.markdown(f"**Hunts:** {hunts_count} · **Incident reports:** {incidents_count} · **Tuning cases:** {len(tuning_df)} · **IOC records:** {len(ioc_df)}")

    st.subheader("Detection validation snapshot")
    if not test_df.empty:
        counts = test_df.groupby(["sigma_check", "status"], dropna=False).size().reset_index(name="Rules")
        st.dataframe(counts, width="stretch", hide_index=True)
        display_cols = [c for c in ["title", "level", "sigma_check", "status", "matches", "benign_matches", "notes"] if c in test_df]
        st.dataframe(test_df[display_cols], width="stretch", hide_index=True)

elif page == "ATT&CK Coverage":
    if show_missing([COVERAGE_MATRIX]):
        st.stop()
    st.subheader("MITRE ATT&CK coverage matrix")
    st.caption("Source: coverage/matrix-v2.md. Tactics are taxonomy labels; coverage is based on the project's documented test contract.")
    if coverage_df.empty:
        st.warning("No technique rows could be parsed from coverage/matrix-v2.md.")
    else:
        statuses = [s for s in ["Covered", "Partially Covered", "Not Covered"] if s in coverage_df["Coverage"].unique()]
        selected_status = st.multiselect("Filter by coverage", statuses, default=statuses)
        tactic_options = sorted({t.strip() for item in coverage_df["Tactics"] for t in item.split(",") if t.strip()})
        selected_tactics = st.multiselect("Filter by tactic", tactic_options)
        view = coverage_df[coverage_df["Coverage"].isin(selected_status)].copy()
        if selected_tactics:
            view = view[view["Tactics"].apply(lambda x: any(t in [v.strip() for v in x.split(",")] for t in selected_tactics))]
        counts = coverage_df["Coverage"].value_counts().rename_axis("Coverage").reset_index(name="Technique count")
        st.plotly_chart(px.pie(counts, names="Coverage", values="Technique count", hole=0.55, title="Technique coverage distribution"), width="stretch")
        st.dataframe(view, width="stretch", hide_index=True)
        st.download_button("Download filtered coverage CSV", view.to_csv(index=False).encode("utf-8"), "threatshield-coverage.csv", "text/csv")

elif page == "Detection Rules":
    if show_missing([TEST_RESULTS]):
        st.stop()
    st.subheader("Detection rule test results")
    st.caption("Evidence identifiers are intentionally omitted from the dashboard table to reduce accidental disclosure of local telemetry references.")
    if test_df.empty:
        st.warning("No detection test results were loaded.")
    else:
        filtered = test_df.copy()
        levels = sorted(filtered["level"].dropna().astype(str).unique()) if "level" in filtered else []
        selected_levels = st.multiselect("Severity", levels, default=levels)
        selected_statuses = st.multiselect("Test status", sorted(filtered["status"].astype(str).unique()), default=sorted(filtered["status"].astype(str).unique())) if "status" in filtered else []
        if "level" in filtered:
            filtered = filtered[filtered["level"].isin(selected_levels)]
        if "status" in filtered:
            filtered = filtered[filtered["status"].isin(selected_statuses)]
        search = st.text_input("Search rule title, technique or file")
        if search:
            mask = pd.Series(False, index=filtered.index)
            for col in ["title", "techniques", "rule_file"]:
                if col in filtered:
                    mask |= filtered[col].astype(str).str.contains(search, case=False, na=False)
            filtered = filtered[mask]
        cols = [c for c in ["title", "rule_file", "techniques", "level", "datasets", "sigma_check", "status", "matches", "expected_hits", "benign_matches", "declared_negatives", "negatives_held", "notes"] if c in filtered]
        st.dataframe(filtered[cols], width="stretch", hide_index=True)
        st.download_button("Download filtered rule results CSV", filtered[cols].to_csv(index=False).encode("utf-8"), "threatshield-rule-results-sanitized.csv", "text/csv")
        st.caption("Interpretation: 'PASS' means the recorded automated check passed. Positive matches and benign comparisons are separate evidence dimensions.")

elif page == "Hunts & Incidents":
    st.subheader("Threat hunts")
    hunt_files = sorted(HUNTS_DIR.glob("HUNT-*.md")) if HUNTS_DIR.exists() else []
    if not hunt_files:
        st.info("No hunt reports found.")
    for path in hunt_files:
        content = read_text(path)
        title = content.splitlines()[0].lstrip("# ") if content else path.stem
        with st.expander(title, expanded=False):
            first_lines = "\n".join(content.splitlines()[:14])
            st.markdown(first_lines)
            conclusion = extract_section(content, "Conclusion")
            if conclusion:
                st.markdown("**Conclusion excerpt**")
                st.write(conclusion)
            st.caption(f"Source file: {path.relative_to(ROOT)}")

    st.subheader("Incident cases")
    incident_files = sorted(INCIDENTS_DIR.glob("INC-*.md")) if INCIDENTS_DIR.exists() else []
    records = []
    for path in incident_files:
        content = read_text(path)
        meta = parse_metadata(content)
        title = content.splitlines()[0].lstrip("# ") if content else path.stem
        records.append({
            "Case": meta.get("Case ID", path.stem),
            "Incident": title,
            "Classification": meta.get("Closure classification", "Not specified"),
            "Techniques": meta.get("Techniques involved", "Not specified"),
            "Corroboration": meta.get("Corroboration", "Not specified"),
            "Source file": str(path.relative_to(ROOT)),
        })
    if records:
        st.dataframe(pd.DataFrame(records), width="stretch", hide_index=True)
        st.caption("Hostnames and account identifiers from the source case files are not shown in this summary view.")

elif page == "Tuning & IOCs":
    st.subheader("Rule tuning")
    if tuning_df.empty:
        st.info("No tuning-results.csv was found.")
    else:
        display_cols = [c for c in ["id", "title", "before_matches", "before_benign", "before_attack", "after_matches", "after_benign", "after_attack", "known_benign_suppressed", "known_benign_remaining", "attack_matches_lost", "status"] if c in tuning_df]
        st.dataframe(tuning_df[display_cols], width="stretch", hide_index=True)
        st.caption("Tuning counts are from the documented tuning cases; they are not a global false-positive rate.")

    st.subheader("IOC inventory summary")
    if ioc_df.empty:
        st.info("No IOC watchlist was found.")
    else:
        c1, c2, c3 = st.columns(3)
        c1.metric("IOC records", len(ioc_df))
        c2.metric("Indicator types", ioc_df["type"].nunique() if "type" in ioc_df else "—")
        c3.metric("Confidence labels", ioc_df["confidence"].nunique() if "confidence" in ioc_df else "—")
        if "type" in ioc_df:
            type_counts = ioc_df["type"].value_counts().rename_axis("Indicator type").reset_index(name="Count")
            st.plotly_chart(px.bar(type_counts, x="Indicator type", y="Count", title="IOC records by type", text="Count"), width="stretch")
        if "confidence" in ioc_df:
            confidence_counts = ioc_df["confidence"].value_counts().rename_axis("Confidence").reset_index(name="Count")
            st.dataframe(confidence_counts, width="stretch", hide_index=True)
        st.warning("Indicator values are deliberately not displayed or exported here. Review the original watchlist locally and sanitize lab-specific indicators before any public release.")

else:
    st.subheader("About this dashboard")
    st.markdown(
        """
        This is an **optional, local, read-only visualization layer** for the Cyberion ThreatShield detection-engineering project.

        **Data sources**
        - `detections/test-results.csv`
        - `detections/tuning-results.csv`
        - `coverage/matrix-v2.md`
        - `hunts/HUNT-*.md`
        - `incidents/INC-*.md`
        - `ioc/watchlist.csv` (aggregate counts only)

        **Not a live SIEM:** the dashboard does not ingest streaming telemetry, execute detections, contain endpoints, or block indicators. It summarizes existing project artefacts.

        **Important limitations**
        - ATT&CK coverage remains 1 Covered, 12 Partially Covered and 8 Not Covered in the current matrix.
        - `HUNT-002` remains inconclusive.
        - Rule validation, evidence matching, and benign testing are separate measures.
        - No global false-positive rate is inferred from the limited tuning cases.
        - The source reports and raw telemetry may contain lab-specific identifiers. Do not publish them without review and sanitization.
        """
    )
    st.markdown("**Launch command**")
    st.code(r".\.venv\Scripts\python.exe -m streamlit run dashboard\app.py", language="powershell")
    st.markdown("**Refresh data:** use the project's existing scripts to regenerate source outputs, then use the dashboard's Refresh button or restart the app.")
    if st.button("Refresh dashboard data"):
        st.cache_data.clear()
        st.rerun()

st.caption("Cyberion ThreatShield · Local evidence summary · No live monitoring or automated response")
