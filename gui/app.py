from pathlib import Path
import sys

import streamlit as st

GUI_DIR = Path(__file__).resolve().parent
if str(GUI_DIR) not in sys.path:
    sys.path.append(str(GUI_DIR))

from services.nav import get_logo_path, render_sidebar
from services.data_loader import (
    get_graph_db_path,
    load_graph_counts_from_consolidated,
    load_hosts_df_from_consolidated,
    load_latest_assessment_summary_payload,
    load_latest_findings_df,
)
from services.metrics import build_dashboard_metrics


logo_path = get_logo_path()

st.set_page_config(
    page_title="SAGE-CH",
    page_icon=str(logo_path) if logo_path.exists() else None,
    layout="wide",
)

render_sidebar()

hosts_df, hosts_path = load_hosts_df_from_consolidated()
findings_df, findings_path = load_latest_findings_df()
assessment_summary, summary_path = load_latest_assessment_summary_payload()
graph_counts, graph_path = load_graph_counts_from_consolidated()
metrics = build_dashboard_metrics(hosts_df, findings_df, assessment_summary)
vulnerability_df = (
    findings_df[findings_df["finding_type"] == "Vulnerability"].copy()
    if not findings_df.empty and "finding_type" in findings_df.columns
    else findings_df.iloc[0:0].copy()
)
cis_findings_df = (
    findings_df[findings_df["finding_type"] != "Vulnerability"].copy()
    if not findings_df.empty and "finding_type" in findings_df.columns
    else findings_df.copy()
)

graph_persistence_status = graph_counts.get("graph_persistence_status", "unknown")
batch_id = assessment_summary.get("batch_id", "N/A") if assessment_summary else "N/A"

hero = st.container(border=True)
with hero:
    left, right = st.columns([1, 4])
    with left:
        if logo_path.exists():
            st.image(str(logo_path), use_container_width=True)
    with right:
        st.title("SAGE-CH Security Console")
        st.caption("Security Assessment using Graph-based Evaluation for Cyber Hygiene")
        st.write(
            "A Streamlit console for endpoint telemetry, CIS-aligned findings, CVE correlation, "
            "graph analysis, and AI-assisted remediation."
        )

overview = st.container(border=True)
with overview:
    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Hosts", metrics["total_hosts"])
    m2.metric("CIS Findings", len(cis_findings_df))
    m3.metric(
        "CIS Critical",
        int((cis_findings_df["severity"].astype(str).str.lower() == "critical").sum())
        if not cis_findings_df.empty and "severity" in cis_findings_df.columns
        else 0,
    )
    m4.metric("Graph", graph_persistence_status)
    m5.metric("CVE Findings", len(vulnerability_df))
    m6.metric("Batch", batch_id)

main_left, main_right = st.columns([1, 1])

with main_left:
    workflow = st.container(border=True)
    with workflow:
        st.subheader("Primary Workflow")
        st.write("1. Run collector from Actions.")
        st.write("2. Confirm status in Pipeline Health.")
        st.write("3. Review CIS findings and CVE findings on Dashboard.")
        st.write("4. Inspect hosts, findings, controls, and graph relationships.")

with main_right:
    health = st.container(border=True)
    with health:
        st.subheader("Data Sources")
        st.write(f"Hosts: `{hosts_path.name if hosts_path else 'Not found'}`")
        st.write(f"CIS findings: `{findings_path.name if findings_path else 'Not found'}`")
        st.write(f"Summary: `{summary_path.name if summary_path else 'Not found'}`")
        st.write(f"Graph: `{graph_path.name if graph_path else 'Not found'}`")

with st.expander("Full Artifact Paths"):
    st.markdown(f"**Hosts source:** `{hosts_path if hosts_path else 'Not found'}`")
    st.markdown(f"**Findings source:** `{findings_path if findings_path else 'Not found'}`")
    st.markdown(f"**Assessment summary:** `{summary_path if summary_path else 'Not found'}`")
    st.markdown(f"**Graph source:** `{graph_path if graph_path else 'Not found'}`")
    st.markdown(f"**Kuzu DB:** `{get_graph_db_path()}`")
