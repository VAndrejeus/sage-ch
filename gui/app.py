from pathlib import Path
import sys

import streamlit as st

st.set_page_config(
    page_title="SAGE-CH",
    page_icon="🛡️",
    layout="wide",
)

GUI_DIR = Path(__file__).resolve().parent
if str(GUI_DIR) not in sys.path:
    sys.path.append(str(GUI_DIR))

from services.nav import render_sidebar
from services.data_loader import (
    get_graph_db_path,
    load_graph_counts_from_consolidated,
    load_hosts_df_from_consolidated,
    load_latest_assessment_summary_payload,
    load_latest_findings_df,
)
from services.metrics import build_dashboard_metrics


def _is_graph_persistence_success(status: str | None) -> bool:
    if not status:
        return False
    return str(status).strip().lower() in {"ok", "complete", "completed", "success"}


render_sidebar()

st.title("SAGE-CH Security Console")
st.caption("Security Assessment using Graph-based Evaluation for Cyber Hygiene")

st.markdown(
    "Operational console for cyber hygiene assessment combining endpoint data, "
    "network discovery, knowledge graph analysis, CIS Controls mapping, "
    "and AI-assisted remediation insights."
)

top_bar = st.container(border=True)
with top_bar:
    left, right = st.columns([1, 4])

    with left:
        if st.button("Refresh", use_container_width=True):
            st.rerun()

    with right:
        st.info(
            "Use the sidebar to navigate across dashboards, graph views, batch artifacts, "
            "collector settings, and collector actions.",
            icon="ℹ️",
        )

hosts_df, hosts_path = load_hosts_df_from_consolidated()
findings_df, findings_path = load_latest_findings_df()
assessment_summary, summary_path = load_latest_assessment_summary_payload()
graph_counts, graph_path = load_graph_counts_from_consolidated()

metrics = build_dashboard_metrics(hosts_df, findings_df, assessment_summary)
graph_persistence_status = graph_counts.get("graph_persistence_status", "unknown")

overview_box = st.container(border=True)
with overview_box:
    st.subheader("Overview")

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Hosts", metrics["total_hosts"])
    m2.metric("Managed Hosts", metrics["managed_hosts"])
    m3.metric("Discovered Hosts", metrics["discovered_hosts"])
    m4.metric("Total Findings", metrics["total_findings"])
    m5.metric("Graph Persistence", graph_persistence_status)

    if not _is_graph_persistence_success(graph_persistence_status):
        st.warning("Graph persistence is not currently marked successful. Some views may fall back to output JSON instead of Kuzu.")
    else:
        st.success("Graph persistence is available for the current batch.")

main_left, main_right = st.columns([1.1, 1])

with main_left:
    intro_box = st.container(border=True)
    with intro_box:
        st.subheader("Platform Summary")
        st.write(
            "SAGE-CH provides an operational interface for cyber hygiene assessment across "
            "endpoint telemetry, discovery-driven visibility, graph relationships, findings analysis, "
            "and AI-assisted remediation."
        )

        st.markdown("#### Core Areas")
        st.write("- Dashboard for overall status and findings")
        st.write("- Hosts for system-level inspection")
        st.write("- Findings for filterable issue review")
        st.write("- Graph for Kuzu-backed graph exploration")
        st.write("- Batches for recent artifacts and outputs")
        st.write("- Settings and Actions for collector operations")

with main_right:
    sources_box = st.container(border=True)
    with sources_box:
        st.subheader("Data Sources")
        st.markdown(f"**Hosts source**  \n`{hosts_path if hosts_path else 'Not found'}`")
        st.markdown(f"**Findings source**  \n`{findings_path if findings_path else 'Not found'}`")
        st.markdown(f"**Assessment summary**  \n`{summary_path if summary_path else 'Not found'}`")
        st.markdown(f"**Graph source**  \n`{graph_path if graph_path else 'Not found'}`")
        st.markdown(f"**Kuzu DB path**  \n`{get_graph_db_path()}`")