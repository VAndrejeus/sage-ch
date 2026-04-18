from pathlib import Path
import sys

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Dashboard", page_icon="📊", layout="wide")

GUI_DIR = Path(__file__).resolve().parents[1]
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
from services.kuzu_service import get_kuzu_graph_counts
from services.metrics import build_dashboard_metrics

render_sidebar()

st.title("Dashboard")
st.caption("High-level operational view of hosts, findings, graph state, and latest generated artifacts.")

top_bar = st.container(border=True)
with top_bar:
    left, right = st.columns([1, 4])

    with left:
        if st.button("Refresh", use_container_width=True):
            st.rerun()

    with right:
        st.info(
            "This dashboard combines collector outputs with Kuzu graph data when available.",
            icon="ℹ️",
        )

hosts_df, hosts_path = load_hosts_df_from_consolidated()
findings_df, findings_path = load_latest_findings_df()
assessment_summary, summary_path = load_latest_assessment_summary_payload()
json_graph_counts, graph_path = load_graph_counts_from_consolidated()
kuzu_counts = get_kuzu_graph_counts(get_graph_db_path())

graph_counts = kuzu_counts if kuzu_counts.get("ok") else json_graph_counts
graph_source = "Kuzu" if kuzu_counts.get("ok") else "Consolidated JSON"
metrics = build_dashboard_metrics(hosts_df, findings_df, assessment_summary)

overview_box = st.container(border=True)
with overview_box:
    st.subheader("Overview")

    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Total Hosts", metrics["total_hosts"])
    m2.metric("Managed", metrics["managed_hosts"])
    m3.metric("Discovered", metrics["discovered_hosts"])
    m4.metric("Total Findings", metrics["total_findings"])
    m5.metric("Exposed Services", graph_counts.get("edge_counts", {}).get("EXPOSES_SERVICE", 0))
    m6.metric("Latest Batch ID", metrics["latest_batch_id"] or "N/A")

    st.markdown("#### Findings by Severity")
    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Critical", metrics["severity_counts"].get("critical", 0))
    s2.metric("High", metrics["severity_counts"].get("high", 0))
    s3.metric("Medium", metrics["severity_counts"].get("medium", 0))
    s4.metric("Low", metrics["severity_counts"].get("low", 0))

main_left, main_mid, main_right = st.columns([1.2, 1, 0.9])

with main_left:
    hosts_box = st.container(border=True)
    with hosts_box:
        st.subheader("Hosts")

        if hosts_df.empty:
            st.warning("No managed host records found in consolidated dataset.")
        else:
            preview_cols = [c for c in ["hostname", "ip", "platform", "software_count"] if c in hosts_df.columns]
            st.dataframe(hosts_df[preview_cols], use_container_width=True, hide_index=True)

    findings_box = st.container(border=True)
    with findings_box:
        st.subheader("Recent Findings Snapshot")

        if findings_df.empty:
            st.info("No findings dataset available.")
        else:
            preview_cols = [
                c for c in ["finding_id", "hostname", "title", "severity", "category", "status"]
                if c in findings_df.columns
            ]
            st.dataframe(findings_df[preview_cols].head(15), use_container_width=True, hide_index=True)

with main_mid:
    graph_box = st.container(border=True)
    with graph_box:
        st.subheader("Graph")

        g1, g2 = st.columns(2)
        g1.metric("Source", graph_source)
        g2.metric("Persistence", json_graph_counts.get("graph_persistence_status", "N/A"))

        st.markdown("#### Node Counts")
        node_counts = graph_counts.get("node_counts", {})
        if node_counts:
            node_df = pd.DataFrame(
                [{"node_type": key, "count": value} for key, value in sorted(node_counts.items())]
            )
            st.dataframe(node_df, use_container_width=True, hide_index=True)
        else:
            st.info("No node counts available.")

        st.markdown("#### Edge Counts")
        edge_counts = graph_counts.get("edge_counts", {})
        if edge_counts:
            edge_df = pd.DataFrame(
                [{"edge_type": key, "count": value} for key, value in sorted(edge_counts.items())]
            )
            st.dataframe(edge_df, use_container_width=True, hide_index=True)
        else:
            st.info("No edge counts available.")

with main_right:
    latest_box = st.container(border=True)
    with latest_box:
        st.subheader("Latest Output Summary")

        st.markdown(f"**Hosts source**  \n`{hosts_path if hosts_path else 'Not found'}`")
        st.markdown(f"**Findings source**  \n`{findings_path if findings_path else 'Not found'}`")
        st.markdown(f"**Assessment summary**  \n`{summary_path if summary_path else 'Not found'}`")
        st.markdown(f"**Graph JSON source**  \n`{graph_path if graph_path else 'Not found'}`")
        st.markdown(f"**Kuzu DB path**  \n`{get_graph_db_path()}`")

        if assessment_summary:
            st.divider()
            st.write(f"**Total hosts:** `{assessment_summary.get('total_hosts', 'N/A')}`")
            st.write(f"**Total findings:** `{assessment_summary.get('total_findings', 'N/A')}`")
            st.write(f"**Affected hosts:** `{assessment_summary.get('affected_hosts', 'N/A')}`")

        graph_persistence = json_graph_counts.get("graph_persistence", {})
        if isinstance(graph_persistence, dict):
            error = graph_persistence.get("error", "")
            if error:
                with st.expander("Graph persistence details"):
                    st.code(str(error))