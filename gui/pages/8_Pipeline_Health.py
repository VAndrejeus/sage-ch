from pathlib import Path
import sys

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Pipeline Health", layout="wide")

GUI_DIR = Path(__file__).resolve().parents[1]
if str(GUI_DIR) not in sys.path:
    sys.path.append(str(GUI_DIR))

from services.nav import render_sidebar
from services.pipeline_health_service import get_latest_log_lines, get_pipeline_health_summary


render_sidebar()

st.title("Pipeline Health")
st.caption("Track collector state, graph persistence, AI enrichment, queues, and recent logs.")

top_bar = st.container(border=True)
with top_bar:
    left, right = st.columns([1, 4])
    with left:
        if st.button("Refresh", use_container_width=True):
            st.rerun()

health = get_pipeline_health_summary()
queue_info = health["queue_info"]

overview_box = st.container(border=True)
with overview_box:
    st.subheader("Current State")

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Latest Batch", health.get("batch_id") or "N/A")
    m2.metric("Collector", health.get("collector_status") or "unknown")
    m3.metric("Core Graph", health.get("core_graph_persistence_status") or "unknown")
    m4.metric("AI Enrichment", health.get("ai_enrichment_status") or "unknown")
    m5.metric("Kuzu", "ok" if health.get("kuzu_ok") else "unavailable")

    warnings = health.get("warnings", [])
    if warnings:
        for warning in warnings:
            st.warning(warning)
    else:
        st.success("No pipeline warnings detected.")

graph_box = st.container(border=True)
with graph_box:
    st.subheader("Graph Health")

    g1, g2, g3, g4 = st.columns(4)
    g1.metric("JSON Nodes", health["json_node_count"])
    g2.metric("JSON Edges", health["json_edge_count"])
    g3.metric("Kuzu Nodes", health["kuzu_node_count"])
    g4.metric("Kuzu Edges", health["kuzu_edge_count"])

    if health.get("kuzu_error"):
        with st.expander("Kuzu details"):
            st.code(str(health["kuzu_error"]))

queue_box = st.container(border=True)
with queue_box:
    st.subheader("Queues")

    q1, q2, q3, q4 = st.columns(4)
    q1.metric("Incoming Files", queue_info["incoming_count"])
    q2.metric("Processing Batches", queue_info["processing_count"])
    q3.metric("Processed Batches", queue_info["processed_batch_count"])
    q4.metric("Failed Batches", queue_info["failed_batch_count"])

    processing_df = queue_info.get("processing_df", pd.DataFrame())
    if processing_df is not None and not processing_df.empty:
        st.markdown("#### Batches In Processing")
        st.dataframe(processing_df, use_container_width=True, hide_index=True)

with st.expander("Latest Artifacts"):
    st.markdown(f"**Consolidated dataset**  \n`{health.get('consolidated_path') or 'Not found'}`")
    st.markdown(f"**Assessment summary**  \n`{health.get('assessment_path') or 'Not found'}`")
    st.markdown(f"**Graph JSON source**  \n`{health.get('graph_path') or 'Not found'}`")

log_lines, log_path = get_latest_log_lines(limit=100)
with st.expander("Latest Collector Log"):
    st.markdown(f"**Log source**  \n`{log_path if log_path else 'Not found'}`")
    if log_lines:
        st.code("\n".join(log_lines), language="text")
    else:
        st.info("No collector log lines available.")
