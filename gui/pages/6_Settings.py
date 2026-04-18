from pathlib import Path
import sys

import streamlit as st

st.set_page_config(page_title="Settings", page_icon="⚙️", layout="wide")

GUI_DIR = Path(__file__).resolve().parents[1]
if str(GUI_DIR) not in sys.path:
    sys.path.append(str(GUI_DIR))

from services.nav import render_sidebar
from services.config_service import get_basic_health_summary, get_path_status_df
from services.action_service import inspect_input_queue, get_latest_output_summary

render_sidebar()

st.title("Collector Settings")
st.caption("Collector-side system status, path visibility, incoming queue health, and latest output state.")

top_bar = st.container(border=True)
with top_bar:
    left, right = st.columns([1, 4])

    with left:
        if st.button("Refresh", use_container_width=True):
            st.rerun()

    with right:
        st.info(
            "Use this page to inspect collector paths, queue status, and latest output health. "
            "This page is intentionally limited and mostly read-only.",
            icon="ℹ️",
        )

health = get_basic_health_summary()
queue_info = inspect_input_queue()
latest_output = get_latest_output_summary()
path_df = get_path_status_df()

overview_box = st.container(border=True)
with overview_box:
    st.subheader("Overview")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Input Root", "OK" if health["collector_input_root_exists"] else "Missing")
    c2.metric("Incoming Dir", "OK" if health["collector_incoming_exists"] else "Missing")
    c3.metric("Output Dir", "OK" if health["collector_output_exists"] else "Missing")
    c4.metric("Kuzu DB", "Present" if health["kuzu_db_exists"] else "Missing")
    c5.metric("Pending Files", queue_info["total_files"])

main_left, main_right = st.columns([1.3, 1])

with main_left:
    paths_box = st.container(border=True)
    with paths_box:
        st.subheader("System Paths")
        if path_df.empty:
            st.info("No path status information available.")
        else:
            st.dataframe(path_df, use_container_width=True, hide_index=True)

    queue_box = st.container(border=True)
    with queue_box:
        st.subheader("Incoming Queue Status")

        if not queue_info["exists"]:
            st.warning(f"Incoming directory not found: {queue_info['input_dir']}")
        else:
            st.markdown(f"**Incoming directory**  \n`{queue_info['input_dir']}`")

            files_df = queue_info.get("files_df")
            if files_df is not None and not files_df.empty:
                st.dataframe(files_df, use_container_width=True, hide_index=True)
            else:
                st.info("No files currently in collector input/incoming.")

with main_right:
    output_box = st.container(border=True)
    with output_box:
        st.subheader("Latest Output Status")

        st.markdown(f"**Latest batch ID**  \n`{latest_output.get('batch_id') or 'N/A'}`")
        st.markdown(f"**Consolidated dataset**  \n`{latest_output.get('consolidated_path') or 'Not found'}`")
        st.markdown(f"**Findings dataset**  \n`{latest_output.get('findings_path') or 'Not found'}`")
        st.markdown(f"**Assessment summary**  \n`{latest_output.get('assessment_summary_path') or 'Not found'}`")

        st.divider()

        m1, m2 = st.columns(2)
        m3, m4 = st.columns(2)
        m1.metric(
            "Total Hosts",
            latest_output.get("total_hosts") if latest_output.get("total_hosts") is not None else "N/A",
        )
        m2.metric(
            "Total Findings",
            latest_output.get("total_findings") if latest_output.get("total_findings") is not None else "N/A",
        )
        m3.metric("Loaded Findings Rows", latest_output.get("findings_rows", 0))
        m4.metric("Graph Persistence", latest_output.get("graph_persistence_status") or "N/A")

        severity_counts = latest_output.get("severity_counts", {})
        if severity_counts:
            st.markdown("#### Severity Counts")
            s1, s2 = st.columns(2)
            s3, s4 = st.columns(2)
            s1.metric("Critical", severity_counts.get("critical", 0))
            s2.metric("High", severity_counts.get("high", 0))
            s3.metric("Medium", severity_counts.get("medium", 0))
            s4.metric("Low", severity_counts.get("low", 0))

        graph_persistence = latest_output.get("graph_persistence", {})
        if isinstance(graph_persistence, dict):
            error = graph_persistence.get("error", "")
            if error:
                with st.expander("Graph persistence details"):
                    st.code(str(error))