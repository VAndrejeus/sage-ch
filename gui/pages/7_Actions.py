from pathlib import Path
import sys

import streamlit as st

st.set_page_config(page_title="Actions", page_icon="▶️", layout="wide")

GUI_DIR = Path(__file__).resolve().parents[1]
if str(GUI_DIR) not in sys.path:
    sys.path.append(str(GUI_DIR))

from services.nav import render_sidebar
from services.action_service import (
    get_latest_output_summary,
    get_recent_output_files_df,
    inspect_input_queue,
    run_collector,
)

render_sidebar()

st.title("Collector Actions")
st.caption("Operate the collector, inspect the incoming queue, and review the latest generated outputs.")

if "collector_run_result" not in st.session_state:
    st.session_state["collector_run_result"] = None

if "show_run_collector_confirm" not in st.session_state:
    st.session_state["show_run_collector_confirm"] = False


@st.dialog("Confirm collector run", width="small")
def confirm_run_collector_dialog() -> None:
    st.warning(
        "This will run the collector pipeline against the current contents of collector/input/incoming.",
        icon="⚠️",
    )
    st.write("Continue only if you are ready to process the queued files.")

    c1, c2 = st.columns(2)

    with c1:
        if st.button("Cancel", use_container_width=True, key="cancel_run_collector"):
            st.session_state["show_run_collector_confirm"] = False
            st.rerun()

    with c2:
        if st.button("Confirm Run", type="primary", use_container_width=True, key="confirm_run_collector"):
            with st.spinner("Running collector..."):
                st.session_state["collector_run_result"] = run_collector()
            st.session_state["show_run_collector_confirm"] = False
            st.rerun()


top_actions = st.container(border=True)
with top_actions:
    left, mid, right = st.columns([1, 1, 4])

    with left:
        if st.button("Run Collector", type="primary", use_container_width=True):
            st.session_state["show_run_collector_confirm"] = True

    with mid:
        if st.button("Refresh", use_container_width=True):
            st.rerun()

    with right:
        st.info("Use Refresh after adding files to input/incoming or after a collector run.", icon="ℹ️")

if st.session_state.get("show_run_collector_confirm"):
    confirm_run_collector_dialog()

queue_info = inspect_input_queue()
latest_output = get_latest_output_summary()
recent_outputs_df = get_recent_output_files_df()
run_result = st.session_state.get("collector_run_result")

metrics_box = st.container(border=True)
with metrics_box:
    st.subheader("Overview")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Pending Input Files", queue_info["total_files"])
    m2.metric("Latest Batch", latest_output.get("batch_id") or "N/A")
    m3.metric(
        "Latest Findings",
        latest_output.get("total_findings") if latest_output.get("total_findings") is not None else "N/A",
    )
    m4.metric("Graph Persistence", latest_output.get("graph_persistence_status") or "N/A")

if run_result:
    run_box = st.container(border=True)
    with run_box:
        st.subheader("Collector Run Result")

        if run_result.get("ok"):
            st.success("Collector completed successfully.", icon="✅")
        else:
            st.error("Collector run failed.", icon="🚨")

        c1, c2, c3 = st.columns([1, 2, 2])
        c1.metric("Return Code", run_result.get("returncode") if run_result.get("returncode") is not None else "N/A")
        c2.markdown(f"**Command**  \n`{run_result.get('cmd', '')}`")
        c3.markdown(f"**Working Directory**  \n`{run_result.get('cwd', '')}`")

        latest_after_run = get_latest_output_summary()

        st.markdown("#### Post-Run Summary")
        l1, l2, l3, l4 = st.columns(4)
        l1.metric("Batch ID", latest_after_run.get("batch_id") or "N/A")
        l2.metric("Total Hosts", latest_after_run.get("total_hosts") if latest_after_run.get("total_hosts") is not None else "N/A")
        l3.metric("Total Findings", latest_after_run.get("total_findings") if latest_after_run.get("total_findings") is not None else "N/A")
        l4.metric("Graph Persistence", latest_after_run.get("graph_persistence_status") or "N/A")

        stdout = run_result.get("stdout", "")
        stderr = run_result.get("stderr", "")

        output_tab, error_tab = st.tabs(["stdout", "stderr"])
        with output_tab:
            if stdout:
                st.code(stdout)
            else:
                st.info("No stdout captured.")
        with error_tab:
            if stderr:
                st.code(stderr)
            else:
                st.info("No stderr captured.")

main_left, main_right = st.columns([1.3, 1])

with main_left:
    queue_box = st.container(border=True)
    with queue_box:
        st.subheader("Incoming Queue")

        if not queue_info["exists"]:
            st.warning(f"Incoming directory not found: {queue_info['input_dir']}")
        else:
            st.markdown(f"**Directory**  \n`{queue_info['input_dir']}`")

            files_df = queue_info.get("files_df")
            if files_df is not None and not files_df.empty:
                st.dataframe(files_df, use_container_width=True, hide_index=True)
            else:
                st.info("No files are currently waiting in collector input/incoming.")

    outputs_box = st.container(border=True)
    with outputs_box:
        st.subheader("Recent Output Files")

        if recent_outputs_df.empty:
            st.info("No output files found.")
        else:
            st.dataframe(recent_outputs_df, use_container_width=True, hide_index=True)

with main_right:
    latest_box = st.container(border=True)
    with latest_box:
        st.subheader("Latest Output Summary")

        st.markdown(f"**Consolidated dataset**  \n`{latest_output.get('consolidated_path') or 'Not found'}`")
        st.markdown(f"**Findings dataset**  \n`{latest_output.get('findings_path') or 'Not found'}`")
        st.markdown(f"**Assessment summary**  \n`{latest_output.get('assessment_summary_path') or 'Not found'}`")

        st.divider()

        st.write(f"**Batch ID:** `{latest_output.get('batch_id') or 'N/A'}`")
        st.write(f"**Total hosts:** `{latest_output.get('total_hosts') if latest_output.get('total_hosts') is not None else 'N/A'}`")
        st.write(f"**Total findings:** `{latest_output.get('total_findings') if latest_output.get('total_findings') is not None else 'N/A'}`")
        st.write(f"**Graph persistence:** `{latest_output.get('graph_persistence_status') or 'N/A'}`")

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