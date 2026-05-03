from pathlib import Path
import json
import subprocess
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

import streamlit as st

st.set_page_config(page_title="Actions", page_icon="▶️", layout="wide")

GUI_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]

if str(GUI_DIR) not in sys.path:
    sys.path.append(str(GUI_DIR))

from services.nav import render_sidebar
from services.action_service import (
    get_latest_output_summary,
    get_recent_output_files_df,
    inspect_input_queue,
    rebuild_kuzu_from_latest_consolidated,
    run_ai_enrichment,
    run_collector,
)

render_sidebar()

st.title("Collector Actions")
st.caption("Operate the collector, CVE pipeline, input queue, and generated outputs.")


def run_python_tool(script_path: Path) -> dict:
    if not script_path.exists():
        return {
            "ok": False,
            "returncode": None,
            "cmd": f"{sys.executable} {script_path}",
            "cwd": str(REPO_ROOT),
            "stdout": "",
            "stderr": f"Script not found: {script_path}",
        }

    cmd = [sys.executable, str(script_path)]

    try:
        completed = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=900,
        )

        return {
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "cmd": " ".join(cmd),
            "cwd": str(REPO_ROOT),
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "returncode": None,
            "cmd": " ".join(cmd),
            "cwd": str(REPO_ROOT),
            "stdout": exc.stdout or "",
            "stderr": "Command timed out.",
        }
    except Exception as exc:
        return {
            "ok": False,
            "returncode": None,
            "cmd": " ".join(cmd),
            "cwd": str(REPO_ROOT),
            "stdout": "",
            "stderr": str(exc),
        }


def safe_read_json(path: Path) -> dict:
    if not path.exists():
        return {}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def format_snapshot_time(value: str) -> str:
    if not value:
        return "Not found"

    try:
        clean_value = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_value)

        pacific = dt.astimezone(ZoneInfo("America/Los_Angeles"))
        eastern = dt.astimezone(ZoneInfo("America/New_York"))

        pacific_text = pacific.strftime("%b %d, %Y %I:%M %p PST")
        eastern_text = eastern.strftime("%I:%M %p EST")

        return f"{pacific_text} ({eastern_text})"
    except Exception:
        return value


def get_snapshot_generated_at(path: Path) -> str:
    data = safe_read_json(path)
    generated_at = data.get("generated_at", "")
    return format_snapshot_time(str(generated_at)) if generated_at else "Not found"


def run_create_software_snapshot() -> dict:
    return run_python_tool(REPO_ROOT / "tools" / "create_software_snapshot.py")


def run_update_cve_snapshot() -> dict:
    return run_python_tool(REPO_ROOT / "tools" / "update_cve_snapshot.py")


def run_correlate_cves_to_findings() -> dict:
    return run_python_tool(REPO_ROOT / "tools" / "correlate_cves_to_findings.py")


def run_full_cve_pipeline() -> dict:
    steps = [
        ("Create Software Snapshot", REPO_ROOT / "tools" / "create_software_snapshot.py"),
        ("Update CVE Snapshot", REPO_ROOT / "tools" / "update_cve_snapshot.py"),
        ("Generate CVE Findings", REPO_ROOT / "tools" / "correlate_cves_to_findings.py"),
    ]

    outputs = []
    overall_ok = True

    for label, script_path in steps:
        result = run_python_tool(script_path)
        result["step"] = label
        outputs.append(result)

        if not result.get("ok"):
            overall_ok = False
            break

    stdout = "\n\n".join(
        [
            f"===== {item.get('step')} =====\n{item.get('stdout', '')}"
            for item in outputs
        ]
    )

    stderr = "\n\n".join(
        [
            f"===== {item.get('step')} =====\n{item.get('stderr', '')}"
            for item in outputs
            if item.get("stderr")
        ]
    )

    return {
        "ok": overall_ok,
        "returncode": 0 if overall_ok else 1,
        "cmd": "Full CVE Pipeline",
        "cwd": str(REPO_ROOT),
        "stdout": stdout,
        "stderr": stderr,
        "steps": outputs,
    }


def path_status(path: Path) -> str:
    return str(path) if path.exists() else "Not found"


def display_action_result(title: str, result: dict) -> None:
    result_box = st.container(border=True)
    with result_box:
        st.subheader(title)

        if result.get("ok"):
            st.success("Action completed successfully.", icon="✅")
        else:
            st.error("Action failed.", icon="🚨")

        c1, c2, c3 = st.columns([1, 2, 2])
        c1.metric("Return Code", result.get("returncode") if result.get("returncode") is not None else "N/A")
        c2.markdown(f"**Command**  \n`{result.get('cmd', '')}`")
        c3.markdown(f"**Working Directory**  \n`{result.get('cwd', '')}`")

        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")

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


if "collector_run_result" not in st.session_state:
    st.session_state["collector_run_result"] = None

if "ai_enrichment_result" not in st.session_state:
    st.session_state["ai_enrichment_result"] = None

if "kuzu_rebuild_result" not in st.session_state:
    st.session_state["kuzu_rebuild_result"] = None

if "cve_action_result" not in st.session_state:
    st.session_state["cve_action_result"] = None

if "show_run_collector_confirm" not in st.session_state:
    st.session_state["show_run_collector_confirm"] = False

if "show_update_cve_confirm" not in st.session_state:
    st.session_state["show_update_cve_confirm"] = False

if "show_full_cve_confirm" not in st.session_state:
    st.session_state["show_full_cve_confirm"] = False


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


@st.dialog("Confirm CVE snapshot update", width="small")
def confirm_update_cve_dialog() -> None:
    st.warning(
        "This will query the NVD API and may take a few minutes because the updater uses rate limiting.",
        icon="⚠️",
    )
    st.write("Avoid running this repeatedly because NVD may return rate-limit errors.")

    c1, c2 = st.columns(2)

    with c1:
        if st.button("Cancel", use_container_width=True, key="cancel_update_cve"):
            st.session_state["show_update_cve_confirm"] = False
            st.rerun()

    with c2:
        if st.button("Confirm Update", type="primary", use_container_width=True, key="confirm_update_cve"):
            with st.spinner("Updating CVE snapshot from NVD..."):
                st.session_state["cve_action_result"] = run_update_cve_snapshot()
            st.session_state["show_update_cve_confirm"] = False
            st.rerun()


@st.dialog("Confirm full CVE pipeline", width="small")
def confirm_full_cve_dialog() -> None:
    st.warning(
        "This will create the software snapshot, update the CVE snapshot from NVD, and generate CVE findings.",
        icon="⚠️",
    )
    st.write("Run the collector first if endpoint reports changed. The NVD step may take a few minutes due to rate limiting.")

    c1, c2 = st.columns(2)

    with c1:
        if st.button("Cancel", use_container_width=True, key="cancel_full_cve"):
            st.session_state["show_full_cve_confirm"] = False
            st.rerun()

    with c2:
        if st.button("Confirm Run", type="primary", use_container_width=True, key="confirm_full_cve"):
            with st.spinner("Running full CVE pipeline..."):
                st.session_state["cve_action_result"] = run_full_cve_pipeline()
            st.session_state["show_full_cve_confirm"] = False
            st.rerun()


top_actions = st.container(border=True)
with top_actions:
    left, mid, rebuild_col, right = st.columns([1, 1, 1, 1])

    with left:
        if st.button("Run Collector", type="primary", use_container_width=True):
            st.session_state["show_run_collector_confirm"] = True

    with mid:
        if st.button("Run AI Enrichment", use_container_width=True):
            with st.spinner("Running AI enrichment..."):
                st.session_state["ai_enrichment_result"] = run_ai_enrichment()
            st.rerun()

    with rebuild_col:
        if st.button("Rebuild Kuzu", use_container_width=True):
            with st.spinner("Rebuilding Kuzu from latest consolidated graph..."):
                st.session_state["kuzu_rebuild_result"] = rebuild_kuzu_from_latest_consolidated()
            st.rerun()

    with right:
        if st.button("Refresh", use_container_width=True):
            st.rerun()

if st.session_state.get("show_run_collector_confirm"):
    confirm_run_collector_dialog()

if st.session_state.get("show_update_cve_confirm"):
    confirm_update_cve_dialog()

if st.session_state.get("show_full_cve_confirm"):
    confirm_full_cve_dialog()

queue_info = inspect_input_queue()
latest_output = get_latest_output_summary()
recent_outputs_df = get_recent_output_files_df()
run_result = st.session_state.get("collector_run_result")
ai_enrichment_result = st.session_state.get("ai_enrichment_result")
kuzu_rebuild_result = st.session_state.get("kuzu_rebuild_result")
cve_action_result = st.session_state.get("cve_action_result")

software_snapshot_path = REPO_ROOT / "collector" / "output" / "software_snapshot" / "software_snapshot_latest.json"
cve_snapshot_path = REPO_ROOT / "collector" / "output" / "cve_snapshot" / "cve_snapshot_latest.json"
cve_findings_path = REPO_ROOT / "collector" / "output" / "cve_findings" / "cve_findings_latest.json"

software_snapshot_time = get_snapshot_generated_at(software_snapshot_path)
cve_snapshot_time = get_snapshot_generated_at(cve_snapshot_path)
cve_findings_time = get_snapshot_generated_at(cve_findings_path)

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

cve_actions_box = st.container(border=True)
with cve_actions_box:
    st.subheader("CVE Operations")

    st.info(
        "Recommended order: 1) Run Collector after endpoint reports are added, "
        "2) Create Software Snapshot, 3) Update CVE Snapshot, 4) Generate CVE Findings. "
        "The Full CVE Pipeline button runs steps 2–4 together, but it does not run the collector.",
        icon="ℹ️",
    )

    st.markdown(
        """
        **Button behavior**

        - **Create Software Snapshot** reads the latest collector output and extracts installed software.
        - **Update CVE Snapshot** queries NVD for CVEs related to the software snapshot and saves the results locally.
        - **Generate CVE Findings** converts the CVE snapshot into SAGE-CH findings.
        - **Run Full CVE Pipeline** runs all three CVE steps in order: software snapshot → CVE snapshot → CVE findings.
        """
    )

    t1, t2, t3 = st.columns(3)
    t1.metric("Last Software Snapshot", software_snapshot_time)
    t2.metric("Last CVE Update Pulled", cve_snapshot_time)
    t3.metric("Last CVE Findings Generated", cve_findings_time)

    a1, a2, a3, a4 = st.columns(4)

    with a1:
        if st.button("Create Software Snapshot", use_container_width=True):
            with st.spinner("Creating software snapshot..."):
                st.session_state["cve_action_result"] = run_create_software_snapshot()
            st.rerun()

    with a2:
        if st.button("Update CVE Snapshot", use_container_width=True):
            st.session_state["show_update_cve_confirm"] = True
            st.rerun()

    with a3:
        if st.button("Generate CVE Findings", use_container_width=True):
            with st.spinner("Generating CVE findings..."):
                st.session_state["cve_action_result"] = run_correlate_cves_to_findings()
            st.rerun()

    with a4:
        if st.button("Run Full CVE Pipeline", type="primary", use_container_width=True):
            st.session_state["show_full_cve_confirm"] = True
            st.rerun()

    with st.expander("CVE Artifact Paths"):
        st.markdown(f"**Software snapshot**  \n`{path_status(software_snapshot_path)}`")
        st.markdown(f"**CVE snapshot**  \n`{path_status(cve_snapshot_path)}`")
        st.markdown(f"**CVE findings**  \n`{path_status(cve_findings_path)}`")

if run_result:
    display_action_result("Collector Run Result", run_result)

if ai_enrichment_result:
    display_action_result("AI Enrichment Result", ai_enrichment_result)

if kuzu_rebuild_result:
    display_action_result("Kuzu Rebuild Result", kuzu_rebuild_result)

if cve_action_result:
    display_action_result("CVE Action Result", cve_action_result)

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

    with st.expander("Recent Output Files"):
        if recent_outputs_df.empty:
            st.info("No output files found.")
        else:
            st.dataframe(recent_outputs_df, use_container_width=True, hide_index=True)

with main_right:
    latest_box = st.container(border=True)
    with latest_box:
        st.subheader("Latest Output Summary")

        st.write(f"**Batch ID:** `{latest_output.get('batch_id') or 'N/A'}`")
        st.write(f"**Total hosts:** `{latest_output.get('total_hosts') if latest_output.get('total_hosts') is not None else 'N/A'}`")
        st.write(f"**Total findings:** `{latest_output.get('total_findings') if latest_output.get('total_findings') is not None else 'N/A'}`")
        st.write(f"**Graph persistence:** `{latest_output.get('graph_persistence_status') or 'N/A'}`")

        with st.expander("Output Artifact Paths"):
            st.markdown(f"**Consolidated dataset**  \n`{latest_output.get('consolidated_path') or 'Not found'}`")
            st.markdown(f"**Findings dataset**  \n`{latest_output.get('findings_path') or 'Not found'}`")
            st.markdown(f"**Assessment summary**  \n`{latest_output.get('assessment_summary_path') or 'Not found'}`")

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
