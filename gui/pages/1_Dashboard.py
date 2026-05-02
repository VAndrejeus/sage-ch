from pathlib import Path
import sys

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
st.caption("Executive overview of the latest SAGE-CH cyber hygiene assessment.")

hosts_df, hosts_path = load_hosts_df_from_consolidated()
findings_df, findings_path = load_latest_findings_df()
assessment_summary, summary_path = load_latest_assessment_summary_payload()
json_graph_counts, graph_path = load_graph_counts_from_consolidated()
kuzu_counts = get_kuzu_graph_counts(get_graph_db_path())

graph_counts = kuzu_counts if kuzu_counts.get("ok") else json_graph_counts
metrics = build_dashboard_metrics(hosts_df, findings_df, assessment_summary)
batch_label = assessment_summary.get("batch_id", "N/A") if assessment_summary else "N/A"


def build_risk_message() -> tuple[str, str, str]:
    total_findings = metrics["total_findings"]
    critical = metrics["severity_counts"].get("critical", 0)
    high = metrics["severity_counts"].get("high", 0)
    medium = metrics["severity_counts"].get("medium", 0)

    if total_findings == 0:
        return "No findings loaded", "No assessment findings are currently available.", "info"

    if critical > 0:
        return (
            "Critical attention required",
            f"{critical} critical finding(s) were detected. Prioritize affected hosts and remediation steps.",
            "error",
        )

    if high > 0:
        return (
            "High-priority review recommended",
            f"{high} high finding(s) were detected. Review affected hosts and address high-impact issues first.",
            "warning",
        )

    if medium > 0:
        return (
            "Moderate review recommended",
            f"{medium} medium finding(s) were detected. Review configuration and access-control related issues.",
            "info",
        )

    return (
        "Low-risk assessment state",
        "No critical, high, or medium findings were detected in the latest assessment.",
        "success",
    )


brief_title, brief_message, risk_level = build_risk_message()

top_bar = st.container(border=True)
with top_bar:
    left, right = st.columns([1, 4])

    with left:
        if st.button("Refresh", use_container_width=True):
            st.rerun()

    with right:
        st.info(f"Latest assessment batch: {batch_label}", icon="ℹ️")

brief_box = st.container(border=True)
with brief_box:
    st.subheader("Assessment Brief")

    b1, b2 = st.columns([3, 1])

    with b1:
        st.markdown(
            f"Latest run assessed **{metrics['total_hosts']} host(s)** and produced "
            f"**{metrics['total_findings']} finding(s)** across the environment."
        )

        if risk_level == "error":
            st.error(f"**{brief_title}:** {brief_message}", icon="🚨")
        elif risk_level == "warning":
            st.warning(f"**{brief_title}:** {brief_message}", icon="⚠️")
        elif risk_level == "success":
            st.success(f"**{brief_title}:** {brief_message}", icon="✅")
        else:
            st.info(f"**{brief_title}:** {brief_message}", icon="ℹ️")

    with b2:
        st.metric("Affected Hosts", assessment_summary.get("affected_hosts", "N/A") if assessment_summary else "N/A")
        st.metric("Exposed Services", graph_counts.get("edge_counts", {}).get("EXPOSES_SERVICE", 0))

overview_box = st.container(border=True)
with overview_box:
    st.subheader("Security Posture")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Findings", metrics["total_findings"])
    m2.metric("Critical", metrics["severity_counts"].get("critical", 0))
    m3.metric("High", metrics["severity_counts"].get("high", 0))
    m4.metric("Discovered Assets", metrics["discovered_hosts"])

    st.markdown("#### Severity Breakdown")
    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Critical", metrics["severity_counts"].get("critical", 0))
    s2.metric("High", metrics["severity_counts"].get("high", 0))
    s3.metric("Medium", metrics["severity_counts"].get("medium", 0))
    s4.metric("Low", metrics["severity_counts"].get("low", 0))

main_left, main_right = st.columns([1.25, 1])

with main_left:
    findings_box = st.container(border=True)
    with findings_box:
        st.subheader("Recent Findings")

        if findings_df.empty:
            st.info("No findings dataset available.")
        else:
            display_df = findings_df.copy()

            if "severity" in display_df.columns:
                severity_order = {
                    "critical": 0,
                    "high": 1,
                    "medium": 2,
                    "low": 3,
                }

                display_df["_severity_rank"] = (
                    display_df["severity"]
                    .fillna("")
                    .astype(str)
                    .str.lower()
                    .map(severity_order)
                    .fillna(99)
                )

                sort_cols = ["_severity_rank"]
                ascending = [True]

                if "hostname" in display_df.columns:
                    sort_cols.append("hostname")
                    ascending.append(True)

                if "title" in display_df.columns:
                    sort_cols.append("title")
                    ascending.append(True)

                display_df = display_df.sort_values(by=sort_cols, ascending=ascending)

            preview_cols = [
                c
                for c in [
                    "hostname",
                    "title",
                    "severity",
                    "category",
                    "cis_controls",
                    "status",
                ]
                if c in display_df.columns
            ]

            st.dataframe(
                display_df[preview_cols].head(15),
                use_container_width=True,
                hide_index=True,
                height=360,
            )

with main_right:
    hosts_box = st.container(border=True)
    with hosts_box:
        st.subheader("Host Coverage")

        if hosts_df.empty:
            st.warning("No host records found.")
        else:
            preview_cols = [
                c for c in ["hostname", "ip", "platform", "software_count"]
                if c in hosts_df.columns
            ]
            st.dataframe(
                hosts_df[preview_cols],
                use_container_width=True,
                hide_index=True,
                height=360,
            )

latest_box = st.container(border=True)
with latest_box:
    st.subheader("Output Artifacts")

    o1, o2 = st.columns(2)

    with o1:
        st.markdown(f"**Hosts dataset**  \n`{hosts_path if hosts_path else 'Not found'}`")
        st.markdown(f"**Findings dataset**  \n`{findings_path if findings_path else 'Not found'}`")
        st.markdown(f"**Assessment summary**  \n`{summary_path if summary_path else 'Not found'}`")

    with o2:
        st.markdown(f"**Graph JSON**  \n`{graph_path if graph_path else 'Not found'}`")
        st.markdown(f"**Kuzu DB**  \n`{get_graph_db_path()}`")