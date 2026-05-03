from pathlib import Path
import sys

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Dashboard", layout="wide")

GUI_DIR = Path(__file__).resolve().parents[1]
if str(GUI_DIR) not in sys.path:
    sys.path.append(str(GUI_DIR))

from services.nav import render_sidebar
from services.data_loader import (
    get_graph_db_path,
    load_cve_summary,
    load_graph_counts_from_consolidated,
    load_hosts_df_from_consolidated,
    load_latest_assessment_summary_payload,
    load_latest_findings_df,
)
from services.kuzu_service import get_kuzu_graph_counts
from services.metrics import build_dashboard_metrics


render_sidebar()

hosts_df, hosts_path = load_hosts_df_from_consolidated()
findings_df, findings_path = load_latest_findings_df()
cve_summary, cve_path = load_cve_summary()
assessment_summary, summary_path = load_latest_assessment_summary_payload()
json_graph_counts, graph_path = load_graph_counts_from_consolidated()
kuzu_counts = get_kuzu_graph_counts(get_graph_db_path())

graph_counts = kuzu_counts if kuzu_counts.get("ok") else json_graph_counts
graph_source = "Kuzu" if kuzu_counts.get("ok") else "JSON fallback"
metrics = build_dashboard_metrics(hosts_df, findings_df, assessment_summary)
batch_label = assessment_summary.get("batch_id", "N/A") if assessment_summary else "N/A"

vulnerability_df = (
    findings_df[findings_df["finding_type"] == "Vulnerability"].copy()
    if not findings_df.empty and "finding_type" in findings_df.columns
    else findings_df.iloc[0:0].copy()
)
configuration_df = (
    findings_df[findings_df["finding_type"] != "Vulnerability"].copy()
    if not findings_df.empty and "finding_type" in findings_df.columns
    else findings_df.copy()
)


def severity_sorted(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty or "severity" not in df.columns:
        return df
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    out = df.copy()
    out["_rank"] = out["severity"].fillna("").astype(str).str.lower().map(order).fillna(99)
    sort_cols = ["_rank"]
    if "hostname" in out.columns:
        sort_cols.append("hostname")
    if "title" in out.columns:
        sort_cols.append("title")
    return out.sort_values(sort_cols).drop(columns=["_rank"], errors="ignore")


def status_label(value: object, good_values: set[str] | None = None) -> str:
    text = str(value or "unknown").strip()
    if not text:
        return "unknown"
    if good_values and text.lower() in good_values:
        return text
    return text


severity_counts = metrics["severity_counts"]
critical_count = severity_counts.get("critical", 0)
high_count = severity_counts.get("high", 0)
affected_hosts = (
    findings_df["hostname"].nunique()
    if not findings_df.empty and "hostname" in findings_df.columns
    else assessment_summary.get("affected_hosts", 0) if assessment_summary else 0
)
node_total = sum(graph_counts.get("node_counts", {}).values()) if graph_counts.get("node_counts") else 0
edge_total = sum(graph_counts.get("edge_counts", {}).values()) if graph_counts.get("edge_counts") else 0

if critical_count:
    posture = "Critical attention required"
    posture_body = f"{critical_count} critical findings are present. Prioritize affected hosts with repeated high-impact findings."
elif high_count:
    posture = "High-priority review"
    posture_body = f"{high_count} high findings are present. Review host exposure, patch status, and secure configuration issues."
elif metrics["total_findings"]:
    posture = "Findings require review"
    posture_body = "No critical or high findings are loaded, but medium and low findings should be triaged."
else:
    posture = "No findings loaded"
    posture_body = "Run the collector to load assessment findings."

st.title("Security Posture")
st.caption("Latest SAGE-CH assessment summary for cyber hygiene, vulnerability exposure, and graph health.")

header = st.container(border=True)
with header:
    left, right = st.columns([3, 1])
    with left:
        st.subheader(posture)
        st.write(posture_body)
        st.caption(f"Latest batch: {batch_label}")
    with right:
        if st.button("Refresh", use_container_width=True):
            st.rerun()

kpi_box = st.container(border=True)
with kpi_box:
    k1, k2, k3, k4, k5, k6 = st.columns(6)
    k1.metric("Hosts", metrics["total_hosts"])
    k2.metric("Affected Hosts", affected_hosts)
    k3.metric("Findings", metrics["total_findings"])
    k4.metric("Critical", critical_count)
    k5.metric("High", high_count)
    k6.metric("CVE Findings", len(vulnerability_df))

left_col, right_col = st.columns([1.25, 1])

with left_col:
    risk_box = st.container(border=True)
    with risk_box:
        st.subheader("Highest-Risk Hosts")
        if findings_df.empty or "hostname" not in findings_df.columns:
            st.info("No host finding data is available.")
        else:
            weights = {"critical": 10, "high": 6, "medium": 3, "low": 1}
            host_risk = findings_df.copy()
            host_risk["severity_weight"] = (
                host_risk["severity"].fillna("").astype(str).str.lower().map(weights).fillna(0)
                if "severity" in host_risk.columns
                else 0
            )
            grouped = (
                host_risk.groupby("hostname")
                .agg(
                    risk_score=("severity_weight", "sum"),
                    findings=("hostname", "size"),
                    critical=("severity", lambda s: int((s.astype(str).str.lower() == "critical").sum())),
                    high=("severity", lambda s: int((s.astype(str).str.lower() == "high").sum())),
                )
                .reset_index()
                .sort_values(["risk_score", "critical", "high", "findings"], ascending=False)
                .head(10)
            )
            st.dataframe(
                grouped.rename(
                    columns={
                        "hostname": "Host",
                        "risk_score": "Risk Score",
                        "findings": "Findings",
                        "critical": "Critical",
                        "high": "High",
                    }
                ),
                use_container_width=True,
                hide_index=True,
                height=330,
            )

with right_col:
    graph_box = st.container(border=True)
    with graph_box:
        st.subheader("Pipeline And Graph")
        g1, g2 = st.columns(2)
        g1.metric("Graph Source", graph_source)
        g2.metric("Graph Persistence", json_graph_counts.get("graph_persistence_status", "unknown"))
        g3, g4 = st.columns(2)
        g3.metric("Graph Nodes", node_total)
        g4.metric("Graph Edges", edge_total)
        st.caption(f"Kuzu DB: {get_graph_db_path()}")

    cve_box = st.container(border=True)
    with cve_box:
        st.subheader("Vulnerability Intelligence")
        c1, c2 = st.columns(2)
        c1.metric("Products With CVEs", cve_summary.get("products_with_findings", 0))
        c2.metric("Filtered CVEs", cve_summary.get("total_cves_after_filter", 0))
        c3, c4 = st.columns(2)
        c3.metric("Min CVSS", cve_summary.get("min_cvss_score", "N/A"))
        c4.metric("Max Age", f"{cve_summary.get('max_cve_age_years', 'N/A')} years")

middle_left, middle_right = st.columns([1, 1])

with middle_left:
    controls_box = st.container(border=True)
    with controls_box:
        st.subheader("Weakest CIS Controls")
        control_scores = assessment_summary.get("control_scores", {}) if assessment_summary else {}
        rows = []
        if isinstance(control_scores, dict):
            for control, item in control_scores.items():
                if isinstance(item, dict):
                    rows.append(
                        {
                            "Control": control,
                            "Score": item.get("score", 0),
                            "Status": item.get("status", "unknown"),
                            "Failed Rules": item.get("failed_rules", 0),
                        }
                    )
        controls_df = pd.DataFrame(rows)
        if controls_df.empty:
            st.info("No CIS control scores available.")
        else:
            controls_df = controls_df.sort_values(["Score", "Failed Rules"], ascending=[True, False]).head(8)
            st.dataframe(controls_df, use_container_width=True, hide_index=True, height=300)

with middle_right:
    severity_box = st.container(border=True)
    with severity_box:
        st.subheader("Severity Distribution")
        sev_df = pd.DataFrame(
            [
                {"Severity": "Critical", "Count": critical_count},
                {"Severity": "High", "Count": high_count},
                {"Severity": "Medium", "Count": severity_counts.get("medium", 0)},
                {"Severity": "Low", "Count": severity_counts.get("low", 0)},
            ]
        )
        st.bar_chart(sev_df.set_index("Severity"), height=300)

findings_box = st.container(border=True)
with findings_box:
    st.subheader("Priority Findings")
    if findings_df.empty:
        st.info("No findings dataset available.")
    else:
        display_df = severity_sorted(findings_df)
        preview_cols = [
            col
            for col in ["hostname", "severity", "finding_type", "cis_controls", "software_name", "cve_id", "title", "status"]
            if col in display_df.columns
        ]
        rename_map = {
            "hostname": "Host",
            "severity": "Severity",
            "finding_type": "Type",
            "cis_controls": "CIS Control",
            "software_name": "Component",
            "cve_id": "CVE",
            "title": "Finding",
            "status": "Status",
        }
        st.dataframe(
            display_df[preview_cols].rename(columns=rename_map).head(18),
            use_container_width=True,
            hide_index=True,
            height=420,
        )

with st.expander("Artifact Sources"):
    st.markdown(f"**Hosts dataset:** `{hosts_path if hosts_path else 'Not found'}`")
    st.markdown(f"**Findings dataset:** `{findings_path if findings_path else 'Not found'}`")
    st.markdown(f"**CVE findings:** `{cve_path if cve_path else 'Not found'}`")
    st.markdown(f"**Assessment summary:** `{summary_path if summary_path else 'Not found'}`")
    st.markdown(f"**Graph JSON:** `{graph_path if graph_path else 'Not found'}`")
