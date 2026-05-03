from pathlib import Path
import sys

import streamlit as st

st.set_page_config(page_title="Findings", page_icon="🚨", layout="wide")

GUI_DIR = Path(__file__).resolve().parents[1]
if str(GUI_DIR) not in sys.path:
    sys.path.append(str(GUI_DIR))

from services.nav import render_sidebar
from services.data_loader import (
    load_cve_summary,
    load_hosts_df_from_consolidated,
    load_latest_assessment_summary_payload,
    load_latest_findings_df,
)
from services.report_service import build_system_pdf_report

render_sidebar()

st.title("Findings")
st.caption("Filter and review CIS-mapped configuration findings and CVE-based vulnerability findings.")

top_bar = st.container(border=True)
with top_bar:
    left, right = st.columns([1, 4])

    with left:
        if st.button("Refresh", use_container_width=True):
            st.rerun()

    with right:
        st.info("Filter findings by type, severity, host, category, or control mapping.", icon="ℹ️")

findings_df, findings_path = load_latest_findings_df()
hosts_df, hosts_path = load_hosts_df_from_consolidated()
assessment_summary, summary_path = load_latest_assessment_summary_payload()
cve_summary, cve_path = load_cve_summary()

if findings_df.empty:
    st.warning("No findings dataset found.")
    st.stop()

vulnerability_df = findings_df[findings_df["finding_type"] == "Vulnerability"].copy() if "finding_type" in findings_df.columns else findings_df.iloc[0:0].copy()
configuration_df = findings_df[findings_df["finding_type"] != "Vulnerability"].copy() if "finding_type" in findings_df.columns else findings_df.copy()

severity_options = (
    sorted(findings_df["severity"].dropna().astype(str).unique().tolist())
    if "severity" in findings_df.columns
    else []
)
host_options = (
    sorted(findings_df["hostname"].dropna().astype(str).unique().tolist())
    if "hostname" in findings_df.columns
    else []
)
category_options = (
    sorted(findings_df["category"].dropna().astype(str).unique().tolist())
    if "category" in findings_df.columns
    else []
)
type_options = (
    sorted(findings_df["finding_type"].dropna().astype(str).unique().tolist())
    if "finding_type" in findings_df.columns
    else []
)
cis_options = (
    sorted(findings_df["cis_controls"].dropna().astype(str).unique().tolist())
    if "cis_controls" in findings_df.columns
    else []
)


def sort_by_severity(df):
    if df.empty or "severity" not in df.columns:
        return df

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
    }

    output = df.copy()
    output["_severity_rank"] = (
        output["severity"]
        .fillna("")
        .astype(str)
        .str.lower()
        .map(severity_order)
        .fillna(99)
    )

    sort_cols = ["_severity_rank"]
    ascending = [True]

    if "finding_type" in output.columns:
        sort_cols.append("finding_type")
        ascending.append(True)

    if "hostname" in output.columns:
        sort_cols.append("hostname")
        ascending.append(True)

    if "title" in output.columns:
        sort_cols.append("title")
        ascending.append(True)

    return output.sort_values(by=sort_cols, ascending=ascending)


overview_box = st.container(border=True)
with overview_box:
    st.subheader("Overview")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Findings", len(findings_df))
    m2.metric("Configuration", len(configuration_df))
    m3.metric("CVE Findings", len(vulnerability_df))
    m4.metric("Affected Hosts", findings_df["hostname"].nunique() if "hostname" in findings_df.columns else 0)

cve_box = st.container(border=True)
with cve_box:
    st.subheader("CVE Intelligence")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("CVE Findings", cve_summary.get("total_findings", 0))
    c2.metric("Products With CVEs", cve_summary.get("products_with_findings", 0))
    c3.metric("Filtered CVEs", cve_summary.get("total_cves_after_filter", 0))
    c4.metric("Min CVSS", cve_summary.get("min_cvss_score", "N/A"))

report_box = st.container(border=True)
with report_box:
    left, right = st.columns([3, 1])

    with left:
        st.subheader("Export System Report")
        st.caption("Generate a PDF report covering all hosts, configuration findings, and CVE findings.")

    with right:
        try:
            pdf_bytes = build_system_pdf_report(
                findings_df=findings_df,
                hosts_df=hosts_df,
                assessment_summary=assessment_summary,
            )

            st.download_button(
                label="Download PDF",
                data=pdf_bytes,
                file_name="sage_ch_system_assessment_report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as exc:
            st.warning(str(exc))

filters_box = st.container(border=True)
with filters_box:
    st.subheader("Filters")

    f1, f2, f3, f4, f5 = st.columns(5)
    with f1:
        selected_types = st.multiselect("Type", type_options, default=type_options)
    with f2:
        selected_severity = st.multiselect("Severity", severity_options, default=severity_options)
    with f3:
        selected_hosts = st.multiselect("Host", host_options)
    with f4:
        selected_categories = st.multiselect("Category", category_options)
    with f5:
        selected_cis = st.multiselect("Control", cis_options)

filtered_df = findings_df.copy()

if selected_types and "finding_type" in filtered_df.columns:
    filtered_df = filtered_df[filtered_df["finding_type"].astype(str).isin(selected_types)]

if selected_severity and "severity" in filtered_df.columns:
    filtered_df = filtered_df[filtered_df["severity"].astype(str).isin(selected_severity)]

if selected_hosts and "hostname" in filtered_df.columns:
    filtered_df = filtered_df[filtered_df["hostname"].astype(str).isin(selected_hosts)]

if selected_categories and "category" in filtered_df.columns:
    filtered_df = filtered_df[filtered_df["category"].astype(str).isin(selected_categories)]

if selected_cis and "cis_controls" in filtered_df.columns:
    filtered_df = filtered_df[filtered_df["cis_controls"].astype(str).isin(selected_cis)]

filtered_df = sort_by_severity(filtered_df)

summary_box = st.container(border=True)
with summary_box:
    st.subheader("Filtered Summary")

    filtered_vulns = filtered_df[filtered_df["finding_type"] == "Vulnerability"] if "finding_type" in filtered_df.columns else filtered_df.iloc[0:0]
    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Filtered Findings", len(filtered_df))
    s2.metric("Affected Hosts", filtered_df["hostname"].nunique() if "hostname" in filtered_df.columns else 0)
    s3.metric("CVE Findings", len(filtered_vulns))
    s4.metric("Categories", filtered_df["category"].nunique() if "category" in filtered_df.columns else 0)

table_box = st.container(border=True)
with table_box:
    st.subheader("Findings Table")

    display_cols = [
        c
        for c in [
            "hostname",
            "finding_type",
            "title",
            "severity",
            "category",
            "software_name",
            "cve_id",
            "cvss_score",
            "cis_controls",
            "status",
            "recommendation",
        ]
        if c in filtered_df.columns
    ]

    st.dataframe(filtered_df[display_cols], use_container_width=True, hide_index=True, height=520)

details_box = st.container(border=True)
with details_box:
    st.subheader("Finding Detail Review")

    if filtered_df.empty:
        st.info("No filtered findings to review.")
    else:
        options = (
            filtered_df["title"]
            .fillna("")
            .astype(str)
            .drop_duplicates()
            .head(200)
            .tolist()
        )

        selected_title = st.selectbox("Select finding", options)
        selected_rows = filtered_df[filtered_df["title"].astype(str) == selected_title].head(1)

        if not selected_rows.empty:
            row = selected_rows.iloc[0]
            st.markdown(f"#### {row.get('title', '')}")

            d1, d2, d3, d4 = st.columns(4)
            d1.metric("Type", row.get("finding_type", ""))
            d2.metric("Severity", row.get("severity", ""))
            d3.metric("Host", row.get("hostname", ""))
            d4.metric("CVSS", row.get("cvss_score", "N/A") or "N/A")

            if row.get("description", ""):
                st.markdown("**Description**")
                st.write(row.get("description", ""))

            if row.get("ai_explanation", ""):
                st.markdown("**AI Explanation**")
                st.info(row.get("ai_explanation", ""), icon="🧠")

            if row.get("recommendation", ""):
                st.markdown("**Recommendation**")
                st.success(row.get("recommendation", ""), icon="✅")

footer_box = st.container(border=True)
with footer_box:
    st.subheader("Data Sources")
    st.markdown(f"**Findings source**  \n`{findings_path}`")
    st.markdown(f"**CVE findings source**  \n`{cve_path if cve_path else 'Not found'}`")
    st.markdown(f"**Hosts source**  \n`{hosts_path}`")
    st.markdown(f"**Assessment summary**  \n`{summary_path if summary_path else 'Not found'}`")