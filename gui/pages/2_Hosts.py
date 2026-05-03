from pathlib import Path
import sys

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Hosts", page_icon="💻", layout="wide")

GUI_DIR = Path(__file__).resolve().parents[1]
if str(GUI_DIR) not in sys.path:
    sys.path.append(str(GUI_DIR))

from services.nav import render_sidebar
from services.data_loader import load_ai_for_host, load_hosts_df_from_consolidated, load_latest_findings_df
from services.report_service import build_host_pdf_report

render_sidebar()

st.title("Hosts")
st.caption("Host-level security posture, vulnerability findings, software inventory, AI explanation, and remediation guidance.")

hosts_df, hosts_path = load_hosts_df_from_consolidated()
findings_df, findings_path = load_latest_findings_df()

if hosts_df.empty:
    st.warning("No host data found.")
    st.stop()

if "hostname" not in hosts_df.columns:
    st.warning("Host dataset is missing the hostname field.")
    st.stop()

host_options = hosts_df["hostname"].fillna("unknown").astype(str).tolist()

top_bar = st.container(border=True)
with top_bar:
    left, right = st.columns([3, 1])

    with left:
        selected_host = st.selectbox("Select Host", host_options)

    with right:
        st.write("")
        st.write("")
        if st.button("Refresh", use_container_width=True):
            st.rerun()

host_row = hosts_df[hosts_df["hostname"].astype(str) == selected_host].head(1)
if host_row.empty:
    st.stop()

host_record = host_row.iloc[0].to_dict()
raw_report = host_record.get("raw_report", {}) if isinstance(host_record.get("raw_report"), dict) else {}

software_items = []
software_inventory = raw_report.get("software_inventory", {})
if isinstance(software_inventory, dict):
    software_items = software_inventory.get("items", []) if isinstance(software_inventory.get("items"), list) else []

host_findings = pd.DataFrame()
if not findings_df.empty and "hostname" in findings_df.columns:
    host_findings = findings_df[findings_df["hostname"].astype(str) == selected_host].copy()

host_vulnerabilities = pd.DataFrame()
if not host_findings.empty and "finding_type" in host_findings.columns:
    host_vulnerabilities = host_findings[host_findings["finding_type"].astype(str) == "Vulnerability"].copy()

ai_data = load_ai_for_host(selected_host)
explanation = ai_data.get("explanation")
remediation = ai_data.get("remediation", [])

severity_counts = {}
if not host_findings.empty and "severity" in host_findings.columns:
    severity_counts = host_findings["severity"].fillna("").astype(str).str.lower().value_counts().to_dict()


def sort_by_severity(df: pd.DataFrame) -> pd.DataFrame:
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

    if "category" in output.columns:
        sort_cols.append("category")
        ascending.append(True)

    if "title" in output.columns:
        sort_cols.append("title")
        ascending.append(True)

    return output.sort_values(by=sort_cols, ascending=ascending)


summary_box = st.container(border=True)
with summary_box:
    st.subheader("Selected Host Summary")

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Hostname", host_record.get("hostname", ""))
    c2.metric("IP", host_record.get("ip", "") or "N/A")
    c3.metric("Software", len(software_items))
    c4.metric("Findings", len(host_findings))
    c5.metric("CVE Findings", len(host_vulnerabilities))
    c6.metric("Critical", severity_counts.get("critical", 0))

export_box = st.container(border=True)
with export_box:
    left, right = st.columns([3, 1])

    with left:
        st.subheader("Export Host Report")
        st.caption("Generate a host-level PDF with system details, findings, AI explanation, and remediation guidance.")

    with right:
        try:
            pdf_bytes = build_host_pdf_report(
                host_record=host_record,
                software_items=software_items,
                host_findings=host_findings,
                ai_data=ai_data,
            )

            safe_hostname = str(selected_host).replace(" ", "_").replace("/", "_").replace("\\", "_")
            st.download_button(
                label="Download PDF",
                data=pdf_bytes,
                file_name=f"sage_ch_host_report_{safe_hostname}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as exc:
            st.warning(str(exc))

main_left, main_right = st.columns([0.95, 1.35])

with main_left:
    host_box = st.container(border=True)
    with host_box:
        st.subheader("System Details")

        info_rows = [
            {"Field": "Hostname", "Value": host_record.get("hostname", "")},
            {"Field": "IP Address", "Value": host_record.get("ip", "")},
            {"Field": "Platform", "Value": host_record.get("platform", "")},
            {"Field": "OS Name", "Value": host_record.get("os_name", "")},
            {"Field": "OS Version", "Value": host_record.get("os_version", "")},
        ]
        st.dataframe(pd.DataFrame(info_rows), use_container_width=True, hide_index=True)

    software_box = st.container(border=True)
    with software_box:
        st.subheader("Software Inventory")

        if software_items:
            software_df = pd.DataFrame(
                [
                    {
                        "Name": item.get("name", ""),
                        "Version": item.get("version", ""),
                        "Arch": item.get("arch", ""),
                    }
                    for item in software_items
                    if isinstance(item, dict)
                ]
            )
            st.dataframe(software_df, use_container_width=True, hide_index=True, height=360)
        else:
            st.info("No software items found.")

with main_right:
    findings_box = st.container(border=True)
    with findings_box:
        st.subheader("Findings")

        if host_findings.empty:
            st.success("No findings found for this host.")
        else:
            display_df = sort_by_severity(host_findings)

            rename_map = {
                "cis_controls": "CIS Control",
                "category": "Category",
                "severity": "Severity",
                "software_name": "Component",
                "cve_id": "CVE",
                "title": "Title",
                "recommendation": "Recommendation",
            }

            show_cols = [
                c
                for c in [
                    "cis_controls",
                    "category",
                    "severity",
                    "software_name",
                    "cve_id",
                    "title",
                    "recommendation",
                ]
                if c in display_df.columns
            ]

            st.dataframe(
                display_df[show_cols].rename(columns=rename_map),
                use_container_width=True,
                hide_index=True,
                height=495,
            )

vulnerability_box = st.container(border=True)
with vulnerability_box:
    st.subheader("CVE Vulnerability Findings")

    if host_vulnerabilities.empty:
        st.info("No CVE findings found for this host.")
    else:
        display_df = sort_by_severity(host_vulnerabilities)

        rename_map = {
            "cis_controls": "CIS Control",
            "software_name": "Software",
            "installed_versions": "Installed Version",
            "cve_id": "CVE",
            "severity": "Severity",
            "cvss_score": "CVSS",
            "published": "Published",
            "recommendation": "Recommendation",
        }

        show_cols = [
            c
            for c in [
                "cis_controls",
                "software_name",
                "installed_versions",
                "cve_id",
                "severity",
                "cvss_score",
                "published",
                "recommendation",
            ]
            if c in display_df.columns
        ]

        st.dataframe(
            display_df[show_cols].rename(columns=rename_map),
            use_container_width=True,
            hide_index=True,
            height=420,
        )

        selected_cve = st.selectbox(
            "Review CVE details",
            display_df["cve_id"].dropna().astype(str).unique().tolist(),
        )

        selected_rows = display_df[display_df["cve_id"].astype(str) == selected_cve].head(1)
        if not selected_rows.empty:
            row = selected_rows.iloc[0]
            st.markdown(f"#### {row.get('title', selected_cve)}")
            st.write(row.get("description", ""))
            if row.get("ai_explanation", ""):
                st.info(row.get("ai_explanation", ""), icon="🧠")
            if row.get("recommendation", ""):
                st.success(row.get("recommendation", ""), icon="✅")

ai_box = st.container(border=True)
with ai_box:
    st.subheader("AI Explanation")

    if explanation:
        st.write(explanation.get("overall_explanation", ""))

        key_risk_drivers = explanation.get("key_risk_drivers", [])
        if key_risk_drivers:
            st.markdown("#### Key Risk Drivers")
            for item in key_risk_drivers:
                st.write(f"- {item}")
    else:
        st.info("No AI explanation found.")

remediation_box = st.container(border=True)
with remediation_box:
    st.subheader("Remediation Plan")

    if remediation:
        for item in remediation:
            priority = item.get("priority", "")
            title = item.get("title", "")
            reason = item.get("reason", "")
            actions = item.get("actions", [])

            st.markdown(f"#### Priority {priority}: {title}")

            if reason:
                st.write(reason)

            if actions:
                for action in actions:
                    st.write(f"- {action}")

            st.divider()
    else:
        st.info("No remediation entries found.")

footer_box = st.container(border=True)
with footer_box:
    st.subheader("Data Sources")
    st.markdown(f"**Hosts source**  \n`{hosts_path}`")
    st.markdown(f"**Findings source**  \n`{findings_path if findings_path else 'Not found'}`")