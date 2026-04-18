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

render_sidebar()

st.title("Hosts")
st.caption("Browse managed hosts, inspect host details, review findings, and view AI explanation and remediation output.")

top_bar = st.container(border=True)
with top_bar:
    left, right = st.columns([1, 4])

    with left:
        if st.button("Refresh", use_container_width=True):
            st.rerun()

    with right:
        st.info(
            "Select a host to inspect inventory, findings, AI explanation, and remediation plan.",
            icon="ℹ️",
        )

hosts_df, hosts_path = load_hosts_df_from_consolidated()
findings_df, findings_path = load_latest_findings_df()

if hosts_df.empty:
    st.warning("No host data found in consolidated dataset.")
    st.stop()

if "hostname" not in hosts_df.columns:
    st.warning("Host dataset is missing the hostname field.")
    st.stop()

top_metrics = st.container(border=True)
with top_metrics:
    st.subheader("Overview")

    total_hosts = len(hosts_df)
    total_software = int(pd.to_numeric(hosts_df.get("software_count", 0), errors="coerce").fillna(0).sum()) if "software_count" in hosts_df.columns else 0
    total_findings = len(findings_df) if not findings_df.empty else 0

    m1, m2, m3 = st.columns(3)
    m1.metric("Hosts", total_hosts)
    m2.metric("Software Items", total_software)
    m3.metric("Findings Loaded", total_findings)

table_box = st.container(border=True)
with table_box:
    st.subheader("Host Table")

    table_cols = [c for c in ["hostname", "ip", "platform", "os_name", "software_count"] if c in hosts_df.columns]
    st.dataframe(hosts_df[table_cols], use_container_width=True, hide_index=True)

selector_box = st.container(border=True)
with selector_box:
    st.subheader("Host Selection")
    host_options = hosts_df["hostname"].fillna("unknown").astype(str).tolist()
    selected_host = st.selectbox("Select host", host_options)

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

ai_data = load_ai_for_host(selected_host)
explanation = ai_data.get("explanation")
remediation = ai_data.get("remediation", [])

detail_metrics = st.container(border=True)
with detail_metrics:
    st.subheader("Selected Host Summary")

    dm1, dm2, dm3, dm4 = st.columns(4)
    dm1.metric("Hostname", host_record.get("hostname", ""))
    dm2.metric("IP", host_record.get("ip", "") or "N/A")
    dm3.metric("Software", len(software_items))
    dm4.metric("Findings", len(host_findings))

main_left, main_mid, main_right = st.columns([1, 1.1, 1])

with main_left:
    info_box = st.container(border=True)
    with info_box:
        st.subheader("Host Info")

        info_rows = [
            {"field": "hostname", "value": host_record.get("hostname", "")},
            {"field": "ip", "value": host_record.get("ip", "")},
            {"field": "platform", "value": host_record.get("platform", "")},
            {"field": "os_name", "value": host_record.get("os_name", "")},
            {"field": "os_version", "value": host_record.get("os_version", "")},
        ]
        st.dataframe(pd.DataFrame(info_rows), use_container_width=True, hide_index=True)

    software_box = st.container(border=True)
    with software_box:
        st.subheader("Software")

        if software_items:
            software_df = pd.DataFrame(
                [
                    {
                        "name": item.get("name", ""),
                        "version": item.get("version", ""),
                        "arch": item.get("arch", ""),
                    }
                    for item in software_items
                    if isinstance(item, dict)
                ]
            )
            st.dataframe(software_df, use_container_width=True, hide_index=True)
        else:
            st.info("No software items found.")

with main_mid:
    findings_box = st.container(border=True)
    with findings_box:
        st.subheader("Findings")

        if host_findings.empty:
            st.info("No findings found for this host.")
        else:
            show_cols = [c for c in ["finding_id", "title", "severity", "category", "status", "recommendation"] if c in host_findings.columns]
            st.dataframe(host_findings[show_cols], use_container_width=True, hide_index=True)

with main_right:
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
        st.subheader("Remediation")

        if remediation:
            for item in remediation:
                priority = item.get("priority", "")
                title = item.get("title", "")
                reason = item.get("reason", "")
                actions = item.get("actions", [])

                st.markdown(f"**Priority {priority}: {title}**")
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