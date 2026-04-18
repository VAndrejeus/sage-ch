from __future__ import annotations

import pandas as pd


def build_dashboard_metrics(hosts_df: pd.DataFrame, findings_df: pd.DataFrame, assessment_summary: dict | None = None) -> dict:
    assessment_summary = assessment_summary or {}

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    if not findings_df.empty and "severity" in findings_df.columns:
        sev = findings_df["severity"].fillna("").astype(str).str.lower()
        for key in severity_counts:
            severity_counts[key] = int((sev == key).sum())

    total_hosts = int(len(hosts_df)) if not hosts_df.empty else int(assessment_summary.get("total_hosts", 0))
    total_findings = int(len(findings_df)) if not findings_df.empty else int(assessment_summary.get("total_findings", 0))

    latest_batch_id = None
    if assessment_summary:
        latest_batch_id = assessment_summary.get("batch_id")

    metrics = {
        "total_hosts": total_hosts,
        "managed_hosts": int(hosts_df["managed"].fillna(False).astype(bool).sum()) if not hosts_df.empty and "managed" in hosts_df.columns else total_hosts,
        "discovered_hosts": int(hosts_df["discovered"].fillna(False).astype(bool).sum()) if not hosts_df.empty and "discovered" in hosts_df.columns else 0,
        "total_findings": total_findings,
        "total_exposed_services": 0,
        "latest_batch_id": latest_batch_id,
        "severity_counts": severity_counts,
    }

    return metrics