from __future__ import annotations

from datetime import datetime
from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape

import pandas as pd


def _clean(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and pd.isna(value):
        return ""
    return str(value)


def _short(value: Any, max_len: int = 220) -> str:
    text = _clean(value)
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _p(value: Any, style):
    from reportlab.platypus import Paragraph

    return Paragraph(escape(_clean(value)), style)


def _severity_counts(findings_df: pd.DataFrame) -> dict[str, int]:
    if findings_df.empty or "severity" not in findings_df.columns:
        return {}

    return findings_df["severity"].fillna("").astype(str).str.lower().value_counts().to_dict()


def _unique_count(df: pd.DataFrame, column: str) -> int:
    if df.empty or column not in df.columns:
        return 0
    return int(df[column].dropna().astype(str).nunique())


def _filter_cve_findings(findings_df: pd.DataFrame) -> pd.DataFrame:
    if findings_df.empty:
        return pd.DataFrame()

    if "finding_type" in findings_df.columns:
        return findings_df[findings_df["finding_type"].fillna("").astype(str) == "Vulnerability"].copy()

    if "cve_id" in findings_df.columns:
        return findings_df[findings_df["cve_id"].fillna("").astype(str).str.strip() != ""].copy()

    return pd.DataFrame()


def _filter_config_findings(findings_df: pd.DataFrame) -> pd.DataFrame:
    if findings_df.empty:
        return pd.DataFrame()

    if "finding_type" in findings_df.columns:
        return findings_df[findings_df["finding_type"].fillna("").astype(str) != "Vulnerability"].copy()

    if "cve_id" in findings_df.columns:
        return findings_df[findings_df["cve_id"].fillna("").astype(str).str.strip() == ""].copy()

    return findings_df.copy()


def _sort_findings_by_severity(findings_df: pd.DataFrame) -> pd.DataFrame:
    if findings_df.empty or "severity" not in findings_df.columns:
        return findings_df

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
    }

    output = findings_df.copy()
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

    if "cvss_score" in output.columns:
        output["_cvss_sort"] = pd.to_numeric(output["cvss_score"], errors="coerce").fillna(0)
        sort_cols.append("_cvss_sort")
        ascending.append(False)

    if "hostname" in output.columns:
        sort_cols.append("hostname")
        ascending.append(True)

    if "title" in output.columns:
        sort_cols.append("title")
        ascending.append(True)

    return output.sort_values(by=sort_cols, ascending=ascending)


def _make_pdf_doc(buffer: BytesIO):
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate

    return SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.55 * inch,
        leftMargin=0.55 * inch,
        topMargin=0.55 * inch,
        bottomMargin=0.55 * inch,
    )


def _styles():
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "SAGETitle",
            parent=base["Title"],
            fontSize=18,
            leading=22,
            spaceAfter=10,
        ),
        "heading": ParagraphStyle(
            "SAGEHeading",
            parent=base["Heading2"],
            fontSize=12,
            leading=15,
            spaceBefore=10,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "SAGEBody",
            parent=base["BodyText"],
            fontSize=9,
            leading=12,
        ),
        "small": ParagraphStyle(
            "SAGESmall",
            parent=base["BodyText"],
            fontSize=7,
            leading=9,
        ),
    }


def _table(data: list[list[Any]], col_widths: list[float]):
    from reportlab.lib import colors
    from reportlab.platypus import Table, TableStyle

    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9ca3af")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _add_software_inventory_snapshot(story: list, styles: dict, software_items: list[dict[str, Any]]) -> None:
    from reportlab.lib.units import inch
    from reportlab.platypus import Spacer

    story.append(_p("Software Inventory Snapshot", styles["heading"]))

    if software_items:
        software_rows = [["Name", "Version", "Arch"]]
        for item in software_items[:40]:
            software_rows.append(
                [
                    _p(_short(item.get("name", ""), 120), styles["small"]),
                    _p(_short(item.get("version", ""), 45), styles["small"]),
                    _p(_short(item.get("arch", ""), 30), styles["small"]),
                ]
            )

        story.append(_table(software_rows, [4.0 * inch, 1.7 * inch, 1.0 * inch]))

        if len(software_items) > 40:
            story.append(Spacer(1, 6))
            story.append(_p(f"Showing first 40 of {len(software_items)} software items.", styles["small"]))
    else:
        story.append(_p("No software inventory was available.", styles["body"]))


def build_host_pdf_report(
    host_record: dict[str, Any],
    software_items: list[dict[str, Any]],
    host_findings: pd.DataFrame,
    ai_data: dict[str, Any],
) -> bytes:
    try:
        from reportlab.lib.units import inch
        from reportlab.platypus import PageBreak, Spacer
    except Exception as exc:
        raise RuntimeError("reportlab is required. Install it with: pip install reportlab") from exc

    buffer = BytesIO()
    doc = _make_pdf_doc(buffer)
    styles = _styles()
    story = []

    hostname = _clean(host_record.get("hostname", "Unknown Host"))
    report_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    cve_findings = _filter_cve_findings(host_findings)
    config_findings = _filter_config_findings(host_findings)

    story.append(_p("SAGE-CH Host Assessment Report", styles["title"]))
    story.append(_p(f"Host: {hostname}", styles["body"]))
    story.append(_p(f"Generated: {report_time}", styles["body"]))
    story.append(Spacer(1, 8))

    host_rows = [
        ["Field", "Value"],
        ["Hostname", _clean(host_record.get("hostname"))],
        ["IP Address", _clean(host_record.get("ip"))],
        ["Platform", _clean(host_record.get("platform"))],
        ["OS Name", _clean(host_record.get("os_name"))],
        ["OS Version", _clean(host_record.get("os_version"))],
    ]

    story.append(_p("Host Summary", styles["heading"]))
    story.append(_table(host_rows, [1.6 * inch, 5.1 * inch]))
    story.append(Spacer(1, 8))

    severity_counts = _severity_counts(host_findings)
    cve_severity_counts = _severity_counts(cve_findings)

    metrics_rows = [
        ["Metric", "Value"],
        ["Total Findings", str(len(host_findings))],
        ["Configuration Findings", str(len(config_findings))],
        ["CVE Findings", str(len(cve_findings))],
        ["Critical Findings", str(severity_counts.get("critical", 0))],
        ["High Findings", str(severity_counts.get("high", 0))],
        ["Critical CVEs", str(cve_severity_counts.get("critical", 0))],
        ["High CVEs", str(cve_severity_counts.get("high", 0))],
        ["Software Items", str(len(software_items))],
    ]

    story.append(_p("Assessment Summary", styles["heading"]))
    story.append(_table(metrics_rows, [2.0 * inch, 4.7 * inch]))
    story.append(Spacer(1, 8))

    story.append(_p("Configuration Findings", styles["heading"]))
    if not config_findings.empty:
        sorted_config = _sort_findings_by_severity(config_findings)

        finding_rows = [["CIS Control", "Title", "Severity", "Recommendation"]]
        for _, row in sorted_config.head(60).iterrows():
            finding_rows.append(
                [
                    _p(_short(row.get("cis_controls", ""), 80), styles["small"]),
                    _p(_short(row.get("title", ""), 90), styles["small"]),
                    _p(_clean(row.get("severity", "")).title(), styles["small"]),
                    _p(_short(row.get("recommendation", ""), 160), styles["small"]),
                ]
            )

        story.append(_table(finding_rows, [1.2 * inch, 2.0 * inch, 0.8 * inch, 2.7 * inch]))

        if len(sorted_config) > 60:
            story.append(Spacer(1, 6))
            story.append(_p(f"Showing first 60 of {len(sorted_config)} configuration findings.", styles["small"]))
    else:
        story.append(_p("No configuration findings were identified for this host.", styles["body"]))

    story.append(Spacer(1, 8))

    story.append(_p("CVE Vulnerability Findings", styles["heading"]))
    if not cve_findings.empty:
        sorted_cves = _sort_findings_by_severity(cve_findings)

        cve_rows = [["CIS Control", "Component", "CVE", "Severity", "CVSS", "Recommendation"]]
        for _, row in sorted_cves.head(40).iterrows():
            cve_rows.append(
                [
                    _p(_short(row.get("cis_controls", ""), 55), styles["small"]),
                    _p(_short(row.get("software_name", ""), 75), styles["small"]),
                    _p(_short(row.get("cve_id", ""), 35), styles["small"]),
                    _p(_clean(row.get("severity", "")).title(), styles["small"]),
                    _p(_clean(row.get("cvss_score", "")), styles["small"]),
                    _p(_short(row.get("recommendation", ""), 120), styles["small"]),
                ]
            )

        story.append(
            _table(
                cve_rows,
                [0.9 * inch, 1.1 * inch, 0.85 * inch, 0.65 * inch, 0.45 * inch, 2.75 * inch],
            )
        )

        if len(sorted_cves) > 40:
            story.append(Spacer(1, 6))
            story.append(_p(f"Showing first 40 of {len(sorted_cves)} CVE findings.", styles["small"]))
    else:
        story.append(_p("No CVE vulnerability findings were identified for this host.", styles["body"]))

    story.append(Spacer(1, 8))
    _add_software_inventory_snapshot(story, styles, software_items)

    story.append(PageBreak())

    story.append(_p("AI Explanation and Remediation", styles["heading"]))

    explanation = ai_data.get("explanation") if isinstance(ai_data, dict) else None
    remediation = ai_data.get("remediation", []) if isinstance(ai_data, dict) else []

    if explanation:
        story.append(_p("Overall Explanation", styles["heading"]))
        story.append(_p(explanation.get("overall_explanation", ""), styles["body"]))

        drivers = explanation.get("key_risk_drivers", [])
        if drivers:
            story.append(_p("Key Risk Drivers", styles["heading"]))
            for item in drivers:
                story.append(_p(f"- {item}", styles["body"]))
    else:
        story.append(_p("No AI explanation was available for this host.", styles["body"]))

    if remediation:
        story.append(_p("Prioritized Remediation", styles["heading"]))
        for item in remediation:
            story.append(_p(f"Priority {_clean(item.get('priority'))}: {_clean(item.get('title'))}", styles["body"]))

            reason = item.get("reason", "")
            if reason:
                story.append(_p(reason, styles["body"]))

            actions = item.get("actions", [])
            for action in actions:
                story.append(_p(f"- {action}", styles["body"]))

            story.append(Spacer(1, 6))
    else:
        story.append(_p("No remediation plan was available for this host.", styles["body"]))

    if not cve_findings.empty:
        story.append(_p("CVE Risk Notes", styles["heading"]))
        sorted_cves = _sort_findings_by_severity(cve_findings)
        for _, row in sorted_cves.head(5).iterrows():
            story.append(_p(f"{_clean(row.get('cve_id'))}: {_clean(row.get('ai_explanation'))}", styles["body"]))
            story.append(Spacer(1, 4))

    doc.build(story)
    return buffer.getvalue()


def build_system_pdf_report(
    findings_df: pd.DataFrame,
    hosts_df: pd.DataFrame,
    assessment_summary: dict[str, Any] | None = None,
) -> bytes:
    try:
        from reportlab.lib.units import inch
        from reportlab.platypus import PageBreak, Spacer
    except Exception as exc:
        raise RuntimeError("reportlab is required. Install it with: pip install reportlab") from exc

    buffer = BytesIO()
    doc = _make_pdf_doc(buffer)
    styles = _styles()
    story = []

    assessment_summary = assessment_summary or {}
    report_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    severity_counts = _severity_counts(findings_df)

    cve_findings = _filter_cve_findings(findings_df)
    config_findings = _filter_config_findings(findings_df)
    cve_severity_counts = _severity_counts(cve_findings)

    total_hosts = len(hosts_df) if not hosts_df.empty else assessment_summary.get("total_hosts", 0)
    total_findings = len(findings_df)
    affected_hosts = _unique_count(findings_df, "hostname")
    affected_cve_hosts = _unique_count(cve_findings, "hostname")
    cis_mappings = _unique_count(findings_df, "cis_controls")
    affected_products = _unique_count(cve_findings, "software_name")
    unique_cves = _unique_count(cve_findings, "cve_id")

    story.append(_p("SAGE-CH System Assessment Report", styles["title"]))
    story.append(_p(f"Generated: {report_time}", styles["body"]))
    story.append(_p("Scope: Full system findings summary, including configuration findings and CVE vulnerability findings.", styles["body"]))
    story.append(Spacer(1, 8))

    summary_rows = [
        ["Metric", "Value"],
        ["Total Hosts", str(total_hosts)],
        ["Affected Hosts", str(affected_hosts)],
        ["Total Findings", str(total_findings)],
        ["Configuration Findings", str(len(config_findings))],
        ["CVE Findings", str(len(cve_findings))],
        ["Unique CVEs", str(unique_cves)],
        ["Products With CVEs", str(affected_products)],
        ["Hosts With CVEs", str(affected_cve_hosts)],
        ["Critical Findings", str(severity_counts.get("critical", 0))],
        ["High Findings", str(severity_counts.get("high", 0))],
        ["Critical CVEs", str(cve_severity_counts.get("critical", 0))],
        ["High CVEs", str(cve_severity_counts.get("high", 0))],
        ["CIS Control Mappings", str(cis_mappings)],
    ]

    story.append(_p("Executive Summary", styles["heading"]))
    story.append(_table(summary_rows, [2.2 * inch, 4.5 * inch]))
    story.append(Spacer(1, 8))

    if not findings_df.empty and "severity" in findings_df.columns:
        story.append(_p("Findings by Severity", styles["heading"]))
        severity_rows = [["Severity", "All Findings", "CVE Findings"]]
        for severity in ["critical", "high", "medium", "low"]:
            severity_rows.append(
                [
                    severity.title(),
                    str(severity_counts.get(severity, 0)),
                    str(cve_severity_counts.get(severity, 0)),
                ]
            )
        story.append(_table(severity_rows, [2.2 * inch, 2.2 * inch, 2.3 * inch]))
        story.append(Spacer(1, 8))

    if not findings_df.empty and "hostname" in findings_df.columns:
        story.append(_p("All Findings by Host", styles["heading"]))
        host_counts = findings_df["hostname"].fillna("Unknown").astype(str).value_counts().head(20)
        host_rows = [["Host", "Findings"]]
        for hostname, count in host_counts.items():
            host_rows.append([_short(hostname, 80), str(count)])
        story.append(_table(host_rows, [4.7 * inch, 2.0 * inch]))
        story.append(Spacer(1, 8))

    if not findings_df.empty and "cis_controls" in findings_df.columns:
        story.append(_p("Findings by CIS Control", styles["heading"]))
        cis_counts = findings_df["cis_controls"].fillna("Unmapped").astype(str).value_counts().head(20)
        cis_rows = [["CIS Control", "Findings"]]
        for control, count in cis_counts.items():
            cis_rows.append([_short(control, 120), str(count)])
        story.append(_table(cis_rows, [4.7 * inch, 2.0 * inch]))
        story.append(Spacer(1, 8))

    story.append(PageBreak())

    story.append(_p("Detailed Configuration Findings", styles["heading"]))

    if config_findings.empty:
        story.append(_p("No configuration findings were available for this report.", styles["body"]))
    else:
        sorted_config = _sort_findings_by_severity(config_findings)

        finding_rows = [["Host", "CIS Control", "Title", "Severity", "Recommendation"]]
        for _, row in sorted_config.head(100).iterrows():
            finding_rows.append(
                [
                    _p(_short(row.get("hostname", ""), 70), styles["small"]),
                    _p(_short(row.get("cis_controls", ""), 80), styles["small"]),
                    _p(_short(row.get("title", ""), 90), styles["small"]),
                    _p(_clean(row.get("severity", "")).title(), styles["small"]),
                    _p(_short(row.get("recommendation", ""), 150), styles["small"]),
                ]
            )

        story.append(_table(finding_rows, [1.1 * inch, 1.1 * inch, 1.8 * inch, 0.7 * inch, 2.0 * inch]))

        if len(sorted_config) > 100:
            story.append(Spacer(1, 6))
            story.append(_p(f"Showing first 100 of {len(sorted_config)} configuration findings.", styles["small"]))

    story.append(PageBreak())

    if not cve_findings.empty:
        story.append(_p("CVE Findings by Product", styles["heading"]))
        product_counts = cve_findings["software_name"].fillna("Unknown").astype(str).value_counts().head(15)
        product_rows = [["Product", "CVE Findings"]]
        for product, count in product_counts.items():
            product_rows.append([_short(product, 100), str(count)])
        story.append(_table(product_rows, [4.7 * inch, 2.0 * inch]))
        story.append(Spacer(1, 8))

        if "hostname" in cve_findings.columns:
            story.append(_p("CVE Findings by Host", styles["heading"]))
            cve_host_counts = cve_findings["hostname"].fillna("Unknown").astype(str).value_counts().head(20)
            cve_host_rows = [["Host", "CVE Findings"]]
            for hostname, count in cve_host_counts.items():
                cve_host_rows.append([_short(hostname, 80), str(count)])
            story.append(_table(cve_host_rows, [4.7 * inch, 2.0 * inch]))
            story.append(Spacer(1, 8))

    story.append(_p("Top CVE Vulnerability Findings", styles["heading"]))

    if cve_findings.empty:
        story.append(_p("No CVE vulnerability findings were available for this report.", styles["body"]))
    else:
        sorted_cves = _sort_findings_by_severity(cve_findings)

        cve_rows = [["Host", "CIS Control", "Component", "CVE", "Severity", "CVSS", "Recommendation"]]
        for _, row in sorted_cves.head(100).iterrows():
            cve_rows.append(
                [
                    _p(_short(row.get("hostname", ""), 55), styles["small"]),
                    _p(_short(row.get("cis_controls", ""), 45), styles["small"]),
                    _p(_short(row.get("software_name", ""), 65), styles["small"]),
                    _p(_short(row.get("cve_id", ""), 35), styles["small"]),
                    _p(_clean(row.get("severity", "")).title(), styles["small"]),
                    _p(_clean(row.get("cvss_score", "")), styles["small"]),
                    _p(_short(row.get("recommendation", ""), 110), styles["small"]),
                ]
            )

        story.append(
            _table(
                cve_rows,
                [0.8 * inch, 0.75 * inch, 0.9 * inch, 0.75 * inch, 0.6 * inch, 0.4 * inch, 2.5 * inch],
            )
        )

        if len(sorted_cves) > 100:
            story.append(Spacer(1, 6))
            story.append(_p(f"Showing first 100 of {len(sorted_cves)} CVE findings.", styles["small"]))

    doc.build(story)
    return buffer.getvalue()