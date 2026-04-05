from typing import Any, Dict, List


def build_assessment_summary(
    consolidated_dataset: Dict[str, Any],
    findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    hosts = consolidated_dataset.get("hosts", [])

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    category_counts: Dict[str, int] = {}
    cis_control_counts: Dict[str, int] = {}

    affected_hosts = set()

    for finding in findings:
        severity = str(finding.get("severity", "")).lower()
        category = finding.get("category", "unknown")
        hostname = finding.get("hostname", "unknown")
        controls = finding.get("cis_controls", [])

        if severity in severity_counts:
            severity_counts[severity] += 1

        category_counts[category] = category_counts.get(category, 0) + 1
        affected_hosts.add(hostname)

        for control in controls:
            cis_control_counts[control] = cis_control_counts.get(control, 0) + 1

    return {
        "total_hosts": len(hosts),
        "total_findings": len(findings),
        "affected_hosts": len(affected_hosts),
        "severity_counts": severity_counts,
        "category_counts": dict(sorted(category_counts.items())),
        "cis_control_counts": dict(sorted(cis_control_counts.items())),
    }


def build_scoreboard_markdown(
    consolidated_dataset: Dict[str, Any],
    findings: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> str:
    lines: List[str] = []

    lines.append("# SAGE-CH Assessment Scoreboard")
    lines.append("")

    lines.append("## Overview")
    lines.append(f"- Total hosts assessed: {summary.get('total_hosts', 0)}")
    lines.append(f"- Total findings: {summary.get('total_findings', 0)}")
    lines.append(f"- Affected hosts: {summary.get('affected_hosts', 0)}")
    lines.append("")

    severity_counts = summary.get("severity_counts", {})
    lines.append("## Findings by Severity")
    lines.append(f"- Critical: {severity_counts.get('critical', 0)}")
    lines.append(f"- High: {severity_counts.get('high', 0)}")
    lines.append(f"- Medium: {severity_counts.get('medium', 0)}")
    lines.append(f"- Low: {severity_counts.get('low', 0)}")
    lines.append("")

    category_counts = summary.get("category_counts", {})
    lines.append("## Findings by Category")
    if category_counts:
        for category, count in category_counts.items():
            lines.append(f"- {category}: {count}")
    else:
        lines.append("- None")
    lines.append("")

    cis_control_counts = summary.get("cis_control_counts", {})
    lines.append("## Findings by CIS Control")
    if cis_control_counts:
        for control, count in cis_control_counts.items():
            lines.append(f"- {control}: {count}")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Detailed Findings")
    if not findings:
        lines.append("No findings identified.")
        lines.append("")
        return "\n".join(lines)

    for index, finding in enumerate(findings, start=1):
        lines.append(f"### {index}. {finding.get('title', 'Untitled Finding')}")
        lines.append(f"- Finding ID: {finding.get('finding_id', 'unknown')}")
        lines.append(f"- Rule ID: {finding.get('rule_id', 'unknown')}")
        lines.append(f"- Severity: {finding.get('severity', 'unknown')}")
        lines.append(f"- Category: {finding.get('category', 'unknown')}")
        lines.append(f"- Hostname: {finding.get('hostname', 'unknown')}")
        lines.append(f"- Platform: {finding.get('platform', 'unknown')}")
        lines.append(f"- IP Address: {finding.get('ip_address', 'unknown')}")
        lines.append(f"- Status: {finding.get('status', 'unknown')}")
        lines.append(f"- Description: {finding.get('description', '')}")
        lines.append(f"- Expected: {finding.get('expected', '')}")
        lines.append(f"- Recommendation: {finding.get('recommendation', '')}")

        controls = finding.get("cis_controls", [])
        if controls:
            lines.append(f"- CIS Controls: {', '.join(controls)}")
        else:
            lines.append("- CIS Controls: None")

        evidence = finding.get("evidence", [])
        if evidence:
            lines.append("- Evidence:")
            for item in evidence:
                field_name = item.get("field", "unknown")
                value = item.get("value")
                reason = item.get("reason", "")
                lines.append(f"  - {field_name}: {value} ({reason})")
        else:
            lines.append("- Evidence: None")

        lines.append("")

    return "\n".join(lines)