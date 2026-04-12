from datetime import datetime, timezone
from typing import Any, Dict, List


def _timestamp_suffix() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")


def generate_ai_output_paths(batch_id: str) -> Dict[str, str]:
    timestamp = _timestamp_suffix()
    safe_batch_id = batch_id.replace(":", "_").replace("/", "_").replace("\\", "_")

    return {
        "host_explanations": f"collector/output/ai_host_explanations_{safe_batch_id}_{timestamp}.json",
        "remediation_plan": f"collector/output/ai_remediation_plan_{safe_batch_id}_{timestamp}.md",
    }


def build_remediation_markdown(
    batch_id: str,
    batch_narrative: Dict[str, Any],
    host_explanations: List[Dict[str, Any]],
    remediation_plan: Dict[str, List[Dict[str, Any]]],
) -> str:
    lines: List[str] = []

    lines.append("# AI Remediation Plan")
    lines.append("")
    lines.append("## Batch")
    lines.append(f"- Batch ID: {batch_id}")
    lines.append(f"- Overview: {batch_narrative.get('overview', '')}")
    lines.append("")

    if batch_narrative.get("highest_priority_hosts"):
        lines.append("## Highest Priority Hosts")
        for host in batch_narrative["highest_priority_hosts"]:
            lines.append(f"- {host}")
        lines.append("")

    for explanation in host_explanations:
        hostname = explanation.get("hostname", "unknown")
        lines.append(f"## Host: {hostname}")
        lines.append(f"- Risk Level: {explanation.get('risk_level', 'unknown')}")
        lines.append(f"- Findings: {explanation.get('finding_count', 0)}")
        lines.append(f"- Explanation: {explanation.get('overall_explanation', '')}")

        drivers = explanation.get("key_risk_drivers", [])
        if drivers:
            lines.append("- Key Risk Drivers:")
            for driver in drivers:
                lines.append(f"  - {driver}")

        lines.append("")

        for item in remediation_plan.get(hostname, []):
            lines.append(f"### Priority {item.get('priority', '?')}")
            lines.append(item.get("title", ""))
            lines.append(f"- Reason: {item.get('reason', '')}")

            categories = item.get("categories", [])
            if categories:
                lines.append(f"- Categories: {', '.join(categories)}")

            controls = item.get("controls", [])
            if controls:
                lines.append(f"- Controls: {', '.join(controls)}")

            finding_ids = item.get("affected_findings", [])
            if finding_ids:
                lines.append(f"- Affected Findings: {', '.join(finding_ids)}")

            actions = item.get("actions", [])
            if actions:
                lines.append("- Actions:")
                for action in actions:
                    lines.append(f"  - {action}")

            commands = item.get("commands", [])
            if commands:
                lines.append("- Commands:")
                for command in commands:
                    lines.append(f"  - `{command}`")

            implementation_notes = str(item.get("implementation_notes", "")).strip()
            if implementation_notes:
                lines.append(f"- Implementation Notes: {implementation_notes}")

            confidence = str(item.get("confidence", "")).strip()
            if confidence:
                lines.append(f"- Confidence: {confidence}")

            lines.append("")

    return "\n".join(lines).rstrip() + "\n"