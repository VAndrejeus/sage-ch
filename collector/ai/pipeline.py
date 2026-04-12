from datetime import datetime, timezone
from typing import Any, Dict, List

from agents.common.utils.json_writer import write_json

from collector.ai.host_explainer import explain_host
from collector.ai.remediation_prioritizer import prioritize_remediation
from collector.ai.report_writer import build_remediation_markdown, generate_ai_output_paths
from collector.ai.risk_grouper import group_findings_by_host


DEFAULT_MODEL = "gemma2:9b"
DEFAULT_ENDPOINT = "http://localhost:11434/api/generate"


def _build_batch_narrative(
    batch_id: str,
    host_explanations: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> Dict[str, Any]:
    sorted_hosts = sorted(
        host_explanations,
        key=lambda item: (
            {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(item.get("risk_level", "low"), 0),
            item.get("finding_count", 0),
        ),
        reverse=True,
    )

    highest_priority_hosts = [item.get("hostname", "unknown") for item in sorted_hosts[:3]]

    top_problem_areas = []
    category_counts = summary.get("category_counts", {})
    if isinstance(category_counts, dict):
        top_problem_areas = [
            category
            for category, _count in sorted(category_counts.items(), key=lambda item: item[1], reverse=True)[:3]
        ]

    if highest_priority_hosts:
        overview = (
            f"This batch shows the highest priority risk on {highest_priority_hosts[0]}, "
            f"with the most common problem areas in {', '.join(top_problem_areas) if top_problem_areas else 'multiple categories'}."
        )
    else:
        overview = "This batch contains no host explanations to prioritize."

    return {
        "batch_id": batch_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overview": overview,
        "highest_priority_hosts": highest_priority_hosts,
        "top_problem_areas": top_problem_areas,
    }


def run_ai_phase_1(
    batch_id: str,
    consolidated: Dict[str, Any],
    findings: List[Dict[str, Any]],
    summary: Dict[str, Any],
    logger: Any = None,
) -> Dict[str, Any]:
    hosts = consolidated.get("hosts", [])
    findings_by_host = group_findings_by_host(findings)

    host_explanations: List[Dict[str, Any]] = []
    remediation_plan: Dict[str, List[Dict[str, Any]]] = {}

    for host in hosts:
        hostname = str(host.get("hostname", "unknown")).strip() or "unknown"
        platform = str(host.get("platform", host.get("source_os", "unknown"))).strip() or "unknown"
        host_findings = findings_by_host.get(hostname, [])

        explanation = explain_host(
            host,
            host_findings,
            model=DEFAULT_MODEL,
            endpoint=DEFAULT_ENDPOINT,
            timeout=120,
            max_findings_for_model=12,
        )
        host_explanations.append(explanation)

        remediation_plan[hostname] = prioritize_remediation(
            hostname=hostname,
            findings=host_findings,
            platform=platform,
            model=DEFAULT_MODEL,
            endpoint=DEFAULT_ENDPOINT,
            timeout=120,
            max_findings_for_model=8,
        )

    batch_narrative = _build_batch_narrative(
        batch_id=batch_id,
        host_explanations=host_explanations,
        summary=summary,
    )

    output_payload = {
        "batch_id": batch_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "batch_narrative": batch_narrative,
        "hosts": host_explanations,
        "remediation_plan": remediation_plan,
    }

    output_paths = generate_ai_output_paths(batch_id)
    remediation_markdown = build_remediation_markdown(
        batch_id=batch_id,
        batch_narrative=batch_narrative,
        host_explanations=host_explanations,
        remediation_plan=remediation_plan,
    )

    write_json(output_paths["host_explanations"], output_payload)

    with open(output_paths["remediation_plan"], "w", encoding="utf-8") as file_handle:
        file_handle.write(remediation_markdown)

    if logger:
        logger.info(
            f"AI Phase 1 complete. "
            f"Host explanations={len(host_explanations)}, "
            f"Remediation hosts={len(remediation_plan)}"
        )
        logger.info(f"AI host explanations written to: {output_paths['host_explanations']}")
        logger.info(f"AI remediation plan written to: {output_paths['remediation_plan']}")

    return {
        "ok": True,
        "batch_id": batch_id,
        "host_count": len(host_explanations),
        "output_paths": output_paths,
    }