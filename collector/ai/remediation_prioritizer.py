from typing import Any, Dict, List

from collector.ai.models import RemediationItem
from collector.ai.remediation_ai import enrich_remediation_item
from collector.ai.risk_grouper import build_remediation_candidates


def _build_reason(title: str, findings: List[Dict[str, Any]]) -> str:
    categories = sorted({
        str(finding.get("category", "")).strip()
        for finding in findings
        if str(finding.get("category", "")).strip()
    })

    severities = sorted({
        str(finding.get("severity", "")).lower().strip()
        for finding in findings
        if str(finding.get("severity", "")).strip()
    })

    category_text = ", ".join(categories) if categories else "multiple issue areas"
    severity_text = ", ".join(severities) if severities else "multiple severities"

    return (
        f"{title} should be prioritized because it reduces findings across "
        f"{category_text} and addresses {severity_text} exposure at once."
    )


def prioritize_remediation(
    hostname: str,
    findings: List[Dict[str, Any]],
    platform: str = "unknown",
    model: str = "gemma2:9b",
    endpoint: str = "http://localhost:11434/api/generate",
    timeout: int = 120,
    max_findings_for_model: int = 8,
) -> List[Dict[str, Any]]:
    candidates = build_remediation_candidates(findings)
    results: List[Dict[str, Any]] = []

    for index, candidate in enumerate(candidates[:5], start=1):
        affected_findings: List[str] = []
        candidate_findings = candidate["findings"]

        for finding in candidate_findings:
            finding_id = finding.get("finding_id")
            if isinstance(finding_id, str) and finding_id.strip():
                affected_findings.append(finding_id)

        base_item = RemediationItem(
            hostname=hostname,
            priority=index,
            title=candidate["title"],
            reason=_build_reason(candidate["title"], candidate_findings),
            affected_findings=affected_findings[:8],
            categories=candidate["categories"],
            controls=candidate["controls"],
            actions=[],
            commands=[],
            implementation_notes="",
            confidence="medium",
        ).to_dict()

        enriched_item = enrich_remediation_item(
            hostname=hostname,
            platform=platform,
            item=base_item,
            findings=candidate_findings,
            model=model,
            endpoint=endpoint,
            timeout=timeout,
            max_findings_for_model=max_findings_for_model,
        )

        results.append(enriched_item)

    return results