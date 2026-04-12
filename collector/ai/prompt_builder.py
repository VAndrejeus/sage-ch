import json
from collections import Counter
from typing import Any, Dict, List


SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _truncate(value: str, limit: int = 220) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."


def _normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    finding_id = _safe_text(finding.get("finding_id") or finding.get("id")) or "unknown"
    title = _safe_text(finding.get("title") or finding.get("name")) or "Untitled finding"
    severity = _safe_text(finding.get("severity")).lower() or "low"
    category = _safe_text(finding.get("category")) or "unknown"
    description = _truncate(_safe_text(finding.get("description")))
    recommendation = _truncate(_safe_text(finding.get("recommendation")))

    raw_controls = finding.get("cis_controls", [])
    controls: List[str] = []
    if isinstance(raw_controls, list):
        controls = [str(item).strip() for item in raw_controls if str(item).strip()]
    elif raw_controls:
        controls = [str(raw_controls).strip()]

    return {
        "finding_id": finding_id,
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "recommendation": recommendation,
        "cis_controls": controls[:4],
    }


def _top_items(counter: Counter, limit: int = 3) -> List[str]:
    return [name for name, _count in counter.most_common(limit)]


def summarize_findings_for_prompt(findings: List[Dict[str, Any]], max_findings: int = 12) -> Dict[str, Any]:
    normalized = [_normalize_finding(finding) for finding in findings]

    normalized.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 0),
            item["category"],
            item["title"],
        ),
        reverse=True,
    )

    selected = normalized[:max_findings]

    severity_counts = Counter(item["severity"] for item in normalized)
    category_counts = Counter(item["category"] for item in normalized)
    control_counts = Counter()

    for item in normalized:
        for control in item["cis_controls"]:
            control_counts[control] += 1

    return {
        "finding_count": len(normalized),
        "severity_counts": dict(severity_counts),
        "top_categories": _top_items(category_counts, 3),
        "top_controls": _top_items(control_counts, 3),
        "findings_for_model": selected,
    }


def build_host_explainer_prompt(
    host_record: Dict[str, Any],
    findings: List[Dict[str, Any]],
    summary: Dict[str, Any],
    max_findings: int = 12,
) -> str:
    hostname = _safe_text(host_record.get("hostname")) or "unknown"
    platform = _safe_text(host_record.get("platform") or host_record.get("source_os")) or "unknown"

    prompt_summary = summarize_findings_for_prompt(findings, max_findings=max_findings)

    instructions = """
You are analyzing endpoint security assessment findings for a single host.

Return valid JSON only.
Do not wrap the JSON in markdown.
Do not include any text before or after the JSON.

Required JSON schema:
{
  "overall_explanation": "string",
  "key_risk_drivers": ["string", "string", "string"],
  "confidence": "low|medium|high"
}

Rules:
- overall_explanation must be 1 sentence.
- key_risk_drivers must contain 2 or 3 short phrases.
- Use the host summary and findings provided.
- Do not invent tools, users, or settings that are not present.
- Focus on the most important risk themes, not every detail.
- Confidence should be:
  - high when the evidence is strong and consistent
  - medium when evidence is adequate but partial
  - low when evidence is sparse or ambiguous
""".strip()

    payload = {
        "host": {
            "hostname": hostname,
            "platform": platform,
            "derived_risk_level": summary.get("risk_level", "unknown"),
            "finding_count": summary.get("finding_count", len(findings)),
            "top_categories": prompt_summary["top_categories"],
            "top_controls": prompt_summary["top_controls"],
            "severity_counts": prompt_summary["severity_counts"],
        },
        "findings": prompt_summary["findings_for_model"],
    }

    return f"{instructions}\n\nInput:\n{json.dumps(payload, indent=2)}"