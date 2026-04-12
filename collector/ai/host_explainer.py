from typing import Any, Dict, List

from collector.ai.local_llm import LocalLLMError, generate_json
from collector.ai.models import HostExplanation
from collector.ai.prompt_builder import build_host_explainer_prompt
from collector.ai.response_parser import parse_host_explainer_response
from collector.ai.risk_grouper import detect_risk_drivers, summarize_host_findings, top_categories, top_controls


DEFAULT_MODEL = "gemma2:9b"
DEFAULT_ENDPOINT = "http://localhost:11434/api/generate"


def explain_host(
    host_record: Dict[str, Any],
    findings: List[Dict[str, Any]],
    model: str = DEFAULT_MODEL,
    endpoint: str = DEFAULT_ENDPOINT,
    timeout: int = 120,
    max_findings_for_model: int = 12,
) -> Dict[str, Any]:
    hostname = str(host_record.get("hostname", "unknown")).strip() or "unknown"
    platform = str(host_record.get("platform", host_record.get("source_os", "unknown"))).strip() or "unknown"

    summary = summarize_host_findings(hostname, findings)
    fallback_drivers = detect_risk_drivers(findings)

    prompt = build_host_explainer_prompt(
        host_record=host_record,
        findings=findings,
        summary=summary,
        max_findings=max_findings_for_model,
    )

    try:
        raw_response = generate_json(
            prompt=prompt,
            model=model,
            endpoint=endpoint,
            timeout=timeout,
            temperature=0.2,
            num_predict=700,
        )
        parsed = parse_host_explainer_response(
            raw_text=raw_response,
            hostname=hostname,
            risk_level=summary["risk_level"],
            finding_count=summary["finding_count"],
            fallback_drivers=fallback_drivers,
        )
    except LocalLLMError:
        parsed = {
            "overall_explanation": (
                f"{hostname} is rated {summary['risk_level']} because its findings indicate elevated risk "
                f"across {summary['finding_count']} assessed issues."
            ),
            "key_risk_drivers": fallback_drivers[:3] if fallback_drivers else ["Multiple security weaknesses"],
            "confidence": "low",
        }

    explanation = HostExplanation(
        hostname=hostname,
        platform=platform,
        risk_level=summary["risk_level"],
        finding_count=summary["finding_count"],
        top_categories=top_categories(summary["category_counts"]),
        top_controls=top_controls(summary["control_counts"]),
        key_risk_drivers=parsed["key_risk_drivers"],
        overall_explanation=parsed["overall_explanation"],
        supporting_findings=summary["supporting_findings"],
        confidence=parsed["confidence"],
    )

    return explanation.to_dict()