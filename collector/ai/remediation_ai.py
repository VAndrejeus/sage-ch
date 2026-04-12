from typing import Any, Dict, List

from collector.ai.local_llm import LocalLLMError, generate_json
from collector.ai.remediation_prompt_builder import build_remediation_prompt
from collector.ai.remediation_response_parser import parse_remediation_response


DEFAULT_MODEL = "gemma2:9b"
DEFAULT_ENDPOINT = "http://localhost:11434/api/generate"


def enrich_remediation_item(
    hostname: str,
    platform: str,
    item: Dict[str, Any],
    findings: List[Dict[str, Any]],
    model: str = DEFAULT_MODEL,
    endpoint: str = DEFAULT_ENDPOINT,
    timeout: int = 120,
    max_findings_for_model: int = 8,
) -> Dict[str, Any]:
    prompt = build_remediation_prompt(
        hostname=hostname,
        platform=platform,
        remediation_title=str(item.get("title", "")).strip(),
        reason=str(item.get("reason", "")).strip(),
        categories=item.get("categories", []) if isinstance(item.get("categories"), list) else [],
        controls=item.get("controls", []) if isinstance(item.get("controls"), list) else [],
        findings=findings[:max_findings_for_model],
        max_findings=max_findings_for_model,
    )

    try:
        raw_response = generate_json(
            prompt=prompt,
            model=model,
            endpoint=endpoint,
            timeout=timeout,
            temperature=0.2,
            num_predict=900,
        )
        enriched = parse_remediation_response(
            raw_text=raw_response,
            title=str(item.get("title", "")).strip(),
            platform=platform,
        )
    except LocalLLMError:
        enriched = parse_remediation_response(
            raw_text="{}",
            title=str(item.get("title", "")).strip(),
            platform=platform,
        )

    result = dict(item)
    result["actions"] = enriched["actions"]
    result["commands"] = enriched["commands"]
    result["implementation_notes"] = enriched["implementation_notes"]
    result["confidence"] = enriched["confidence"]
    return result