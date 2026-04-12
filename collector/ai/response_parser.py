import json
import re
from typing import Any, Dict, List


def _fallback_explanation(hostname: str, risk_level: str, finding_count: int, drivers: List[str]) -> Dict[str, Any]:
    if drivers:
        if len(drivers) == 1:
            text = f"{hostname} is rated {risk_level} because its findings are primarily driven by {drivers[0].lower()}."
        elif len(drivers) == 2:
            text = (
                f"{hostname} is rated {risk_level} because its findings are primarily driven by "
                f"{drivers[0].lower()} and {drivers[1].lower()} across {finding_count} findings."
            )
        else:
            text = (
                f"{hostname} is rated {risk_level} because its findings are primarily driven by "
                f"{drivers[0].lower()}, {drivers[1].lower()}, and {drivers[2].lower()} across {finding_count} findings."
            )
    else:
        text = f"{hostname} is rated {risk_level} based on {finding_count} current findings that require review."

    return {
        "overall_explanation": text,
        "key_risk_drivers": drivers[:3] if drivers else ["Multiple security weaknesses"],
        "confidence": "low",
    }


def _clean_driver_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []

    cleaned: List[str] = []
    seen = set()

    for item in value:
        text = str(item).strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(text)
        if len(cleaned) == 3:
            break

    return cleaned


def _extract_json_blob(text: str) -> str:
    raw = text.strip()

    try:
        json.loads(raw)
        return raw
    except Exception:
        pass

    match = re.search(r"\{.*\}", raw, flags=re.DOTALL)
    if match:
        return match.group(0)

    raise ValueError("No JSON object found in host explainer response")


def parse_host_explainer_response(
    raw_text: str,
    hostname: str,
    risk_level: str,
    finding_count: int,
    fallback_drivers: List[str],
) -> Dict[str, Any]:
    try:
        blob = _extract_json_blob(raw_text)
        data = json.loads(blob)

        overall_explanation = str(data.get("overall_explanation", "")).strip()
        key_risk_drivers = _clean_driver_list(data.get("key_risk_drivers"))
        confidence = str(data.get("confidence", "")).strip().lower()

        if not overall_explanation:
            raise ValueError("Missing overall_explanation")

        if confidence not in {"low", "medium", "high"}:
            confidence = "medium"

        if not key_risk_drivers:
            key_risk_drivers = fallback_drivers[:3] if fallback_drivers else ["Multiple security weaknesses"]

        return {
            "overall_explanation": overall_explanation,
            "key_risk_drivers": key_risk_drivers,
            "confidence": confidence,
        }
    except Exception:
        return _fallback_explanation(
            hostname=hostname,
            risk_level=risk_level,
            finding_count=finding_count,
            drivers=fallback_drivers,
        )