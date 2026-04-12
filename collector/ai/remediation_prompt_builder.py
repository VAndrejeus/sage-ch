import json
from typing import Any, Dict, List


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _truncate(value: str, limit: int = 220) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."


def _normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    raw_controls = finding.get("cis_controls", [])
    controls: List[str] = []

    if isinstance(raw_controls, list):
        controls = [str(item).strip() for item in raw_controls if str(item).strip()]
    elif raw_controls:
        controls = [str(raw_controls).strip()]

    return {
        "finding_id": _safe_text(finding.get("finding_id") or finding.get("id")) or "unknown",
        "title": _safe_text(finding.get("title") or finding.get("name")) or "Untitled finding",
        "severity": _safe_text(finding.get("severity")).lower() or "low",
        "category": _safe_text(finding.get("category")) or "unknown",
        "description": _truncate(_safe_text(finding.get("description"))),
        "recommendation": _truncate(_safe_text(finding.get("recommendation"))),
        "cis_controls": controls[:4],
    }


def build_remediation_prompt(
    hostname: str,
    platform: str,
    remediation_title: str,
    reason: str,
    categories: List[str],
    controls: List[str],
    findings: List[Dict[str, Any]],
    max_findings: int = 8,
) -> str:
    normalized_findings = [_normalize_finding(finding) for finding in findings][:max_findings]

    instructions = """
You are generating endpoint remediation guidance for a security assessment item.

Return valid JSON only.
Do not wrap the JSON in markdown.
Do not include any text before or after the JSON.

Required JSON schema:
{
  "actions": ["string", "string", "string"],
  "commands": ["string", "string", "string"],
  "implementation_notes": "string",
  "confidence": "low|medium|high"
}

Rules:
- actions must contain 3 to 5 concrete remediation steps.
- commands must contain 1 to 5 platform-appropriate commands.
- Strongly prefer READ-ONLY and NON-GUI commands.
- Prefer inspection, verification, query, listing, and audit commands.
- Avoid GUI tools such as secpol.msc, gpedit.msc, control.exe, rundll32, mmc, or opening settings panels.
- Avoid destructive or state-changing commands unless they are extremely standard and clearly justified by the findings.
- If exact remediation commands are uncertain, return safe verification commands instead.
- Do not invent registry paths, service names, or control panel applets.
- implementation_notes must be 1 sentence.
- Keep the guidance aligned to the remediation title, findings, and host platform.
- Do not invent settings or software that are not supported by the findings.
- Prefer Windows commands for Windows hosts and Linux commands for Linux hosts.
- Confidence should be high only when the findings strongly support the remediation guidance.
""".strip()

    payload = {
        "host": {
            "hostname": hostname,
            "platform": platform,
        },
        "remediation_item": {
            "title": remediation_title,
            "reason": reason,
            "categories": categories,
            "controls": controls,
        },
        "supporting_findings": normalized_findings,
    }

    return f"{instructions}\n\nInput:\n{json.dumps(payload, indent=2)}"