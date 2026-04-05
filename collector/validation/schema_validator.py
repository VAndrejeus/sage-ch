from typing import Any, Dict, List

REQUIRED_TOP_LEVEL_FIELDS = [
    "project",
    "timestamp_utc",
    "agent",
    "host_info",
    "software_inventory",
    "update_status",
]

REQUIRED_AGENT_FIELDS = [
    "os",
]

REQUIRED_HOST_INFO_FIELDS = [
    "hostname",
    "os_name",
    "os_version",
]

def _check_required_fields(obj: Dict[str, Any], required_fields: List[str], prefix: str) -> List[str]:
    errors: List[str] = []

    for field in required_fields:
        if field not in obj:
            errors.append(f"Missing {prefix} field: {field}")

    return errors

def validate_report(report: Dict[str, Any]) -> Dict[str, Any]:
    errors: List[str] = []

    if not isinstance(report, dict):
        return {
            "ok": False,
            "errors": ["Report is not a dictionary."]
        }

    errors.extend(_check_required_fields(report, REQUIRED_TOP_LEVEL_FIELDS, "top-level"))

    agent = report.get("agent")
    if isinstance(agent, dict):
        errors.extend(_check_required_fields(agent, REQUIRED_AGENT_FIELDS, "agent"))
    else:
        errors.append("Field 'agent' is missing or not a dictionary.")

    host_info = report.get("host_info")
    if isinstance(host_info, dict):
        errors.extend(_check_required_fields(host_info, REQUIRED_HOST_INFO_FIELDS, "host_info"))
    else:
        errors.append("Field 'host_info' is missing or not a dictionary.")

    return {
        "ok": len(errors) == 0,
        "errors": errors
    }