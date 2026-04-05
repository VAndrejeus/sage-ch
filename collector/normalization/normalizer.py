from typing import Any, Dict, List

def _build_host_id(report: Dict[str, Any]) -> str:
    agent = report.get("agent", {})
    host_info = report.get("host_info", {})

    os_name = str(agent.get("os", "unknown")).lower()
    hostname = str(host_info.get("hostname", "unknown"))

    return f"{os_name}-{hostname}"

def normalize_report(report: Dict[str, Any], source_path: str) -> Dict[str, Any]:
    agent = report.get("agent", {})
    host_info = report.get("host_info", {})
    software_inventory = report.get("software_inventory", {})
    update_status = report.get("update_status", {})
    security_config = report.get("security_config", {})
    account_info = report.get("account_info", {})
    audit_policy = report.get("audit_policy", {})
    backup_info = report.get("backup_info", {})

    normalized = {
        "host_id": _build_host_id(report),
        "source_os": agent.get("os"),
        "hostname": host_info.get("hostname"),
        "os_name": host_info.get("os_name"),
        "os_version": host_info.get("os_version"),
        "platform": host_info.get("platform"),
        "network": host_info.get("network", {}),
        "software": software_inventory.get("items", []),
        "update_status": update_status,
        "security_config": security_config,
        "account_info": account_info,
        "audit_policy": audit_policy,
        "backup_info": backup_info,
        "source_report": {
            "timestamp_utc": report.get("timestamp_utc"),
            "path": source_path,
        },
    }

    return normalized