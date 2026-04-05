from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    finding_id: str
    rule_id: str
    title: str
    severity: str
    category: str
    status: str
    hostname: str
    platform: str
    ip_address: Optional[str]
    description: str
    expected: str
    recommendation: str
    cis_controls: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def build_finding(
    finding_id: str,
    rule: Any,
    host_record: Dict[str, Any],
    evidence: Optional[List[Dict[str, Any]]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    status: str = "open",
) -> Dict[str, Any]:
    return Finding(
        finding_id=finding_id,
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        status=status,
        hostname=get_hostname(host_record),
        platform=get_platform(host_record),
        ip_address=get_primary_ip(host_record),
        description=rule.description,
        expected=rule.expected,
        recommendation=rule.recommendation,
        cis_controls=list(rule.cis_controls),
        evidence=evidence or [],
        metadata=metadata or {},
    ).to_dict()


def get_hostname(host: Dict[str, Any]) -> str:
    value = get_first_present(
        host,
        ["hostname", "host_name", "device_name", "endpoint_name"]
    )
    return "unknown" if value is None or str(value).strip() == "" else str(value).strip()


def get_platform(host: Dict[str, Any]) -> str:
    value = get_first_present(
        host,
        ["platform", "os_family", "os_type"]
    )
    return "unknown" if value is None or str(value).strip() == "" else str(value).strip().lower()


def get_primary_ip(host: Dict[str, Any]) -> str:
    direct_ip = get_first_present(
        host,
        ["primary_ip", "ip_address", "ipv4", "primary_ipv4"]
    )
    if direct_ip is not None and str(direct_ip).strip():
        return str(direct_ip).strip()

    network = host.get("network", {})
    interfaces = network.get("interfaces", [])

    if isinstance(interfaces, list):
        for interface in interfaces:
            if not isinstance(interface, dict):
                continue

            ipv4_values = interface.get("ipv4", [])
            if isinstance(ipv4_values, list) and len(ipv4_values) > 0:
                first_ip = ipv4_values[0]
                if first_ip is not None and str(first_ip).strip():
                    return str(first_ip).strip()

            candidate = (
                interface.get("ip_address")
                or interface.get("address")
            )
            if candidate is not None and str(candidate).strip():
                return str(candidate).strip()

    return ""


def get_first_present(host: Dict[str, Any], field_names: List[str]) -> Any:
    for field_name in field_names:
        if field_name in host:
            return host.get(field_name)
    return None