from typing import Any, Dict, List

from collector.analysis.evidence_mapper import map_evidence
from collector.analysis.finding_builder import build_finding
from collector.analysis.rules import get_rules_for_platform


def evaluate_hosts(hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    finding_counter = 1

    for host in hosts:
        platform = get_platform(host)
        rules = get_rules_for_platform(platform)

        for rule in rules:
            if rule_matches_host(rule, host):
                finding_id = f"FIND-{finding_counter:04d}"
                evidence = map_evidence(rule, host)

                finding = build_finding(
                    finding_id=finding_id,
                    rule=rule,
                    host_record=host,
                    evidence=evidence,
                )

                findings.append(finding)
                finding_counter += 1

    return findings


def rule_matches_host(rule: Any, host: Dict[str, Any]) -> bool:
    condition = getattr(rule, "condition", "")

    if condition == "missing_update_data":
        update_data = get_update_data(host)
        return is_missing(update_data)

    if condition == "missing_security_updates":
        missing_updates = get_missing_updates(host)
        return len(missing_updates) > 0

    if condition == "missing_software_inventory":
        software_inventory = get_software_inventory(host)
        return is_missing(software_inventory)

    if condition == "missing_host_identity":
        hostname = get_hostname(host)
        platform = get_platform(host)
        primary_ip = get_primary_ip(host)

        return (
            is_blank(hostname)
            or is_blank(platform)
            or is_blank(primary_ip)
        )

    if condition == "uckg_alignment_missing":
        uckg_entity_id = get_first_present(
            host,
            ["uckg_entity_id", "entity_id", "aligned_entity_id"]
        )
        return is_blank(uckg_entity_id)

    if condition == "excessive_interface_count":
        interfaces = get_network_interfaces(host)
        threshold = rule.metadata.get("threshold", 10)
        return len(interfaces) > threshold

    return False


def get_hostname(host: Dict[str, Any]) -> str:
    value = get_first_present(
        host,
        ["hostname", "host_name", "device_name", "endpoint_name"]
    )
    return "" if value is None else str(value).strip()


def get_platform(host: Dict[str, Any]) -> str:
    value = get_first_present(
        host,
        ["platform", "os_family", "os_type"]
    )

    if value is None:
        return ""

    platform = str(value).strip().lower()

    if "windows" in platform:
        return "windows"

    if (
        "linux" in platform
        or "ubuntu" in platform
        or "debian" in platform
        or "centos" in platform
        or "rhel" in platform
        or "fedora" in platform
    ):
        return "linux"

    return platform

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


def get_update_data(host: Dict[str, Any]) -> Any:
    return get_first_present(
        host,
        ["update_assessment", "update_status", "updates", "patch_status"]
    )


def get_missing_updates(host: Dict[str, Any]) -> List[Any]:
    missing_updates = get_first_present(
        host,
        ["missing_updates", "missing_security_updates", "available_updates"]
    )

    if missing_updates is None:
        update_data = get_update_data(host)

        if isinstance(update_data, dict):
            nested = (
                update_data.get("missing_updates")
                or update_data.get("missing_security_updates")
                or update_data.get("available_updates")
            )
            if isinstance(nested, list):
                return nested

        return []

    if isinstance(missing_updates, list):
        return missing_updates

    return []


def get_software_inventory(host: Dict[str, Any]) -> Any:
    return get_first_present(
        host,
        ["software", "software_inventory", "installed_software", "packages", "applications"]
    )


def get_network_interfaces(host: Dict[str, Any]) -> List[Any]:
    interfaces = get_first_present(
        host,
        ["network_interfaces", "interfaces", "ip_addresses", "network_adapters"]
    )

    if isinstance(interfaces, list):
        return interfaces

    return []


def get_first_present(host: Dict[str, Any], field_names: List[str]) -> Any:
    for field_name in field_names:
        if field_name in host:
            return host.get(field_name)
    return None


def is_missing(value: Any) -> bool:
    if value is None:
        return True

    if isinstance(value, str):
        return value.strip() == ""

    if isinstance(value, (list, dict, tuple, set)):
        return len(value) == 0

    return False


def is_blank(value: Any) -> bool:
    if value is None:
        return True

    if isinstance(value, str):
        return value.strip() == ""

    return False