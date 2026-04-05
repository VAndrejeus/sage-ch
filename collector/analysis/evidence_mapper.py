from typing import Any, Dict, List


def map_evidence(rule: Any, host_record: Dict[str, Any]) -> List[Dict[str, Any]]:
    condition = getattr(rule, "condition", "")
    evidence: List[Dict[str, Any]] = []

    if condition == "missing_update_data":
        evidence.append({
            "field": "update_assessment",
            "value": get_update_data(host_record),
            "reason": "Update assessment data is missing or empty.",
        })

    elif condition == "missing_security_updates":
        missing_updates = get_missing_updates(host_record)
        evidence.append({
            "field": "missing_updates",
            "value": missing_updates,
            "reason": "Host reports missing security updates.",
        })
        evidence.append({
            "field": "missing_update_count",
            "value": len(missing_updates),
            "reason": "Count of missing security updates.",
        })

    elif condition == "missing_software_inventory":
        evidence.append({
            "field": "software",
            "value": get_software_inventory(host_record),
            "reason": "Software inventory is missing or empty.",
        })

    elif condition == "missing_host_identity":
        evidence.append({
            "field": "hostname",
            "value": get_hostname(host_record),
            "reason": "Collected hostname value.",
        })
        evidence.append({
            "field": "platform",
            "value": get_platform(host_record),
            "reason": "Collected platform value.",
        })
        evidence.append({
            "field": "primary_ip",
            "value": get_primary_ip(host_record),
            "reason": "Collected primary IP value.",
        })

    elif condition == "uckg_alignment_missing":
        evidence.append({
            "field": "uckg_entity_id",
            "value": get_first_present(
                host_record,
                ["uckg_entity_id", "entity_id", "aligned_entity_id"]
            ),
            "reason": "UCKG alignment field is missing or empty.",
        })

    elif condition == "excessive_interface_count":
        interfaces = get_network_interfaces(host_record)
        threshold = getattr(rule, "metadata", {}).get("threshold", 10)

        evidence.append({
            "field": "network_interfaces",
            "value": interfaces,
            "reason": "Collected network interface list for the host.",
        })
        evidence.append({
            "field": "interface_count",
            "value": len(interfaces),
            "reason": "Total number of discovered interfaces.",
        })
        evidence.append({
            "field": "threshold",
            "value": threshold,
            "reason": "Configured interface threshold for this rule.",
        })

    elif condition == "no_network_interfaces":
        interfaces = get_network_interfaces(host_record)
        evidence.append({
            "field": "network_interfaces",
            "value": interfaces,
            "reason": "No network interfaces detected.",
        })

    elif condition == "no_ipv4_address":
        evidence.append({
            "field": "primary_ip",
            "value": get_primary_ip(host_record),
            "reason": "No valid IPv4 address detected.",
        })

    elif condition == "no_dns_servers":
        dns = host_record.get("network", {}).get("dns_servers", [])
        evidence.append({
            "field": "dns_servers",
            "value": dns,
            "reason": "DNS server list is empty or missing.",
        })

    elif condition == "incomplete_update_status":
        evidence.append({
            "field": "update_status",
            "value": get_update_data(host_record),
            "reason": "Update status fields are incomplete.",
        })

    elif condition == "no_default_gateway":
        gateway = host_record.get("network", {}).get("default_gateway")
        evidence.append({
            "field": "default_gateway",
            "value": gateway,
            "reason": "Default gateway is missing or empty.",
        })

    elif condition == "no_dns_servers":
        dns_servers = host_record.get("network", {}).get("dns_servers", [])
        evidence.append({
            "field": "dns_servers",
            "value": dns_servers,
            "reason": "DNS server list is missing or empty.",
        })

    elif condition == "missing_update_counts":
        evidence.append({
            "field": "update_status",
            "value": get_update_data(host_record),
            "reason": "Update status does not include update count fields.",
        })   
    return evidence


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
    return "" if value is None else str(value).strip().lower()


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
        ["update_status", "update_assessment", "updates", "patch_status"]
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

    network = host.get("network", {})
    nested_interfaces = network.get("interfaces", [])
    if isinstance(nested_interfaces, list):
        return nested_interfaces

    return []


def get_first_present(host: Dict[str, Any], field_names: List[str]) -> Any:
    for field_name in field_names:
        if field_name in host:
            return host.get(field_name)
    return None