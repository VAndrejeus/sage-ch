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

    if condition == "no_network_interfaces":
        interfaces = get_network_interfaces(host)
        return len(interfaces) == 0

    if condition == "no_ipv4_address":
        ip = get_primary_ip(host)
        return is_blank(ip)

    if condition == "no_dns_servers":
        network = host.get("network", {})
        dns = network.get("dns_servers", [])
        return not isinstance(dns, list) or len(dns) == 0

    if condition == "incomplete_update_status":
        update = get_update_data(host)
        if not isinstance(update, dict):
            return True

        return (
            update.get("updates_available") is None
            and update.get("updates_count") is None
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

    if condition == "no_default_gateway":
        network = host.get("network", {})
        gateway = network.get("default_gateway")
        return gateway is None or str(gateway).strip() == ""

    if condition == "no_dns_servers":
        network = host.get("network", {})
        dns_servers = network.get("dns_servers", [])
        return not isinstance(dns_servers, list) or len(dns_servers) == 0

    if condition == "missing_update_counts":
        update = get_update_data(host)
        if not isinstance(update, dict):
            return True
        return update.get("updates_count") is None

    if condition == "uac_disabled":
        sc = host.get("security_config", {})
        return sc.get("uac", {}).get("enabled") is False

    if condition == "firewall_disabled":
        profiles = host.get("security_config", {}).get("firewall", {}).get("profiles", {})
        return any(
            profiles.get(profile_name, {}).get("enabled") is False
            for profile_name in ["domain", "private", "public"]
        )

    if condition == "defender_realtime_disabled":
        sc = host.get("security_config", {})
        return sc.get("defender", {}).get("realtime_protection_enabled") is False

    if condition == "guest_account_enabled":
        sc = host.get("security_config", {})
        return sc.get("guest_account", {}).get("disabled") is False

    if condition == "rdp_enabled":
        sc = host.get("security_config", {})
        return sc.get("remote_desktop", {}).get("disabled") is False

    if condition == "autorun_enabled":
        sc = host.get("security_config", {})
        return sc.get("autorun", {}).get("disabled") is False

    if condition == "no_inactivity_timeout":
        sc = host.get("security_config", {})
        return sc.get("inactivity_timeout", {}).get("configured") is False

    if condition == "weak_inactivity_timeout":
        timeout = host.get("security_config", {}).get("inactivity_timeout", {}).get("seconds")
        return isinstance(timeout, int) and timeout > 900

    if condition == "password_complexity_disabled":
        sc = host.get("security_config", {})
        return sc.get("password_complexity", {}).get("enabled") is False

    if condition == "weak_password_length":
        length = host.get("security_config", {}).get("account_policy", {}).get("minimum_password_length")
        return isinstance(length, int) and length < 14

    if condition == "weak_password_history":
        history = host.get("security_config", {}).get("account_policy", {}).get("password_history_length")
        return isinstance(history, int) and history < 24

    if condition == "weak_lockout_threshold":
        threshold = host.get("security_config", {}).get("account_policy", {}).get("lockout_threshold")
        return isinstance(threshold, int) and (threshold == 0 or threshold > 10)
    
    if condition == "missing_password_policy":
        policy = host.get("security_config", {}).get("account_policy", {})
        return all(v is None for v in policy.values())

    if condition == "missing_password_complexity":
        pc = host.get("security_config", {}).get("password_complexity", {})
        return pc.get("enabled") is None

    if condition == "missing_autorun_config":
        ar = host.get("security_config", {}).get("autorun", {})
        return ar.get("disabled") is None
    
    if condition == "guest_account_present":
        accounts = host.get("account_info", {}).get("accounts", [])
        return any(a.get("username").lower() == "guest" for a in accounts)

    if condition == "multiple_admin_accounts":
        accounts = host.get("account_info", {}).get("accounts", [])
        admins = [a for a in accounts if a.get("is_admin")]
        return len(admins) > 2

    if condition == "password_never_expires":
        accounts = host.get("account_info", {}).get("accounts", [])
        return any(a.get("password_never_expires") for a in accounts)

    if condition == "disabled_accounts_present":
        accounts = host.get("account_info", {}).get("accounts", [])
        return any(not a.get("enabled") for a in accounts)
    
    if condition == "admin_accounts_exist":
        accounts = host.get("account_info", {}).get("accounts", [])
        return any(a.get("is_admin") for a in accounts)

    if condition == "too_many_admins":
        accounts = host.get("account_info", {}).get("accounts", [])
        admins = [a for a in accounts if a.get("is_admin")]
        return len(admins) > 2

    if condition == "admin_account_without_password_expiry":
        accounts = host.get("account_info", {}).get("accounts", [])
        return any(a.get("is_admin") and a.get("password_never_expires") for a in accounts)
    
    if condition == "audit_logging_not_configured":
        settings = host.get("audit_policy", {}).get("settings", [])
        return len(settings) == 0

    if condition == "no_logon_auditing":
        settings = host.get("audit_policy", {}).get("settings", [])
        return not any("Logon" in s.get("category", "") for s in settings)
    
    if condition == "risky_software_installed":
        software = host.get("software_inventory", {}).get("items", [])
        risky = ["chrome", "firefox", "edge"]

        return any(
            any(r in (item.get("name", "").lower()) for r in risky)
            for item in software
        )
    
    if condition == "defender_disabled":
        defender = host.get("security_config", {}).get("defender", {})
        return defender.get("antivirus_enabled") is False

    if condition == "realtime_protection_disabled":
        defender = host.get("security_config", {}).get("defender", {})
        return defender.get("realtime_protection_enabled") is False

    if condition == "antispyware_disabled":
        defender = host.get("security_config", {}).get("defender", {})
        return defender.get("antispyware_enabled") is False
    
    if condition == "no_backups_detected":
        return not host.get("backup_info", {}).get("shadow_copies_present", False)
    
    if condition == "no_multiple_interfaces":
        interfaces = host.get("host_info", {}).get("network", {}).get("interfaces", [])
        return len(interfaces) < 1
    
    if condition == "no_security_tools_detected":
        software = host.get("software_inventory", {}).get("items", [])
        return not any(
            "defender" in (s.get("name", "").lower()) or
            "security" in (s.get("name", "").lower())
            for s in software
        )
    
    if condition == "third_party_software_present":
        software = host.get("software_inventory", {}).get("items", [])
        return any(
            "vpn" in (s.get("name", "").lower()) or
            "virtualbox" in (s.get("name", "").lower())
            for s in software
        )
    
    if condition == "many_installed_applications":
        software = host.get("software_inventory", {}).get("items", [])
        return len(software) > 50

    if condition == "developer_tools_installed":
        software = host.get("software_inventory", {}).get("items", [])
        risky = ["python", "git", "wsl"]

        return any(
            any(r in (s.get("name", "").lower()) for r in risky)
            for s in software
        )
    
    if condition == "insufficient_audit_events":
        settings = host.get("audit_policy", {}).get("settings", [])
        return len(settings) < 5

    if condition == "no_backup_and_logs":
        backup = host.get("backup_info", {}).get("shadow_copies_present", False)
        logs = host.get("audit_policy", {}).get("settings", [])
        return not backup or len(logs) == 0
    
    if condition == "high_vulnerability_density":
        findings = host.get("findings", [])
        return len(findings) > 10
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