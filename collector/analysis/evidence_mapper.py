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
        dns_servers = host_record.get("network", {}).get("dns_servers", [])
        evidence.append({
            "field": "dns_servers",
            "value": dns_servers,
            "reason": "DNS server list is missing or empty.",
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

    elif condition == "missing_update_counts":
        evidence.append({
            "field": "update_status",
            "value": get_update_data(host_record),
            "reason": "Update status does not include update count fields.",
        })

    elif condition == "smb_exposed_in_discovery":
        evidence.append({
            "field": "discovery_services",
            "value": host_record.get("discovery_services", []),
            "reason": "Discovery data includes SMB-related ports.",
        })

    elif condition == "sensitive_apps_present":
        software = get_software_inventory(host_record)
        matched = _match_software_names(software, ["chrome", "edge", "vpn", "remote", "steam"])
        evidence.append({
            "field": "software",
            "value": matched,
            "reason": "Applications associated with potentially sensitive data access were detected.",
        })

    elif condition == "uac_disabled":
        evidence.append({
            "field": "security_config.uac.enabled",
            "value": host_record.get("security_config", {}).get("uac", {}).get("enabled"),
            "reason": "UAC is disabled.",
        })

    elif condition == "firewall_disabled":
        profiles = host_record.get("security_config", {}).get("firewall", {}).get("profiles", {})
        evidence.append({
            "field": "security_config.firewall.profiles",
            "value": profiles,
            "reason": "One or more firewall profiles are disabled.",
        })

    elif condition == "defender_realtime_disabled":
        evidence.append({
            "field": "security_config.defender.realtime_protection_enabled",
            "value": host_record.get("security_config", {}).get("defender", {}).get("realtime_protection_enabled"),
            "reason": "Defender realtime protection is disabled.",
        })

    elif condition == "guest_account_enabled":
        evidence.append({
            "field": "security_config.guest_account.disabled",
            "value": host_record.get("security_config", {}).get("guest_account", {}).get("disabled"),
            "reason": "Guest account is enabled.",
        })

    elif condition == "rdp_enabled":
        evidence.append({
            "field": "security_config.remote_desktop.disabled",
            "value": host_record.get("security_config", {}).get("remote_desktop", {}).get("disabled"),
            "reason": "Remote Desktop is enabled.",
        })

    elif condition == "autorun_enabled":
        evidence.append({
            "field": "security_config.autorun.disabled",
            "value": host_record.get("security_config", {}).get("autorun", {}).get("disabled"),
            "reason": "Autorun is not disabled.",
        })

    elif condition == "no_inactivity_timeout":
        evidence.append({
            "field": "security_config.inactivity_timeout",
            "value": host_record.get("security_config", {}).get("inactivity_timeout"),
            "reason": "No inactivity timeout configured.",
        })

    elif condition == "weak_inactivity_timeout":
        evidence.append({
            "field": "security_config.inactivity_timeout.seconds",
            "value": host_record.get("security_config", {}).get("inactivity_timeout", {}).get("seconds"),
            "reason": "Inactivity timeout exceeds recommended threshold.",
        })

    elif condition == "password_complexity_disabled":
        evidence.append({
            "field": "security_config.password_complexity.enabled",
            "value": host_record.get("security_config", {}).get("password_complexity", {}).get("enabled"),
            "reason": "Password complexity is disabled.",
        })

    elif condition == "weak_password_length":
        evidence.append({
            "field": "security_config.account_policy.minimum_password_length",
            "value": host_record.get("security_config", {}).get("account_policy", {}).get("minimum_password_length"),
            "reason": "Password length is below recommended minimum.",
        })

    elif condition == "weak_password_history":
        evidence.append({
            "field": "security_config.account_policy.password_history_length",
            "value": host_record.get("security_config", {}).get("account_policy", {}).get("password_history_length"),
            "reason": "Password history is below recommended minimum.",
        })

    elif condition == "weak_lockout_threshold":
        evidence.append({
            "field": "security_config.account_policy.lockout_threshold",
            "value": host_record.get("security_config", {}).get("account_policy", {}).get("lockout_threshold"),
            "reason": "Lockout threshold is not securely configured.",
        })

    elif condition == "missing_password_policy":
        evidence.append({
            "field": "security_config.account_policy",
            "value": host_record.get("security_config", {}).get("account_policy"),
            "reason": "Password policy data is missing or null.",
        })

    elif condition == "missing_password_complexity":
        evidence.append({
            "field": "security_config.password_complexity",
            "value": host_record.get("security_config", {}).get("password_complexity"),
            "reason": "Password complexity setting is missing.",
        })

    elif condition == "missing_autorun_config":
        evidence.append({
            "field": "security_config.autorun",
            "value": host_record.get("security_config", {}).get("autorun"),
            "reason": "Autorun configuration could not be determined.",
        })

    elif condition == "weak_password_policy_combined":
        evidence.append({
            "field": "security_config.account_policy",
            "value": host_record.get("security_config", {}).get("account_policy"),
            "reason": "Password policy values are weak.",
        })
        evidence.append({
            "field": "security_config.password_complexity",
            "value": host_record.get("security_config", {}).get("password_complexity"),
            "reason": "Password complexity is disabled while other password settings are weak.",
        })

    elif condition == "guest_account_present":
        evidence.append({
            "field": "account_info.accounts",
            "value": _match_accounts(host_record, lambda a: str(a.get("username", "")).lower() == "guest"),
            "reason": "Guest account is present in collected local accounts.",
        })

    elif condition == "multiple_admin_accounts":
        admins = _match_accounts(host_record, lambda a: a.get("is_admin"))
        evidence.append({
            "field": "account_info.accounts",
            "value": admins,
            "reason": "Multiple local administrator accounts were detected.",
        })
        evidence.append({
            "field": "admin_count",
            "value": len(admins),
            "reason": "Count of administrator accounts.",
        })

    elif condition == "password_never_expires":
        matches = _match_accounts(host_record, lambda a: a.get("password_never_expires"))
        evidence.append({
            "field": "account_info.accounts",
            "value": matches,
            "reason": "Accounts with non-expiring passwords were detected.",
        })

    elif condition == "disabled_accounts_present":
        matches = _match_accounts(host_record, lambda a: not a.get("enabled"))
        evidence.append({
            "field": "account_info.accounts",
            "value": matches,
            "reason": "Disabled accounts were detected.",
        })

    elif condition == "admin_accounts_exist":
        admins = _match_accounts(host_record, lambda a: a.get("is_admin"))
        evidence.append({
            "field": "account_info.accounts",
            "value": admins,
            "reason": "Administrative accounts were detected.",
        })

    elif condition == "too_many_admins":
        admins = _match_accounts(host_record, lambda a: a.get("is_admin"))
        evidence.append({
            "field": "account_info.accounts",
            "value": admins,
            "reason": "Too many administrative accounts were detected.",
        })
        evidence.append({
            "field": "admin_count",
            "value": len(admins),
            "reason": "Count of administrator accounts.",
        })

    elif condition == "admin_high_risk_profile":
        matches = _match_accounts(
            host_record,
            lambda a: a.get("is_admin") and a.get("password_never_expires") and a.get("enabled")
        )
        evidence.append({
            "field": "account_info.accounts",
            "value": matches,
            "reason": "Enabled administrator accounts with non-expiring passwords were detected.",
        })

    elif condition == "audit_logging_not_configured":
        evidence.append({
            "field": "audit_policy.settings",
            "value": host_record.get("audit_policy", {}).get("settings", []),
            "reason": "Audit policy settings are missing or empty.",
        })

    elif condition == "no_logon_auditing":
        evidence.append({
            "field": "audit_policy.settings",
            "value": host_record.get("audit_policy", {}).get("settings", []),
            "reason": "No logon auditing setting was found.",
        })

    elif condition == "risky_software_installed":
        matches = _match_software_names(get_software_inventory(host_record), ["chrome", "firefox", "edge"])
        evidence.append({
            "field": "software",
            "value": matches,
            "reason": "Browser software associated with exposure risk was detected.",
        })

    elif condition == "defender_disabled":
        evidence.append({
            "field": "security_config.defender.antivirus_enabled",
            "value": host_record.get("security_config", {}).get("defender", {}).get("antivirus_enabled"),
            "reason": "Antivirus is disabled.",
        })

    elif condition == "realtime_protection_disabled":
        evidence.append({
            "field": "security_config.defender.realtime_protection_enabled",
            "value": host_record.get("security_config", {}).get("defender", {}).get("realtime_protection_enabled"),
            "reason": "Realtime protection is disabled.",
        })

    elif condition == "antispyware_disabled":
        evidence.append({
            "field": "security_config.defender.antispyware_enabled",
            "value": host_record.get("security_config", {}).get("defender", {}).get("antispyware_enabled"),
            "reason": "Antispyware protection is disabled.",
        })

    elif condition == "no_backups_detected":
        evidence.append({
            "field": "backup_info",
            "value": host_record.get("backup_info", {}),
            "reason": "No backup or shadow copy evidence was detected.",
        })

    elif condition == "no_multiple_interfaces":
        evidence.append({
            "field": "network.interfaces",
            "value": host_record.get("network", {}).get("interfaces", []),
            "reason": "Insufficient network interface visibility was detected.",
        })

    elif condition == "no_security_tools_detected":
        evidence.append({
            "field": "software",
            "value": get_software_inventory(host_record),
            "reason": "No visible security tooling was detected in software inventory.",
        })

    elif condition == "third_party_software_present":
        matches = _match_software_names(get_software_inventory(host_record), ["vpn", "virtualbox"])
        evidence.append({
            "field": "software",
            "value": matches,
            "reason": "Third-party software requiring vendor review was detected.",
        })

    elif condition == "many_installed_applications":
        software = get_software_inventory(host_record)
        evidence.append({
            "field": "software_count",
            "value": len(software) if isinstance(software, list) else 0,
            "reason": "Large installed software footprint detected.",
        })

    elif condition == "developer_tools_installed":
        matches = _match_software_names(get_software_inventory(host_record), ["python", "git", "wsl"])
        evidence.append({
            "field": "software",
            "value": matches,
            "reason": "Developer tooling associated with increased attack surface was detected.",
        })

    elif condition == "high_attack_surface":
        matches = _match_software_names(get_software_inventory(host_record), ["python", "git", "wsl", "virtualbox", "vpn"])
        evidence.append({
            "field": "software",
            "value": matches,
            "reason": "Multiple high-risk tools contributing to attack surface were detected.",
        })

    elif condition == "insufficient_audit_events":
        settings = host_record.get("audit_policy", {}).get("settings", [])
        evidence.append({
            "field": "audit_policy.settings",
            "value": settings,
            "reason": "Audit coverage is limited.",
        })
        evidence.append({
            "field": "audit_setting_count",
            "value": len(settings) if isinstance(settings, list) else 0,
            "reason": "Count of collected audit policy settings.",
        })

    elif condition == "no_backup_and_logs":
        evidence.append({
            "field": "backup_info.shadow_copies_present",
            "value": host_record.get("backup_info", {}).get("shadow_copies_present"),
            "reason": "Backup availability used in incident response assessment.",
        })
        evidence.append({
            "field": "audit_policy.settings",
            "value": host_record.get("audit_policy", {}).get("settings", []),
            "reason": "Audit log availability used in incident response assessment.",
        })

    elif condition == "high_vulnerability_density":
        findings = host_record.get("findings", [])
        evidence.append({
            "field": "findings",
            "value": findings,
            "reason": "Finding count used to assess vulnerability density.",
        })
        evidence.append({
            "field": "finding_count",
            "value": len(findings) if isinstance(findings, list) else 0,
            "reason": "Total findings associated with the host.",
        })

    elif condition == "recent_patch_missing":
        evidence.append({
            "field": "update_status.latest_hotfix_date",
            "value": host_record.get("update_status", {}).get("latest_hotfix_date"),
            "reason": "Latest installed hotfix date was used to assess patch recency.",
        })
    #LINUX CONDITIONS
    elif condition == "linux_firewall_disabled":
        evidence.append({
            "field": "security_config.firewall",
            "value": host_record.get("security_config", {}).get("firewall"),
            "reason": "Linux firewall is disabled or not detected.",
        })

    elif condition == "linux_ssh_root_login_enabled":
        evidence.append({
            "field": "security_config.ssh.permit_root_login",
            "value": host_record.get("security_config", {}).get("ssh", {}).get("permit_root_login"),
            "reason": "SSH root login is enabled.",
        })

    elif condition == "linux_ssh_password_auth_enabled":
        evidence.append({
            "field": "security_config.ssh.password_authentication",
            "value": host_record.get("security_config", {}).get("ssh", {}).get("password_authentication"),
            "reason": "SSH password authentication is enabled.",
        })

    elif condition == "linux_auto_updates_disabled":
        evidence.append({
            "field": "security_config.automatic_updates",
            "value": host_record.get("security_config", {}).get("automatic_updates"),
            "reason": "Automatic updates are disabled or not configured.",
        })

    elif condition == "linux_fail2ban_missing":
        evidence.append({
            "field": "security_config.fail2ban",
            "value": host_record.get("security_config", {}).get("fail2ban"),
            "reason": "Fail2ban is not installed or not running.",
        })

    elif condition == "linux_weak_password_length":
        evidence.append({
            "field": "security_config.password_policy.minimum_password_length",
            "value": host_record.get("security_config", {}).get("password_policy", {}).get("minimum_password_length"),
            "reason": "Linux password minimum length is below recommended minimum.",
        })
    elif condition == "linux_ssh_config_unreadable":
        evidence.append({
            "field": "security_config.ssh",
            "value": host_record.get("security_config", {}).get("ssh", {}),
            "reason": "SSH configuration exists but could not be read by the non-privileged agent.",
        })

    elif condition == "linux_selinux_not_enforcing":
        evidence.append({
            "field": "security_config.selinux",
            "value": host_record.get("security_config", {}).get("selinux", {}),
            "reason": "SELinux is not enforcing.",
        })

    elif condition == "linux_weak_password_max_age":
        evidence.append({
            "field": "security_config.password_policy.maximum_password_age_days",
            "value": host_record.get("security_config", {}).get("password_policy", {}).get("maximum_password_age_days"),
            "reason": "Linux maximum password age exceeds recommended maximum.",
        })
    return evidence


def _match_accounts(host: Dict[str, Any], predicate) -> List[Dict[str, Any]]:
    accounts = host.get("account_info", {}).get("accounts", [])
    if not isinstance(accounts, list):
        return []
    return [a for a in accounts if isinstance(a, dict) and predicate(a)]


def _match_software_names(software: Any, keywords: List[str]) -> List[Dict[str, Any]]:
    if not isinstance(software, list):
        return []

    matches: List[Dict[str, Any]] = []
    for item in software:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).lower()
        if any(keyword in name for keyword in keywords):
            matches.append(item)
    return matches


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


def get_primary_ip(host):
    network = host.get("network", {})
    interfaces = network.get("interfaces", [])

    best_ipv4 = None
    best_ipv6 = None

    for iface in interfaces:
        if not isinstance(iface, dict):
            continue

        # IPv4 (skip loopback)
        for ip in iface.get("ipv4", []):
            if ip and not ip.startswith("127."):
                best_ipv4 = ip

        # IPv6 (skip loopback + link-local)
        for ip in iface.get("ipv6", []):
            if not ip:
                continue
            ip = ip.lower()
            if ip == "::1":
                continue
            if ip.startswith("fe80:"):
                continue
            if not best_ipv6:
                best_ipv6 = ip

    if best_ipv4:
        return best_ipv4

    if best_ipv6:
        return best_ipv6

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