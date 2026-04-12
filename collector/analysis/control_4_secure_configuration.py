from typing import Any, Dict, List


def _make_finding(
    host_id: str,
    hostname: str,
    rule_id: str,
    title: str,
    severity: str,
    description: str,
    remediation: str,
    evidence: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "category": "secure_configuration",
        "cis_control": "4",
        "description": description,
        "remediation": remediation,
        "host_id": host_id,
        "hostname": hostname,
        "evidence": evidence,
    }


def evaluate_control_4(host: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    host_id = host.get("host_id")
    hostname = host.get("hostname")
    security_config = host.get("security_config", {})

    uac = security_config.get("uac", {})
    firewall = security_config.get("firewall", {})
    defender = security_config.get("defender", {})
    guest_account = security_config.get("guest_account", {})
    remote_desktop = security_config.get("remote_desktop", {})
    autorun = security_config.get("autorun", {})
    inactivity_timeout = security_config.get("inactivity_timeout", {})
    account_policy = security_config.get("account_policy", {})
    password_complexity = security_config.get("password_complexity", {})

    firewall_profiles = firewall.get("profiles", {})
    firewall_domain = firewall_profiles.get("domain", {})
    firewall_private = firewall_profiles.get("private", {})
    firewall_public = firewall_profiles.get("public", {})

    # C4-1 UAC enabled
    if uac.get("enabled") is False:
        findings.append(_make_finding(
            host_id=host_id,
            hostname=hostname,
            rule_id="C4-UAC-ENABLED",
            title="User Account Control is disabled",
            severity="medium",
            description="User Account Control is not enabled on the host.",
            remediation="Enable User Account Control on Windows endpoints.",
            evidence={
                "security_config_path": "security_config.uac.enabled",
                "actual": uac.get("enabled"),
                "raw_value": uac.get("raw_value"),
            },
        ))

    # C4-2 Firewall profiles enabled
    disabled_profiles = []
    if firewall_domain.get("enabled") is False:
        disabled_profiles.append("domain")
    if firewall_private.get("enabled") is False:
        disabled_profiles.append("private")
    if firewall_public.get("enabled") is False:
        disabled_profiles.append("public")

    if disabled_profiles:
        findings.append(_make_finding(
            host_id=host_id,
            hostname=hostname,
            rule_id="C4-FIREWALL-ENABLED",
            title="Windows Firewall profile disabled",
            severity="high",
            description="One or more Windows Firewall profiles are disabled.",
            remediation="Enable Windows Firewall for domain, private, and public profiles.",
            evidence={
                "security_config_path": "security_config.firewall.profiles",
                "disabled_profiles": disabled_profiles,
                "profiles": firewall_profiles,
            },
        ))

    # C4-3 Defender real-time protection enabled
    if defender.get("realtime_protection_enabled") is False:
        findings.append(_make_finding(
            host_id=host_id,
            hostname=hostname,
            rule_id="C4-DEFENDER-REALTIME",
            title="Microsoft Defender real-time protection is disabled",
            severity="high",
            description="Microsoft Defender real-time protection is not enabled.",
            remediation="Enable Microsoft Defender real-time protection.",
            evidence={
                "security_config_path": "security_config.defender.realtime_protection_enabled",
                "actual": defender.get("realtime_protection_enabled"),
                "defender": defender,
            },
        ))

    # C4-4 Guest account disabled
    if guest_account.get("disabled") is False:
        findings.append(_make_finding(
            host_id=host_id,
            hostname=hostname,
            rule_id="C4-GUEST-ACCOUNT-DISABLED",
            title="Guest account is enabled",
            severity="medium",
            description="The built-in Guest account is enabled.",
            remediation="Disable the built-in Guest account.",
            evidence={
                "security_config_path": "security_config.guest_account.disabled",
                "actual": guest_account.get("disabled"),
                "account_active_raw": guest_account.get("account_active_raw"),
            },
        ))

    # C4-5 Remote Desktop disabled
    if remote_desktop.get("disabled") is False:
        findings.append(_make_finding(
            host_id=host_id,
            hostname=hostname,
            rule_id="C4-RDP-DISABLED",
            title="Remote Desktop is enabled",
            severity="medium",
            description="Remote Desktop is enabled on the host.",
            remediation="Disable Remote Desktop unless explicitly required and managed.",
            evidence={
                "security_config_path": "security_config.remote_desktop.disabled",
                "actual": remote_desktop.get("disabled"),
                "raw_value": remote_desktop.get("raw_value"),
            },
        ))

    # C4-6 AutoRun disabled
    if autorun.get("disabled") is False:
        findings.append(_make_finding(
            host_id=host_id,
            hostname=hostname,
            rule_id="C4-AUTORUN-DISABLED",
            title="AutoRun is not disabled",
            severity="medium",
            description="AutoRun protections are not configured as disabled.",
            remediation="Disable AutoRun for removable and other media types.",
            evidence={
                "security_config_path": "security_config.autorun.disabled",
                "actual": autorun.get("disabled"),
                "NoDriveTypeAutoRun": autorun.get("NoDriveTypeAutoRun"),
                "NoAutorun": autorun.get("NoAutorun"),
            },
        ))

    # C4-7 Inactivity timeout configured
    timeout_seconds = inactivity_timeout.get("seconds")
    if inactivity_timeout.get("configured") is False:
        findings.append(_make_finding(
            host_id=host_id,
            hostname=hostname,
            rule_id="C4-INACTIVITY-TIMEOUT",
            title="Interactive session lock timeout is not configured",
            severity="low",
            description="No inactivity timeout is configured for the host.",
            remediation="Configure an inactivity timeout for user sessions.",
            evidence={
                "security_config_path": "security_config.inactivity_timeout",
                "configured": inactivity_timeout.get("configured"),
                "seconds": timeout_seconds,
            },
        ))
    elif isinstance(timeout_seconds, int) and timeout_seconds > 900:
        findings.append(_make_finding(
            host_id=host_id,
            hostname=hostname,
            rule_id="C4-INACTIVITY-TIMEOUT-WEAK",
            title="Interactive session lock timeout is too long",
            severity="low",
            description="The configured inactivity timeout exceeds 900 seconds.",
            remediation="Reduce inactivity timeout to 900 seconds or less.",
            evidence={
                "security_config_path": "security_config.inactivity_timeout.seconds",
                "seconds": timeout_seconds,
                "recommended_max_seconds": 900,
            },
        ))

    # C4-8 Password complexity enabled
    if password_complexity.get("enabled") is False:
        findings.append(_make_finding(
            host_id=host_id,
            hostname=hostname,
            rule_id="C4-PASSWORD-COMPLEXITY",
            title="Password complexity is disabled",
            severity="medium",
            description="Password complexity requirements are not enabled.",
            remediation="Enable password complexity requirements.",
            evidence={
                "security_config_path": "security_config.password_complexity.enabled",
                "actual": password_complexity.get("enabled"),
                "raw_value": password_complexity.get("raw_value"),
                "error": password_complexity.get("error"),
            },
        ))

    # C4-9 Minimum password length
    min_length = account_policy.get("minimum_password_length")
    if isinstance(min_length, int) and min_length < 14:
        findings.append(_make_finding(
            host_id=host_id,
            hostname=hostname,
            rule_id="C4-PASSWORD-LENGTH",
            title="Minimum password length is weak",
            severity="medium",
            description="Minimum password length is below 14 characters.",
            remediation="Set minimum password length to at least 14 characters.",
            evidence={
                "security_config_path": "security_config.account_policy.minimum_password_length",
                "actual": min_length,
                "recommended_minimum": 14,
            },
        ))

    # C4-10 Password history
    password_history = account_policy.get("password_history_length")
    if isinstance(password_history, int) and password_history < 24:
        findings.append(_make_finding(
            host_id=host_id,
            hostname=hostname,
            rule_id="C4-PASSWORD-HISTORY",
            title="Password history setting is weak",
            severity="low",
            description="Password history length is below 24 remembered passwords.",
            remediation="Set password history to 24 or more remembered passwords.",
            evidence={
                "security_config_path": "security_config.account_policy.password_history_length",
                "actual": password_history,
                "recommended_minimum": 24,
            },
        ))

    # C4-11 Lockout threshold
    lockout_threshold = account_policy.get("lockout_threshold")
    if isinstance(lockout_threshold, int) and (lockout_threshold == 0 or lockout_threshold > 10):
        findings.append(_make_finding(
            host_id=host_id,
            hostname=hostname,
            rule_id="C4-LOCKOUT-THRESHOLD",
            title="Account lockout threshold is weak",
            severity="medium",
            description="Account lockout threshold is not configured securely.",
            remediation="Set account lockout threshold to 10 or fewer invalid attempts.",
            evidence={
                "security_config_path": "security_config.account_policy.lockout_threshold",
                "actual": lockout_threshold,
                "recommended_maximum": 10,
            },
        ))

    return findings