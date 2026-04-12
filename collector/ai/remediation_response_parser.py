import json
import re
from typing import Any, Dict, List


WINDOWS_GUI_PATTERNS = (
    "secpol.msc",
    "gpedit.msc",
    "control ",
    "control.exe",
    "control userpasswords2",
    "rundll32",
    "mmc",
    "wf.msc",
    "eventvwr.msc",
    "services.msc",
    "compmgmt.msc",
    "lusrmgr.msc",
)

LINUX_GUI_PATTERNS = (
    "gnome-control-center",
    "systemsettings",
    "nm-connection-editor",
)

BANNED_COMMAND_PATTERNS = (
    "rdp-tcp",
    "defaultpasswordcomplexity",
    "keymgr.dll",
    "wevtutil el /f:",
)

READ_ONLY_WINDOWS_PREFIXES = (
    "net accounts",
    "net user",
    "whoami",
    "hostname",
    "qwinsta",
    "query user",
    "query session",
    "auditpol /get",
    "wevtutil",
    "reg query",
    "sc query",
    "gpresult",
    "wmic ",
    "powershell get-",
    "powershell -command \"get-",
    "powershell -command get-",
    "get-netfirewallprofile",
    "netsh advfirewall",
    "netstat",
    "secedit /export",
)

READ_ONLY_LINUX_PREFIXES = (
    "ss ",
    "sudo ss ",
    "systemctl status",
    "sudo systemctl status",
    "systemctl list-unit-files",
    "sudo systemctl list-unit-files",
    "ufw status",
    "sudo ufw status",
    "auditctl -s",
    "sudo auditctl -s",
    "journalctl",
    "sudo journalctl",
    "grep ",
    "sudo grep ",
    "cat ",
    "sudo cat ",
    "find ",
    "sudo find ",
    "dpkg -l",
    "rpm -qa",
    "passwd -s",
    "sudo passwd -s",
    "faillock --user",
    "sudo faillock --user",
)


def _clean_list(value: Any, limit: int) -> List[str]:
    if not isinstance(value, list):
        return []

    result: List[str] = []
    seen = set()

    for item in value:
        text = str(item).strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(text)
        if len(result) >= limit:
            break

    return result


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

    raise ValueError("No JSON object found in remediation response")


def _fallback_actions(title: str, platform: str) -> List[str]:
    lowered = title.lower()
    is_windows = "windows" in platform.lower()
    is_linux = "linux" in platform.lower()

    if "account policy" in lowered or "password" in lowered:
        return [
            "Review current password complexity, password length, expiration, and account lockout settings.",
            "Identify privileged, guest, and dormant local accounts that do not meet policy expectations.",
            "Validate that account and password controls align with the required security baseline before making changes.",
        ]

    if "remote access" in lowered:
        return [
            "Review which remote access services are enabled and whether they are required.",
            "Validate firewall exposure, session controls, and remote administration pathways.",
            "Confirm that remote access is limited to approved users, hosts, and authentication methods.",
        ]

    if "endpoint security configuration" in lowered or "security configuration" in lowered:
        return [
            "Review host hardening settings against the expected workstation security baseline.",
            "Validate local firewall, endpoint protection, and session control settings.",
            "Confirm insecure defaults and unnecessary exposure are identified before remediation changes are applied.",
        ]

    if "software exposure" in lowered:
        return [
            "Inventory installed software and identify applications that increase risk or are no longer required.",
            "Review software versions, access permissions, and business justification for sensitive applications.",
            "Validate that retained software is supported, necessary, and aligned with policy.",
        ]

    if "audit logging" in lowered or "recovery" in lowered:
        return [
            "Review whether security logging is enabled for the relevant event categories.",
            "Validate retention, visibility, and audit coverage for recovery and protection workflows.",
            "Confirm patch visibility and recovery readiness through existing system telemetry and logs.",
        ]

    if is_windows or is_linux:
        return [
            "Review the affected configuration area and confirm the current host state.",
            "Validate the applicable security baseline, policy, and current findings before making changes.",
            "Re-run assessment checks after remediation planning to confirm the scope of the issue.",
        ]

    return [
        "Review the affected configuration area and confirm the current host state.",
        "Validate the applicable security baseline, policy, and current findings before making changes.",
        "Re-run assessment checks after remediation planning to confirm the scope of the issue.",
    ]


def _fallback_commands(title: str, platform: str) -> List[str]:
    lowered = title.lower()
    platform_lower = platform.lower()

    if "windows" in platform_lower:
        if "account policy" in lowered or "password" in lowered:
            return [
                "net accounts",
                "net user",
                "secedit /export /cfg C:\\Windows\\Temp\\secpol.cfg",
            ]
        if "remote access" in lowered:
            return [
                "qwinsta",
                "query user",
                "netsh advfirewall firewall show rule name=all",
                'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"',
            ]
        if "endpoint security configuration" in lowered or "security configuration" in lowered:
            return [
                "Get-NetFirewallProfile",
                "sc query WinDefend",
                "gpresult /r",
                'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"',
            ]
        if "software exposure" in lowered:
            return [
                'powershell -Command "Get-Package | Sort-Object Name"',
                "wmic product get name,version",
                'powershell -Command "Get-Process | Select-Object Name,Id,Path"',
            ]
        if "audit logging" in lowered or "recovery" in lowered:
            return [
                "auditpol /get /category:*",
                "wevtutil el",
                'powershell -Command "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20"',
            ]

    if "linux" in platform_lower:
        if "account policy" in lowered or "password" in lowered:
            return [
                "sudo grep -E 'minlen|retry|maxrepeat|minclass' /etc/security/pwquality.conf",
                "sudo faillock --user <username>",
                "sudo passwd -S <username>",
            ]
        if "remote access" in lowered:
            return [
                "sudo ss -tulpn",
                "sudo systemctl status ssh",
                "sudo ufw status numbered",
            ]
        if "endpoint security configuration" in lowered or "security configuration" in lowered:
            return [
                "sudo ss -tulpn",
                "sudo systemctl list-unit-files --type=service",
                "sudo ufw status verbose",
            ]
        if "software exposure" in lowered:
            return [
                "dpkg -l",
                "rpm -qa",
                "sudo find /usr/bin -maxdepth 1 -type f",
            ]
        if "audit logging" in lowered or "recovery" in lowered:
            return [
                "sudo auditctl -s",
                "journalctl --disk-usage",
                "sudo journalctl -n 200",
            ]

    return []


def _fallback_notes(title: str) -> str:
    lowered = title.lower()

    if "account policy" in lowered or "password" in lowered:
        return "Use read-only validation first, then apply account policy changes carefully to avoid unintended access disruption."

    if "remote access" in lowered:
        return "Validate remote exposure with read-only checks before restricting services so legitimate administration paths are preserved."

    if "endpoint security configuration" in lowered or "security configuration" in lowered:
        return "Use baseline verification commands first so hardening decisions are based on observed host state rather than assumptions."

    if "software exposure" in lowered:
        return "Inventory and verify software state first, then remove or restrict applications only after confirming business ownership."

    if "audit logging" in lowered or "recovery" in lowered:
        return "Confirm current logging and recovery visibility with read-only checks before changing policy or audit settings."

    return "Prefer read-only validation first, then apply remediation changes only after confirming the actual host state."


def _normalize_command(command: str) -> str:
    cmd = command.strip()
    cmd = re.sub(r"\s+", " ", cmd)
    cmd = cmd.rstrip(",;")
    cmd = cmd.replace("C:\\ emp", "C:\\emp")
    return cmd


def _looks_gui(text: str) -> bool:
    lowered = text.lower()
    return any(pattern in lowered for pattern in WINDOWS_GUI_PATTERNS + LINUX_GUI_PATTERNS)


def _looks_banned(command: str) -> bool:
    lowered = command.lower()
    return any(pattern in lowered for pattern in BANNED_COMMAND_PATTERNS)


def _contains_placeholder(command: str) -> bool:
    lowered = command.lower()
    return any(
        token in lowered
        for token in (
            "<",
            ">",
            "your_domain",
            "domain_name",
            "yourdomain",
            ".local",
            "example",
            "placeholder",
        )
    )


def _is_state_changing(command: str) -> bool:
    lowered = command.lower()
    return any(
        token in lowered
        for token in (
            "acceptall",
            " install",
            " install-",
            " set-",
            " new-",
            " remove-",
            " enable-",
            " disable-",
            " add-",
            " /set",
            " start=",
            " stop ",
            " restart ",
            " shutdown ",
            "del ",
            "rm ",
        )
    )


def _is_read_only_windows(command: str) -> bool:
    lowered = command.lower()
    return any(lowered.startswith(prefix) for prefix in READ_ONLY_WINDOWS_PREFIXES)


def _is_read_only_linux(command: str) -> bool:
    lowered = command.lower()
    return any(lowered.startswith(prefix) for prefix in READ_ONLY_LINUX_PREFIXES)


def _sanitize_actions_strict(actions: List[str], title: str, platform: str) -> List[str]:
    cleaned: List[str] = []
    seen = set()

    for action in actions:
        text = str(action).strip()
        lowered = text.lower()

        if not text:
            continue
        if _looks_gui(text):
            continue
        if _looks_banned(text):
            continue
        if _contains_placeholder(text):
            continue
        if _is_state_changing(text):
            continue

        if lowered in seen:
            continue
        seen.add(lowered)
        cleaned.append(text)

    if cleaned:
        return cleaned[:5]

    return _fallback_actions(title, platform)[:5]


def _sanitize_commands(commands: List[str], title: str, platform: str) -> List[str]:
    cleaned: List[str] = []
    seen = set()
    platform_lower = platform.lower()

    for raw in commands:
        cmd = _normalize_command(str(raw))
        if not cmd:
            continue

        lowered = cmd.lower()

        if _looks_gui(cmd):
            continue
        if _looks_banned(cmd):
            continue
        if _contains_placeholder(cmd):
            continue
        if _is_state_changing(cmd):
            continue
        if "get-localgroupmember" in lowered and "-groupname" not in lowered:
            continue

        is_allowed = False
        if "windows" in platform_lower:
            is_allowed = _is_read_only_windows(cmd)
        elif "linux" in platform_lower:
            is_allowed = _is_read_only_linux(cmd)

        if not is_allowed:
            continue

        if lowered in seen:
            continue
        seen.add(lowered)
        cleaned.append(cmd)

    fallback = _fallback_commands(title, platform)

    while len(cleaned) < 3 and fallback:
        candidate = _normalize_command(fallback.pop(0))
        lowered = candidate.lower()

        if not candidate:
            continue
        if _looks_gui(candidate):
            continue
        if _looks_banned(candidate):
            continue
        if _contains_placeholder(candidate):
            continue
        if _is_state_changing(candidate):
            continue
        if "get-localgroupmember" in lowered and "-groupname" not in lowered:
            continue

        is_allowed = False
        if "windows" in platform_lower:
            is_allowed = _is_read_only_windows(candidate)
        elif "linux" in platform_lower:
            is_allowed = _is_read_only_linux(candidate)

        if not is_allowed:
            continue
        if lowered in seen:
            continue

        seen.add(lowered)
        cleaned.append(candidate)

    if cleaned:
        return cleaned[:5]

    return []


def parse_remediation_response(raw_text: str, title: str, platform: str) -> Dict[str, Any]:
    try:
        blob = _extract_json_blob(raw_text)
        data = json.loads(blob)

        actions = _clean_list(data.get("actions"), 5)
        commands = _clean_list(data.get("commands"), 5)
        implementation_notes = str(data.get("implementation_notes", "")).strip()
        confidence = str(data.get("confidence", "")).strip().lower()

        actions = _sanitize_actions_strict(actions, title, platform)
        commands = _sanitize_commands(commands, title, platform)

        if not commands:
            commands = _fallback_commands(title, platform)[:3]

        if confidence not in {"low", "medium", "high"}:
            confidence = "medium"

        if not implementation_notes:
            implementation_notes = _fallback_notes(title)

        return {
            "actions": actions,
            "commands": commands,
            "implementation_notes": implementation_notes,
            "confidence": confidence,
        }
    except Exception:
        return {
            "actions": _fallback_actions(title, platform),
            "commands": _fallback_commands(title, platform)[:3],
            "implementation_notes": _fallback_notes(title),
            "confidence": "low",
        }