import os
import re
import subprocess
import tempfile
from datetime import datetime
import winreg


def _run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=False,
            timeout=20
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1
        }


def _run_powershell(script):
    return _run_command([
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script
    ])


def _read_reg_dword(root, path, name):
    try:
        with winreg.OpenKey(root, path) as key:
            value, reg_type = winreg.QueryValueEx(key, name)
            if reg_type == winreg.REG_DWORD:
                return value
            return value
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _parse_bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return None

    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "on"}:
        return True
    if text in {"false", "0", "no", "off"}:
        return False
    return None


def _collect_uac():
    value = _read_reg_dword(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA"
    )
    return {
        "enabled": value == 1 if value is not None else None,
        "raw_value": value
    }


def _collect_remote_desktop():
    value = _read_reg_dword(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections"
    )
    return {
        "disabled": value == 1 if value is not None else None,
        "raw_value": value
    }


def _collect_autorun():
    candidates = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Explorer"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Microsoft\Windows\Explorer"),
    ]

    no_drive_type = None
    no_autorun = None
    checked_paths = []

    for root, path in candidates:
        checked_paths.append(path)

        if no_drive_type is None:
            value = _read_reg_dword(root, path, "NoDriveTypeAutoRun")
            if value is not None:
                no_drive_type = value

        if no_autorun is None:
            value = _read_reg_dword(root, path, "NoAutorun")
            if value is not None:
                no_autorun = value

    disabled = None

    if no_autorun is not None:
        disabled = no_autorun == 1

    if disabled is None and no_drive_type is not None:
        disabled = no_drive_type in (255, 0xFF, 145, 0x91)

    result = {
        "disabled": disabled,
        "NoDriveTypeAutoRun": no_drive_type,
        "NoAutorun": no_autorun,
    }

    if no_drive_type is None and no_autorun is None:
        result["note"] = "AutoRun-related registry values not present in checked policy paths."
        result["checked_paths"] = checked_paths

    return result

def _collect_inactivity_timeout():
    value = _read_reg_dword(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "InactivityTimeoutSecs"
    )
    return {
        "configured": value is not None and value > 0,
        "seconds": value
    }


def _collect_firewall():
    result = _run_powershell(
        "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
    )

    profiles = {
        "domain": {"enabled": None},
        "private": {"enabled": None},
        "public": {"enabled": None}
    }

    if not result["success"] or not result["stdout"]:
        return {
            "profiles": profiles,
            "error": result["stderr"] or "Failed to query firewall profiles"
        }

    try:
        import json
        data = json.loads(result["stdout"])
        if isinstance(data, dict):
            data = [data]

        for item in data:
            name = str(item.get("Name", "")).strip().lower()
            enabled = _parse_bool(item.get("Enabled"))
            if name in profiles:
                profiles[name]["enabled"] = enabled

        return {"profiles": profiles}
    except Exception as e:
        return {
            "profiles": profiles,
            "error": str(e)
        }


def _collect_defender():
    result = _run_powershell(
        "Get-MpComputerStatus | "
        "Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AntispywareEnabled,IoavProtectionEnabled | "
        "ConvertTo-Json -Compress"
    )

    data = {
        "realtime_protection_enabled": None,
        "antivirus_enabled": None,
        "antispyware_enabled": None,
        "ioav_protection_enabled": None
    }

    if not result["success"] or not result["stdout"]:
        return {
            **data,
            "error": result["stderr"] or "Failed to query Microsoft Defender status"
        }

    try:
        import json
        parsed = json.loads(result["stdout"])
        data["realtime_protection_enabled"] = _parse_bool(parsed.get("RealTimeProtectionEnabled"))
        data["antivirus_enabled"] = _parse_bool(parsed.get("AntivirusEnabled"))
        data["antispyware_enabled"] = _parse_bool(parsed.get("AntispywareEnabled"))
        data["ioav_protection_enabled"] = _parse_bool(parsed.get("IoavProtectionEnabled"))
        return data
    except Exception as e:
        return {
            **data,
            "error": str(e)
        }


def _collect_guest_account():
    result = _run_command(["net", "user", "Guest"])

    if not result["success"]:
        return {
            "disabled": None,
            "error": result["stderr"] or "Failed to query Guest account"
        }

    text = result["stdout"]
    match = re.search(r"Account active\s+(\S+)", text, re.IGNORECASE)
    if not match:
        return {
            "disabled": None,
            "error": "Could not parse Guest account status"
        }

    active_value = match.group(1).strip().lower()
    disabled = active_value in {"no", "n"}

    return {
        "disabled": disabled,
        "account_active_raw": active_value
    }


def _collect_net_accounts():
    data = {
        "minimum_password_length": None,
        "maximum_password_age_days": None,
        "password_history_length": None,
        "lockout_threshold": None
    }

    result = _run_command(["net", "accounts"])
    text = result["stdout"] if result["success"] else ""

    patterns = {
        "minimum_password_length": [
            r"Minimum password length\s+(\d+)",
        ],
        "maximum_password_age_days": [
            r"Maximum password age\s+(\d+)",
        ],
        "password_history_length": [
            r"Length of password history maintained\s+(\d+)",
        ],
        "lockout_threshold": [
            r"Lockout threshold\s+(\d+)",
        ],
    }

    for key, pattern_list in patterns.items():
        for pattern in pattern_list:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                data[key] = int(match.group(1))
                break

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".cfg") as tmp:
            temp_path = tmp.name

        sec_result = _run_command(["secedit", "/export", "/cfg", temp_path])

        if sec_result["success"] and os.path.exists(temp_path):
            content = ""
            for encoding in ("utf-16", "utf-8-sig", "utf-8", "latin-1"):
                try:
                    with open(temp_path, "r", encoding=encoding, errors="ignore") as f:
                        content = f.read()
                    if content:
                        break
                except Exception:
                    continue

            secedit_map = {
                "minimum_password_length": r"MinimumPasswordLength\s*=\s*(\d+)",
                "maximum_password_age_days": r"MaximumPasswordAge\s*=\s*(-?\d+)",
                "password_history_length": r"PasswordHistorySize\s*=\s*(\d+)",
                "lockout_threshold": r"LockoutBadCount\s*=\s*(\d+)",
            }

            for key, pattern in secedit_map.items():
                if data[key] is None:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        data[key] = int(match.group(1))

        return data
    except Exception as e:
        return {
            **data,
            "error": str(e)
        }
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


def _collect_password_complexity():
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".cfg") as tmp:
            temp_path = tmp.name

        result = _run_command(["secedit", "/export", "/cfg", temp_path])

        if not result["success"] or not os.path.exists(temp_path):
            return {
                "enabled": None,
                "error": result["stderr"] or "Failed to export local security policy"
            }

        content = ""
        for encoding in ("utf-16", "utf-8-sig", "utf-8", "latin-1"):
            try:
                with open(temp_path, "r", encoding=encoding, errors="ignore") as f:
                    content = f.read()
                if "PasswordComplexity" in content:
                    break
            except Exception:
                continue

        if "PasswordComplexity" not in content:
            return {
                "enabled": None,
                "error": "PasswordComplexity not found in exported policy"
            }

        match = re.search(r"PasswordComplexity\s*=\s*(\d+)", content, re.IGNORECASE)
        if not match:
            return {
                "enabled": None,
                "error": "PasswordComplexity not found"
            }

        raw_value = int(match.group(1).strip())

        return {
            "enabled": raw_value == 1,
            "raw_value": raw_value
        }
    except Exception as e:
        return {
            "enabled": None,
            "error": str(e)
        }
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


def collect_security_config():
    collected_at = datetime.utcnow().isoformat() + "Z"

    security_config = {
        "collected_at": collected_at,
        "uac": _collect_uac(),
        "firewall": _collect_firewall(),
        "defender": _collect_defender(),
        "guest_account": _collect_guest_account(),
        "remote_desktop": _collect_remote_desktop(),
        "autorun": _collect_autorun(),
        "inactivity_timeout": _collect_inactivity_timeout(),
        "account_policy": _collect_net_accounts(),
        "password_complexity": _collect_password_complexity()
    }

    return security_config