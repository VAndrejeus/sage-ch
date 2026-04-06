import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(cmd: List[str]) -> Dict[str, Any]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            encoding="utf-8",
            errors="ignore",
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode,
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
        }


def _command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def _safe_read_file(path: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "path": path,
        "present": False,
        "readable": False,
        "content": None,
        "note": None,
    }

    if not os.path.exists(path):
        result["note"] = "file not found"
        return result

    result["present"] = True

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            result["content"] = f.read()
            result["readable"] = True
    except PermissionError:
        result["note"] = "permission denied"
    except Exception as e:
        result["note"] = str(e)

    return result


def _collect_selinux() -> Dict[str, Any]:
    if not _command_exists("getenforce"):
        return {
            "available": False,
            "status": None,
            "note": "getenforce not found",
        }

    result = _run(["getenforce"])
    if result["success"]:
        return {
            "available": True,
            "status": result["stdout"],
            "note": None,
        }

    return {
        "available": True,
        "status": None,
        "note": result["stderr"] or "failed to execute getenforce",
    }


def _collect_firewall() -> Dict[str, Any]:
    ufw = {
        "available": _command_exists("ufw"),
        "enabled": None,
        "raw": None,
        "note": None,
    }

    firewalld = {
        "available": _command_exists("firewall-cmd"),
        "enabled": None,
        "raw": None,
        "note": None,
    }

    if ufw["available"]:
        result = _run(["ufw", "status"])
        ufw["raw"] = result["stdout"] or result["stderr"]
        if result["success"]:
            ufw["enabled"] = "Status: active" in result["stdout"]
        else:
            ufw["note"] = result["stderr"] or "ufw status failed"

    if firewalld["available"]:
        result = _run(["firewall-cmd", "--state"])
        firewalld["raw"] = result["stdout"] or result["stderr"]
        if result["success"]:
            firewalld["enabled"] = result["stdout"].strip() == "running"
        else:
            firewalld["note"] = result["stderr"] or "firewall-cmd --state failed"

    enabled: Optional[bool] = False
    if ufw["enabled"] is True or firewalld["enabled"] is True:
        enabled = True
    elif ufw["enabled"] is None and firewalld["enabled"] is None:
        enabled = None

    return {
        "enabled": enabled,
        "ufw": ufw,
        "firewalld": firewalld,
    }


def _collect_ssh() -> Dict[str, Any]:
    config_path = "/etc/ssh/sshd_config"
    file_data = _safe_read_file(config_path)

    result: Dict[str, Any] = {
        "config_path": config_path,
        "present": file_data["present"],
        "readable": file_data["readable"],
        "permit_root_login": None,
        "password_authentication": None,
        "note": file_data["note"],
    }

    if not file_data["readable"] or not file_data["content"]:
        return result

    for line in file_data["content"].splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if re.match(r"^PermitRootLogin\s+", stripped, re.IGNORECASE):
            result["permit_root_login"] = stripped.split(None, 1)[1].strip()

        elif re.match(r"^PasswordAuthentication\s+", stripped, re.IGNORECASE):
            result["password_authentication"] = stripped.split(None, 1)[1].strip()

    return result


def _collect_auto_updates() -> Dict[str, Any]:
    apt_path = "/etc/apt/apt.conf.d/20auto-upgrades"
    dnf_path = "/etc/dnf/automatic.conf"

    apt_data = _safe_read_file(apt_path)
    if apt_data["present"]:
        result = {
            "enabled": None,
            "method": "apt",
            "config_path": apt_path,
            "config_readable": apt_data["readable"],
            "raw": apt_data["content"] if apt_data["readable"] else None,
            "note": apt_data["note"],
        }

        if apt_data["readable"] and apt_data["content"]:
            update_match = re.search(
                r'APT::Periodic::Update-Package-Lists\s+"?(\d+)"?;',
                apt_data["content"],
            )
            upgrade_match = re.search(
                r'APT::Periodic::Unattended-Upgrade\s+"?(\d+)"?;',
                apt_data["content"],
            )

            update_enabled = bool(update_match and update_match.group(1) != "0")
            upgrade_enabled = bool(upgrade_match and upgrade_match.group(1) != "0")
            result["enabled"] = bool(update_enabled and upgrade_enabled)

        return result

    dnf_data = _safe_read_file(dnf_path)
    if dnf_data["present"]:
        result = {
            "enabled": None,
            "method": "dnf",
            "config_path": dnf_path,
            "config_readable": dnf_data["readable"],
            "raw": dnf_data["content"] if dnf_data["readable"] else None,
            "note": dnf_data["note"],
        }

        if dnf_data["readable"] and dnf_data["content"]:
            apply_match = re.search(
                r"^\s*apply_updates\s*=\s*(yes|true|1)",
                dnf_data["content"],
                re.IGNORECASE | re.MULTILINE,
            )
            result["enabled"] = bool(apply_match)

        return result

    return {
        "enabled": None,
        "method": None,
        "config_path": None,
        "config_readable": False,
        "raw": None,
        "note": "automatic update configuration not found",
    }


def _collect_fail2ban() -> Dict[str, Any]:
    installed = _command_exists("fail2ban-client")
    running = None
    raw = None
    note = None

    if installed:
        result = _run(["fail2ban-client", "status"])
        raw = result["stdout"] or result["stderr"]
        running = result["success"]
        if not result["success"]:
            note = result["stderr"] or "fail2ban-client status failed"

    return {
        "installed": installed,
        "running": running,
        "raw": raw,
        "note": note,
    }


def _extract_min_length_from_pam(content: str) -> Optional[int]:
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if "pam_pwquality.so" in stripped or "pam_cracklib.so" in stripped:
            match = re.search(r"\bminlen=(\d+)", stripped)
            if match:
                return int(match.group(1))

    return None


def _collect_password_policy() -> Dict[str, Any]:
    login_defs = _safe_read_file("/etc/login.defs")
    common_password = _safe_read_file("/etc/pam.d/common-password")
    system_auth = _safe_read_file("/etc/pam.d/system-auth")

    minimum_password_length = None

    for file_data in (common_password, system_auth):
        if file_data["readable"] and file_data["content"]:
            minimum_password_length = _extract_min_length_from_pam(file_data["content"])
            if minimum_password_length is not None:
                break

    pass_max_days = None
    if login_defs["readable"] and login_defs["content"]:
        match = re.search(
            r"^\s*PASS_MAX_DAYS\s+(\d+)",
            login_defs["content"],
            re.MULTILINE,
        )
        if match:
            pass_max_days = int(match.group(1))

    return {
        "minimum_password_length": minimum_password_length,
        "maximum_password_age_days": pass_max_days,
        "sources": {
            "login_defs": {
                "path": login_defs["path"],
                "present": login_defs["present"],
                "readable": login_defs["readable"],
                "note": login_defs["note"],
            },
            "common_password": {
                "path": common_password["path"],
                "present": common_password["present"],
                "readable": common_password["readable"],
                "note": common_password["note"],
            },
            "system_auth": {
                "path": system_auth["path"],
                "present": system_auth["present"],
                "readable": system_auth["readable"],
                "note": system_auth["note"],
            },
        },
    }


def _collect_sudo() -> Dict[str, Any]:
    sudoers = _safe_read_file("/etc/sudoers")

    nopasswd_enabled = None
    if sudoers["readable"] and sudoers["content"] is not None:
        nopasswd_enabled = "NOPASSWD" in sudoers["content"]

    return {
        "config_path": sudoers["path"],
        "present": sudoers["present"],
        "readable": sudoers["readable"],
        "nopasswd_enabled": nopasswd_enabled,
        "note": sudoers["note"],
    }


def collect() -> Dict[str, Any]:
    return {
        "collected_at": _utc_now(),
        "selinux": _collect_selinux(),
        "firewall": _collect_firewall(),
        "ssh": _collect_ssh(),
        "automatic_updates": _collect_auto_updates(),
        "fail2ban": _collect_fail2ban(),
        "password_policy": _collect_password_policy(),
        "sudo": _collect_sudo(),
    }