import os
import re
import shutil
import subprocess
from datetime import datetime, timezone


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(cmd):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            encoding="utf-8",
            errors="ignore"
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


def _read_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return None


def _command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def _collect_firewall():
    ufw = {
        "available": _command_exists("ufw"),
        "enabled": None,
        "raw": None,
    }

    firewalld = {
        "available": _command_exists("firewall-cmd"),
        "enabled": None,
        "raw": None,
    }

    if ufw["available"]:
        result = _run(["ufw", "status"])
        ufw["raw"] = result["stdout"] or result["stderr"]
        if result["success"]:
            ufw["enabled"] = "Status: active" in result["stdout"]

    if firewalld["available"]:
        result = _run(["firewall-cmd", "--state"])
        firewalld["raw"] = result["stdout"] or result["stderr"]
        if result["success"]:
            firewalld["enabled"] = result["stdout"].strip() == "running"

    enabled = False
    if ufw["enabled"] is True or firewalld["enabled"] is True:
        enabled = True
    elif ufw["enabled"] is None and firewalld["enabled"] is None:
        enabled = None

    return {
        "enabled": enabled,
        "ufw": ufw,
        "firewalld": firewalld,
    }


def _collect_ssh_config():
    path = "/etc/ssh/sshd_config"
    content = _read_file(path)

    data = {
        "config_path": path,
        "present": content is not None,
        "permit_root_login": None,
        "password_authentication": None,
    }

    if content is None:
        return data

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if re.match(r"^PermitRootLogin\s+", stripped, re.IGNORECASE):
            data["permit_root_login"] = stripped.split(None, 1)[1].strip()

        elif re.match(r"^PasswordAuthentication\s+", stripped, re.IGNORECASE):
            data["password_authentication"] = stripped.split(None, 1)[1].strip()

    return data


def _collect_auto_updates():
    apt_periodic = "/etc/apt/apt.conf.d/20auto-upgrades"
    dnf_automatic = "/etc/dnf/automatic.conf"

    result = {
        "enabled": None,
        "method": None,
        "raw": None,
    }

    apt_content = _read_file(apt_periodic)
    if apt_content is not None:
        result["method"] = "apt"
        result["raw"] = apt_content

        update_match = re.search(r'APT::Periodic::Update-Package-Lists\s+"?(\d+)"?;', apt_content)
        upgrade_match = re.search(r'APT::Periodic::Unattended-Upgrade\s+"?(\d+)"?;', apt_content)

        update_enabled = update_match and update_match.group(1) != "0"
        upgrade_enabled = upgrade_match and upgrade_match.group(1) != "0"

        result["enabled"] = bool(update_enabled and upgrade_enabled)
        return result

    dnf_content = _read_file(dnf_automatic)
    if dnf_content is not None:
        result["method"] = "dnf"
        result["raw"] = dnf_content

        apply_match = re.search(r"^\s*apply_updates\s*=\s*(yes|true|1)", dnf_content, re.IGNORECASE | re.MULTILINE)
        result["enabled"] = bool(apply_match)
        return result

    return result


def _collect_fail2ban():
    installed = _command_exists("fail2ban-client")
    running = None
    raw = None

    if installed:
        result = _run(["fail2ban-client", "status"])
        raw = result["stdout"] or result["stderr"]
        running = result["success"]

    return {
        "installed": installed,
        "running": running,
        "raw": raw,
    }


def _collect_password_policy():
    login_defs = _read_file("/etc/login.defs")
    common_password = _read_file("/etc/pam.d/common-password")
    system_auth = _read_file("/etc/pam.d/system-auth")

    minimum_password_length = None

    sources = [common_password, system_auth]
    for content in sources:
        if not content:
            continue

        for line in content.splitlines():
            stripped = line.strip()
            if "pam_pwquality.so" in stripped or "pam_cracklib.so" in stripped:
                match = re.search(r"\bminlen=(\d+)", stripped)
                if match:
                    minimum_password_length = int(match.group(1))
                    break
        if minimum_password_length is not None:
            break

    pass_max_days = None
    if login_defs:
        match = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", login_defs, re.MULTILINE)
        if match:
            pass_max_days = int(match.group(1))

    return {
        "minimum_password_length": minimum_password_length,
        "maximum_password_age_days": pass_max_days,
    }


def collect():
    return {
        "collected_at": _utc_now(),
        "firewall": _collect_firewall(),
        "ssh": _collect_ssh_config(),
        "automatic_updates": _collect_auto_updates(),
        "fail2ban": _collect_fail2ban(),
        "password_policy": _collect_password_policy(),
    }