import os
import shutil
import subprocess
from typing import Any, Dict, List


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


def _read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def _collect_auditd_settings() -> List[Dict[str, Any]]:
    settings: List[Dict[str, Any]] = []

    if _command_exists("auditctl"):
        status_result = _run(["auditctl", "-s"])
        if status_result["stdout"]:
            for line in status_result["stdout"].splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                settings.append({
                    "category": "auditd_status",
                    "setting": stripped,
                })

        rules_result = _run(["auditctl", "-l"])
        if rules_result["stdout"]:
            for line in rules_result["stdout"].splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                settings.append({
                    "category": "audit_rule",
                    "setting": stripped,
                })

    rules_dir = "/etc/audit/rules.d"
    if os.path.isdir(rules_dir):
        for name in sorted(os.listdir(rules_dir)):
            if not name.endswith(".rules"):
                continue

            content = _read_file(os.path.join(rules_dir, name))
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                settings.append({
                    "category": f"rules_file:{name}",
                    "setting": stripped,
                })

    auditd_conf = _read_file("/etc/audit/auditd.conf")
    if auditd_conf:
        for line in auditd_conf.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            settings.append({
                "category": "auditd_conf",
                "setting": stripped,
            })

    return settings


def collect() -> Dict[str, Any]:
    settings = _collect_auditd_settings()

    return {
        "total_settings": len(settings),
        "settings": settings,
    }