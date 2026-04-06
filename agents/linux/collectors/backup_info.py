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


def collect() -> Dict[str, Any]:
    evidence: Dict[str, Any] = {}

    candidate_paths = [
        "/var/backups",
        "/backup",
        "/backups",
        "/etc/timeshift",
        "/etc/rsnapshot.conf",
        "/etc/restic",
        "/etc/borgmatic",
    ]

    existing_paths = [path for path in candidate_paths if os.path.exists(path)]
    evidence["existing_paths"] = existing_paths

    tools = {}
    for tool in ("restic", "borg", "borgmatic", "rsnapshot", "timeshift"):
        tools[tool] = _command_exists(tool)
    evidence["tools"] = tools

    snapshot_count = 0
    if tools.get("timeshift"):
        result = _run(["timeshift", "--list"])
        if result["stdout"]:
            for line in result["stdout"].splitlines():
                stripped = line.strip()
                if stripped and ">" not in stripped and "No snapshots" not in stripped:
                    snapshot_count += 1
        evidence["timeshift_list_returncode"] = result["returncode"]

    shadow_copies_present = bool(existing_paths) or any(tools.values()) or snapshot_count > 0

    return {
        "shadow_copies_present": shadow_copies_present,
        "snapshot_count": snapshot_count,
        "evidence": evidence,
    }