from typing import Any, Dict, List

from agents.linux.collectors.host_info import _run_cmd

def collect(platform_info: Dict[str, Any]) -> Dict[str, Any]:
    # Collects update status based on Linux distro

    family = platform_info.get("family", "unknown")

    if family == "rhel":
        cmd = ["dnf", "-q", "check-update"]
        result = _run_cmd(cmd)

        updates_available = False
        updates_count = 0

        if result["returncode"] == 100:
            updates_available = True

            for line in result["stdout"].splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.lower().startswith("last metadata expiration check"):
                    continue

                parts = line.split()
                if len(parts) >= 3:
                    updates_count += 1

        elif result["returncode"] == 0:
            updates_available = None
            updates_count = None

        return {
            "method": "dnf check-update",
            "family": family,
            "updates_available": updates_available,
            "updates_count": updates_count,
            "note": result["stderr"] if result["returncode"] not in [0, 100] else "",
            "evidence": {
                "cmd": result["cmd"],
                "ok": result["ok"],
                "returncode": result["returncode"],
            },
        }

    if family == "debian":
        cmd = ["apt", "list", "--upgradable"]
        result = _run_cmd(cmd)

        updates_available = None
        updates_count = None

        if result["returncode"] == 0:
            updates_count = 0

            for line in result["stdout"].splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.lower().startswith("listing"):
                    continue

                updates_count += 1

            updates_available = updates_count > 0

        return {
            "method": "apt list --upgradable",
            "family": family,
            "updates_available": updates_available,
            "updates_count": updates_count,
            "note": result["stderr"] if result["returncode"] != 0 else "",
            "evidence": {
                "cmd": result["cmd"],
                "ok": result["ok"],
                "returncode": result["returncode"],
            },
        }

    return {
        "method": "unsupported",
        "family": family,
        "updates_available": None,
        "updates_count": None,
        "note": "Unsupported or unknown Linux family for update status collection.",
    }