import json
import platform
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

def _run_cmd(cmd: List[str]) -> Dict[str, Any]:
    # Runs command safely and returns structured results disctionary
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,            
        )
        return {
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
            "cmd": " ".join(cmd),
        }
    except Exception as e:
        return {
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": str(e),
            "cmd": " ".join(cmd),            
        }
def _read_os_release() -> Dict[str, str]:
    #Reads /etc/os-release (or /usr/lib/os-release) and returns key/value pairs.
    path_candidates = [Path("/etc/os-release"), Path("/usr/lib/os-release")]

    for path in path_candidates:
        if path.exists():
            data: Dict[str, str] = {}
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                data[k.strip()] = v.strip().strip('"').strip("'")
            return data

    return {}