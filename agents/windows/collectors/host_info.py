# collect hostname, os name/version, platform string, full ipconfig /all
import platform, socket, subprocess
from typing import Dict, List

def _run(cmd: List[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout.strip()

def collect() -> Dict:
    return {
        "hostname": socket.gethostname(),
        "os_name": platform.system(),
        "os_version": platform.version(),
        "platform": platform.platform(),
        "raw_ipconfig": _run(["ipconfig", "/all"]),
    }