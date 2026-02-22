import subprocess
from typing import Dict

def _run_powershell(command: str) -> str:
    result = subprocess.run(
        ["powershell", "-Command", command],
        capture_output=True,
        text=True,        
    )
    return result.stdout.strip()
def collect() -> Dict:
    try:
        cmd = "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 -ExpandProperty InstalledOn"
        output = _run_powershell(cmd)

        return {
            "method": "PowerShell Get-HotFix (latest InstalledOn)",
            "latest_hotfix_date": output if output else None,
        }
    except Exception as e:
        return {
            "method": "PowerShell Get-HotFix",
            "latest_hotfix_date": None,
            "error": str(e),
        }