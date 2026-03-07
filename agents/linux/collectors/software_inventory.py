from typing import Any, Dict, List
from agents.linux.collectors.host_info import _run_cmd

def _parse_package_output(stdout: str) -> List[Dict[str, str]]:
    # Parses tab-separated package output into a normalized package list.
    packages: List[Dict[str, str]] = []

    if not stdout:
        return packages
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
            
        parts = line.split("\t")
        if len(parts) != 3:
            continue

        name, version, arch = parts
        packages.append(
            {
                "name": name,
                "version": version,
                "arch": arch,
            }
        )

    return packages

def collect(platform_info: Dict[str, Any]) -> Dict[str, Any]:
    #Collects installed software
    family = platform_info.get("family", "unknown")

    if family == "rhel":
        cmd = ["rpm", "-qa", "--qf", r"%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"]
        result = _run_cmd(cmd)
        packages = _parse_package_output(result["stdout"])

        return {
            "method": "rpm -qa",
            "family": family,
            "total_detected": len(packages),
            "packages": packages,
            "evidence": {
                "cmd": result["cmd"],
                "ok": result["ok"],
                "returncode": result["returncode"],
                                     
            },
        }
    if family == "debian":
        cmd = ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n"]
        result = _run_cmd(cmd)
        packages = _parse_package_output(result["stdout"])

        return {
            "method": "dpkg-query -W",
            "family": family,
            "total_detected": len(packages),
            "packages": packages,
            "evidence": {
                "cmd": result["cmd"],
                "ok": result["ok"],
                "returncode": result["returncode"],
            },
        }

    return {
        "method": "unsupported",
        "family": family,
        "total_detected": 0,
        "packages": [],
        "note": "Unsupported or unknown Linux family for software inventory collection.",
    }