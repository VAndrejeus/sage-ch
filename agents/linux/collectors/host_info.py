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

def _parse_json_output(stdout: str) -> List[Dict[str, Any]]:
    #Safely parse JSON test returned by linux command"
    if not stdout:
        return []
    
    try:
        data = json.loads(stdout)
        if isinstance(data, list):
            return data
        return []
    except json.JSONDecodeError:
        return []
    
def _extract_interfaces(ip_addr_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    #converts raw 'ip -j addr' output into a simplified structure
    interfaces: List[Dict[str, Any]] = []

    for iface in ip_addr_data:
        name = iface.get("ifname", "")
        mac = iface.get("address", "")
        addr_info = iface.get("addr_info", [])

        ipv4: List[str] = []
        ipv6: List[str] = []

        for addr in addr_info:
            family = addr.get("amily")
            local = addr.get("local")

            if not local:
                continue
            if family == "inet":
                ipv4.append(local)
            elif family == "inet6":
                ipv6.append(local)
            
        if name:
            interfaces.append(
                {
                    "name": name,
                    "mac_address": mac,
                    "ipv4": ipv4,
                    "ipv6": ipv6,
                    "subnet_mask": None,
                    "dhcp_enabled": None,
                }
            )
    return interfaces

def _extract_default_gateway(route_data: List[Dict[str, Any]]) -> Optional[str]:
    #finds the default gateway from 'ip -j route' output

    for route in route_data:
        if route.get("dst") == "default":
            return route.get("gateway")
    return None


def _extract_dns_servers() -> List[str]:

    #Reads /etc/resolv.conf and extracts nameserver entries.

    resolv_conf = Path("/etc/resolv.conf")
    if not resolv_conf.exists():
        return []

    dns_servers: List[str] = []

    for line in resolv_conf.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2:
                dns_servers.append(parts[1])

    return dns_servers

def collect() -> Dict[str, Any]:

    #Main Linux host information collector.

    hostname = socket.gethostname()
    os_release = _read_os_release()
    kernel_version = platform.release()

    ip_addr_result = _run_cmd(["ip", "-j", "addr"])
    ip_route_result = _run_cmd(["ip", "-j", "route"])

    ip_addr_data = _parse_json_output(ip_addr_result["stdout"])
    ip_route_data = _parse_json_output(ip_route_result["stdout"])

    interfaces = _extract_interfaces(ip_addr_data)
    default_gateway = _extract_default_gateway(ip_route_data)
    dns_servers = _extract_dns_servers()

    os_name = "Linux"
    os_version = os_release.get("PRETTY_NAME", "")
    platform_string = platform.platform()
    distro_id = os_release.get("ID", "")
    distro_like = os_release.get("ID_LIKE", "").split() if os_release.get("ID_LIKE") else []

    return {
    "hostname": hostname,
    "os_name": os_name,
    "os_version": os_version,
    "platform": platform_string,
    "kernel_version": kernel_version,
    "distro_id": distro_id,
    "distro_like": distro_like,
    "network": {
        "interfaces": interfaces,
        "default_gateway": default_gateway,
        "dns_servers": dns_servers,
    },
    "evidence": {
        "ip_addr_cmd": ip_addr_result["cmd"],
        "ip_addr_ok": ip_addr_result["ok"],
        "ip_route_cmd": ip_route_result["cmd"],
        "ip_route_ok": ip_route_result["ok"],
    },
}