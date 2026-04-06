import json
import platform
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


def _run_cmd(cmd: List[str]) -> Dict[str, Any]:
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
    if not stdout:
        return []

    try:
        data = json.loads(stdout)
        if isinstance(data, list):
            return data
        return []
    except json.JSONDecodeError:
        return []


def _prefix_to_netmask(prefixlen: int) -> Optional[str]:
    if not isinstance(prefixlen, int):
        return None

    if prefixlen < 0 or prefixlen > 32:
        return None

    mask = (0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF if prefixlen > 0 else 0
    return ".".join(str((mask >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def _extract_interfaces(ip_addr_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    interfaces: List[Dict[str, Any]] = []

    for iface in ip_addr_data:
        name = iface.get("ifname", "")
        mac = iface.get("address", "")
        addr_info = iface.get("addr_info", [])

        ipv4: List[str] = []
        ipv6: List[str] = []
        subnet_mask: Optional[str] = None

        for addr in addr_info:
            family = addr.get("family")
            local = addr.get("local")

            if not local:
                continue

            if family == "inet":
                ipv4.append(local)
                if subnet_mask is None:
                    subnet_mask = _prefix_to_netmask(addr.get("prefixlen"))
            elif family == "inet6":
                ipv6.append(local)

        if name:
            interfaces.append(
                {
                    "name": name,
                    "mac_address": mac,
                    "ipv4": ipv4,
                    "ipv6": ipv6,
                    "subnet_mask": subnet_mask,
                    "dhcp_enabled": None,
                }
            )

    return interfaces


def _extract_default_gateway(route_data: List[Dict[str, Any]]) -> Optional[str]:
    for route in route_data:
        if route.get("dst") == "default":
            gateway = route.get("gateway")
            if gateway:
                return gateway
    return None


def _extract_dns_servers() -> List[str]:
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
                value = parts[1].strip()
                if value and value not in dns_servers:
                    dns_servers.append(value)

    return dns_servers


def collect() -> Dict[str, Any]:
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