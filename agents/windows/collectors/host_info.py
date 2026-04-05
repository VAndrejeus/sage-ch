import platform
import re
import socket
import subprocess
from typing import Dict, List, Any


def _run(cmd: List[str]) -> str:
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=20,
        encoding="utf-8",
        errors="ignore"
    )
    return result.stdout.strip()


def _clean_ip_value(value: str) -> str:
    if not value:
        return ""

    value = value.strip()
    value = re.sub(r"\(Preferred\)|\(Deprecated\)", "", value, flags=re.IGNORECASE).strip()

    if "%" in value:
        value = value.split("%", 1)[0].strip()

    return value


def _is_ipv4(value: str) -> bool:
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value.strip()))


def _is_ipv6(value: str) -> bool:
    value = value.strip()
    return ":" in value and len(value) >= 2


def _is_new_field_line(line: str) -> bool:
    if ":" not in line:
        return False

    left, _ = line.split(":", 1)
    left = left.strip()

    if not left:
        return False

    if _is_ipv4(left) or _is_ipv6(left):
        return False

    return True


def parse_ipconfig(raw: str) -> Dict[str, Any]:
    interfaces = []
    dns_servers = []
    default_gateway = None
    current_iface = None
    current_multiline_field = None

    for raw_line in raw.splitlines():
        line = raw_line.rstrip("\r")
        stripped = line.strip()

        if not stripped:
            current_multiline_field = None
            continue

        if stripped.endswith(":") and "adapter" in stripped.lower():
            if current_iface:
                interfaces.append(current_iface)

            current_iface = {
                "name": stripped.replace("adapter", "").replace(":", "").strip(),
                "mac_address": None,
                "ipv4": [],
                "ipv6": [],
                "subnet_mask": None,
                "dhcp_enabled": None,
                "gateway": None,
            }
            current_multiline_field = None
            continue

        if current_iface is None:
            continue

        if current_multiline_field in {"gateway", "dns_servers"} and _is_new_field_line(stripped):
            current_multiline_field = None

        if "Physical Address" in stripped:
            current_iface["mac_address"] = stripped.split(":", 1)[-1].strip()
            current_multiline_field = None

        elif "IPv4 Address" in stripped:
            value = _clean_ip_value(stripped.split(":", 1)[-1])
            if _is_ipv4(value):
                current_iface["ipv4"].append(value)
            current_multiline_field = None

        elif "IPv6 Address" in stripped or "Temporary IPv6 Address" in stripped or "Link-local IPv6 Address" in stripped:
            value = _clean_ip_value(stripped.split(":", 1)[-1])
            if _is_ipv6(value):
                current_iface["ipv6"].append(value)
            current_multiline_field = None

        elif "Subnet Mask" in stripped:
            current_iface["subnet_mask"] = stripped.split(":", 1)[-1].strip()
            current_multiline_field = None

        elif "DHCP Enabled" in stripped:
            current_iface["dhcp_enabled"] = "Yes" in stripped
            current_multiline_field = None

        elif "Default Gateway" in stripped:
            value = _clean_ip_value(stripped.split(":", 1)[-1])
            if value and (_is_ipv4(value) or _is_ipv6(value)):
                current_iface["gateway"] = value
            current_multiline_field = "gateway"

        elif stripped.startswith("DNS Servers"):
            value = _clean_ip_value(stripped.split(":", 1)[-1])
            if value and (_is_ipv4(value) or _is_ipv6(value)):
                if value not in dns_servers:
                    dns_servers.append(value)
            current_multiline_field = "dns_servers"

        elif current_multiline_field == "gateway":
            value = _clean_ip_value(stripped)
            if _is_ipv4(value) or _is_ipv6(value):
                current_iface["gateway"] = value
            else:
                current_multiline_field = None

        elif current_multiline_field == "dns_servers":
            value = _clean_ip_value(stripped)
            if _is_ipv4(value) or _is_ipv6(value):
                if value not in dns_servers:
                    dns_servers.append(value)
            else:
                current_multiline_field = None

        else:
            current_multiline_field = None

    if current_iface:
        interfaces.append(current_iface)

    interfaces = [i for i in interfaces if i["ipv4"] or i["ipv6"]]

    for iface in interfaces:
        if iface.get("gateway"):
            gateway = iface["gateway"]
            if _is_ipv4(gateway):
                default_gateway = gateway
                break
            if default_gateway is None:
                default_gateway = gateway

    for iface in interfaces:
        iface.pop("gateway", None)

    return {
        "interfaces": interfaces,
        "default_gateway": default_gateway,
        "dns_servers": dns_servers
    }


def collect() -> Dict:
    raw = _run(["ipconfig", "/all"])
    parsed = parse_ipconfig(raw)

    return {
        "hostname": socket.gethostname(),
        "os_name": platform.system(),
        "os_version": platform.version(),
        "platform": platform.platform(),
        "network": parsed,
        "evidence": {
            "raw_ipconfig": raw
        }
    }