# collect hostname, os name/version, platform string, full ipconfig /all
import platform, socket, subprocess
from typing import Dict, List

def _run(cmd: List[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout.strip()

def parse_ipconfig(raw: str) -> Dict:
    interfaces = []
    dns_servers = []
    current_iface = None

    for line in raw.splitlines():
        line = line.strip()

        if line.endswith(":") and "adapter"in line.lower():
            if current_iface:
                interfaces.append(current_iface)
            current_iface = {
                "name": line.replace("adapter", "").replace(":","").strip(),
                "mac_address": None,
                "ipv4": None,
                "subnet_mask": None,
                "gateway": None,
                "dhcp_enabled": None
            }
        elif "Physical Address" in line and current_iface:
            current_iface["mac_address"] = line.split(":")[-1].strip()
        
        elif "IPV4 Address" in line and current_iface:
            current_iface["ipv4"] = line.split(":")[-1].replace("(Preferred)", "").strip()
        
        elif "Subnet Mask" in line and current_iface:
            current_iface["subnet_mask"] = line.split(":")[-1].strip()

        elif "Default Gateway" in line and current_iface:
            gw = line.split(":")[-1].strip()
            if gw:
                current_iface["gateway"] = gw
        
        elif "DHCP Enabled" in line and current_iface:
            current_iface["dhcp_enabled"] = "Yes" in line

        elif line.startswith("DNS Servers"):
            dns_servers.append(line.split(":")[-1].strip())

        elif dns_servers and line and line[0].isdigit():
            dns_servers.append(line.strip())
    if current_iface:
        interfaces.append(current_iface)

    #Keep only interfaces that actually have an IP
    interfaces = [i for i in interfaces if i["ipv4"]]

    return {
        "interfaces": interfaces,
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
        "eidence": {
            "raw_ipconfig": raw
        }
    }