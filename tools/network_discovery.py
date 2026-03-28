"""
Standalone non-intrusive network discovery script.

What it does:
- Enumerates active local IPv4 interfaces
- Ignores loopback and common virtual/tunnel/container interfaces
- Derives directly connected subnets
- Performs lightweight host/service discovery with TCP connect()
- Writes one JSON file containing all discovered hosts for the scan
Notes:
- This is intentionally conservative and non-intrusive.
- It does NOT perform vulnerability scanning.
- It does NOT attempt authentication or exploitation.
- Service names are raw guesses; collector normalizes it later.
"""

from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from ipaddress import IPv4Interface, IPv4Network, ip_network
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import psutil
except ImportError:
    print("This script requires psutil. Install it with: pip install psutil")
    sys.exit(1)




CONNECT_TIMEOUT = 0.35
MAX_WORKERS = 128

# Small, common, non-intrusive attack-surface-oriented port set
TARGET_PORTS: List[Tuple[int, str]] = [
    (22, "tcp"),
    (23, "tcp"),
    (53, "tcp"),
    (80, "tcp"),
    (88, "tcp"),
    (135, "tcp"),
    (139, "tcp"),
    (389, "tcp"),
    (443, "tcp"),
    (445, "tcp"),
    (636, "tcp"),
    (1433, "tcp"),
    (1521, "tcp"),
    (3306, "tcp"),
    (3389, "tcp"),
    (5432, "tcp"),
    (5900, "tcp"),
    (5985, "tcp"),
    (5986, "tcp"),
    (8080, "tcp"),
    (8443, "tcp"),
]

# Common interface prefixes/names to ignore
IGNORED_INTERFACE_PREFIXES = (
    "lo",          # loopback
    "loopback",
    "docker",
    "veth",
    "br-",
    "virbr",
    "vmnet",
    "vboxnet",
    "zt",          # ZeroTier
    "tun",
    "tap",
    "tailscale",
    "wg",          # WireGuard
    "utun",
    "ham",
)

PRIVATE_ONLY = True
MAX_HOSTS_PER_SUBNET = 1024  # safety cap


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_hostname_lookup(ip: str) -> Optional[str]:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


def guess_service_name(port: int, protocol: str) -> str:
    """
    Raw service guess only.
    Collector should normalize later if needed.
    """
    known = {
        (22, "tcp"): "ssh",
        (23, "tcp"): "telnet",
        (53, "tcp"): "dns",
        (80, "tcp"): "http",
        (88, "tcp"): "kerberos",
        (135, "tcp"): "msrpc",
        (139, "tcp"): "netbios-ssn",
        (389, "tcp"): "ldap",
        (443, "tcp"): "https",
        (445, "tcp"): "microsoft-ds",
        (636, "tcp"): "ldaps",
        (1433, "tcp"): "ms-sql-s",
        (1521, "tcp"): "oracle",
        (3306, "tcp"): "mysql",
        (3389, "tcp"): "ms-wbt-server",
        (5432, "tcp"): "postgresql",
        (5900, "tcp"): "vnc",
        (5985, "tcp"): "wsman",
        (5986, "tcp"): "wsmans",
        (8080, "tcp"): "http-proxy",
        (8443, "tcp"): "https-alt",
    }
    return known.get((port, protocol), "unknown")


def should_ignore_interface(name: str) -> bool:
    lower = name.lower()
    return lower.startswith(IGNORED_INTERFACE_PREFIXES)


def is_interface_up(name: str) -> bool:
    stats = psutil.net_if_stats()
    st = stats.get(name)
    return bool(st and st.isup)


def is_private_ipv4(addr: str) -> bool:
    try:
        return ip_network(f"{addr}/32", strict=False).is_private
    except Exception:
        return False


def get_local_ipv4_interfaces() -> List[Dict[str, Any]]:
    """
    Returns active, filtered IPv4 interfaces with subnet info.
    """
    interfaces: List[Dict[str, Any]] = []
    addrs = psutil.net_if_addrs()

    for if_name, if_addrs in addrs.items():
        if should_ignore_interface(if_name):
            continue
        if not is_interface_up(if_name):
            continue

        for addr in if_addrs:
            if addr.family != socket.AF_INET:
                continue

            ip = addr.address
            netmask = addr.netmask

            if not ip or not netmask:
                continue
            if ip.startswith("127."):
                continue
            if PRIVATE_ONLY and not is_private_ipv4(ip):
                continue

            try:
                iface = IPv4Interface(f"{ip}/{netmask}")
                network = iface.network
            except Exception:
                continue

            host_count = network.num_addresses
            if host_count > MAX_HOSTS_PER_SUBNET:
                # safety skip for overly broad networks
                continue

            interfaces.append({
                "interface": if_name,
                "ip": str(iface.ip),
                "netmask": str(iface.netmask),
                "cidr": str(network),
                "broadcast": str(network.broadcast_address),
            })

    # Deduplicate if multiple entries map to same network
    seen: Set[Tuple[str, str]] = set()
    deduped: List[Dict[str, Any]] = []
    for item in interfaces:
        key = (item["interface"], item["cidr"])
        if key not in seen:
            seen.add(key)
            deduped.append(item)

    return deduped


def tcp_connect(ip: str, port: int, timeout: float) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((ip, port))
        return result == 0
    except Exception:
        return False
    finally:
        s.close()


def probe_service(ip: str, port: int, protocol: str) -> Optional[Dict[str, Any]]:
    if protocol != "tcp":
        return None

    is_open = tcp_connect(ip, port, CONNECT_TIMEOUT)
    if not is_open:
        return None

    return {
        "port": port,
        "protocol": protocol,
        "raw_service_name": guess_service_name(port, protocol),
        "state": "open",
        "discovery_method": "tcp_connect",
        "confidence": "medium",
        "banner": None,
        "notes": None,
    }


def probe_host(ip: str) -> Optional[Dict[str, Any]]:
    observed_services: List[Dict[str, Any]] = []

    for port, proto in TARGET_PORTS:
        obs = probe_service(ip, port, proto)
        if obs is not None:
            observed_services.append(obs)

    if not observed_services:
        return None

    return {
        "discovered_ip": ip,
        "hostname_clue": safe_hostname_lookup(ip),
        "reachable": True,
        "observed_services": observed_services,
        "observed_at": utc_now_iso(),
    }


def scan_subnet(cidr: str) -> List[Dict[str, Any]]:
    network = ip_network(cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]
    discovered: List[Dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(probe_host, ip): ip for ip in hosts}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    discovered.append(result)
            except Exception:
                # Keep scan resilient
                continue

    discovered.sort(key=lambda x: tuple(int(part) for part in x["discovered_ip"].split(".")))
    return discovered



def build_output(interfaces: List[Dict[str, Any]], discovered_hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
    scanned_networks = []
    for iface in interfaces:
        scanned_networks.append({
            "interface": iface["interface"],
            "local_ip": iface["ip"],
            "cidr": iface["cidr"],
        })

    return {
        "scan_metadata": {
            "project": "SAGE-CH",
            "scan_type": "network_discovery",
            "scan_mode": "non_intrusive",
            "scanner_host": socket.gethostname(),
            "platform": platform.platform(),
            "started_at": None,   # filled by main()
            "completed_at": None, # filled by main()
            "target_port_count": len(TARGET_PORTS),
        },
        "scanned_networks": scanned_networks,
        "discovered_hosts": discovered_hosts,
    }


def write_output(data: Dict[str, Any], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"network_discovery_{timestamp}.json"

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return output_path

def main() -> None:
    start_time = utc_now_iso()

    interfaces = get_local_ipv4_interfaces()
    if not interfaces:
        print("No eligible active private IPv4 interfaces found.")
        sys.exit(0)

    unique_cidrs = sorted({item["cidr"] for item in interfaces})
    print("Eligible networks:")
    for cidr in unique_cidrs:
        print(f"  - {cidr}")

    all_discovered: Dict[str, Dict[str, Any]] = {}

    for cidr in unique_cidrs:
        print(f"Scanning subnet: {cidr}")
        subnet_results = scan_subnet(cidr)

        # Deduplicate discovered hosts across overlapping/duplicate scans by IP
        for host in subnet_results:
            ip = host["discovered_ip"]
            if ip not in all_discovered:
                all_discovered[ip] = host
            else:
                existing = all_discovered[ip]
                existing_services = {
                    (s["port"], s["protocol"]) for s in existing["observed_services"]
                }
                for svc in host["observed_services"]:
                    key = (svc["port"], svc["protocol"])
                    if key not in existing_services:
                        existing["observed_services"].append(svc)

    discovered_hosts = sorted(
        all_discovered.values(),
        key=lambda x: tuple(int(part) for part in x["discovered_ip"].split("."))
    )

    output = build_output(interfaces, discovered_hosts)
    output["scan_metadata"]["started_at"] = start_time
    output["scan_metadata"]["completed_at"] = utc_now_iso()

    output_dir = Path.cwd() / "outputs" / "discovery"
    output_path = write_output(output, output_dir)

    print("\nScan complete.")
    print(f"Discovered hosts: {len(discovered_hosts)}")
    print(f"Output written to: {output_path}")


if __name__ == "__main__":
    main()