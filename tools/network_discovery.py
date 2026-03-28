
from __future__ import annotations

import json
import platform
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from ipaddress import IPv4Interface, ip_network
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import psutil
except ImportError:
    print("This script requires psutil. Install it with: pip install psutil")
    sys.exit(1)


CONNECT_TIMEOUT = 0.35
MAX_WORKERS = 128

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

IGNORED_INTERFACE_PREFIXES = (
    "lo",
    "loopback",
    "docker",
    "veth",
    "br-",
    "virbr",
    "vmnet",
    "vboxnet",
    "zt",
    "tun",
    "tap",
    "tailscale",
    "wg",
    "utun",
    "ham",
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_hostname_lookup(ip: str) -> Optional[str]:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


def guess_service_name(port: int, protocol: str) -> str:
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


def load_discovery_scope(config_path: Path) -> Dict[str, Any]:
    if not config_path.exists():
        raise FileNotFoundError(f"Discovery scope config not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    authorized_networks = data.get("authorized_networks", [])
    authorized_interfaces = data.get("authorized_interfaces", [])
    max_hosts_per_subnet = data.get("max_hosts_per_subnet", 1024)
    private_only = data.get("private_only", True)

    if not isinstance(authorized_networks, list) or not authorized_networks:
        raise ValueError("authorized_networks must be a non-empty list.")

    if not isinstance(authorized_interfaces, list) or not authorized_interfaces:
        raise ValueError("authorized_interfaces must be a non-empty list.")

    allow_all_networks = "*" in authorized_networks
    allow_all_interfaces = "*" in authorized_interfaces

    parsed_networks = []
    if allow_all_networks:
        parsed_networks = ["*"]
    else:
        for cidr in authorized_networks:
            parsed_networks.append(str(ip_network(cidr, strict=False)))

    if not isinstance(max_hosts_per_subnet, int) or max_hosts_per_subnet < 1:
        raise ValueError("max_hosts_per_subnet must be a positive integer.")

    if not isinstance(private_only, bool):
        raise ValueError("private_only must be true or false.")

    return {
        "authorized_networks": parsed_networks,
        "authorized_interfaces": authorized_interfaces,
        "allow_all_networks": allow_all_networks,
        "allow_all_interfaces": allow_all_interfaces,
        "max_hosts_per_subnet": max_hosts_per_subnet,
        "private_only": private_only,
    }


def get_local_ipv4_interfaces(scope: Dict[str, Any]) -> List[Dict[str, Any]]:
    interfaces: List[Dict[str, Any]] = []
    addrs = psutil.net_if_addrs()

    authorized_networks = set(scope["authorized_networks"])
    authorized_interfaces = set(scope["authorized_interfaces"])
    allow_all_networks = scope["allow_all_networks"]
    allow_all_interfaces = scope["allow_all_interfaces"]
    max_hosts_per_subnet = scope["max_hosts_per_subnet"]
    private_only = scope["private_only"]

    for if_name, if_addrs in addrs.items():
        if should_ignore_interface(if_name):
            continue
        if not is_interface_up(if_name):
            continue
        if not allow_all_interfaces and if_name not in authorized_interfaces:
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

            try:
                iface = IPv4Interface(f"{ip}/{netmask}")
                network = iface.network
            except Exception:
                continue

            if private_only and not network.is_private:
                continue

            network_cidr = str(network)

            if not allow_all_networks and network_cidr not in authorized_networks:
                continue

            if network.num_addresses > max_hosts_per_subnet:
                continue

            interfaces.append({
                "interface": if_name,
                "ip": str(iface.ip),
                "netmask": str(iface.netmask),
                "cidr": network_cidr,
                "broadcast": str(network.broadcast_address),
            })

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
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        s.close()


def probe_service(ip: str, port: int, protocol: str) -> Optional[Dict[str, Any]]:
    if protocol != "tcp":
        return None

    if not tcp_connect(ip, port, CONNECT_TIMEOUT):
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
                continue

    discovered.sort(key=lambda x: tuple(int(part) for part in x["discovered_ip"].split(".")))
    return discovered


def build_output(scope: Dict[str, Any], interfaces: List[Dict[str, Any]], discovered_hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
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
            "scan_mode": "non_intrusive_allowlisted",
            "scanner_host": socket.gethostname(),
            "platform": platform.platform(),
            "started_at": None,
            "completed_at": None,
            "target_port_count": len(TARGET_PORTS),
        },
        "discovery_scope": {
            "authorized_networks": scope["authorized_networks"],
            "authorized_interfaces": scope["authorized_interfaces"],
            "allow_all_networks": scope["allow_all_networks"],
            "allow_all_interfaces": scope["allow_all_interfaces"],
            "max_hosts_per_subnet": scope["max_hosts_per_subnet"],
            "private_only": scope["private_only"],
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
    project_root = Path.cwd()
    config_path = project_root / "config" / "discovery_scope.json"
    output_dir = project_root / "outputs" / "discovery"

    start_time = utc_now_iso()
    scope = load_discovery_scope(config_path)

    interfaces = get_local_ipv4_interfaces(scope)
    if not interfaces:
        print("No eligible allowlisted active IPv4 interfaces/networks found.")
        sys.exit(0)

    unique_cidrs = sorted({item["cidr"] for item in interfaces})

    print("Discovery scope from config:")
    if scope["allow_all_networks"]:
        print("  authorized_networks: *")
    else:
        for cidr in scope["authorized_networks"]:
            print(f"  authorized_network: {cidr}")

    if scope["allow_all_interfaces"]:
        print("  authorized_interfaces: *")
    else:
        for iface in scope["authorized_interfaces"]:
            print(f"  authorized_interface: {iface}")

    print(f"  max_hosts_per_subnet: {scope['max_hosts_per_subnet']}")
    print(f"  private_only: {scope['private_only']}")

    print("\nEligible allowlisted networks to scan:")
    for cidr in unique_cidrs:
        print(f"  - {cidr}")

    all_discovered: Dict[str, Dict[str, Any]] = {}

    for cidr in unique_cidrs:
        print(f"Scanning subnet: {cidr}")
        subnet_results = scan_subnet(cidr)

        for host in subnet_results:
            ip = host["discovered_ip"]
            if ip not in all_discovered:
                all_discovered[ip] = host
            else:
                existing = all_discovered[ip]
                existing_keys = {
                    (s["port"], s["protocol"]) for s in existing["observed_services"]
                }
                for svc in host["observed_services"]:
                    key = (svc["port"], svc["protocol"])
                    if key not in existing_keys:
                        existing["observed_services"].append(svc)

    discovered_hosts = sorted(
        all_discovered.values(),
        key=lambda x: tuple(int(part) for part in x["discovered_ip"].split("."))
    )

    output = build_output(scope, interfaces, discovered_hosts)
    output["scan_metadata"]["started_at"] = start_time
    output["scan_metadata"]["completed_at"] = utc_now_iso()

    output_path = write_output(output, output_dir)

    print("\nScan complete.")
    print(f"Discovered hosts: {len(discovered_hosts)}")
    print(f"Output written to: {output_path}")


if __name__ == "__main__":
    main()