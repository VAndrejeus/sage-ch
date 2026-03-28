def normalize_raw_service_name(raw_service_name: str) -> str:
    if not isinstance(raw_service_name, str):
        return "unknown"

    value = raw_service_name.strip().lower()

    service_map = {
        "ssh": "ssh",
        "telnet": "telnet",
        "dns": "dns",
        "http": "http",
        "http-proxy": "http",
        "https": "https",
        "https-alt": "https",
        "kerberos": "kerberos",
        "msrpc": "rpc",
        "netbios-ssn": "netbios-ssn",
        "ldap": "ldap",
        "ldaps": "ldaps",
        "microsoft-ds": "smb",
        "ms-sql-s": "mssql",
        "oracle": "oracle",
        "mysql": "mysql",
        "postgresql": "postgresql",
        "ms-wbt-server": "rdp",
        "vnc": "vnc",
        "wsman": "winrm",
        "wsmans": "winrm",
        "unknown": "unknown",
    }

    return service_map.get(value, value)


def normalize_discovered_hosts(discovered_hosts: list) -> list:
    normalized_hosts = []

    for host in discovered_hosts:
        normalized_host = {
            "discovered_ip": host.get("discovered_ip"),
            "hostname_clue": host.get("hostname_clue"),
            "reachable": host.get("reachable", False),
            "observed_at": host.get("observed_at"),
            "observed_services": [],
        }

        observed_services = host.get("observed_services", [])
        if not isinstance(observed_services, list):
            observed_services = []

        for service in observed_services:
            raw_service_name = service.get("raw_service_name", "unknown")

            normalized_service = {
                "port": service.get("port"),
                "protocol": service.get("protocol"),
                "raw_service_name": raw_service_name,
                "service_name": normalize_raw_service_name(raw_service_name),
                "state": service.get("state"),
                "discovery_method": service.get("discovery_method"),
                "confidence": service.get("confidence"),
                "banner": service.get("banner"),
                "notes": service.get("notes"),
            }

            normalized_host["observed_services"].append(normalized_service)

        normalized_hosts.append(normalized_host)

    return normalized_hosts