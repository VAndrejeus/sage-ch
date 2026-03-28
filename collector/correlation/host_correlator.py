def build_ip_index(endpoint_hosts: list) -> dict:
    ip_index = {}

    for host in endpoint_hosts:
        host_id = host.get("id") or host.get("host_id")
        if not host_id:
            continue

        candidate_ips = []

        # Older / alternate normalized fields
        primary_ip = host.get("primary_ip")
        if isinstance(primary_ip, str) and primary_ip.strip():
            candidate_ips.append(primary_ip.strip())

        ip_addresses = host.get("ip_addresses", [])
        if isinstance(ip_addresses, list):
            for ip in ip_addresses:
                if isinstance(ip, str) and ip.strip():
                    candidate_ips.append(ip.strip())

        network_interfaces = host.get("network_interfaces", [])
        if isinstance(network_interfaces, list):
            for iface in network_interfaces:
                if not isinstance(iface, dict):
                    continue
                iface_ip = iface.get("ip")
                if isinstance(iface_ip, str) and iface_ip.strip():
                    candidate_ips.append(iface_ip.strip())

        # Current normalized structure: host["network"]["interfaces"][...]["ipv4"]
        network = host.get("network", {})
        if isinstance(network, dict):
            interfaces = network.get("interfaces", [])
            if isinstance(interfaces, list):
                for iface in interfaces:
                    if not isinstance(iface, dict):
                        continue

                    ipv4_list = iface.get("ipv4", [])
                    if isinstance(ipv4_list, list):
                        for ip in ipv4_list:
                            if isinstance(ip, str) and ip.strip():
                                candidate_ips.append(ip.strip())

        # De-duplicate while preserving values
        unique_ips = []
        seen = set()
        for ip in candidate_ips:
            if ip not in seen:
                seen.add(ip)
                unique_ips.append(ip)

        for ip in unique_ips:
            ip_index.setdefault(ip, []).append(host_id)

    return ip_index


def build_hostname_index(endpoint_hosts: list) -> dict:
    hostname_index = {}

    for host in endpoint_hosts:
        host_id = host.get("id") or host.get("host_id")
        if not host_id:
            continue

        hostname = host.get("hostname")
        if isinstance(hostname, str) and hostname.strip():
            normalized = hostname.strip().lower()
            hostname_index.setdefault(normalized, []).append(host_id)

    return hostname_index


def correlate_hosts(endpoint_hosts: list, discovered_hosts: list) -> list:
    correlation_results = []

    ip_index = build_ip_index(endpoint_hosts)
    hostname_index = build_hostname_index(endpoint_hosts)

    for discovered_host in discovered_hosts:
        discovered_ip = discovered_host.get("discovered_ip")
        hostname_clue = discovered_host.get("hostname_clue")

        result = {
            "discovered_ip": discovered_ip,
            "hostname_clue": hostname_clue,
            "correlation_status": "unmatched",
            "matched_host_id": None,
            "matched_by": "none",
            "confidence": "low",
            "candidate_host_ids": [],
        }

        ip_matches = []
        if isinstance(discovered_ip, str) and discovered_ip.strip():
            ip_matches = ip_index.get(discovered_ip.strip(), [])

        if len(ip_matches) == 1:
            result["correlation_status"] = "matched"
            result["matched_host_id"] = ip_matches[0]
            result["matched_by"] = "ip"
            result["confidence"] = "high"
            result["candidate_host_ids"] = ip_matches
            correlation_results.append(result)
            continue

        if len(ip_matches) > 1:
            result["correlation_status"] = "ambiguous"
            result["matched_by"] = "ip"
            result["confidence"] = "low"
            result["candidate_host_ids"] = ip_matches
            correlation_results.append(result)
            continue

        hostname_matches = []
        if isinstance(hostname_clue, str) and hostname_clue.strip():
            normalized_hostname = hostname_clue.strip().lower()
            hostname_matches = hostname_index.get(normalized_hostname, [])

        if len(hostname_matches) == 1:
            result["correlation_status"] = "matched"
            result["matched_host_id"] = hostname_matches[0]
            result["matched_by"] = "hostname"
            result["confidence"] = "medium"
            result["candidate_host_ids"] = hostname_matches
            correlation_results.append(result)
            continue

        if len(hostname_matches) > 1:
            result["correlation_status"] = "ambiguous"
            result["matched_by"] = "hostname"
            result["confidence"] = "low"
            result["candidate_host_ids"] = hostname_matches
            correlation_results.append(result)
            continue

        correlation_results.append(result)

    return correlation_results