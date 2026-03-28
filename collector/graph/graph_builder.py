def _safe_str(value, default="unknown"):
    if isinstance(value, str) and value.strip():
        return value.strip()
    return default


def _build_host_node(host):
    host_id = host.get("id") or host.get("host_id") or host.get("hostname") or "unknown-host"

    return {
        "id": host_id,
        "type": "host",
        "label": host.get("hostname", host_id),
        "hostname": host.get("hostname", "unknown"),
        "os_name": host.get("os_name", "unknown"),
        "os_version": host.get("os_version", "unknown"),
        "primary_ip": host.get("primary_ip", "unknown"),
        "source": "endpoint_agent",
        "managed": True,
    }


def _build_software_node(name):
    safe_name = _safe_str(name, "unknown-software")
    return {
        "id": f"software-{safe_name.lower()}",
        "type": "software",
        "label": safe_name,
    }


def _build_update_status_node(status):
    safe_status = _safe_str(status, "unknown")
    return {
        "id": f"update-status-{safe_status.lower()}",
        "type": "update_status",
        "label": safe_status,
    }


def _build_service_node(service_name, port, protocol):
    safe_service_name = _safe_str(service_name, "unknown").lower()
    safe_protocol = _safe_str(protocol, "unknown").lower()
    safe_port = port if port is not None else "unknown"

    return {
        "id": f"service-{safe_service_name}-{safe_port}-{safe_protocol}",
        "type": "service",
        "label": f"{safe_service_name}:{safe_port}/{safe_protocol}",
        "service_name": safe_service_name,
        "port": port,
        "protocol": safe_protocol,
    }


def _build_discovered_host_node(discovered_host, correlation_result):
    discovered_ip = discovered_host.get("discovered_ip", "unknown-ip")
    hostname_clue = discovered_host.get("hostname_clue")
    correlation_status = correlation_result.get("correlation_status", "unmatched")

    label = hostname_clue if isinstance(hostname_clue, str) and hostname_clue.strip() else discovered_ip

    return {
        "id": f"host-discovered-{discovered_ip}",
        "type": "host",
        "label": label,
        "hostname": hostname_clue if hostname_clue else "unknown",
        "os_name": "unknown",
        "os_version": "unknown",
        "primary_ip": discovered_ip,
        "source": "network_discovery",
        "managed": False,
        "discovery_only": True,
        "correlation_status": correlation_status,
    }


def _resolve_target_host_id(discovered_host, correlation_result):
    status = correlation_result.get("correlation_status")
    matched_host_id = correlation_result.get("matched_host_id")

    if status == "matched" and matched_host_id:
        return matched_host_id

    discovered_ip = discovered_host.get("discovered_ip", "unknown-ip")
    return f"host-discovered-{discovered_ip}"


def build_graph(endpoint_hosts, discovered_hosts=None, correlation_results=None):
    discovered_hosts = discovered_hosts or []
    correlation_results = correlation_results or []

    nodes = []
    edges = []

    node_ids = set()
    edge_keys = set()

    def add_node(node):
        node_id = node["id"]
        if node_id not in node_ids:
            nodes.append(node)
            node_ids.add(node_id)

    def add_edge(edge):
        key = (
            edge["source"],
            edge["target"],
            edge["type"],
            tuple(sorted(
                (k, str(v)) for k, v in edge.items()
                if k not in {"source", "target", "type"}
            ))
        )
        if key not in edge_keys:
            edges.append(edge)
            edge_keys.add(key)

    # Existing endpoint graph
    for host in endpoint_hosts:
        host_id = host.get("id") or host.get("host_id") or host.get("hostname") or "unknown-host"

        add_node(_build_host_node(host))

        software_items = host.get("software", [])
        if isinstance(software_items, list):
            for software in software_items:
                if isinstance(software, dict):
                    software_name = software.get("name", "unknown-software")
                    version = software.get("version", "unknown")
                    architecture = software.get("architecture", "unknown")
                else:
                    software_name = str(software)
                    version = "unknown"
                    architecture = "unknown"

                software_node = _build_software_node(software_name)
                add_node(software_node)

                add_edge({
                    "source": host_id,
                    "target": software_node["id"],
                    "type": "HOST_HAS_SOFTWARE",
                    "version": version,
                    "architecture": architecture,
                })

        update_status = host.get("update_status", "unknown")
        update_node = _build_update_status_node(update_status)
        add_node(update_node)

        add_edge({
            "source": host_id,
            "target": update_node["id"],
            "type": "HOST_HAS_UPDATE_STATUS",
        })

    # Map correlation results by discovered IP
    correlation_by_ip = {}
    for result in correlation_results:
        discovered_ip = result.get("discovered_ip")
        if isinstance(discovered_ip, str) and discovered_ip.strip():
            correlation_by_ip[discovered_ip.strip()] = result

    # Add discovered-only host nodes for unmatched/ambiguous hosts
    for discovered_host in discovered_hosts:
        discovered_ip = discovered_host.get("discovered_ip")
        if not isinstance(discovered_ip, str) or not discovered_ip.strip():
            continue

        correlation_result = correlation_by_ip.get(discovered_ip, {
            "correlation_status": "unmatched",
            "matched_host_id": None,
            "matched_by": "none",
            "confidence": "low",
        })

        status = correlation_result.get("correlation_status")
        if status in {"unmatched", "ambiguous"}:
            add_node(_build_discovered_host_node(discovered_host, correlation_result))

    # Add service nodes and HOST_EXPOSES_SERVICE edges
    for discovered_host in discovered_hosts:
        discovered_ip = discovered_host.get("discovered_ip")
        if not isinstance(discovered_ip, str) or not discovered_ip.strip():
            continue

        correlation_result = correlation_by_ip.get(discovered_ip, {
            "correlation_status": "unmatched",
            "matched_host_id": None,
            "matched_by": "none",
            "confidence": "low",
        })

        target_host_id = _resolve_target_host_id(discovered_host, correlation_result)
        observed_services = discovered_host.get("observed_services", [])

        if not isinstance(observed_services, list):
            continue

        for service in observed_services:
            if not isinstance(service, dict):
                continue

            service_name = service.get("service_name") or service.get("raw_service_name") or "unknown"
            port = service.get("port")
            protocol = service.get("protocol", "unknown")

            service_node = _build_service_node(service_name, port, protocol)
            add_node(service_node)

            add_edge({
                "source": target_host_id,
                "target": service_node["id"],
                "type": "HOST_EXPOSES_SERVICE",
                "port": port,
                "protocol": protocol,
                "state": service.get("state", "unknown"),
                "discovery_method": service.get("discovery_method", "unknown"),
                "confidence": service.get("confidence", "unknown"),
                "observed_at": discovered_host.get("observed_at"),
            })

    return {
        "nodes": nodes,
        "edges": edges,
    }