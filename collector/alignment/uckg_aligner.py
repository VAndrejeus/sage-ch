def map_node_type(node_type: str) -> str:
    node_type_map = {
        "host": "Asset",
        "software": "Software",
        "update_status": "PatchStatus",
        "service": "NetworkService",
    }
    return node_type_map.get(node_type, "Entity")


def map_edge_type(edge_type: str) -> str:
    edge_type_map = {
        "HOST_HAS_SOFTWARE": "HAS_SOFTWARE",
        "HOST_HAS_UPDATE_STATUS": "HAS_PATCH_STATUS",
        "HOST_EXPOSES_SERVICE": "EXPOSES_SERVICE",
    }
    return edge_type_map.get(edge_type, edge_type)


def align_node(node: dict) -> dict:
    aligned = {
        "id": node.get("id"),
        "type": map_node_type(node.get("type", "unknown")),
        "original_type": node.get("type", "unknown"),
        "label": node.get("label", "unknown"),
        "properties": {},
    }

    original_type = node.get("type")

    if original_type == "host":
        aligned["properties"] = {
            "hostname": node.get("hostname"),
            "os_name": node.get("os_name"),
            "os_version": node.get("os_version"),
            "primary_ip": node.get("primary_ip"),
            "source": node.get("source"),
            "managed": node.get("managed"),
            "discovery_only": node.get("discovery_only", False),
            "correlation_status": node.get("correlation_status"),
        }

    elif original_type == "software":
        aligned["properties"] = {
            "name": node.get("label"),
        }

    elif original_type == "update_status":
        aligned["properties"] = {
            "status": node.get("label"),
        }

    elif original_type == "service":
        aligned["properties"] = {
            "service_name": node.get("service_name"),
            "port": node.get("port"),
            "protocol": node.get("protocol"),
        }

    else:
        aligned["properties"] = {
            k: v for k, v in node.items()
            if k not in {"id", "type", "label"}
        }

    return aligned


def align_edge(edge: dict) -> dict:
    return {
        "source": edge.get("source"),
        "target": edge.get("target"),
        "type": map_edge_type(edge.get("type", "unknown")),
        "original_type": edge.get("type", "unknown"),
        "properties": {
            k: v for k, v in edge.items()
            if k not in {"source", "target", "type"}
        }
    }


def align_graph_to_uckg(graph: dict) -> dict:
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    aligned_nodes = [align_node(node) for node in nodes if isinstance(node, dict)]
    aligned_edges = [align_edge(edge) for edge in edges if isinstance(edge, dict)]

    return {
        "schema": "UCKG-basic-alignment-v1",
        "summary": {
            "node_count": len(aligned_nodes),
            "edge_count": len(aligned_edges),
        },
        "nodes": aligned_nodes,
        "edges": aligned_edges,
    }