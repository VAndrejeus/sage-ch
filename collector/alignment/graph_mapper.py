from __future__ import annotations

from typing import Any, Dict, List


NODE_TYPE_MAP = {
    "host": "Host",
    "asset": "Asset",
    "software": "Software",
    "update_status": "PatchStatus",
    "service": "Service",
    "finding": "Finding",
    "evidence": "Evidence",
    "control": "Control",
    "assessment": "Assessment",
    "explanation": "Explanation",
    "remediation": "Remediation",
    "observation": "Observation",
}

EDGE_TYPE_MAP = {
    "HOST_HAS_SOFTWARE": "HAS_SOFTWARE",
    "HOST_HAS_UPDATE_STATUS": "HAS_PATCH_STATUS",
    "HOST_EXPOSES_SERVICE": "EXPOSES_SERVICE",
    "HOST_HAS_FINDING": "HAS_FINDING",
    "FINDING_HAS_EVIDENCE": "HAS_EVIDENCE",
    "FINDING_MAPS_TO_CONTROL": "MAPS_TO_CONTROL",
    "ASSESSMENT_GENERATED_FINDING": "GENERATED_FINDING",
    "OBSERVATION_OF": "OBSERVATION_OF",
    "ASSESSES": "ASSESSES",
    "EXPLAINS": "EXPLAINS",
    "REMEDIATES": "REMEDIATES",
}


SEMANTIC_TYPE_MAP = {
    "Host": "device",
    "Asset": "asset",
    "Software": "software",
    "PatchStatus": "patch_status",
    "Service": "network_service",
    "Finding": "security_finding",
    "Evidence": "evidence",
    "Control": "security_control",
    "Assessment": "assessment",
    "Explanation": "explanation",
    "Remediation": "remediation",
    "Observation": "observation",
    "Entity": "entity",
    "Relationship": "relationship",
}


RESERVED_NODE_KEYS = {"id", "type", "label", "properties", "semantic_type", "original_type"}
RESERVED_EDGE_KEYS = {"source", "target", "type", "properties", "semantic_type", "original_type"}


def map_node_type(node_type: str) -> str:
    if not node_type:
        return "Entity"
    return NODE_TYPE_MAP.get(str(node_type).strip().lower(), "Entity")


def map_edge_type(edge_type: str) -> str:
    if not edge_type:
        return "RELATED_TO"
    return EDGE_TYPE_MAP.get(str(edge_type).strip(), str(edge_type).strip())


def map_semantic_type(aligned_type: str) -> str:
    return SEMANTIC_TYPE_MAP.get(aligned_type, "entity")


def _clean_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _clean_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean_value(v) for v in value]
    return value


def _merge_properties(base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in extra.items():
        if key not in merged or merged[key] is None:
            merged[key] = value
    return merged


def _default_node_properties(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        k: _clean_value(v)
        for k, v in node.items()
        if k not in RESERVED_NODE_KEYS
    }


def _default_edge_properties(edge: Dict[str, Any]) -> Dict[str, Any]:
    return {
        k: _clean_value(v)
        for k, v in edge.items()
        if k not in RESERVED_EDGE_KEYS
    }


def _host_properties(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "hostname": node.get("hostname") or node.get("label"),
        "os_name": node.get("os_name"),
        "os_version": node.get("os_version"),
        "primary_ip": node.get("primary_ip"),
        "primary_mac": node.get("primary_mac"),
        "source": node.get("source"),
        "managed": node.get("managed"),
        "discovery_only": node.get("discovery_only", False),
        "correlation_status": node.get("correlation_status"),
        "first_seen": node.get("first_seen"),
        "last_seen": node.get("last_seen"),
        "status": node.get("status"),
        "is_active": node.get("is_active"),
    }


def _asset_properties(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "hostname": node.get("hostname") or node.get("label"),
        "primary_ip": node.get("primary_ip") or node.get("ip"),
        "primary_mac": node.get("primary_mac") or node.get("mac"),
        "asset_type": node.get("asset_type"),
        "managed": node.get("managed"),
        "discovery_only": node.get("discovery_only", False),
        "correlation_status": node.get("correlation_status"),
        "first_seen": node.get("first_seen"),
        "last_seen": node.get("last_seen"),
        "status": node.get("status"),
        "is_active": node.get("is_active"),
    }


def _software_properties(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": node.get("name") or node.get("label"),
        "vendor": node.get("vendor") or node.get("publisher"),
        "version": node.get("version"),
        "normalized_name": node.get("normalized_name"),
    }


def _patch_status_properties(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "status": node.get("status") or node.get("label"),
        "last_checked": node.get("last_checked"),
        "patch_source": node.get("patch_source"),
    }


def _service_properties(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "service_name": node.get("service_name") or node.get("name") or node.get("label"),
        "port": node.get("port"),
        "protocol": node.get("protocol"),
        "state": node.get("state"),
        "banner": node.get("banner"),
    }


def _finding_properties(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "rule_id": node.get("rule_id"),
        "title": node.get("title") or node.get("label"),
        "description": node.get("description"),
        "severity": node.get("severity"),
        "category": node.get("category"),
        "status": node.get("status"),
        "score": node.get("score"),
        "detected_at": node.get("detected_at"),
        "resolved_at": node.get("resolved_at"),
    }


def _evidence_properties(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "evidence_type": node.get("evidence_type") or node.get("type_name") or node.get("label"),
        "source": node.get("source"),
        "value": node.get("value"),
        "captured_at": node.get("captured_at"),
    }


def _control_properties(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "control_id": node.get("control_id") or node.get("label"),
        "title": node.get("title") or node.get("label"),
        "category": node.get("category"),
        "version": node.get("version"),
    }


def _assessment_properties(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "assessed_at": node.get("assessed_at"),
        "engine_version": node.get("engine_version"),
        "rule_set_version": node.get("rule_set_version"),
        "source": node.get("source"),
    }


def _explanation_properties(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "summary": node.get("summary") or node.get("label"),
        "risk_summary": node.get("risk_summary"),
        "confidence": node.get("confidence"),
        "model_name": node.get("model_name"),
        "created_at": node.get("created_at"),
    }


def _remediation_properties(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "summary": node.get("summary") or node.get("label"),
        "priority": node.get("priority"),
        "actions": _clean_value(node.get("actions")),
        "model_name": node.get("model_name"),
        "created_at": node.get("created_at"),
    }


def _observation_properties(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "observed_at": node.get("observed_at"),
        "source": node.get("source"),
        "source_type": node.get("source_type"),
        "risk_score": node.get("risk_score"),
        "status": node.get("status"),
    }


def _type_specific_node_properties(original_type: str, node: Dict[str, Any]) -> Dict[str, Any]:
    node_type = (original_type or "").strip().lower()

    if node_type == "host":
        return _host_properties(node)
    if node_type == "asset":
        return _asset_properties(node)
    if node_type == "software":
        return _software_properties(node)
    if node_type == "update_status":
        return _patch_status_properties(node)
    if node_type == "service":
        return _service_properties(node)
    if node_type == "finding":
        return _finding_properties(node)
    if node_type == "evidence":
        return _evidence_properties(node)
    if node_type == "control":
        return _control_properties(node)
    if node_type == "assessment":
        return _assessment_properties(node)
    if node_type == "explanation":
        return _explanation_properties(node)
    if node_type == "remediation":
        return _remediation_properties(node)
    if node_type == "observation":
        return _observation_properties(node)

    return {}


def _remove_none_values(data: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in data.items() if v is not None}


def align_node(node: Dict[str, Any]) -> Dict[str, Any]:
    original_type = str(node.get("type", "unknown"))
    aligned_type = map_node_type(original_type)
    base_properties = _default_node_properties(node)
    typed_properties = _type_specific_node_properties(original_type, node)
    properties = _remove_none_values(_merge_properties(typed_properties, base_properties))

    return {
        "id": node.get("id"),
        "type": aligned_type,
        "original_type": original_type,
        "label": node.get("label") or node.get("name") or node.get("hostname") or node.get("title") or "unknown",
        "semantic_type": map_semantic_type(aligned_type),
        "properties": properties,
    }


def align_edge(edge: Dict[str, Any]) -> Dict[str, Any]:
    aligned_type = map_edge_type(edge.get("type", "unknown"))
    properties = _remove_none_values(_default_edge_properties(edge))

    return {
        "source": edge.get("source"),
        "target": edge.get("target"),
        "type": aligned_type,
        "original_type": edge.get("type", "unknown"),
        "semantic_type": "relationship",
        "properties": properties,
    }


def align_nodes(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [align_node(node) for node in nodes if isinstance(node, dict)]


def align_edges(edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [align_edge(edge) for edge in edges if isinstance(edge, dict)]


def align_graph(graph: Dict[str, Any]) -> Dict[str, Any]:
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    aligned_nodes = align_nodes(nodes)
    aligned_edges = align_edges(edges)

    return {
        "schema": "graph-mapper-v1",
        "summary": {
            "node_count": len(aligned_nodes),
            "edge_count": len(aligned_edges),
        },
        "nodes": aligned_nodes,
        "edges": aligned_edges,
    }