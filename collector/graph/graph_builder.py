from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Set, Tuple


def _stable_id(prefix: str, *parts: Any) -> str:
    raw = "||".join("" if p is None else str(p).strip() for p in parts)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}-{digest}"


def _slug(value: Any) -> str:
    text = str(value or "").strip().lower()
    chars = []
    for ch in text:
        if ch.isalnum():
            chars.append(ch)
        elif ch in {" ", "-", "_", ".", ":", "/"}:
            chars.append("-")
    out = "".join(chars).strip("-")
    while "--" in out:
        out = out.replace("--", "-")
    return out or "unknown"


def _first(*values: Any, default: str = "") -> str:
    for value in values:
        if value is None:
            continue
        text = value.strip() if isinstance(value, str) else str(value).strip()
        if text:
            return text
    return default


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _add_node(nodes: List[Dict[str, Any]], seen: Set[str], node: Dict[str, Any]) -> None:
    node_id = str(node["id"])
    if node_id in seen:
        return
    nodes.append(node)
    seen.add(node_id)


def _add_edge(
    edges: List[Dict[str, Any]],
    seen: Set[Tuple[str, str, str, str]],
    edge: Dict[str, Any],
) -> None:
    key = (
        str(edge.get("source") or ""),
        str(edge.get("target") or ""),
        str(edge.get("type") or ""),
        json.dumps(edge.get("properties", {}), sort_keys=True, default=str),
    )
    if key in seen:
        return
    edges.append(edge)
    seen.add(key)


def _managed_hostname(host: Dict[str, Any]) -> str:
    return _first(
        host.get("hostname"),
        host.get("device_name"),
        host.get("host_info", {}).get("hostname"),
        default="unknown",
    )


def _managed_platform(host: Dict[str, Any]) -> str:
    return _first(
        host.get("platform"),
        host.get("os_platform"),
        host.get("host_info", {}).get("platform"),
    )


def _managed_os_name(host: Dict[str, Any]) -> str:
    return _first(
        host.get("os_name"),
        host.get("host_info", {}).get("os_name"),
        default="unknown",
    )


def _managed_os_version(host: Dict[str, Any]) -> str:
    return _first(
        host.get("os_version"),
        host.get("host_info", {}).get("os_version"),
        default="unknown",
    )


def _managed_primary_ip(host: Dict[str, Any]) -> str:
    direct = _first(host.get("primary_ip"))
    if direct:
        return direct

    for iface in _as_list(host.get("network", {}).get("interfaces")):
        for ip in _as_list(iface.get("ipv4")):
            text = _first(ip)
            if text:
                return text

    return ""


def _managed_host_id(host: Dict[str, Any]) -> str:
    platform = _managed_platform(host).lower()
    hostname = _managed_hostname(host)
    prefix = "windows" if "windows" in platform else "linux" if "linux" in platform else "host"
    return f"{prefix}-{hostname}"


def _discovered_primary_ip(host: Dict[str, Any]) -> str:
    return _first(
        host.get("discovered_ip"),
        host.get("primary_ip"),
        host.get("ip"),
        host.get("ip_address"),
        host.get("address"),
    )


def _discovered_hostname(host: Dict[str, Any]) -> str:
    return _first(
        host.get("hostname_clue"),
        host.get("hostname"),
        host.get("device_name"),
        host.get("dns_name"),
        host.get("name"),
    )


def _discovered_os_name(host: Dict[str, Any]) -> str:
    return _first(
        host.get("os_name"),
        host.get("os"),
        host.get("platform"),
        default="unknown",
    )


def _discovered_os_version(host: Dict[str, Any]) -> str:
    return _first(
        host.get("os_version"),
        host.get("version"),
        default="unknown",
    )


def _discovered_services(host: Dict[str, Any]) -> List[Dict[str, Any]]:
    services: List[Dict[str, Any]] = []

    for svc in _as_list(host.get("observed_services")):
        if not isinstance(svc, dict):
            continue

        raw_name = _first(svc.get("raw_service_name"), default="unknown")
        normalized_name = _first(svc.get("service_name"), raw_name, default="unknown")

        services.append(
            {
                "port": svc.get("port"),
                "protocol": _first(svc.get("protocol"), default="tcp").lower(),
                "raw_service_name": raw_name,
                "service_name": normalized_name,
                "state": svc.get("state"),
                "banner": svc.get("banner"),
                "discovery_method": svc.get("discovery_method"),
                "confidence": svc.get("confidence"),
                "observed_at": host.get("observed_at"),
                "notes": svc.get("notes"),
            }
        )

    return services


def _discovered_host_id(host: Dict[str, Any]) -> str:
    ip = _discovered_primary_ip(host)
    hostname = _discovered_hostname(host)
    if ip:
        return f"host-discovered-{ip}"
    if hostname:
        return f"host-discovered-{_slug(hostname)}"
    raw = json.dumps(host, sort_keys=True, default=str)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
    return f"host-discovered-anon-{digest}"


def _software_id(name: str) -> str:
    return f"software-{_slug(name)}"


def _patch_status_id(host_id: str) -> str:
    return f"patch-status-{_slug(host_id)}"


def _service_id(name: str, port: Any, protocol: str) -> str:
    return f"service-{_slug(name)}-{port}-{_slug(protocol)}"


def _finding_id(finding: Dict[str, Any]) -> str:
    existing = finding.get("finding_id")
    if existing:
        return str(existing)
    return _stable_id(
        "finding",
        finding.get("hostname"),
        finding.get("rule_id"),
        finding.get("title"),
        finding.get("created_at"),
    )


def _control_id(name: str) -> str:
    return f"control-{_slug(name)}"


def _evidence_id(finding_id: str, idx: int, evidence: Dict[str, Any]) -> str:
    return _stable_id("evidence", finding_id, idx, json.dumps(evidence, sort_keys=True, default=str))


def _explanation_id(host_id: str) -> str:
    return f"explanation-{_slug(host_id)}"


def _remediation_id(host_id: str) -> str:
    return f"remediation-{_slug(host_id)}"


def _host_index(normalized_hosts: List[Dict[str, Any]]) -> Dict[str, str]:
    index: Dict[str, str] = {}

    for host in normalized_hosts:
        host_id = _managed_host_id(host)
        hostname = _managed_hostname(host).lower()
        ip = _managed_primary_ip(host)

        if hostname and hostname != "unknown":
            index[f"host:{hostname}"] = host_id
        if ip:
            index[f"ip:{ip}"] = host_id

    return index


def _correlation_index(correlation_results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}

    for result in correlation_results:
        discovered_ip = _first(
            result.get("discovered_primary_ip"),
            result.get("discovered_ip"),
            result.get("primary_ip"),
            result.get("ip"),
        )
        if discovered_ip:
            out[discovered_ip] = result

    return out


def _findings_for_host(findings: List[Dict[str, Any]], hostname: str) -> List[Dict[str, Any]]:
    target = hostname.strip().lower()
    return [f for f in findings if str(f.get("hostname") or "").strip().lower() == target]


def _ai_host_record(ai_result: Optional[Dict[str, Any]], hostname: str) -> Optional[Dict[str, Any]]:
    if not isinstance(ai_result, dict):
        return None

    for entry in ai_result.get("hosts", []):
        if str(entry.get("hostname") or "").strip().lower() == hostname.strip().lower():
            return entry

    return None


def _ai_remediation_items(ai_result: Optional[Dict[str, Any]], hostname: str) -> List[Dict[str, Any]]:
    if not isinstance(ai_result, dict):
        return []

    remediation_plan = ai_result.get("remediation_plan", {})
    if not isinstance(remediation_plan, dict):
        return []

    for key, items in remediation_plan.items():
        if str(key).strip().lower() == hostname.strip().lower():
            return items if isinstance(items, list) else []

    return []


def build_graph(
    normalized_hosts: List[Dict[str, Any]],
    normalized_discovered_hosts: List[Dict[str, Any]],
    correlation_results: List[Dict[str, Any]],
    findings: Optional[List[Dict[str, Any]]] = None,
    ai_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    findings = findings or []

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen_nodes: Set[str] = set()
    seen_edges: Set[Tuple[str, str, str, str]] = set()

    host_idx = _host_index(normalized_hosts)
    corr_idx = _correlation_index(correlation_results)

    for host in normalized_hosts:
        host_id = _managed_host_id(host)
        hostname = _managed_hostname(host)

        _add_node(
            nodes,
            seen_nodes,
            {
                "id": host_id,
                "type": "host",
                "label": hostname,
                "hostname": hostname,
                "os_name": _managed_os_name(host),
                "os_version": _managed_os_version(host),
                "platform": _managed_platform(host),
                "primary_ip": _managed_primary_ip(host),
                "source": _first(host.get("source"), default="endpoint_agent"),
                "managed": bool(host.get("managed")) if host.get("managed") is not None else True,
                "discovery_only": False,
                "correlation_status": "managed",
            },
        )

        software_items = host.get("software", []) or host.get("software_inventory", {}).get("items", [])
        for item in software_items:
            name = str(item.get("name") or "").strip()
            if not name:
                continue

            software_id = _software_id(name)

            _add_node(
                nodes,
                seen_nodes,
                {
                    "id": software_id,
                    "type": "software",
                    "label": name,
                    "name": name,
                    "version": item.get("version"),
                    "arch": item.get("arch"),
                    "vendor": item.get("vendor") or item.get("publisher"),
                },
            )

            _add_edge(
                edges,
                seen_edges,
                {
                    "source": host_id,
                    "target": software_id,
                    "type": "HOST_HAS_SOFTWARE",
                    "properties": {
                        "version": item.get("version"),
                        "arch": item.get("arch"),
                    },
                },
            )

        update_status = host.get("update_status")
        if isinstance(update_status, dict) and update_status:
            patch_id = _patch_status_id(host_id)
            updates_available = update_status.get("updates_available")
            updates_count = update_status.get("updates_count")

            status_label = "unknown"
            if updates_available is True:
                status_label = "updates_available"
            elif updates_available is False:
                status_label = "up_to_date"
            elif updates_count not in (None, ""):
                status_label = f"updates_count_{updates_count}"

            _add_node(
                nodes,
                seen_nodes,
                {
                    "id": patch_id,
                    "type": "update_status",
                    "label": status_label,
                    "status": status_label,
                    "method": update_status.get("method"),
                    "updates_available": updates_available,
                    "updates_count": updates_count,
                    "latest_hotfix_date": update_status.get("latest_hotfix_date"),
                    "note": update_status.get("note"),
                },
            )

            _add_edge(
                edges,
                seen_edges,
                {
                    "source": host_id,
                    "target": patch_id,
                    "type": "HOST_HAS_UPDATE_STATUS",
                    "properties": {},
                },
            )

        for finding in _findings_for_host(findings, hostname):
            finding_id = _finding_id(finding)

            _add_node(
                nodes,
                seen_nodes,
                {
                    "id": finding_id,
                    "type": "finding",
                    "label": finding.get("title") or finding_id,
                    "finding_id": finding.get("finding_id") or finding_id,
                    "rule_id": finding.get("rule_id"),
                    "title": finding.get("title"),
                    "description": finding.get("description"),
                    "severity": finding.get("severity"),
                    "category": finding.get("category"),
                    "status": finding.get("status"),
                    "score": finding.get("score"),
                    "expected": finding.get("expected"),
                    "recommendation": finding.get("recommendation"),
                    "created_at": finding.get("created_at"),
                    "hostname": finding.get("hostname"),
                },
            )

            _add_edge(
                edges,
                seen_edges,
                {
                    "source": host_id,
                    "target": finding_id,
                    "type": "HOST_HAS_FINDING",
                    "properties": {
                        "severity": finding.get("severity"),
                        "category": finding.get("category"),
                        "status": finding.get("status"),
                    },
                },
            )

            for control_name in finding.get("cis_controls", []) or []:
                control_id = _control_id(control_name)

                _add_node(
                    nodes,
                    seen_nodes,
                    {
                        "id": control_id,
                        "type": "control",
                        "label": control_name,
                        "control_id": control_name,
                        "title": control_name,
                    },
                )

                _add_edge(
                    edges,
                    seen_edges,
                    {
                        "source": finding_id,
                        "target": control_id,
                        "type": "FINDING_MAPS_TO_CONTROL",
                        "properties": {},
                    },
                )

            for idx, evidence in enumerate(finding.get("evidence", []) or []):
                evidence_id = _evidence_id(finding_id, idx, evidence)

                _add_node(
                    nodes,
                    seen_nodes,
                    {
                        "id": evidence_id,
                        "type": "evidence",
                        "label": f"{finding_id}-evidence-{idx + 1}",
                        "evidence_type": evidence.get("field"),
                        "source": "rule_engine",
                        "value": evidence.get("value"),
                        "reason": evidence.get("reason"),
                        "captured_at": finding.get("created_at"),
                    },
                )

                _add_edge(
                    edges,
                    seen_edges,
                    {
                        "source": finding_id,
                        "target": evidence_id,
                        "type": "FINDING_HAS_EVIDENCE",
                        "properties": {},
                    },
                )

        ai_host = _ai_host_record(ai_result, hostname)
        if ai_host:
            explanation_id = _explanation_id(host_id)

            _add_node(
                nodes,
                seen_nodes,
                {
                    "id": explanation_id,
                    "type": "explanation",
                    "label": f"{hostname} explanation",
                    "summary": ai_host.get("overall_explanation"),
                    "risk_summary": ", ".join(ai_host.get("key_risk_drivers", []) or []),
                    "confidence": ai_host.get("confidence"),
                    "model_name": "phase_1_ai",
                    "created_at": ai_result.get("generated_at") if isinstance(ai_result, dict) else None,
                    "risk_level": ai_host.get("risk_level"),
                    "finding_count": ai_host.get("finding_count"),
                },
            )

            _add_edge(
                edges,
                seen_edges,
                {
                    "source": host_id,
                    "target": explanation_id,
                    "type": "HOST_HAS_EXPLANATION",
                    "properties": {
                        "confidence": ai_host.get("confidence"),
                        "risk_level": ai_host.get("risk_level"),
                    },
                },
            )

        remediation_items = _ai_remediation_items(ai_result, hostname)
        if remediation_items:
            remediation_id = _remediation_id(host_id)

            _add_node(
                nodes,
                seen_nodes,
                {
                    "id": remediation_id,
                    "type": "remediation",
                    "label": f"{hostname} remediation plan",
                    "summary": f"Remediation plan for {hostname}",
                    "priority": 1,
                    "actions": remediation_items,
                    "model_name": "phase_1_ai",
                    "created_at": ai_result.get("generated_at") if isinstance(ai_result, dict) else None,
                },
            )

            _add_edge(
                edges,
                seen_edges,
                {
                    "source": host_id,
                    "target": remediation_id,
                    "type": "HOST_HAS_REMEDIATION",
                    "properties": {
                        "item_count": len(remediation_items),
                    },
                },
            )

    for discovered_host in normalized_discovered_hosts:
        discovered_id = _discovered_host_id(discovered_host)
        primary_ip = _discovered_primary_ip(discovered_host)
        hostname = _discovered_hostname(discovered_host)
        display_label = primary_ip or hostname or "unknown"

        correlation = corr_idx.get(primary_ip, {})
        correlation_status = _first(correlation.get("correlation_status"), default="unmatched")

        matched_host_id = ""
        if primary_ip:
            matched_host_id = host_idx.get(f"ip:{primary_ip}", "")
        if not matched_host_id and hostname:
            matched_host_id = host_idx.get(f"host:{hostname.lower()}", "")

        _add_node(
            nodes,
            seen_nodes,
            {
                "id": discovered_id,
                "type": "host",
                "label": display_label,
                "hostname": hostname or "unknown",
                "os_name": _discovered_os_name(discovered_host),
                "os_version": _discovered_os_version(discovered_host),
                "primary_ip": primary_ip,
                "source": "network_discovery",
                "managed": False,
                "discovery_only": True,
                "correlation_status": correlation_status,
                "reachable": discovered_host.get("reachable"),
                "observed_at": discovered_host.get("observed_at"),
            },
        )

        if matched_host_id:
            _add_edge(
                edges,
                seen_edges,
                {
                    "source": discovered_id,
                    "target": matched_host_id,
                    "type": "OBSERVATION_OF",
                    "properties": {
                        "correlation_status": correlation_status,
                        "matched_by": correlation.get("matched_by"),
                        "confidence": correlation.get("confidence"),
                    },
                },
            )

        for service in _discovered_services(discovered_host):
            port = service.get("port")
            protocol = _first(service.get("protocol"), default="tcp").lower()
            service_name = _first(service.get("service_name"), service.get("raw_service_name"), default="unknown")
            service_label = f"{service_name}:{port}/{protocol}" if port not in (None, "") else f"{service_name}/{protocol}"
            service_id = _service_id(service_name, port if port not in (None, "") else "na", protocol)

            _add_node(
                nodes,
                seen_nodes,
                {
                    "id": service_id,
                    "type": "service",
                    "label": service_label,
                    "service_name": service_name,
                    "raw_service_name": service.get("raw_service_name"),
                    "port": port,
                    "protocol": protocol,
                    "state": service.get("state"),
                    "banner": service.get("banner"),
                },
            )

            _add_edge(
                edges,
                seen_edges,
                {
                    "source": discovered_id,
                    "target": service_id,
                    "type": "HOST_EXPOSES_SERVICE",
                    "properties": {
                        "port": port,
                        "protocol": protocol,
                        "state": service.get("state"),
                        "discovery_method": service.get("discovery_method"),
                        "confidence": service.get("confidence"),
                        "observed_at": service.get("observed_at"),
                        "notes": service.get("notes"),
                    },
                },
            )

    return {
        "schema": "sage-ch-graph-v2",
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
        "nodes": nodes,
        "edges": edges,
    }