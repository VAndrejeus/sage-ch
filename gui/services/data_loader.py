from __future__ import annotations

from pathlib import Path
import json
import re
from typing import Any

import pandas as pd


def get_repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def get_collector_output_dir() -> Path:
    return get_repo_root() / "collector" / "output"


def get_graph_db_path() -> Path:
    return get_collector_output_dir() / "graph" / "sage_ch_kuzu.db"


def _safe_read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _find_latest_file(base_dir: Path, patterns: list[str]) -> Path | None:
    if not base_dir.exists():
        return None

    candidates: list[Path] = []
    for pattern in patterns:
        candidates.extend([p for p in base_dir.rglob(pattern) if p.is_file()])

    candidates = list({str(p): p for p in candidates}.values())
    if not candidates:
        return None

    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def _shorten_cis_control(value: Any) -> str:
    text = str(value or "").strip()

    if not text:
        return ""

    match = re.search(r"(CIS\s*Control\s*\d+)", text, flags=re.IGNORECASE)
    if match:
        parts = match.group(1).split()
        return f"CIS Control {parts[-1]}"

    return text


def _extract_evidence_text(item: dict) -> str:
    evidence = item.get("evidence", [])

    if isinstance(evidence, list):
        return "; ".join(
            [
                f"{e.get('field', '')}: {e.get('reason', '')}".strip(": ")
                for e in evidence
                if isinstance(e, dict)
            ]
        )

    return str(evidence)


def _extract_cis_text(item: dict) -> str:
    cis_controls = item.get("cis_controls")

    if isinstance(cis_controls, list):
        return ", ".join([_shorten_cis_control(x) for x in cis_controls if x])

    if item.get("cis_control"):
        return _shorten_cis_control(item.get("cis_control"))

    return ""


def _normalize_severity(value: Any) -> str:
    return str(value or "").strip().lower()


def get_latest_consolidated_path() -> Path | None:
    return _find_latest_file(
        get_collector_output_dir(),
        ["consolidated_dataset*.json"],
    )


def get_latest_findings_path() -> Path | None:
    return _find_latest_file(
        get_collector_output_dir(),
        ["findings_dataset*.json"],
    )


def get_latest_cve_findings_path() -> Path | None:
    return _find_latest_file(
        get_collector_output_dir() / "cve_findings",
        ["cve_findings_latest.json", "cve_findings*.json"],
    )


def get_latest_cve_snapshot_path() -> Path | None:
    return _find_latest_file(
        get_collector_output_dir() / "cve_snapshot",
        ["cve_snapshot_latest.json", "cve_snapshot*.json"],
    )


def get_latest_software_snapshot_path() -> Path | None:
    return _find_latest_file(
        get_collector_output_dir() / "software_snapshot",
        ["software_snapshot_latest.json", "software_snapshot*.json"],
    )


def get_latest_assessment_summary_path() -> Path | None:
    return _find_latest_file(
        get_collector_output_dir(),
        ["assessment_summary*.json"],
    )


def get_latest_ai_host_explanations_path() -> Path | None:
    return _find_latest_file(
        get_collector_output_dir(),
        ["ai_host_explanations*.json"],
    )


def get_latest_ai_remediation_path() -> Path | None:
    return _find_latest_file(
        get_collector_output_dir(),
        ["ai_remediation_plan*.md", "ai_remediation_plan*.json"],
    )


def load_latest_consolidated_payload() -> tuple[dict, Path | None]:
    path = get_latest_consolidated_path()
    if path is None:
        return {}, None

    payload = _safe_read_json(path)
    if not isinstance(payload, dict):
        return {}, path

    return payload, path


def load_latest_assessment_summary_payload() -> tuple[dict, Path | None]:
    path = get_latest_assessment_summary_path()
    if path is None:
        return {}, None

    payload = _safe_read_json(path)
    if not isinstance(payload, dict):
        return {}, path

    return payload, path


def load_latest_cve_findings_payload() -> tuple[dict, Path | None]:
    path = get_latest_cve_findings_path()
    if path is None:
        return {}, None

    payload = _safe_read_json(path)
    if not isinstance(payload, dict):
        return {}, path

    return payload, path


def _build_standard_finding_row(item: dict) -> dict:
    return {
        "finding_id": item.get("finding_id", ""),
        "rule_id": item.get("rule_id", ""),
        "title": item.get("title", ""),
        "severity": _normalize_severity(item.get("severity", "")),
        "category": item.get("category", ""),
        "status": item.get("status", ""),
        "hostname": item.get("hostname", ""),
        "platform": item.get("platform", ""),
        "ip_address": item.get("ip_address", ""),
        "description": item.get("description", ""),
        "expected": item.get("expected", ""),
        "recommendation": item.get("recommendation", ""),
        "cis_controls": _extract_cis_text(item),
        "evidence": _extract_evidence_text(item),
        "batch_id": item.get("batch_id", ""),
        "source": item.get("source", "CIS Rule Engine"),
        "finding_type": "Configuration",
        "software_name": item.get("software_name", ""),
        "installed_versions": "",
        "cve_id": item.get("cve_id", ""),
        "cvss_score": item.get("cvss_score", ""),
        "cvss_severity": item.get("cvss_severity", ""),
        "published": item.get("published", ""),
        "ai_explanation": item.get("ai_explanation", ""),
        "_raw": item,
    }


def _build_cve_finding_row(item: dict) -> dict:
    installed_versions = item.get("installed_versions", [])
    if isinstance(installed_versions, list):
        installed_versions_text = ", ".join([str(x) for x in installed_versions if x])
    else:
        installed_versions_text = str(installed_versions or "")

    return {
        "finding_id": item.get("finding_id", ""),
        "rule_id": item.get("cve_id", ""),
        "title": item.get("title", ""),
        "severity": _normalize_severity(item.get("severity", "")),
        "category": item.get("category", "Vulnerability"),
        "status": item.get("status", "Open"),
        "hostname": item.get("hostname", ""),
        "platform": item.get("platform", ""),
        "ip_address": item.get("ip_address", ""),
        "description": item.get("description", ""),
        "expected": "Installed software should be reviewed against applicable vulnerability intelligence.",
        "recommendation": item.get("recommendation", ""),
        "cis_controls": _shorten_cis_control(item.get("cis_control", "CIS Control 7")),
        "evidence": f"Software: {item.get('software_name', '')}; CVE: {item.get('cve_id', '')}; CVSS: {item.get('cvss_score', '')}",
        "batch_id": "",
        "source": item.get("source", "CVE Correlation"),
        "finding_type": "Vulnerability",
        "software_name": item.get("software_name", ""),
        "installed_versions": installed_versions_text,
        "cve_id": item.get("cve_id", ""),
        "cvss_score": item.get("cvss_score", ""),
        "cvss_severity": item.get("cvss_severity", ""),
        "published": item.get("published", ""),
        "ai_explanation": item.get("ai_explanation", ""),
        "_raw": item,
    }


def load_collector_findings_df() -> tuple[pd.DataFrame, Path | None]:
    path = get_latest_findings_path()
    if path is None:
        return pd.DataFrame(), None

    payload = _safe_read_json(path)
    if not isinstance(payload, list):
        return pd.DataFrame(), path

    rows: list[dict] = []
    for item in payload:
        if isinstance(item, dict):
            rows.append(_build_standard_finding_row(item))

    return pd.DataFrame(rows), path


def load_cve_findings_df() -> tuple[pd.DataFrame, Path | None]:
    payload, path = load_latest_cve_findings_payload()
    if not payload:
        return pd.DataFrame(), path

    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        return pd.DataFrame(), path

    rows: list[dict] = []
    for item in findings:
        if isinstance(item, dict):
            rows.append(_build_cve_finding_row(item))

    return pd.DataFrame(rows), path


def load_latest_findings_df() -> tuple[pd.DataFrame, Path | None]:
    collector_df, collector_path = load_collector_findings_df()
    cve_df, cve_path = load_cve_findings_df()

    frames = [df for df in [collector_df, cve_df] if not df.empty]

    if not frames:
        return pd.DataFrame(), collector_path or cve_path

    combined_df = pd.concat(frames, ignore_index=True, sort=False)

    if "cis_controls" in combined_df.columns:
        combined_df["cis_controls"] = combined_df["cis_controls"].apply(_shorten_cis_control)

    return combined_df, collector_path or cve_path


def load_cve_summary() -> tuple[dict, Path | None]:
    payload, path = load_latest_cve_findings_payload()
    if not payload:
        return {
            "total_findings": 0,
            "products_with_findings": 0,
            "total_cves_after_filter": 0,
            "min_cvss_score": None,
            "max_cve_age_years": None,
        }, path

    return {
        "total_findings": payload.get("total_findings", 0),
        "products_with_findings": payload.get("products_with_findings", 0),
        "total_cves_after_filter": payload.get("total_cves_after_filter", 0),
        "min_cvss_score": payload.get("min_cvss_score"),
        "max_cve_age_years": payload.get("max_cve_age_years"),
        "generated_at": payload.get("generated_at", ""),
    }, path


def load_hosts_df_from_consolidated() -> tuple[pd.DataFrame, Path | None]:
    payload, path = load_latest_consolidated_payload()
    if not payload:
        return pd.DataFrame(), path

    loaded_reports = payload.get("loaded_reports", [])
    if not isinstance(loaded_reports, list):
        return pd.DataFrame(), path

    rows: list[dict] = []
    for report in loaded_reports:
        if not isinstance(report, dict):
            continue

        data = report.get("data", {})
        if not isinstance(data, dict):
            continue

        host_info = data.get("host_info", {}) or {}
        network = host_info.get("network", {}) or {}
        interfaces = network.get("interfaces", []) if isinstance(network.get("interfaces"), list) else []
        software_inventory = data.get("software_inventory", {}) or {}
        software_items = software_inventory.get("items", []) if isinstance(software_inventory.get("items"), list) else []
        findings = data.get("findings", []) if isinstance(data.get("findings"), list) else []

        ip = ""
        if interfaces:
            first_interface = interfaces[0]
            if isinstance(first_interface, dict):
                ipv4 = first_interface.get("ipv4", [])
                if isinstance(ipv4, list) and ipv4:
                    ip = str(ipv4[0])

        os_name = host_info.get("os_name", "")
        host_type = "managed"

        rows.append(
            {
                "hostname": host_info.get("hostname", ""),
                "ip": ip,
                "platform": host_info.get("platform", ""),
                "os_name": os_name,
                "os_version": host_info.get("os_version", ""),
                "host_type": host_type,
                "managed": True,
                "discovered": False,
                "software_count": len(software_items),
                "finding_count": len(findings),
                "service_count": 0,
                "raw_report": data,
            }
        )

    hosts_df = pd.DataFrame(rows)

    findings_df, _ = load_latest_findings_df()
    if not hosts_df.empty and not findings_df.empty and "hostname" in findings_df.columns:
        finding_counts = findings_df.groupby("hostname").size().to_dict()
        vulnerability_counts = (
            findings_df[findings_df.get("finding_type", "") == "Vulnerability"]
            .groupby("hostname")
            .size()
            .to_dict()
            if "finding_type" in findings_df.columns
            else {}
        )

        hosts_df["finding_count"] = hosts_df["hostname"].astype(str).map(finding_counts).fillna(hosts_df["finding_count"]).astype(int)
        hosts_df["vulnerability_count"] = hosts_df["hostname"].astype(str).map(vulnerability_counts).fillna(0).astype(int)
    else:
        hosts_df["vulnerability_count"] = 0

    return hosts_df, path


def load_graph_counts_from_consolidated() -> tuple[dict, Path | None]:
    payload, path = load_latest_consolidated_payload()
    if not payload:
        return {"node_counts": {}, "edge_counts": {}, "graph_persistence_status": "unknown"}, path

    graph_data = _get_graph_payload(payload)
    nodes = graph_data.get("nodes", []) if isinstance(graph_data.get("nodes"), list) else []
    edges = graph_data.get("edges", []) if isinstance(graph_data.get("edges"), list) else []

    node_counts: dict[str, int] = {}
    edge_counts: dict[str, int] = {}

    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_type = str(node.get("type", "Unknown"))
        node_counts[node_type] = node_counts.get(node_type, 0) + 1

    for edge in edges:
        if not isinstance(edge, dict):
            continue
        edge_type = str(edge.get("type", "Unknown"))
        edge_counts[edge_type] = edge_counts.get(edge_type, 0) + 1

    return {
        "node_counts": node_counts,
        "edge_counts": edge_counts,
        "graph_persistence_status": payload.get("graph_persistence_status", "unknown"),
        "graph_persistence": payload.get("graph_persistence", {}),
    }, path


def _get_graph_payload(payload: dict) -> dict:
    for key in ["graph", "mapped_graph", "graph_data"]:
        graph_data = payload.get(key)
        if isinstance(graph_data, dict):
            nodes = graph_data.get("nodes")
            edges = graph_data.get("edges")
            if isinstance(nodes, list) or isinstance(edges, list):
                return graph_data
    return {}


def load_graph_hosts_from_consolidated() -> tuple[pd.DataFrame, Path | None]:
    payload, path = load_latest_consolidated_payload()
    if not payload:
        return pd.DataFrame(columns=["host_id", "hostname"]), path

    graph_data = _get_graph_payload(payload)
    nodes = graph_data.get("nodes", []) if isinstance(graph_data.get("nodes"), list) else []

    rows = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if str(node.get("type", "")).strip().lower() != "host":
            continue
        if node.get("discovery_only") is True:
            continue

        host_id = str(node.get("id", "")).strip()
        if not host_id:
            continue

        rows.append(
            {
                "host_id": host_id,
                "hostname": str(node.get("hostname") or node.get("label") or host_id),
            }
        )

    hosts_df = pd.DataFrame(rows, columns=["host_id", "hostname"])
    if hosts_df.empty:
        return hosts_df, path

    return hosts_df.drop_duplicates(subset=["host_id"]).sort_values("hostname").reset_index(drop=True), path


def load_graph_neighborhood_from_consolidated(
    host_id: str,
    max_nodes: int = 80,
    allowed_node_types: list[str] | None = None,
) -> tuple[dict, Path | None]:
    payload, path = load_latest_consolidated_payload()
    if not payload:
        return {
            "ok": False,
            "error": "No consolidated graph JSON found.",
            "nodes_df": pd.DataFrame(columns=["node_id", "label", "node_type", "is_center"]),
            "edges_df": pd.DataFrame(columns=["source_id", "target_id", "edge_type"]),
            "center_host_id": host_id,
        }, path

    graph_data = _get_graph_payload(payload)
    nodes = graph_data.get("nodes", []) if isinstance(graph_data.get("nodes"), list) else []
    edges = graph_data.get("edges", []) if isinstance(graph_data.get("edges"), list) else []

    node_index = {
        str(node.get("id")): node
        for node in nodes
        if isinstance(node, dict) and node.get("id") is not None
    }

    if host_id not in node_index:
        return {
            "ok": False,
            "error": f"Host not found in consolidated graph: {host_id}",
            "nodes_df": pd.DataFrame(columns=["node_id", "label", "node_type", "is_center"]),
            "edges_df": pd.DataFrame(columns=["source_id", "target_id", "edge_type"]),
            "center_host_id": host_id,
        }, path

    selected_nodes = {host_id: node_index[host_id]}
    edge_rows = []

    for edge in edges:
        if not isinstance(edge, dict):
            continue

        source_id = str(edge.get("source", "")).strip()
        target_id = str(edge.get("target", "")).strip()

        if source_id != host_id and target_id != host_id:
            continue

        if source_id in node_index:
            selected_nodes[source_id] = node_index[source_id]
        if target_id in node_index:
            selected_nodes[target_id] = node_index[target_id]

        edge_rows.append(
            {
                "source_id": source_id,
                "target_id": target_id,
                "edge_type": str(edge.get("type", "RELATED_TO")),
            }
        )

    node_rows = []
    for node_id, node in selected_nodes.items():
        node_rows.append(
            {
                "node_id": node_id,
                "label": str(node.get("label") or node.get("hostname") or node_id),
                "node_type": str(node.get("type") or "Unknown"),
                "is_center": node_id == host_id,
            }
        )

    nodes_df = pd.DataFrame(node_rows, columns=["node_id", "label", "node_type", "is_center"])
    edges_df = pd.DataFrame(edge_rows, columns=["source_id", "target_id", "edge_type"])

    if allowed_node_types and not nodes_df.empty:
        allowed = {str(item) for item in allowed_node_types}
        nodes_df = nodes_df[nodes_df["node_type"].isin(allowed) | nodes_df["is_center"]]
        allowed_ids = set(nodes_df["node_id"].astype(str).tolist())
        edges_df = edges_df[
            edges_df["source_id"].astype(str).isin(allowed_ids)
            & edges_df["target_id"].astype(str).isin(allowed_ids)
        ]

    if not nodes_df.empty:
        max_nodes = max(10, min(int(max_nodes), 300))
        center_df = nodes_df[nodes_df["node_id"].astype(str) == host_id]
        other_df = nodes_df[nodes_df["node_id"].astype(str) != host_id].head(max_nodes - len(center_df))
        nodes_df = pd.concat([center_df, other_df], ignore_index=True)
        allowed_ids = set(nodes_df["node_id"].astype(str).tolist())
        edges_df = edges_df[
            edges_df["source_id"].astype(str).isin(allowed_ids)
            & edges_df["target_id"].astype(str).isin(allowed_ids)
        ]

    return {
        "ok": True,
        "nodes_df": nodes_df.reset_index(drop=True),
        "edges_df": edges_df.drop_duplicates().reset_index(drop=True),
        "center_host_id": host_id,
    }, path


def load_ai_host_explanations_payload() -> tuple[dict, Path | None]:
    path = get_latest_ai_host_explanations_path()
    if path is None:
        return {}, None

    payload = _safe_read_json(path)
    if not isinstance(payload, dict):
        return {}, path

    return payload, path


def load_ai_for_host(hostname: str) -> dict:
    payload, _ = load_ai_host_explanations_payload()
    if not payload:
        return {"explanation": None, "remediation": []}

    explanation = None
    remediation: list[dict] = []

    hosts = payload.get("hosts", [])
    if isinstance(hosts, list):
        for item in hosts:
            if isinstance(item, dict) and str(item.get("hostname", "")) == hostname:
                explanation = item
                break

    remediation_plan = payload.get("remediation_plan", {})
    if isinstance(remediation_plan, dict):
        host_items = remediation_plan.get(hostname, [])
        if isinstance(host_items, list):
            remediation = [x for x in host_items if isinstance(x, dict)]

    return {
        "explanation": explanation,
        "remediation": remediation,
    }


def list_available_output_files() -> pd.DataFrame:
    base_dir = get_collector_output_dir()
    if not base_dir.exists():
        return pd.DataFrame()

    rows = []
    for path in sorted(base_dir.rglob("*")):
        if not path.is_file():
            continue
        rows.append(
            {
                "name": path.name,
                "relative_path": str(path.relative_to(get_repo_root())),
                "size_bytes": path.stat().st_size,
                "modified": pd.to_datetime(path.stat().st_mtime, unit="s"),
            }
        )

    if not rows:
        return pd.DataFrame()

    return pd.DataFrame(rows).sort_values("modified", ascending=False).reset_index(drop=True)
