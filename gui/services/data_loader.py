from __future__ import annotations

from pathlib import Path
import json
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


def _first_non_empty(record: dict, keys: list[str], default: Any = None) -> Any:
    for key in keys:
        value = record.get(key)
        if value not in [None, "", [], {}]:
            return value
    return default


def _normalize_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    if isinstance(value, int):
        return value != 0
    return False


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


def load_latest_findings_df() -> tuple[pd.DataFrame, Path | None]:
    path = get_latest_findings_path()
    if path is None:
        return pd.DataFrame(), None

    payload = _safe_read_json(path)
    if not isinstance(payload, list):
        return pd.DataFrame(), path

    rows: list[dict] = []
    for item in payload:
        if not isinstance(item, dict):
            continue

        evidence = item.get("evidence", [])
        if isinstance(evidence, list):
            evidence_text = "; ".join(
                [
                    f"{e.get('field', '')}: {e.get('reason', '')}".strip(": ")
                    for e in evidence
                    if isinstance(e, dict)
                ]
            )
        else:
            evidence_text = str(evidence)

        rows.append(
            {
                "finding_id": item.get("finding_id", ""),
                "rule_id": item.get("rule_id", ""),
                "title": item.get("title", ""),
                "severity": str(item.get("severity", "")).lower(),
                "category": item.get("category", ""),
                "status": item.get("status", ""),
                "hostname": item.get("hostname", ""),
                "platform": item.get("platform", ""),
                "ip_address": item.get("ip_address", ""),
                "description": item.get("description", ""),
                "expected": item.get("expected", ""),
                "recommendation": item.get("recommendation", ""),
                "cis_controls": ", ".join(item.get("cis_controls", [])) if isinstance(item.get("cis_controls"), list) else "",
                "evidence": evidence_text,
                "batch_id": item.get("batch_id", ""),
                "_raw": item,
            }
        )

    return pd.DataFrame(rows), path


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
        if str(os_name).lower().startswith("linux"):
            host_type = "managed"
        elif str(os_name).lower().startswith("windows"):
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

    return pd.DataFrame(rows), path


def load_graph_counts_from_consolidated() -> tuple[dict, Path | None]:
    payload, path = load_latest_consolidated_payload()
    if not payload:
        return {"node_counts": {}, "edge_counts": {}, "graph_persistence_status": "unknown"}, path

    graph_data = payload.get("graph_data", {}) or {}
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