from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from services.config_service import (
    find_latest_existing_log,
    get_collector_input_root_dir,
    get_collector_incoming_dir,
)
from services.data_loader import (
    get_graph_db_path,
    load_graph_counts_from_consolidated,
    load_latest_assessment_summary_payload,
    load_latest_consolidated_payload,
)
from services.kuzu_service import get_kuzu_graph_counts


def _utc_from_timestamp(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def _age_text(path: Path) -> str:
    age_seconds = max(0, (datetime.now(timezone.utc) - _utc_from_timestamp(path.stat().st_mtime)).total_seconds())
    if age_seconds < 60:
        return f"{int(age_seconds)}s"
    if age_seconds < 3600:
        return f"{int(age_seconds // 60)}m"
    if age_seconds < 86400:
        return f"{int(age_seconds // 3600)}h"
    return f"{int(age_seconds // 86400)}d"


def inspect_pipeline_queues() -> dict[str, Any]:
    input_root = get_collector_input_root_dir()
    incoming_dir = get_collector_incoming_dir()
    processing_dir = input_root / "processing"
    processed_dir = input_root / "processed"
    failed_dir = input_root / "failed"

    incoming_files = [p for p in incoming_dir.glob("*.json") if p.is_file()] if incoming_dir.exists() else []
    processing_rows = []

    if processing_dir.exists():
        for batch_dir in sorted([p for p in processing_dir.iterdir() if p.is_dir()], key=lambda p: p.stat().st_mtime, reverse=True):
            files = [p for p in batch_dir.iterdir() if p.is_file()]
            processing_rows.append(
                {
                    "batch_id": batch_dir.name,
                    "file_count": len(files),
                    "modified": _utc_from_timestamp(batch_dir.stat().st_mtime),
                    "age": _age_text(batch_dir),
                    "path": str(batch_dir),
                }
            )

    return {
        "incoming_count": len(incoming_files),
        "processing_count": len(processing_rows),
        "processed_batch_count": len([p for p in processed_dir.iterdir() if p.is_dir()]) if processed_dir.exists() else 0,
        "failed_batch_count": len([p for p in failed_dir.iterdir() if p.is_dir()]) if failed_dir.exists() else 0,
        "processing_df": pd.DataFrame(processing_rows),
    }


def get_pipeline_health_summary() -> dict[str, Any]:
    consolidated, consolidated_path = load_latest_consolidated_payload()
    assessment_summary, assessment_path = load_latest_assessment_summary_payload()
    json_graph_counts, graph_path = load_graph_counts_from_consolidated()
    kuzu_counts = get_kuzu_graph_counts(get_graph_db_path())
    queue_info = inspect_pipeline_queues()

    json_node_count = sum(json_graph_counts.get("node_counts", {}).values())
    json_edge_count = sum(json_graph_counts.get("edge_counts", {}).values())
    kuzu_node_count = sum(kuzu_counts.get("node_counts", {}).values()) if kuzu_counts.get("ok") else 0
    kuzu_edge_count = sum(kuzu_counts.get("edge_counts", {}).values()) if kuzu_counts.get("ok") else 0

    warnings = []
    if queue_info["processing_count"] > 0:
        warnings.append("One or more batches are currently in processing.")
    if consolidated and consolidated.get("ai_enrichment_status") in {"running"}:
        warnings.append("AI enrichment is marked running.")
    if not kuzu_counts.get("ok"):
        warnings.append(f"Kuzu is unavailable: {kuzu_counts.get('error', 'unknown error')}")
    elif json_node_count and kuzu_node_count and abs(json_node_count - kuzu_node_count) > 10:
        warnings.append("Kuzu and JSON graph node counts differ.")

    ai_status = consolidated.get("ai_enrichment_status") if isinstance(consolidated, dict) else None
    if not ai_status and isinstance(consolidated, dict):
        ai_phase = consolidated.get("ai_phase_1")
        if isinstance(ai_phase, dict) and ai_phase.get("ok"):
            ai_status = "complete"

    return {
        "batch_id": consolidated.get("batch_id") if isinstance(consolidated, dict) else None,
        "collector_status": consolidated.get("status") if isinstance(consolidated, dict) else None,
        "core_graph_persistence_status": (
            consolidated.get("core_graph_persistence_status") or consolidated.get("graph_persistence_status")
            if isinstance(consolidated, dict)
            else None
        ),
        "ai_enrichment_status": ai_status,
        "ai_graph_persistence_status": consolidated.get("ai_graph_persistence_status") if isinstance(consolidated, dict) else None,
        "total_hosts": assessment_summary.get("total_hosts") if isinstance(assessment_summary, dict) else None,
        "total_findings": assessment_summary.get("total_findings") if isinstance(assessment_summary, dict) else None,
        "json_node_count": json_node_count,
        "json_edge_count": json_edge_count,
        "kuzu_ok": kuzu_counts.get("ok", False),
        "kuzu_error": kuzu_counts.get("error", ""),
        "kuzu_node_count": kuzu_node_count,
        "kuzu_edge_count": kuzu_edge_count,
        "consolidated_path": str(consolidated_path) if consolidated_path else "",
        "assessment_path": str(assessment_path) if assessment_path else "",
        "graph_path": str(graph_path) if graph_path else "",
        "warnings": warnings,
        "queue_info": queue_info,
    }


def get_latest_log_lines(limit: int = 80) -> tuple[list[str], Path | None]:
    log_path = find_latest_existing_log()
    if log_path is None:
        return [], None

    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return [], log_path

    return lines[-limit:], log_path
