from __future__ import annotations

from typing import Any
import subprocess
import sys

import pandas as pd

from services.config_service import get_collector_incoming_dir
from services.data_loader import (
    get_repo_root,
    list_available_output_files,
    load_latest_assessment_summary_payload,
    load_latest_consolidated_payload,
    load_latest_findings_df,
)


COLLECTOR_TIMEOUT_SECONDS = 7200


def inspect_input_queue() -> dict[str, Any]:
    incoming_dir = get_collector_incoming_dir()

    result = {
        "input_dir": str(incoming_dir),
        "exists": incoming_dir.exists() and incoming_dir.is_dir(),
        "total_files": 0,
        "files_df": pd.DataFrame(),
    }

    if not result["exists"]:
        return result

    files: list[dict[str, Any]] = []

    for path in sorted(incoming_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name.lower() in {".gitkeep"}:
            continue

        rel = path.relative_to(incoming_dir)
        files.append(
            {
                "name": path.name,
                "relative_path": str(rel),
                "size_bytes": path.stat().st_size,
                "modified": pd.to_datetime(path.stat().st_mtime, unit="s"),
            }
        )

    result["total_files"] = len(files)
    result["files_df"] = pd.DataFrame(files).sort_values("modified", ascending=False).reset_index(drop=True) if files else pd.DataFrame()
    return result


def run_collector() -> dict[str, Any]:
    repo_root = get_repo_root()
    cmd = [sys.executable, "-m", "collector.main"]

    try:
        completed = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=COLLECTOR_TIMEOUT_SECONDS,
        )
        return {
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "cmd": " ".join(cmd),
            "cwd": str(repo_root),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": (exc.stderr or "") + f"\nCollector run timed out after {COLLECTOR_TIMEOUT_SECONDS} seconds.",
            "cmd": " ".join(cmd),
            "cwd": str(repo_root),
        }
    except Exception as exc:
        return {
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
            "cmd": " ".join(cmd),
            "cwd": str(repo_root),
        }


def run_ai_enrichment() -> dict[str, Any]:
    repo_root = get_repo_root()
    script_path = repo_root / "tools" / "run_ai_enrichment.py"
    cmd = [sys.executable, str(script_path)]

    try:
        completed = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=COLLECTOR_TIMEOUT_SECONDS,
        )
        return {
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "cmd": " ".join(cmd),
            "cwd": str(repo_root),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": (exc.stderr or "") + f"\nAI enrichment timed out after {COLLECTOR_TIMEOUT_SECONDS} seconds.",
            "cmd": " ".join(cmd),
            "cwd": str(repo_root),
        }
    except Exception as exc:
        return {
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
            "cmd": " ".join(cmd),
            "cwd": str(repo_root),
        }


def rebuild_kuzu_from_latest_consolidated() -> dict[str, Any]:
    repo_root = get_repo_root()
    script_path = repo_root / "tools" / "rebuild_kuzu_from_consolidated.py"
    cmd = [sys.executable, str(script_path)]

    try:
        completed = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=COLLECTOR_TIMEOUT_SECONDS,
        )
        return {
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "cmd": " ".join(cmd),
            "cwd": str(repo_root),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": (exc.stderr or "") + f"\nKuzu rebuild timed out after {COLLECTOR_TIMEOUT_SECONDS} seconds.",
            "cmd": " ".join(cmd),
            "cwd": str(repo_root),
        }
    except Exception as exc:
        return {
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
            "cmd": " ".join(cmd),
            "cwd": str(repo_root),
        }


def get_latest_output_summary() -> dict[str, Any]:
    consolidated_payload, consolidated_path = load_latest_consolidated_payload()
    findings_df, findings_path = load_latest_findings_df()
    assessment_summary, summary_path = load_latest_assessment_summary_payload()
    core_graph_status = None
    ai_enrichment_status = None
    ai_graph_status = None

    if isinstance(consolidated_payload, dict):
        core_graph_status = (
            consolidated_payload.get("core_graph_persistence_status")
            or consolidated_payload.get("graph_persistence_status")
        )
        ai_enrichment_status = consolidated_payload.get("ai_enrichment_status")
        if not ai_enrichment_status:
            ai_phase = consolidated_payload.get("ai_phase_1")
            if isinstance(ai_phase, dict) and ai_phase.get("ok"):
                ai_enrichment_status = "complete"
        ai_graph_status = consolidated_payload.get("ai_graph_persistence_status")

    return {
        "consolidated_path": str(consolidated_path) if consolidated_path else "",
        "findings_path": str(findings_path) if findings_path else "",
        "assessment_summary_path": str(summary_path) if summary_path else "",
        "batch_id": assessment_summary.get("batch_id") if isinstance(assessment_summary, dict) else None,
        "total_hosts": assessment_summary.get("total_hosts") if isinstance(assessment_summary, dict) else None,
        "total_findings": assessment_summary.get("total_findings") if isinstance(assessment_summary, dict) else None,
        "severity_counts": assessment_summary.get("severity_counts", {}) if isinstance(assessment_summary, dict) else {},
        "graph_persistence_status": consolidated_payload.get("graph_persistence_status") if isinstance(consolidated_payload, dict) else None,
        "graph_persistence": consolidated_payload.get("graph_persistence", {}) if isinstance(consolidated_payload, dict) else {},
        "core_graph_persistence_status": core_graph_status,
        "ai_enrichment_status": ai_enrichment_status,
        "ai_graph_persistence_status": ai_graph_status,
        "findings_rows": int(len(findings_df)) if not findings_df.empty else 0,
    }


def get_recent_output_files_df(limit: int = 20) -> pd.DataFrame:
    df = list_available_output_files()
    if df.empty:
        return df
    return df.head(limit).reset_index(drop=True)
