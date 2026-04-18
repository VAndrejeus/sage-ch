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
            timeout=900,
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
            "stderr": (exc.stderr or "") + "\nCollector run timed out.",
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
        "findings_rows": int(len(findings_df)) if not findings_df.empty else 0,
    }


def get_recent_output_files_df(limit: int = 20) -> pd.DataFrame:
    df = list_available_output_files()
    if df.empty:
        return df
    return df.head(limit).reset_index(drop=True)