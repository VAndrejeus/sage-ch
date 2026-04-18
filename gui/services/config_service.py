from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from services.data_loader import get_graph_db_path, get_repo_root


def get_collector_root() -> Path:
    return get_repo_root() / "collector"


def get_collector_input_root_dir() -> Path:
    return get_collector_root() / "input"


def get_collector_incoming_dir() -> Path:
    return get_collector_input_root_dir() / "incoming"


def get_collector_output_dir() -> Path:
    return get_collector_root() / "output"


def get_collector_log_candidates() -> list[Path]:
    repo_root = get_repo_root()
    collector_root = get_collector_root()

    candidates = [
        collector_root / "collector_audit.log",
        collector_root / "logs" / "collector_audit.log",
        repo_root / "collector_audit.log",
    ]

    output_dir = get_collector_output_dir()
    if output_dir.exists():
        for path in sorted(output_dir.rglob("*.log")):
            candidates.append(path)

    deduped: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        key = str(path.resolve()) if path.exists() else str(path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)

    return deduped


def find_latest_existing_log() -> Path | None:
    existing = [p for p in get_collector_log_candidates() if p.exists() and p.is_file()]
    if not existing:
        return None
    existing.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return existing[0]


def get_system_paths() -> dict[str, Path]:
    return {
        "repo_root": get_repo_root(),
        "collector_root": get_collector_root(),
        "collector_input_root_dir": get_collector_input_root_dir(),
        "collector_incoming_dir": get_collector_incoming_dir(),
        "collector_output_dir": get_collector_output_dir(),
        "kuzu_db_path": get_graph_db_path(),
    }


def get_path_status_rows() -> list[dict[str, Any]]:
    paths = get_system_paths()
    rows: list[dict[str, Any]] = []

    for name, path in paths.items():
        rows.append(
            {
                "name": name,
                "path": str(path),
                "exists": path.exists(),
                "type": "dir" if path.exists() and path.is_dir() else "file" if path.exists() and path.is_file() else "missing",
            }
        )

    log_path = find_latest_existing_log()
    rows.append(
        {
            "name": "latest_collector_log",
            "path": str(log_path) if log_path else "",
            "exists": bool(log_path and log_path.exists()),
            "type": "file" if log_path and log_path.exists() else "missing",
        }
    )

    return rows


def get_path_status_df() -> pd.DataFrame:
    return pd.DataFrame(get_path_status_rows())


def get_basic_health_summary() -> dict[str, Any]:
    paths = get_system_paths()
    input_root_dir = paths["collector_input_root_dir"]
    incoming_dir = paths["collector_incoming_dir"]
    output_dir = paths["collector_output_dir"]
    kuzu_db_path = paths["kuzu_db_path"]

    return {
        "collector_input_root_exists": input_root_dir.exists() and input_root_dir.is_dir(),
        "collector_incoming_exists": incoming_dir.exists() and incoming_dir.is_dir(),
        "collector_output_exists": output_dir.exists() and output_dir.is_dir(),
        "kuzu_db_exists": kuzu_db_path.exists() and kuzu_db_path.is_file(),
        "latest_log_exists": find_latest_existing_log() is not None,
    }