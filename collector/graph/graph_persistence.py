from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from collector.graph.kuzu_backend import KuzuGraphBackend


def persist_mapped_graph(
    mapped_graph: Dict[str, Any],
    db_path: str,
    run_id: Optional[str] = None,
    observed_at: Optional[str] = None,
) -> Dict[str, Any]:
    effective_run_id = run_id or datetime.now(timezone.utc).strftime("run_%Y%m%dT%H%M%SZ")
    effective_observed_at = observed_at or datetime.now(timezone.utc).isoformat()

    backend = KuzuGraphBackend(db_path=db_path)
    backend.initialize()

    return backend.ingest_mapped_graph(
        mapped_graph=mapped_graph,
        observed_at=effective_observed_at,
        run_id=effective_run_id,
    )