from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = REPO_ROOT / "collector" / "output"
KUZU_DB_PATH = OUTPUT_DIR / "graph" / "sage_ch_kuzu.db"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from collector.graph.graph_persistence import persist_mapped_graph


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def find_latest_consolidated() -> Path | None:
    candidates = [path for path in OUTPUT_DIR.glob("consolidated_dataset*.json") if path.is_file()]
    if not candidates:
        return None
    candidates.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    return candidates[0]


def main() -> int:
    consolidated_path = find_latest_consolidated()
    if consolidated_path is None:
        print("No consolidated dataset found.")
        return 1

    payload = load_json(consolidated_path)
    if not isinstance(payload, dict):
        print(f"Consolidated dataset is not a JSON object: {consolidated_path}")
        return 1

    mapped_graph = payload.get("mapped_graph")
    if not isinstance(mapped_graph, dict):
        print(f"Consolidated dataset does not contain mapped_graph: {consolidated_path}")
        return 1

    batch_id = str(payload.get("batch_id") or "rebuild_kuzu")
    result = persist_mapped_graph(
        mapped_graph=mapped_graph,
        db_path=str(KUZU_DB_PATH),
        run_id=batch_id,
        observed_at=datetime.now(timezone.utc).isoformat(),
    )

    print(f"Rebuilt Kuzu from: {consolidated_path}")
    print(f"Kuzu DB: {KUZU_DB_PATH}")
    print(f"Nodes: {result.get('node_count', 0)}")
    print(f"Edges: {result.get('edge_count', 0)}")
    print(f"Nodes marked missing: {result.get('nodes_marked_missing', 0)}")
    print(f"Edges marked inactive: {result.get('edges_marked_inactive', 0)}")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
