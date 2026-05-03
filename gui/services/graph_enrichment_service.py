from __future__ import annotations

import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENRICH_GRAPH_SCRIPT = PROJECT_ROOT / "tools" / "enrich_graph_with_cves.py"
ENRICHED_GRAPH_PATH = PROJECT_ROOT / "collector" / "output" / "graph" / "graph_latest_enriched.json"


def enrich_graph_with_cves() -> dict:
    if not ENRICH_GRAPH_SCRIPT.exists():
        return {
            "success": False,
            "message": f"Missing script: {ENRICH_GRAPH_SCRIPT}",
        }

    result = subprocess.run(
        [sys.executable, str(ENRICH_GRAPH_SCRIPT)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return {
            "success": False,
            "message": result.stderr or result.stdout or "Graph enrichment failed.",
        }

    return {
        "success": True,
        "message": result.stdout.strip() or "Graph enriched with CVEs.",
        "output_path": str(ENRICHED_GRAPH_PATH),
    }


def get_enriched_graph_path() -> Path:
    return ENRICHED_GRAPH_PATH