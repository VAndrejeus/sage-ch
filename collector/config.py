from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = PROJECT_ROOT / "output"
GRAPH_OUTPUT_DIR = OUTPUT_DIR / "graph"
KUZU_DB_PATH = str(GRAPH_OUTPUT_DIR / "sage_ch_kuzu.db")