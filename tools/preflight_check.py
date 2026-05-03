from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_MODULES = [
    "streamlit",
    "pandas",
    "plotly",
    "networkx",
    "kuzu",
    "requests",
    "psutil",
    "reportlab",
]


def check_modules() -> list[str]:
    missing = []
    for module_name in REQUIRED_MODULES:
        try:
            importlib.import_module(module_name)
        except Exception as exc:
            missing.append(f"{module_name}: {exc}")
    return missing


def check_paths() -> list[str]:
    required_paths = [
        "gui/app.py",
        "collector/main.py",
        "requirements.txt",
        ".streamlit/config.toml",
    ]
    missing = []
    for relative_path in required_paths:
        path = REPO_ROOT / relative_path
        if not path.exists():
            missing.append(relative_path)
    return missing


def check_latest_outputs() -> dict[str, object]:
    output_dir = REPO_ROOT / "collector" / "output"
    consolidated_files = list(output_dir.glob("consolidated_dataset*.json")) if output_dir.exists() else []
    kuzu_db = output_dir / "graph" / "sage_ch_kuzu.db"
    latest_consolidated = None

    if consolidated_files:
        consolidated_files.sort(key=lambda path: path.stat().st_mtime, reverse=True)
        latest_consolidated = consolidated_files[0]

    payload = {}
    if latest_consolidated:
        try:
            payload = json.loads(latest_consolidated.read_text(encoding="utf-8"))
        except Exception:
            payload = {}

    return {
        "latest_consolidated": str(latest_consolidated) if latest_consolidated else "",
        "latest_batch": payload.get("batch_id", ""),
        "kuzu_db_exists": kuzu_db.exists(),
        "kuzu_db_path": str(kuzu_db),
    }


def main() -> int:
    print("SAGE-CH preflight check")
    print(f"Repository: {REPO_ROOT}")
    print(f"Python: {sys.version.split()[0]}")

    missing_modules = check_modules()
    missing_paths = check_paths()
    outputs = check_latest_outputs()

    if missing_modules:
        print("\nMissing or failed Python modules:")
        for item in missing_modules:
            print(f"  - {item}")
    else:
        print("Python modules: ok")

    if missing_paths:
        print("\nMissing required files:")
        for item in missing_paths:
            print(f"  - {item}")
    else:
        print("Required files: ok")

    print("\nData outputs:")
    print(f"  Latest consolidated: {outputs['latest_consolidated'] or 'not found'}")
    print(f"  Latest batch: {outputs['latest_batch'] or 'not found'}")
    print(f"  Kuzu DB: {outputs['kuzu_db_path']}")
    print(f"  Kuzu DB exists: {outputs['kuzu_db_exists']}")

    if missing_modules or missing_paths:
        return 1

    print("\nPreflight complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
