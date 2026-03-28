import json
import os
from pathlib import Path


def get_latest_discovery_file(directory: str) -> str | None:
    path = Path(directory)

    if not path.exists() or not path.is_dir():
        return None

    files = sorted(
        path.glob("network_discovery_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )

    if not files:
        return None

    return str(files[0])


def load_discovery_file(path: str) -> dict:
    result = {
        "path": path,
        "ok": False,
        "data": None,
        "error": None,
    }

    if not os.path.exists(path):
        result["error"] = f"Discovery file does not exist: {path}"
        return result

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        result["ok"] = True
        result["data"] = data
        return result

    except Exception as e:
        result["error"] = f"Failed to load discovery file: {str(e)}"
        return result