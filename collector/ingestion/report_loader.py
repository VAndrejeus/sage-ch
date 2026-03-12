import json
from pathlib import Path
from typing import Any, Dict, List

def _load_json_file(path: Path) -> Dict[str, Any]:
    
    # Safely loads a single JSON file and returns a structured result.
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {
            "ok": True,
            "path": str(path),
            "data": data,
            "error": ""
        }
    except Exception as e:
        return {
            "ok": False,
            "path": str(path),
            "data": None,
            "error": str(e)
        }
    
def load_reports(directory: str) -> List[Dict[str, Any]]:
    
    # Loads all JSON endpoint reports from a given directory
    
    folder = Path(directory)

    if not folder.exists():
        return []

    results: List[Dict[str, Any]] = []

    for path in sorted(folder.glob("*.json")):
        result = _load_json_file(path)
        results.append(result)

    return results