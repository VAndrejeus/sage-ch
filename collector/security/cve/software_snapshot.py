from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
INCOMING_DIR = REPO_ROOT / "collector" / "input" / "incoming"
SOFTWARE_SNAPSHOT_DIR = REPO_ROOT / "collector" / "output" / "software_snapshot"
SOFTWARE_SNAPSHOT_PATH = SOFTWARE_SNAPSHOT_DIR / "software_snapshot_latest.json"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def normalize_software_name(name: str) -> str:
    value = name.lower().strip()
    value = re.sub(r"\(.*?\)", "", value)
    value = re.sub(r"[^a-z0-9.+# -]", " ", value)
    value = re.sub(r"\s+", " ", value).strip()

    aliases = {
        "mozilla firefox": "firefox",
        "firefox": "firefox",
        "vlc media player": "vlc",
        "vlc": "vlc",
        "mysql server": "mysql server",
        "mysql workbench": "mysql workbench",
        "python": "python",
        "git": "git",
        "winrar": "winrar",
        "notepad++": "notepad++",
        "openssl": "openssl",
        "bash": "bash",
        "glibc": "glibc",
    }

    for key, normalized in aliases.items():
        if key in value:
            return normalized

    return value


def extract_report_software(report: dict[str, Any], source_file: str) -> list[dict[str, Any]]:
    host_info = report.get("host_info", {})
    hostname = str(host_info.get("hostname", "unknown"))

    software_inventory = report.get("software_inventory", {})
    items = software_inventory.get("items", [])

    if not isinstance(items, list):
        return []

    software_rows = []

    for item in items:
        if not isinstance(item, dict):
            continue

        raw_name = str(item.get("name", "") or "").strip()
        if not raw_name:
            continue

        software_rows.append(
            {
                "raw_name": raw_name,
                "normalized_name": normalize_software_name(raw_name),
                "version": str(item.get("version", "") or "").strip(),
                "arch": str(item.get("arch", "") or "").strip(),
                "hostname": hostname,
                "source_file": source_file,
            }
        )

    return software_rows


def create_software_snapshot(
    input_dir: Path = INCOMING_DIR,
    output_path: Path = SOFTWARE_SNAPSHOT_PATH,
) -> dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not input_dir.exists():
        return {
            "ok": False,
            "message": f"Input directory not found: {input_dir}",
            "input_dir": str(input_dir),
            "output_path": str(output_path),
        }

    report_files = sorted(input_dir.glob("*.json"))
    grouped: dict[str, dict[str, Any]] = {}
    loaded_reports = 0
    skipped_reports = 0

    for path in report_files:
        report = load_json(path)

        if not report:
            skipped_reports += 1
            continue

        loaded_reports += 1
        software_rows = extract_report_software(report, path.name)

        for row in software_rows:
            key = row["normalized_name"]

            if key not in grouped:
                grouped[key] = {
                    "normalized_name": key,
                    "raw_names": set(),
                    "versions_seen": set(),
                    "architectures_seen": set(),
                    "hosts_seen": set(),
                    "source_files": set(),
                }

            grouped[key]["raw_names"].add(row["raw_name"])

            if row["version"]:
                grouped[key]["versions_seen"].add(row["version"])

            if row["arch"]:
                grouped[key]["architectures_seen"].add(row["arch"])

            grouped[key]["hosts_seen"].add(row["hostname"])
            grouped[key]["source_files"].add(row["source_file"])

    software = []

    for item in grouped.values():
        software.append(
            {
                "normalized_name": item["normalized_name"],
                "raw_names": sorted(item["raw_names"]),
                "versions_seen": sorted(item["versions_seen"]),
                "architectures_seen": sorted(item["architectures_seen"]),
                "hosts_seen": sorted(item["hosts_seen"]),
                "source_files": sorted(item["source_files"]),
            }
        )

    software = sorted(software, key=lambda item: item["normalized_name"])

    snapshot = {
        "generated_at": utc_now_iso(),
        "source": str(input_dir),
        "source_report_count": loaded_reports,
        "skipped_report_count": skipped_reports,
        "software_count": len(software),
        "software": software,
    }

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(snapshot, file, indent=2)

    return {
        "ok": True,
        "message": f"Created software snapshot with {len(software)} unique software entries from {loaded_reports} report(s).",
        "input_dir": str(input_dir),
        "output_path": str(output_path),
        "generated_at": snapshot["generated_at"],
        "source_report_count": loaded_reports,
        "skipped_report_count": skipped_reports,
        "software_count": len(software),
    }


def get_software_snapshot_status(
    snapshot_path: Path = SOFTWARE_SNAPSHOT_PATH,
) -> dict[str, Any]:
    if not snapshot_path.exists():
        return {
            "exists": False,
            "path": str(snapshot_path),
            "generated_at": None,
            "software_count": 0,
            "source_report_count": 0,
            "skipped_report_count": 0,
        }

    data = load_json(snapshot_path) or {}

    return {
        "exists": True,
        "path": str(snapshot_path),
        "generated_at": data.get("generated_at"),
        "software_count": data.get("software_count", 0),
        "source_report_count": data.get("source_report_count", 0),
        "skipped_report_count": data.get("skipped_report_count", 0),
    }