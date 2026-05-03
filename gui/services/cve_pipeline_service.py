from __future__ import annotations

import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

CREATE_SOFTWARE_SNAPSHOT_SCRIPT = PROJECT_ROOT / "tools" / "create_software_snapshot.py"
UPDATE_CVE_SNAPSHOT_SCRIPT = PROJECT_ROOT / "tools" / "update_cve_snapshot.py"
GENERATE_CVE_FINDINGS_SCRIPT = PROJECT_ROOT / "tools" / "correlate_cves_to_findings.py"
ENRICH_GRAPH_WITH_CVES_SCRIPT = PROJECT_ROOT / "tools" / "enrich_graph_with_cves.py"


def run_script(script_path: Path) -> dict:
    if not script_path.exists():
        return {
            "success": False,
            "script": str(script_path),
            "message": f"Missing script: {script_path}",
        }

    result = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    return {
        "success": result.returncode == 0,
        "script": str(script_path),
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "message": result.stdout.strip() if result.returncode == 0 else result.stderr.strip(),
    }


def create_software_snapshot() -> dict:
    return run_script(CREATE_SOFTWARE_SNAPSHOT_SCRIPT)


def update_cve_snapshot() -> dict:
    return run_script(UPDATE_CVE_SNAPSHOT_SCRIPT)


def generate_cve_findings() -> dict:
    return run_script(GENERATE_CVE_FINDINGS_SCRIPT)


def enrich_graph_with_cves() -> dict:
    return run_script(ENRICH_GRAPH_WITH_CVES_SCRIPT)


def run_full_cve_pipeline() -> list[dict]:
    steps = [
        ("Create Software Snapshot", create_software_snapshot),
        ("Update CVE Snapshot", update_cve_snapshot),
        ("Generate CVE Findings", generate_cve_findings),
        ("Enrich Graph with CVEs", enrich_graph_with_cves),
    ]

    results = []

    for step_name, step_function in steps:
        result = step_function()
        result["step"] = step_name
        results.append(result)

        if not result.get("success"):
            break

    return results