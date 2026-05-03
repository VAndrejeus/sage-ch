from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agents.common.utils.audit_logger import AuditLogger
from agents.common.utils.json_writer import write_json
from collector.ai.pipeline import run_ai_phase_1
from collector.alignment.graph_mapper import align_graph
from collector.config import KUZU_DB_PATH
from collector.graph.graph_builder import build_graph
from collector.graph.graph_persistence import persist_mapped_graph


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = REPO_ROOT / "collector" / "output"
LOG_PATH = "collector/output/collector_audit.log"


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def find_latest(pattern: str) -> Path | None:
    candidates = [path for path in OUTPUT_DIR.glob(pattern) if path.is_file()]
    if not candidates:
        return None
    candidates.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    return candidates[0]


def persist_ai_graph(mapped_graph: dict[str, Any], batch_id: str, logger: AuditLogger) -> dict[str, Any]:
    try:
        logger.info(f"Persisting AI-enriched graph to Kuzu: {KUZU_DB_PATH}")
        result = persist_mapped_graph(
            mapped_graph=mapped_graph,
            db_path=KUZU_DB_PATH,
            run_id=batch_id,
            observed_at=datetime.now(timezone.utc).isoformat(),
        )
        logger.info(
            f"AI graph persistence complete. "
            f"Nodes={result.get('node_count', 0)}, "
            f"Edges={result.get('edge_count', 0)}"
        )
        return {
            "status": "complete",
            "result": result,
        }
    except Exception as exc:
        logger.info(f"AI graph persistence failed: {exc}")
        return {
            "status": "failed",
            "result": {
                "ok": False,
                "error": str(exc),
            },
        }


def main() -> int:
    logger = AuditLogger(LOG_PATH)
    logger.info("SAGE-CH AI enrichment started.")

    consolidated_path = find_latest("consolidated_dataset*.json")
    findings_path = find_latest("findings_dataset*.json")
    summary_path = find_latest("assessment_summary*.json")

    if consolidated_path is None or findings_path is None or summary_path is None:
        print("Missing consolidated, findings, or assessment summary output.")
        return 1

    consolidated = load_json(consolidated_path)
    findings = load_json(findings_path)
    summary = load_json(summary_path)

    if not isinstance(consolidated, dict) or not isinstance(findings, list) or not isinstance(summary, dict):
        print("Latest output files are not in the expected format.")
        return 1

    batch_id = str(consolidated.get("batch_id") or summary.get("batch_id") or "ai_enrichment")
    consolidated["ai_enrichment_status"] = "running"
    consolidated["ai_enrichment_started_at"] = datetime.now(timezone.utc).isoformat()
    write_json(str(consolidated_path), consolidated)

    try:
        ai_result = run_ai_phase_1(
            batch_id=batch_id,
            consolidated=consolidated,
            findings=findings,
            summary=summary,
            logger=logger,
        )
    except Exception as exc:
        logger.info(f"AI enrichment failed: {exc}")
        consolidated["ai_enrichment_status"] = "failed"
        consolidated["ai_enrichment_completed_at"] = datetime.now(timezone.utc).isoformat()
        consolidated["ai_phase_1"] = {
            "ok": False,
            "error": str(exc),
            "batch_id": batch_id,
        }
        write_json(str(consolidated_path), consolidated)
        print(f"AI enrichment failed for {batch_id}: {exc}")
        return 1

    graph = build_graph(
        consolidated.get("hosts", []),
        consolidated.get("normalized_discovered_hosts", []),
        consolidated.get("correlation_results", []),
        findings=findings,
        ai_result=ai_result,
    )
    mapped_graph = align_graph(graph)
    persistence = persist_ai_graph(mapped_graph, batch_id, logger)

    consolidated["status"] = "complete"
    consolidated["graph"] = graph
    consolidated["mapped_graph"] = mapped_graph
    consolidated["ai_phase_1"] = ai_result
    consolidated["ai_enrichment_status"] = "complete" if ai_result.get("ok") else "failed"
    consolidated["ai_enrichment_completed_at"] = datetime.now(timezone.utc).isoformat()
    consolidated["ai_graph_persistence_status"] = persistence["status"]
    consolidated["ai_graph_persistence"] = persistence["result"]
    consolidated["graph_persistence_status"] = persistence["status"]
    consolidated["graph_persistence"] = persistence["result"]
    write_json(str(consolidated_path), consolidated)

    logger.info("SAGE-CH AI enrichment complete.")
    print(f"AI enrichment complete for {batch_id}.")
    print(f"Updated consolidated dataset: {consolidated_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
