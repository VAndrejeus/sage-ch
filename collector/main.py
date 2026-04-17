from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from agents.common.utils.audit_logger import AuditLogger
from agents.common.utils.json_writer import write_json

from collector.ai.pipeline import run_ai_phase_1
from collector.config import KUZU_DB_PATH
from collector.ingestion.discovery_loader import (
    get_latest_discovery_file,
    load_discovery_file,
)
from collector.ingestion.report_loader import load_reports_from_paths
from collector.ingestion.staged_ingestion import StagedIngestionService
from collector.validation.schema_validator import validate_report
from collector.validation.discovery_validator import validate_discovery_file
from collector.normalization.normalizer import normalize_report
from collector.normalization.discovery_normalizer import normalize_discovered_hosts
from collector.correlation.host_correlator import correlate_hosts
from collector.graph.graph_builder import build_graph
from collector.alignment.graph_mapper import align_graph
from collector.graph.graph_persistence import persist_mapped_graph
from collector.analysis.rule_engine import evaluate_hosts
from collector.analysis.report_generator import (
    build_assessment_summary,
    build_scoreboard_markdown,
)

PROJECT_ROOT = Path(__file__).resolve().parent
LOG_PATH = "collector/output/collector_audit.log"
DISCOVERY_OUTPUT_DIR = "outputs/discovery"


def generate_output_paths(batch_id: str) -> dict:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    safe_batch_id = batch_id.replace(":", "_").replace("/", "_").replace("\\", "_")

    return {
        "consolidated": f"collector/output/consolidated_dataset_{safe_batch_id}_{timestamp}.json",
        "findings": f"collector/output/findings_dataset_{safe_batch_id}_{timestamp}.json",
        "summary": f"collector/output/assessment_summary_{safe_batch_id}_{timestamp}.json",
        "scoreboard": f"collector/output/scoreboard_report_{safe_batch_id}_{timestamp}.md",
    }


def write_text_file(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as file_handle:
        file_handle.write(content)


def process_reports(report_paths: List[str], batch_id: str, logger: AuditLogger) -> Dict[str, Any]:
    logger.info(f"Processing staged batch {batch_id} with {len(report_paths)} report file(s).")

    loaded_reports = load_reports_from_paths(report_paths)
    logger.info(f"Loaded {len(loaded_reports)} report file(s).")

    logger.info("Validating loaded reports.")
    validated_reports = []

    for loaded in loaded_reports:
        if not loaded["ok"] or not isinstance(loaded["data"], dict):
            validated_reports.append({
                "path": loaded["path"],
                "load_ok": loaded["ok"],
                "validation_ok": False,
                "errors": [loaded["error"]] if loaded["error"] else ["Loaded data is missing or invalid."],
                "data": loaded["data"],
            })
            continue

        validation = validate_report(loaded["data"])
        validated_reports.append({
            "path": loaded["path"],
            "load_ok": loaded["ok"],
            "validation_ok": validation["ok"],
            "errors": validation["errors"],
            "data": loaded["data"],
        })

    valid_reports = [r for r in validated_reports if r["validation_ok"]]
    invalid_reports = [r for r in validated_reports if not r["validation_ok"]]

    logger.info(f"Validated {len(validated_reports)} report(s).")
    logger.info(f"Valid reports: {len(valid_reports)}")
    logger.info(f"Invalid reports: {len(invalid_reports)}")

    logger.info("Normalizing valid reports.")
    normalized_hosts = []

    for report_result in valid_reports:
        normalized = normalize_report(report_result["data"], report_result["path"])
        normalized_hosts.append(normalized)

    logger.info(f"Normalized {len(normalized_hosts)} host record(s).")

    normalized_discovered_hosts = []
    correlation_results = []

    logger.info(f"Searching for latest discovery file in: {DISCOVERY_OUTPUT_DIR}")
    discovery_path = get_latest_discovery_file(DISCOVERY_OUTPUT_DIR)

    discovery_scan = None
    discovered_hosts = []
    discovery_validation = {
        "ok": False,
        "errors": []
    }

    if not discovery_path:
        logger.info("No discovery file found.")
        discovery_validation["errors"].append("No discovery file found.")
    else:
        logger.info(f"Loading discovery file from: {discovery_path}")
        loaded_discovery = load_discovery_file(discovery_path)

        if not loaded_discovery["ok"] or not isinstance(loaded_discovery["data"], dict):
            logger.info("Discovery file failed to load.")
            discovery_validation["errors"].append(
                loaded_discovery["error"] if loaded_discovery["error"] else "Discovery data missing or invalid."
            )
        else:
            logger.info("Validating discovery file.")
            discovery_validation = validate_discovery_file(loaded_discovery["data"])

            if not discovery_validation["ok"]:
                logger.info("Discovery file validation failed.")
                logger.info(f"Discovery validation errors: {discovery_validation['errors']}")
            else:
                discovery_scan = loaded_discovery["data"]
                discovered_hosts = discovery_scan.get("discovered_hosts", [])
                normalized_discovered_hosts = normalize_discovered_hosts(discovered_hosts)
                correlation_results = correlate_hosts(normalized_hosts, normalized_discovered_hosts)

                logger.info("Discovery file loaded and validated successfully.")
                logger.info(f"Discovered hosts loaded: {len(discovered_hosts)}")
                logger.info(f"Normalized discovered hosts: {len(normalized_discovered_hosts)}")
                logger.info(f"Correlation results generated: {len(correlation_results)}")

    logger.info("Building base graph.")
    graph = build_graph(
        normalized_hosts,
        normalized_discovered_hosts,
        correlation_results,
        findings=[],
        ai_result=None,
    )

    logger.info("Applying graph mapper to base graph.")
    mapped_graph = align_graph(graph)
    logger.info(
        f"Base graph mapping complete. "
        f"Mapped nodes: {mapped_graph['summary']['node_count']}, "
        f"Mapped edges: {mapped_graph['summary']['edge_count']}"
    )

    logger.info("Building consolidated dataset.")
    consolidated = {
        "project": "SAGE-CH",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "component": "collector",
        "status": "complete",
        "batch_id": batch_id,
        "loaded_reports": loaded_reports,
        "validated_reports": validated_reports,
        "valid_report_count": len(valid_reports),
        "invalid_report_count": len(invalid_reports),
        "hosts": normalized_hosts,
        "discovery_scan": discovery_scan,
        "discovery_validation": discovery_validation,
        "discovered_hosts": discovered_hosts,
        "normalized_discovered_hosts": normalized_discovered_hosts,
        "correlation_results": correlation_results,
        "graph": graph,
        "graph_mapping_status": "complete",
        "mapped_graph": mapped_graph,
        "graph_persistence_status": "not_started",
        "graph_persistence": None,
    }

    logger.info("Running Phase 5 analysis.")
    findings = evaluate_hosts(normalized_hosts)

    for finding in findings:
        if isinstance(finding, dict):
            finding["batch_id"] = batch_id

    logger.info(f"Generated {len(findings)} finding(s).")

    summary = build_assessment_summary(consolidated, findings)
    summary["batch_id"] = batch_id
    summary["timestamp_utc"] = datetime.now(timezone.utc).isoformat()

    ai_result = run_ai_phase_1(
        batch_id=batch_id,
        consolidated=consolidated,
        findings=findings,
        summary=summary,
        logger=logger,
    )

    logger.info("Rebuilding graph with findings and AI outputs.")
    graph = build_graph(
        normalized_hosts,
        normalized_discovered_hosts,
        correlation_results,
        findings=findings,
        ai_result=ai_result,
    )

    logger.info("Applying graph mapper to enriched graph.")
    mapped_graph = align_graph(graph)
    logger.info(
        f"Enriched graph mapping complete. "
        f"Mapped nodes: {mapped_graph['summary']['node_count']}, "
        f"Mapped edges: {mapped_graph['summary']['edge_count']}"
    )

    consolidated["graph"] = graph
    consolidated["mapped_graph"] = mapped_graph
    consolidated["ai_phase_1"] = ai_result

    scoreboard_markdown = build_scoreboard_markdown(consolidated, findings, summary)
    scoreboard_markdown = (
        f"# Batch\n"
        f"- Batch ID: {batch_id}\n"
        f"- AI Phase 1 OK: {ai_result['ok']}\n\n"
        f"{scoreboard_markdown}"
    )

    outputs = generate_output_paths(batch_id)

    logger.info(f"Writing consolidated dataset to: {outputs['consolidated']}")
    write_json(outputs["consolidated"], consolidated)

    logger.info(f"Writing findings dataset to: {outputs['findings']}")
    write_json(outputs["findings"], findings)

    logger.info(f"Writing assessment summary to: {outputs['summary']}")
    write_json(outputs["summary"], summary)

    logger.info(f"Writing scoreboard markdown report to: {outputs['scoreboard']}")
    write_text_file(outputs["scoreboard"], scoreboard_markdown)

    logger.info("Primary collector outputs written successfully.")

    graph_persistence = None
    try:
        logger.info(f"Persisting mapped graph to Kuzu: {KUZU_DB_PATH}")
        graph_persistence = persist_mapped_graph(
            mapped_graph=mapped_graph,
            db_path=KUZU_DB_PATH,
            run_id=batch_id,
            observed_at=datetime.now(timezone.utc).isoformat(),
        )
        consolidated["graph_persistence_status"] = "complete"
        consolidated["graph_persistence"] = graph_persistence

        logger.info(
            f"Kuzu persistence complete. "
            f"Nodes={graph_persistence.get('node_count', 0)}, "
            f"Edges={graph_persistence.get('edge_count', 0)}, "
            f"MissingNodes={graph_persistence.get('nodes_marked_missing', 0)}, "
            f"InactiveEdges={graph_persistence.get('edges_marked_inactive', 0)}"
        )
    except Exception as exc:
        consolidated["graph_persistence_status"] = "failed"
        consolidated["graph_persistence"] = {
            "ok": False,
            "error": str(exc),
        }
        logger.info(f"Kuzu persistence failed: {exc}")

    logger.info(f"Re-writing consolidated dataset to include graph persistence status: {outputs['consolidated']}")
    write_json(outputs["consolidated"], consolidated)

    logger.info("Collector execution complete.")

    success_paths = [r["path"] for r in valid_reports]
    failed = [
        {
            "path": r["path"],
            "reason": "; ".join(r["errors"]) if r["errors"] else "validation_failed"
        }
        for r in invalid_reports
    ]

    return {
        "success": success_paths,
        "failed": failed,
    }


def main() -> int:
    logger = AuditLogger(LOG_PATH)
    logger.info("SAGE-CH collector started.")

    ingestion = StagedIngestionService(
        collector_root=PROJECT_ROOT,
        max_batch_size=25,
    )

    batch = ingestion.claim_batch()

    if batch is None:
        logger.info("No incoming files found.")
        return 0

    logger.info(f"Claimed batch {batch.batch_id} with {len(batch.files)} file(s).")

    result = ingestion.process_batch(
        batch,
        lambda report_paths: process_reports(
            [str(path) for path in report_paths],
            batch.batch_id,
            logger,
        )
    )

    logger.info(
        f"Batch {result.batch_id} complete. "
        f"Success={result.success_count}, Failure={result.failure_count}"
    )

    return 1 if result.failure_count > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())