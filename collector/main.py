from datetime import datetime, timezone

from agents.common.utils.audit_logger import AuditLogger
from agents.common.utils.json_writer import write_json

from collector.ingestion.report_loader import load_reports
from collector.ingestion.discovery_loader import (
    get_latest_discovery_file,
    load_discovery_file,
)
from collector.validation.schema_validator import validate_report
from collector.validation.discovery_validator import validate_discovery_file
from collector.normalization.normalizer import normalize_report
from collector.normalization.discovery_normalizer import normalize_discovered_hosts
from collector.correlation.host_correlator import correlate_hosts
from collector.graph.graph_builder import build_graph
from collector.alignment.uckg_aligner import align_graph_to_uckg


def generate_output_path() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    return f"collector/output/consolidated_dataset_{timestamp}.json"


INPUT_DIR = "collector/input"
LOG_PATH = "collector/output/collector_audit.log"
DISCOVERY_OUTPUT_DIR = "outputs/discovery"


def main():
    logger = AuditLogger(LOG_PATH)
    logger.info("SAGE-CH collector started.")

    logger.info(f"Loading reports from: {INPUT_DIR}")
    loaded_reports = load_reports(INPUT_DIR)
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
        normalized = normalize_report(
            report_result["data"],
            report_result["path"]
        )
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

    graph = build_graph(
        normalized_hosts,
        normalized_discovered_hosts,
        correlation_results
    )

    logger.info("Aligning graph to basic UCKG schema.")
    uckg_aligned_graph = align_graph_to_uckg(graph)
    logger.info(
        f"UCKG alignment complete. "
        f"Aligned nodes: {uckg_aligned_graph['summary']['node_count']}, "
        f"aligned edges: {uckg_aligned_graph['summary']['edge_count']}"
    )

    logger.info("Initializing placeholder consolidated dataset.")
    consolidated = {
        "project": "SAGE-CH",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "component": "collector",
        "status": "initialized",
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
        "uckg_alignment_status": "basic_alignment_complete",
        "uckg_aligned_graph": uckg_aligned_graph
    }

    logger.info("Writing placeholder consolidated dataset.")
    output_path = generate_output_path()
    write_json(output_path, consolidated)

    logger.info("Collector execution complete.")


if __name__ == "__main__":
    main()