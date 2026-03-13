from datetime import datetime, timezone

from agents.common.utils.audit_logger import AuditLogger
from agents.common.utils.json_writer import write_json

from collector.ingestion.report_loader import load_reports
from collector.validation.schema_validator import validate_report
def generate_output_path() -> str:
  
    #generates consolidated_dataset_YYYYMMDD_HHMM.json

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    return f"collector/output/consolidated_dataset_{timestamp}.json"

INPUT_DIR = "collector/input"
LOG_PATH = "collector/output/collector_audit.log"


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
        "hosts": [],
        "graph": {
            "nodes": [],
            "edges": []
        }
    }

    logger.info("Writing placeholder consolidated dataset.")
    output_path = generate_output_path()
    write_json(output_path, consolidated)

    logger.info("Collector execution complete.")


if __name__ == "__main__":
    main()