from datetime import datetime, timezone

from agents.common.utils.audit_logger import AuditLogger
from agents.common.utils.json_writer import write_json

from collector.ingestion.report_loader import load_reports

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

    logger.info("Initializing placeholder consolidated dataset.")
    consolidated = {
        "project": "SAGE-CH",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "component": "collector",
        "status": "initialized",
        "loaded_reports": loaded_reports,
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