from datetime import datetime, timezone

from agents.common.utils.audit_logger import AuditLogger
from agents.common.utils.json_writer import write_json

from agents.windows.collectors.host_info import collect as collect_host
from agents.windows.collectors.software_inventory import collect as collect_software
from agents.windows.collectors.update_checker import collect as collect_updates

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def main():
    output_dir = "agents/windows/output"
    report_path = f"{output_dir}/endpoint_report.json"
    log_path = f"{output_dir}/agent_audit.log"

    logger = AuditLogger(log_path)
    logger.info("SAGE-CH Windows agent started.")

    logger.info("Collection host info.")
    host = collect_host()

    logger.info("Collecting software inventory.")
    software = collect_software()

    logger.info("Collecting update indicators.")
    updates = collect_updates()

    report = {
        "project": "SAGE-CH",
        "timestamp_utc": utc_now(),
        "agent": {
            "os": "windows",
            "mode": "read-only"
        },
        "host_info": host,
        "software_inventory": software,
        "update_status": updates,
    }

    write_json(report_path, report)
    logger.info("Report successfully written.")
    logger.info("SAGE-CH Windows agent finished.")

if __name__ == "__main__":
    main()