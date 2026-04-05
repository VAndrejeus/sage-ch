from datetime import datetime, timezone

from agents.common.utils.audit_logger import AuditLogger
from agents.common.utils.json_writer import write_json

from agents.windows.collectors.host_info import collect as collect_host
from agents.windows.collectors.software_inventory import collect as collect_software
from agents.windows.collectors.update_checker import collect as collect_updates
from agents.windows.collectors.security_config import collect_security_config
from agents.windows.collectors.account_info import collect as collect_accounts
from agents.windows.collectors.audit_policy import collect as collect_audit
from agents.windows.collectors.backup_info import collect as collect_backup

def generate_output_path() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    return f"agents/windows/output/endpoint_report_{timestamp}.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main():
    output_dir = "agents/windows/output"
    report_path = generate_output_path()
    log_path = f"{output_dir}/agent_audit.log"

    logger = AuditLogger(log_path)
    logger.info("SAGE-CH Windows agent started.")

    logger.info("Collecting host info.")
    host = collect_host()

    logger.info("Collecting software inventory.")
    software = collect_software()

    logger.info("Collecting update indicators.")
    updates = collect_updates()

    logger.info("Collecting security configuration.")
    security_config = collect_security_config()

    logger.info("Collecting account information.")
    accounts = collect_accounts()

    logger.info("Collecting audit policy.")
    audit_policy = collect_audit()

    logger.info("Collecting backup information.")
    backup = collect_backup()

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
        "security_config": security_config,
        "account_info": accounts,
        "audit_policy": audit_policy,
        "backup_info": backup,
    }

    write_json(report_path, report)
    logger.info("Report successfully written.")
    logger.info("SAGE-CH Windows agent finished.")


if __name__ == "__main__":
    main()