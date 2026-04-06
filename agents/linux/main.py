from datetime import datetime, timezone

from agents.common.utils.audit_logger import AuditLogger
from agents.common.utils.json_writer import write_json
from agents.linux.platform_detect import detect_platform
from agents.linux.collectors.host_info import collect as collect_host_info
from agents.linux.collectors.software_inventory import collect as collect_software_inventory
from agents.linux.collectors.update_checker import collect as collect_update_status
from agents.linux.collectors.security_config import collect as collect_security_config
from agents.linux.collectors.account_info import collect as collect_account_info
from agents.linux.collectors.audit_policy import collect as collect_audit_policy
from agents.linux.collectors.backup_info import collect as collect_backup_info


def generate_output_path() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    return f"agents/linux/output/endpoint_report_{timestamp}.json"


LOG_PATH = "agents/linux/output/agent_audit.log"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> None:
    logger = AuditLogger(LOG_PATH)
    logger.info("SAGE-CH Linux agent started.")

    logger.info("Detecting Linux platform.")
    platform_info = detect_platform()

    logger.info(f"Detected distro: {platform_info.get('distro_id', 'unknown')}")
    logger.info(f"Package manager: {platform_info.get('pkg_manager', 'unknown')}")

    logger.info("Collecting Linux host information.")
    host_info = collect_host_info()

    logger.info("Collecting Linux software inventory.")
    software_inventory = collect_software_inventory(platform_info)

    logger.info("Collecting Linux update status.")
    update_status = collect_update_status(platform_info)

    logger.info("Collecting Linux security configuration.")
    security_config = collect_security_config()

    logger.info("Collecting Linux account information.")
    account_info = collect_account_info()

    logger.info("Collecting Linux audit policy information.")
    audit_policy = collect_audit_policy()

    logger.info("Collecting Linux backup information.")
    backup_info = collect_backup_info()

    report = {
        "project": "SAGE-CH",
        "timestamp_utc": utc_now(),
        "agent": {
            "os": "linux",
            "mode": "read-only",
        },
        "host_info": host_info,
        "software_inventory": software_inventory,
        "update_status": update_status,
        "security_config": security_config,
        "account_info": account_info,
        "audit_policy": audit_policy,
        "backup_info": backup_info,
    }

    logger.info("Writing JSON report.")
    output_path = generate_output_path()
    write_json(output_path, report)

    logger.info("Linux agent execution complete.")


if __name__ == "__main__":
    main()