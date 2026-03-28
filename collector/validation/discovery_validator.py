def validate_discovery_file(data: dict) -> dict:
    errors = []

    if not isinstance(data, dict):
        return {
            "ok": False,
            "errors": ["Discovery file root must be a JSON object."]
        }

    scan_metadata = data.get("scan_metadata")
    scanned_networks = data.get("scanned_networks")
    discovered_hosts = data.get("discovered_hosts")

    if "scan_metadata" not in data:
        errors.append("Missing required top-level field: scan_metadata")
    elif not isinstance(scan_metadata, dict):
        errors.append("Field 'scan_metadata' must be an object.")

    if "scanned_networks" not in data:
        errors.append("Missing required top-level field: scanned_networks")
    elif not isinstance(scanned_networks, list):
        errors.append("Field 'scanned_networks' must be a list.")

    if "discovered_hosts" not in data:
        errors.append("Missing required top-level field: discovered_hosts")
    elif not isinstance(discovered_hosts, list):
        errors.append("Field 'discovered_hosts' must be a list.")

    return {
        "ok": len(errors) == 0,
        "errors": errors
    }