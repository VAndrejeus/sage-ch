import subprocess
import re


def _run(cmd):
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=20,
        encoding="utf-8",
        errors="ignore"
    )
    return result.stdout


def collect():
    output = _run(["auditpol", "/get", "/category:*"])

    audit_settings = []

    for line in output.splitlines():
        if "Success" in line or "Failure" in line:
            parts = re.split(r"\s{2,}", line.strip())
            if len(parts) >= 2:
                audit_settings.append({
                    "category": parts[0],
                    "setting": parts[1]
                })

    return {
        "total_settings": len(audit_settings),
        "settings": audit_settings
    }