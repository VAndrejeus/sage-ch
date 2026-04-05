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


def _parse_users():
    output = _run(["net", "user"])
    users = []

    capture = False

    for line in output.splitlines():
        stripped = line.strip()

        if "----" in stripped:
            capture = not capture
            continue

        if not capture:
            continue

        if not stripped:
            continue

        if "The command completed successfully" in stripped:
            break

        users.extend(stripped.split())

    return users


def _parse_user_details(username):
    output = _run(["net", "user", username])

    data = {
        "username": username,
        "enabled": True,
        "password_never_expires": False,
        "is_admin": False
    }

    for line in output.splitlines():
        if "Account active" in line:
            data["enabled"] = "Yes" in line

        elif "Password expires" in line:
            data["password_never_expires"] = "Never" in line

        elif "Local Group Memberships" in line:
            if "Administrators" in line:
                data["is_admin"] = True

    return data


def collect():
    users = _parse_users()

    details = []
    for user in users:
        try:
            details.append(_parse_user_details(user))
        except Exception:
            continue

    return {
        "total_accounts": len(details),
        "accounts": details
    }