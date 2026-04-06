import grp
import pwd
import shutil
import subprocess
from typing import Any, Dict, List, Set


def _run(cmd: List[str]) -> Dict[str, Any]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            encoding="utf-8",
            errors="ignore",
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode,
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
        }


def _command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def _get_admin_users() -> Set[str]:
    admin_users: Set[str] = set()

    for group_name in ("sudo", "wheel", "admin"):
        try:
            group = grp.getgrnam(group_name)
            admin_users.update(group.gr_mem)
        except KeyError:
            continue
        except Exception:
            continue

    try:
        for entry in pwd.getpwall():
            if entry.pw_uid == 0:
                admin_users.add(entry.pw_name)
    except Exception:
        pass

    return admin_users


def _infer_enabled(shell: str) -> bool:
    shell_value = (shell or "").strip().lower()
    disabled_shells = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "nologin", "false"}
    return shell_value not in disabled_shells


def _get_password_never_expires(username: str) -> Any:
    if not _command_exists("chage"):
        return None

    result = _run(["chage", "-l", username])
    if not result["success"] or not result["stdout"]:
        return None

    for line in result["stdout"].splitlines():
        lower = line.strip().lower()
        if lower.startswith("password expires"):
            return "never" in lower
    return None


def _get_groups_for_user(username: str, primary_gid: int) -> List[str]:
    group_names: Set[str] = set()

    try:
        group_names.add(grp.getgrgid(primary_gid).gr_name)
    except Exception:
        pass

    try:
        for group in grp.getgrall():
            if username in group.gr_mem:
                group_names.add(group.gr_name)
    except Exception:
        pass

    return sorted(group_names)


def collect() -> Dict[str, Any]:
    accounts: List[Dict[str, Any]] = []
    admin_users = _get_admin_users()

    try:
        passwd_entries = sorted(pwd.getpwall(), key=lambda x: x.pw_name.lower())
    except Exception as e:
        return {
            "total_accounts": 0,
            "accounts": [],
            "note": f"Failed to enumerate local accounts: {e}",
        }

    for entry in passwd_entries:
        username = entry.pw_name
        shell = entry.pw_shell or ""
        home_dir = entry.pw_dir or ""

        account = {
            "username": username,
            "uid": entry.pw_uid,
            "gid": entry.pw_gid,
            "home": home_dir,
            "shell": shell,
            "enabled": _infer_enabled(shell),
            "password_never_expires": _get_password_never_expires(username),
            "is_admin": username in admin_users,
            "groups": _get_groups_for_user(username, entry.pw_gid),
        }

        accounts.append(account)

    return {
        "total_accounts": len(accounts),
        "accounts": accounts,
    }