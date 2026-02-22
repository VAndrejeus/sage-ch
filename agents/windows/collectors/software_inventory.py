import winreg
from typing import Dict, List


def _read_uninstall_key(root, path) -> List[Dict]:
    software_list = []

    try:
        key = winreg.OpenKey(root, path)
    except FileNotFoundError:
        return software_list

    i = 0
    while True:
        try:
            subkey_name = winreg.EnumKey(key, i)
            subkey_path = f"{path}\\{subkey_name}"
            subkey = winreg.OpenKey(root, subkey_path)

            try:
                name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                software_list.append({
                    "name": name,
                    "version": version
                })
            except FileNotFoundError:
                pass

            i += 1

        except OSError:
            break

    return software_list


def collect() -> Dict:
    """
    Registry-based installed software inventory.
    Read-only. Works on modern Windows builds.
    """

    software = []

    # 64-bit installed programs
    software += _read_uninstall_key(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    # 32-bit installed programs
    software += _read_uninstall_key(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    return {
        "method": "Windows Registry Uninstall Keys",
        "total_detected": len(software),
        "software": software
    }