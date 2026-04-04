import json
from pathlib import Path


SERVICE_DIR = Path(__file__).resolve().parent
APP_DIR = SERVICE_DIR.parent
PROJECT_ROOT = APP_DIR.parent.parent

CONFIG_DIR = PROJECT_ROOT / "config"
SCOPE_FILE = CONFIG_DIR / "discovery_scope.json"


DEFAULT_SCOPE = {
    "authorized_networks": ["*"],
    "authorized_interfaces": ["*"],
    "max_hosts_per_subnet": 1024,
    "private_only": True
}


def ensure_scope_file():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    if not SCOPE_FILE.exists():
        save_scope(DEFAULT_SCOPE)


def load_scope():
    ensure_scope_file()

    with open(SCOPE_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    return {
        "authorized_networks": data.get("authorized_networks", ["*"]),
        "authorized_interfaces": data.get("authorized_interfaces", ["*"]),
        "max_hosts_per_subnet": int(data.get("max_hosts_per_subnet", 1024)),
        "private_only": bool(data.get("private_only", True)),
    }


def save_scope(scope_data):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    cleaned_scope = {
        "authorized_networks": _normalize_list(scope_data.get("authorized_networks", ["*"])),
        "authorized_interfaces": _normalize_list(scope_data.get("authorized_interfaces", ["*"])),
        "max_hosts_per_subnet": _normalize_max_hosts(scope_data.get("max_hosts_per_subnet", 1024)),
        "private_only": bool(scope_data.get("private_only", True)),
    }

    with open(SCOPE_FILE, "w", encoding="utf-8") as f:
        json.dump(cleaned_scope, f, indent=2)

    return cleaned_scope


def _normalize_list(value):
    if value is None:
        return ["*"]

    if isinstance(value, list):
        cleaned = [str(item).strip() for item in value if str(item).strip()]
        return cleaned or ["*"]

    if isinstance(value, str):
        cleaned = [item.strip() for item in value.split(",") if item.strip()]
        return cleaned or ["*"]

    return ["*"]


def _normalize_max_hosts(value):
    try:
        number = int(value)
        return max(1, number)
    except (TypeError, ValueError):
        return 1024