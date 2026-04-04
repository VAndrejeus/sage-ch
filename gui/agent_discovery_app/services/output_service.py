from pathlib import Path
import platform


SERVICE_DIR = Path(__file__).resolve().parent
APP_DIR = SERVICE_DIR.parent
PROJECT_ROOT = APP_DIR.parent.parent

IS_WINDOWS = platform.system().lower() == "windows"
IS_LINUX = platform.system().lower() == "linux"

OUTPUT_DIRS = [
    PROJECT_ROOT / "outputs",
    PROJECT_ROOT / "reports",
    PROJECT_ROOT / "logs",
    PROJECT_ROOT / "collector" / "output",
]

if IS_WINDOWS:
    OUTPUT_DIRS.append(PROJECT_ROOT / "agents" / "windows" / "output")

if IS_LINUX:
    OUTPUT_DIRS.append(PROJECT_ROOT / "agents" / "linux" / "output")

SKIP_PREFIXES = [".", "~"]
ALLOWED_SUFFIXES = {".json", ".log", ".txt", ".csv"}


def list_outputs():
    results = []

    for folder in OUTPUT_DIRS:
        if not folder.exists() or not folder.is_dir():
            continue

        for path in folder.iterdir():
            if not path.is_file():
                continue

            if _should_skip(path):
                continue

            stat = path.stat()

            results.append({
                "name": path.name,
                "path": str(path),
                "folder": _friendly_folder_name(folder),
                "size": stat.st_size,
                "modified_at": stat.st_mtime,
            })

    results.sort(key=lambda item: item["modified_at"], reverse=True)
    return results


def _should_skip(path: Path) -> bool:
    name = path.name

    if any(name.startswith(prefix) for prefix in SKIP_PREFIXES):
        return True

    if path.suffix and path.suffix.lower() not in ALLOWED_SUFFIXES:
        return True

    return False


def _friendly_folder_name(folder: Path) -> str:
    try:
        relative = folder.relative_to(PROJECT_ROOT)
        return str(relative)
    except ValueError:
        return folder.name