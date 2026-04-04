import subprocess
import threading
import sys
from datetime import datetime
from pathlib import Path


# Paths

SERVICE_DIR = Path(__file__).resolve().parent
APP_DIR = SERVICE_DIR.parent
PROJECT_ROOT = APP_DIR.parent.parent

CONFIG_DIR = PROJECT_ROOT / "config"
AGENTS_DIR = PROJECT_ROOT / "agents"
COLLECTOR_DIR = PROJECT_ROOT / "collector"
TOOLS_DIR = PROJECT_ROOT / "tools"


# Shared state + lock

MAX_LOG_LINES = 1000

_state_lock = threading.Lock()

_app_state = {
    "job_type": None,
    "status": "idle",          # idle / running / completed / failed
    "logs": [],
    "output_path": None,
    "error_message": None,
    "started_at": None,
    "finished_at": None
}


# Public API

def get_job_status():
    with _state_lock:
        return {
            "job_type": _app_state["job_type"],
            "status": _app_state["status"],
            "running": _app_state["status"] == "running",
            "logs": list(_app_state["logs"]),
            "output_path": _app_state["output_path"],
            "error_message": _app_state["error_message"],
            "started_at": _app_state["started_at"],
            "finished_at": _app_state["finished_at"]
        }


def start_agent_job(agent_type, output_dir):
    command = _build_agent_command(agent_type, output_dir)
    return _start_job("agent", command, output_dir)


def start_discovery_job(output_dir):
    command = _build_discovery_command(output_dir)
    return _start_job("discovery", command, output_dir)


# Core job control

def _start_job(job_type, command, output_dir):
    with _state_lock:
        if _app_state["status"] == "running":
            return {"success": False, "error": "A job is already running"}

        _app_state["job_type"] = job_type
        _app_state["status"] = "running"
        _app_state["logs"] = []
        _app_state["output_path"] = None
        _app_state["error_message"] = None
        _app_state["started_at"] = _now()
        _app_state["finished_at"] = None

    thread = threading.Thread(
        target=_run_job,
        args=(job_type, command, output_dir),
        daemon=True
    )
    thread.start()

    return {"success": True}


def _run_job(job_type, command, output_dir):
    try:
        resolved_output_dir = _resolve_output_dir(output_dir)
        resolved_output_dir.mkdir(parents=True, exist_ok=True)

        _append_log(f"Starting {job_type} job")
        _append_log(f"Project root: {PROJECT_ROOT}")
        _append_log(f"Output dir: {resolved_output_dir}")
        _append_log(f"Command: {' '.join(command)}")

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(PROJECT_ROOT)
        )

        if process.stdout is not None:
            for line in process.stdout:
                _append_log(line.rstrip())

        process.wait()

        if process.returncode == 0:
            output_path = _detect_output(job_type, resolved_output_dir)
            _finalize_success(output_path)
        else:
            error_message = f"Process exited with code {process.returncode}"
            _append_log(f"ERROR: {error_message}")
            _finalize_failure(error_message)

    except Exception as e:
        _append_log(f"ERROR: {str(e)}")
        _finalize_failure(str(e))


# Helpers

def _append_log(line):
    with _state_lock:
        _app_state["logs"].append(line)

        if len(_app_state["logs"]) > MAX_LOG_LINES:
            _app_state["logs"] = _app_state["logs"][-MAX_LOG_LINES:]


def _finalize_success(output_path):
    with _state_lock:
        _app_state["status"] = "completed"
        _app_state["output_path"] = str(output_path) if output_path else None
        _app_state["finished_at"] = _now()


def _finalize_failure(error):
    with _state_lock:
        _app_state["status"] = "failed"
        _app_state["error_message"] = error
        _app_state["finished_at"] = _now()


def _now():
    return datetime.utcnow().isoformat()


def _resolve_output_dir(output_dir):
    output_path = Path(output_dir)

    if output_path.is_absolute():
        return output_path

    return PROJECT_ROOT / output_path


# Command builders
def _build_agent_command(agent_type, output_dir):
    if agent_type == "windows_agent":
        module_name = "agents.windows.main"
    elif agent_type == "linux_agent":
        module_name = "agents.linux.main"
    else:
        raise ValueError(f"Unknown agent type: {agent_type}")

    return [
        sys.executable,
        "-m",
        module_name,
    ]


def _build_discovery_command(output_dir):
    resolved_output_dir = _resolve_output_dir(output_dir)

    discovery_candidates = [
        TOOLS_DIR / "network_discovery.py",
        COLLECTOR_DIR / "network_discovery.py",
        COLLECTOR_DIR / "discovery.py",
    ]

    discovery_script = next((p for p in discovery_candidates if p.exists()), None)
    scope_file = CONFIG_DIR / "discovery_scope.json"

    if discovery_script is None:
        searched = "\n".join(str(p) for p in discovery_candidates)
        raise FileNotFoundError(
            f"No discovery script found. Searched:\n{searched}"
        )

    if not scope_file.exists():
        raise FileNotFoundError(f"Scope file not found: {scope_file}")

    return [
        sys.executable,
        str(discovery_script),
        "--scope",
        str(scope_file),
        "--output",
        str(resolved_output_dir)
    ]


# Output detection, simple v1

def _detect_output(job_type, output_dir):
    try:
        candidate_dirs = []

        if job_type == "agent":
            candidate_dirs.extend([
                AGENTS_DIR / "windows" / "output",
                AGENTS_DIR / "linux" / "output",
                output_dir,
            ])
        elif job_type == "discovery":
            candidate_dirs.extend([
                TOOLS_DIR / "output",
                COLLECTOR_DIR / "output",
                output_dir,
            ])
        else:
            candidate_dirs.append(output_dir)

        files = []

        for folder in candidate_dirs:
            if folder.exists() and folder.is_dir():
                for p in folder.iterdir():
                    if p.is_file() and not p.name.startswith("."):
                        files.append(p)

        if not files:
            return None

        latest = max(files, key=lambda p: p.stat().st_mtime)
        return latest

    except Exception:
        return None