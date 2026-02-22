import os
from datetime import datetime, timezone


class AuditLogger:
    """Simple append-only audit logger."""

    def __init__(self, log_path: str):
        self.log_path = log_path  # <-- this is what your file is missing
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

    def _write(self, level: str, message: str) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        line = f"{ts} [{level}] {message}\n"
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line)

    def info(self, message: str) -> None:
        self._write("INFO", message)

    def error(self, message: str) -> None:
        self._write("ERROR", message)