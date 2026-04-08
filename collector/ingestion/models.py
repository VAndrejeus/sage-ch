from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class StagedFile:
    original_name: str
    claimed_path: Path
    sha256: str
    size_bytes: int
    host_identifier: Optional[str] = None
    report_timestamp: Optional[str] = None
    report_id: Optional[str] = None


@dataclass
class StagedBatch:
    batch_id: str
    batch_dir: Path
    manifest_path: Path
    files: List[StagedFile] = field(default_factory=list)


@dataclass
class BatchProcessResult:
    batch_id: str
    succeeded: List[StagedFile] = field(default_factory=list)
    failed: List[tuple[StagedFile, str]] = field(default_factory=list)

    @property
    def success_count(self) -> int:
        return len(self.succeeded)

    @property
    def failure_count(self) -> int:
        return len(self.failed)