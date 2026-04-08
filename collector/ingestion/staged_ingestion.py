from __future__ import annotations

import hashlib
import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, List, Optional

from collector.ingestion.models import BatchProcessResult, StagedBatch, StagedFile


class StagedIngestionService:
    def __init__(
        self,
        collector_root: Path,
        max_batch_size: int = 25,
        accepted_suffixes: Optional[Iterable[str]] = None,
    ) -> None:
        self.collector_root = collector_root
        self.input_root = collector_root / "input"
        self.incoming_dir = self.input_root / "incoming"
        self.processing_dir = self.input_root / "processing"
        self.processed_dir = self.input_root / "processed"
        self.failed_dir = self.input_root / "failed"
        self.manifests_dir = collector_root / "manifests"
        self.max_batch_size = max_batch_size
        self.accepted_suffixes = tuple(accepted_suffixes or [".json"])

        self._ensure_directories()

    def _ensure_directories(self) -> None:
        for path in [
            self.input_root,
            self.incoming_dir,
            self.processing_dir,
            self.processed_dir,
            self.failed_dir,
            self.manifests_dir,
        ]:
            path.mkdir(parents=True, exist_ok=True)

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    def _build_batch_id(self) -> str:
        return f"batch_{self._utc_now()}_{uuid.uuid4().hex[:8]}"

    def _sha256(self, file_path: Path) -> str:
        digest = hashlib.sha256()

        with file_path.open("rb") as file_handle:
            for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
                digest.update(chunk)

        return digest.hexdigest()

    def _extract_metadata(self, report_path: Path) -> dict:
        try:
            with report_path.open("r", encoding="utf-8") as file_handle:
                data = json.load(file_handle)

            host_identifier = None
            report_timestamp = None
            report_id = None

            if isinstance(data, dict):
                report_id = data.get("report_id")

                host_info = data.get("host_info", {})
                if isinstance(host_info, dict):
                    host_identifier = (
                        host_info.get("hostname")
                        or host_info.get("host_name")
                        or host_info.get("device_name")
                    )

                metadata = data.get("metadata", {})
                if isinstance(metadata, dict):
                    report_timestamp = (
                        metadata.get("collected_at")
                        or metadata.get("generated_at")
                        or metadata.get("timestamp")
                    )

                if not report_timestamp:
                    report_timestamp = data.get("timestamp_utc") or data.get("generated_at")

            return {
                "host_identifier": host_identifier,
                "report_timestamp": report_timestamp,
                "report_id": report_id,
            }
        except Exception:
            return {
                "host_identifier": None,
                "report_timestamp": None,
                "report_id": None,
            }

    def discover_incoming_files(self) -> List[Path]:
        files = []

        for path in sorted(self.incoming_dir.iterdir()):
            if path.is_file() and path.suffix.lower() in self.accepted_suffixes:
                files.append(path)

        return files[:self.max_batch_size]

    def claim_batch(self) -> Optional[StagedBatch]:
        incoming_files = self.discover_incoming_files()

        if not incoming_files:
            return None

        batch_id = self._build_batch_id()
        batch_dir = self.processing_dir / batch_id
        batch_dir.mkdir(parents=True, exist_ok=True)

        manifest_path = self.manifests_dir / f"{batch_id}.json"
        staged_files: List[StagedFile] = []

        for source_path in incoming_files:
            destination_path = batch_dir / source_path.name

            try:
                source_path.replace(destination_path)
            except FileNotFoundError:
                continue

            file_hash = self._sha256(destination_path)
            size_bytes = destination_path.stat().st_size
            metadata = self._extract_metadata(destination_path)

            staged_files.append(
                StagedFile(
                    original_name=source_path.name,
                    claimed_path=destination_path,
                    sha256=file_hash,
                    size_bytes=size_bytes,
                    host_identifier=metadata["host_identifier"],
                    report_timestamp=metadata["report_timestamp"],
                    report_id=metadata["report_id"],
                )
            )

        if not staged_files:
            shutil.rmtree(batch_dir, ignore_errors=True)
            return None

        batch = StagedBatch(
            batch_id=batch_id,
            batch_dir=batch_dir,
            manifest_path=manifest_path,
            files=staged_files,
        )

        self.write_manifest(batch)
        return batch

    def write_manifest(self, batch: StagedBatch) -> None:
        payload = {
            "batch_id": batch.batch_id,
            "created_at_utc": self._utc_now(),
            "batch_dir": str(batch.batch_dir),
            "files": [
                {
                    "original_name": file.original_name,
                    "claimed_path": str(file.claimed_path),
                    "sha256": file.sha256,
                    "size_bytes": file.size_bytes,
                    "host_identifier": file.host_identifier,
                    "report_timestamp": file.report_timestamp,
                    "report_id": file.report_id,
                }
                for file in batch.files
            ],
        }

        with batch.manifest_path.open("w", encoding="utf-8") as file_handle:
            json.dump(payload, file_handle, indent=2)

    def process_batch(
        self,
        batch: StagedBatch,
        processor: Callable[[List[Path]], dict],
    ) -> BatchProcessResult:
        result = BatchProcessResult(batch_id=batch.batch_id)

        try:
            processor_result = processor([file.claimed_path for file in batch.files])
        except Exception as exc:
            for file in batch.files:
                result.failed.append((file, f"batch_processor_exception: {exc}"))
            self._finalize_batch(batch, result)
            return result

        success_paths = set()
        failed_map = {}

        if isinstance(processor_result, dict):
            for item in processor_result.get("success", []):
                success_paths.add(str(Path(item)))

            for item in processor_result.get("failed", []):
                if isinstance(item, dict) and "path" in item:
                    failed_map[str(Path(item["path"]))] = item.get("reason", "processing_failed")

        for file in batch.files:
            path_str = str(file.claimed_path)

            if path_str in failed_map:
                result.failed.append((file, failed_map[path_str]))
            elif success_paths:
                if path_str in success_paths:
                    result.succeeded.append(file)
                else:
                    result.failed.append((file, "not_marked_success"))
            else:
                result.succeeded.append(file)

        self._finalize_batch(batch, result)
        return result

    def _finalize_batch(self, batch: StagedBatch, result: BatchProcessResult) -> None:
        processed_batch_dir = self.processed_dir / batch.batch_id
        failed_batch_dir = self.failed_dir / batch.batch_id

        processed_batch_dir.mkdir(parents=True, exist_ok=True)
        failed_batch_dir.mkdir(parents=True, exist_ok=True)

        for file in result.succeeded:
            destination_path = processed_batch_dir / file.original_name
            if file.claimed_path.exists():
                file.claimed_path.replace(destination_path)

        for file, _reason in result.failed:
            destination_path = failed_batch_dir / file.original_name
            if file.claimed_path.exists():
                file.claimed_path.replace(destination_path)

        self._write_result_manifest(batch, result)

        try:
            batch.batch_dir.rmdir()
        except OSError:
            pass

    def _write_result_manifest(self, batch: StagedBatch, result: BatchProcessResult) -> None:
        payload = {
            "batch_id": batch.batch_id,
            "completed_at_utc": self._utc_now(),
            "success_count": result.success_count,
            "failure_count": result.failure_count,
            "succeeded": [
                {
                    "original_name": file.original_name,
                    "sha256": file.sha256,
                    "host_identifier": file.host_identifier,
                    "report_timestamp": file.report_timestamp,
                    "report_id": file.report_id,
                }
                for file in result.succeeded
            ],
            "failed": [
                {
                    "original_name": file.original_name,
                    "sha256": file.sha256,
                    "host_identifier": file.host_identifier,
                    "report_timestamp": file.report_timestamp,
                    "report_id": file.report_id,
                    "reason": reason,
                }
                for file, reason in result.failed
            ],
        }

        result_manifest_path = self.manifests_dir / f"{batch.batch_id}_result.json"

        with result_manifest_path.open("w", encoding="utf-8") as file_handle:
            json.dump(payload, file_handle, indent=2)