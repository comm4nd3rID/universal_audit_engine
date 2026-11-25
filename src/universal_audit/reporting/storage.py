
from __future__ import annotations

import os
import re
import tempfile
from datetime import datetime
from pathlib import Path

from universal_audit.reporting.report_builder import ReportBuilder
from universal_audit.reporting.schema_validator import ReportSchemaValidator


def _safe_component(value: str | None, fallback: str) -> str:
    value = (value or fallback).strip()
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    value = value.strip("._-")
    return value[:80] or fallback


class ResultStorage:
    def __init__(self, base_dir: str | Path = "results"):
        self.base_dir = Path(base_dir).expanduser().resolve()
        self.run_dir: Path | None = None
        self.builder = ReportBuilder()
        self.schema_validator = ReportSchemaValidator()

    def create_run_directory(self, run) -> Path:
        device_id = _safe_component(run.target.hostname or run.target.ip_address, "unknown-device")
        version = _safe_component(run.target.software_version, "unknown-version")
        timestamp = datetime.fromisoformat(run.started_at).strftime("%Y%m%dT%H%M%S")
        run_name = f"{timestamp}_{run.assessment_id[:8]}"
        device_dir = self.base_dir / device_id
        parent = device_dir / version
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        for directory in (self.base_dir, device_dir, parent):
            try:
                os.chmod(directory, 0o700)
            except OSError:
                pass
        self.run_dir = parent / run_name
        self.run_dir.mkdir(mode=0o700, exist_ok=False)
        return self.run_dir

    def checkpoint(self, run) -> Path:
        if self.run_dir is None:
            self.create_run_directory(run)
        report = self.builder.build(run)
        path = self.run_dir / "checkpoint.json"
        self._atomic_write(path, self.builder.to_json(report), replace=True)
        return path

    def save(self, run) -> dict[str, Path]:
        if self.run_dir is None:
            self.create_run_directory(run)
        report = self.builder.build(run)
        self._validate(report)
        report_path = self.run_dir / "report.json"
        log_path = self.run_dir / "execution.log"
        self._atomic_write(report_path, self.builder.to_json(report), replace=False)
        self._atomic_write(log_path, "\n".join(run.execution_log) + "\n", replace=False)
        return {"directory": self.run_dir, "report": report_path, "log": log_path}

    def _validate(self, report: dict) -> None:
        self.schema_validator.validate(report)

    @staticmethod
    def _atomic_write(path: Path, content: str, replace: bool) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temp_name = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
        temp_path = Path(temp_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            if replace:
                os.replace(temp_path, path)
            else:
                # Hard-link publication is atomic and refuses to overwrite an existing report.
                os.link(temp_path, path)
                temp_path.unlink()
            try:
                dir_fd = os.open(path.parent, os.O_DIRECTORY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except (AttributeError, OSError):
                pass
        finally:
            if temp_path.exists():
                temp_path.unlink()
