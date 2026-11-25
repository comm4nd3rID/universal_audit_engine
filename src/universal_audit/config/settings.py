
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class EngineSettings:
    output_dir: Path = Path("results")
    connect_timeout: int = 15
    command_timeout: int = 45
    max_retries: int = 2
    max_audit_bytes: int = 8 * 1024 * 1024
    max_evidence_chars: int = 2_000_000
    require_host_key_verification: bool = True
    allow_remediation: bool = False
