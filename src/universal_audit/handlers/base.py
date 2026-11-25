
from __future__ import annotations

from typing import Protocol

from universal_audit.core.models import CheckDefinition, Evidence
from universal_audit.adapters.base import PlatformAdapter


class CheckHandler(Protocol):
    handler_id: str
    supported_check_types: set[str]

    def can_handle(self, check: CheckDefinition, adapter: PlatformAdapter) -> bool: ...
    def collect(self, check: CheckDefinition, adapter: PlatformAdapter, context: dict) -> Evidence: ...


class BaseHandler:
    handler_id = "base"
    supported_check_types: set[str] = set()

    def can_handle(self, check: CheckDefinition, adapter: PlatformAdapter) -> bool:
        return check.canonical_check_type in self.supported_check_types and check.platform == adapter.platform_id

    def evidence(self, source: str, command: str | None, output: str,
                 exit_code: int | None = None, stderr: str | None = None,
                 truncated: bool = False) -> Evidence:
        return Evidence(
            source=source,
            command_or_query=command,
            raw_output=output,
            exit_code=exit_code,
            stderr=stderr,
            truncated=truncated,
        )
