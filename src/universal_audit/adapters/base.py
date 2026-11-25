
from __future__ import annotations

import re
from typing import Protocol, runtime_checkable

from universal_audit.adapters.ssh_transport import (
    CommandResult, SSHTransport, SSHCommandFailure
)
from universal_audit.core.models import DeviceInfo
from universal_audit.security.command_policy import CommandPolicy


class UnsupportedOperation(RuntimeError):
    pass


class AdapterOperationError(RuntimeError):
    pass


@runtime_checkable
class PlatformAdapter(Protocol):
    platform_id: str
    vendor: str

    def identify(self, ip_address: str) -> DeviceInfo | None: ...
    def execute_readonly(self, command: str, timeout: int = 30) -> CommandResult: ...
    def read_file(self, path: str, timeout: int = 30) -> CommandResult: ...
    def get_config(self, timeout: int = 60) -> CommandResult: ...
    def close(self) -> None: ...


class BaseSSHAdapter:
    platform_id = "unknown"
    vendor = "Unknown"

    def __init__(self, transport: SSHTransport, policy: CommandPolicy | None = None):
        self.transport = transport
        self.policy = policy or CommandPolicy()
        self._config_cache: CommandResult | None = None
        self._hostname: str | None = None
        self._version: str | None = None

    def execute_readonly(self, command: str, timeout: int = 30) -> CommandResult:
        decision = self.policy.authorize(self.platform_id, command)
        if not decision.allowed or not decision.command_to_execute:
            raise UnsupportedOperation(decision.reason or "Command rejected by read-only policy")
        result = self.transport.execute(decision.command_to_execute, timeout=timeout)
        if decision.local_filter:
            result.stdout = self._apply_local_filter(result.stdout, decision.local_filter)
            result.command = command
        output = result.stdout.lower()
        permission_markers = (
            r"(?im)^\s*(?:%\s*)?permission denied\b",
            r"(?im)^\s*(?:%\s*)?authorization failed\b",
            r"(?im)^\s*command authorization failed\b",
            r"(?im)^\s*not authorized\b",
            r"(?im)^\s*insufficient privilege\b",
            r"(?im)^\s*access denied\b",
        )
        command_error_markers = (
            r"(?im)^\s*%\s*invalid input detected",
            r"(?im)^\s*command fail\. return code",
            r"(?im)^\s*command parse error",
            r"(?im)^\s*unknown action",
            r"(?im)^\s*(?:sh: )?command not found",
        )
        if any(re.search(marker, output) for marker in permission_markers):
            raise PermissionError("Device rejected the read-only command due to insufficient privilege")
        if any(re.search(marker, output) for marker in command_error_markers):
            raise SSHCommandFailure("Device rejected the read-only command")
        return result

    @staticmethod
    def _apply_local_filter(output: str, spec: dict) -> str:
        pattern = str(spec["pattern"])
        ignore_case = bool(spec.get("ignore_case"))
        invert = bool(spec.get("invert"))
        flags = re.I if ignore_case else 0
        try:
            compiled = re.compile(pattern, flags)
        except re.error as exc:
            raise UnsupportedOperation(f"Unsafe local filter pattern: {exc}") from exc
        lines = output.splitlines()
        selected = [line for line in lines if bool(compiled.search(line)) != invert]
        return "\n".join(selected)

    def read_file(self, path: str, timeout: int = 30) -> CommandResult:
        decision = self.policy.authorize_file_read(self.platform_id, path)
        if not decision.allowed:
            raise UnsupportedOperation(decision.reason or "File read rejected by policy")
        return self.transport.read_file(path, timeout=timeout)

    def get_config(self, timeout: int = 60) -> CommandResult:
        raise UnsupportedOperation(f"{self.platform_id} does not expose a generic configuration operation")

    def identify(self, ip_address: str) -> DeviceInfo | None:
        raise NotImplementedError

    def close(self) -> None:
        self.transport.close()
