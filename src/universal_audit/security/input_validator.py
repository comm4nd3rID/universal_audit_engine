
from __future__ import annotations

import ipaddress
from pathlib import Path


class InputValidator:
    def validate_target_ipv4(self, value: str) -> str:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"Invalid target IP address: {value}") from exc
        if parsed.version != 4:
            raise ValueError("Only IPv4 targets are supported in this MVP")
        return str(parsed)

    def validate_audit_file(self, value: str, max_bytes: int = 8 * 1024 * 1024) -> Path:
        path = Path(value).expanduser()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Audit file does not exist or is not a regular file: {path}")
        size = path.stat().st_size
        if size <= 0:
            raise ValueError("Audit file is empty")
        if size > max_bytes:
            raise ValueError(f"Audit file exceeds size limit ({max_bytes} bytes)")
        return path.resolve()
