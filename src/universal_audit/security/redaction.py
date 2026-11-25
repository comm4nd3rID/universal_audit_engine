
from __future__ import annotations

import re

MAX_EVIDENCE_CHARS = 2_000_000

SECRET_LINE_PATTERNS = [
    re.compile(
        r'(?im)^(\s*(?:set\s+)?(?:password|passwd|auth-password|enc-password|secret|community|psksecret|token|private-key|access-key|api-key)\s+)(?:"[^"]*"|\'[^\']*\'|\S+)',
    ),
    re.compile(
        r'(?im)^(\s*(?:snmp-server\s+community)\s+)(?:\S+)',
    ),
    re.compile(
        r'(?im)^(\s*(?:username\s+\S+\s+secret)\s+)(?:\S+)',
    ),
]


def redact_text(text: str) -> tuple[str, list[str]]:
    redactions: list[str] = []
    if len(text) > MAX_EVIDENCE_CHARS:
        text = text[:MAX_EVIDENCE_CHARS]
        redactions.append("OUTPUT_TRUNCATED")
    for pattern in SECRET_LINE_PATTERNS:
        text, count = pattern.subn(r"\1[REDACTED]", text)
        if count:
            redactions.append(f"SECRET_LINES:{count}")
    return text, redactions


def safe_exception_message(exc: BaseException) -> str:
    message = str(exc)
    message = re.sub(r"(?i)(password|passwd|token|secret)\s*[=:]\s*\S+", r"\1=[REDACTED]", message)
    return message[:1000]
