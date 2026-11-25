
from __future__ import annotations

import re
from dataclasses import dataclass


OPEN_TAG_RE = re.compile(r"^\s*<([A-Za-z_][A-Za-z0-9_-]*)(.*?)>\s*$")
CLOSE_TAG_RE = re.compile(r"^\s*</([A-Za-z_][A-Za-z0-9_-]*)>\s*$")
FIELD_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*:\s*(.*?)\s*$")


@dataclass(frozen=True)
class LineToken:
    kind: str
    tag: str | None = None
    attrs_text: str | None = None
    field: str | None = None
    value: str | None = None


class AuditLexer:
    """Line-oriented lexer for structural pseudo-XML and key:value fields."""

    def tokenize(self, line: str) -> LineToken:
        if not line.strip():
            return LineToken("BLANK")
        if line.lstrip().startswith("#"):
            return LineToken("COMMENT")
        close = CLOSE_TAG_RE.match(line)
        if close:
            return LineToken("CLOSE_TAG", tag=close.group(1).lower())
        opening = OPEN_TAG_RE.match(line)
        if opening:
            return LineToken("OPEN_TAG", tag=opening.group(1).lower(), attrs_text=opening.group(2))
        field = FIELD_RE.match(line)
        if field:
            return LineToken("FIELD", field=field.group(1).lower(), value=field.group(2))
        return LineToken("RAW")
