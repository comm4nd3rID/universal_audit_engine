
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from universal_audit.core.models import AuditASTNode, AuditDocument
from universal_audit.audit.lexer import AuditLexer, OPEN_TAG_RE
from universal_audit.audit.metadata import MetadataExtractor


MAX_AUDIT_BYTES = 8 * 1024 * 1024
MAX_NODES = 20_000
MAX_DEPTH = 64


class AuditParseError(ValueError):
    def __init__(self, message: str, line: int | None = None, column: int = 1):
        self.line = line
        self.column = column
        suffix = f" (line {line}, column {column})" if line is not None else ""
        super().__init__(message + suffix)


def _unescaped_quote_index(value: str, start: int = 0) -> int:
    escaped = False
    for idx in range(start, len(value)):
        char = value[idx]
        if char == '"' and not escaped:
            return idx
        if char == "\\" and not escaped:
            escaped = True
        else:
            escaped = False
    return -1


def _decode_audit_string(value: str) -> str:
    # Tenable strings escape backslashes and quotes. Decode only those two
    # escape forms so regex tokens such as \\s remain intact.
    output = []
    index = 0
    while index < len(value):
        if value[index] == "\\" and index + 1 < len(value) and (value[index + 1] == "\\" or value[index + 1] == '"'):
            output.append(value[index + 1])
            index += 2
        else:
            output.append(value[index])
            index += 1
    return "".join(output)


def _parse_attrs(tag: str, rest: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for match in re.finditer(r'([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*"((?:\\.|[^"])*)"', rest):
        attrs[match.group(1).lower()] = _decode_audit_string(match.group(2))
    for match in re.finditer(r'([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*"((?:\\.|[^"])*)"', rest):
        attrs[match.group(1).lower()] = _decode_audit_string(match.group(2))
    if tag.lower() == "check_type" and not attrs:
        value = rest.strip().lstrip(":").strip().strip('"')
        if value:
            attrs["value"] = value
    return attrs


class AuditParser:
    """Tolerant parser for the Tenable-compatible pseudo-XML audit syntax.

    It deliberately does not execute or evaluate any source content.
    """

    def __init__(self, max_bytes: int = MAX_AUDIT_BYTES, max_nodes: int = MAX_NODES,
                 max_depth: int = MAX_DEPTH):
        self.max_bytes = max_bytes
        self.max_nodes = max_nodes
        self.max_depth = max_depth
        self.lines: list[str] = []
        self.index = 0
        self.node_count = 0
        self.lexer = AuditLexer()
        self.metadata_extractor = MetadataExtractor()

    def parse_file(self, path: str | Path) -> AuditDocument:
        file_path = Path(path)
        raw = file_path.read_bytes()
        if len(raw) > self.max_bytes:
            raise AuditParseError(f"Audit file exceeds size limit ({self.max_bytes} bytes)")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise AuditParseError("Audit file is not valid UTF-8") from exc
        return self.parse_text(text, source_path=str(file_path), file_hash=hashlib.sha256(raw).hexdigest())

    def parse_text(self, text: str, source_path: str = "<memory>",
                   file_hash: str | None = None) -> AuditDocument:
        encoded = text.encode("utf-8")
        if len(encoded) > self.max_bytes:
            raise AuditParseError(f"Audit text exceeds size limit ({self.max_bytes} bytes)")
        self.lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        self.index = 0
        self.node_count = 0

        metadata, variables, metadata_warnings = self._parse_metadata()
        body_start = None
        for i, line in enumerate(self.lines):
            if re.match(r'^\s*<check_type\s*:', line, re.I):
                body_start = i
                break
        if body_start is None:
            raise AuditParseError("Missing <check_type:\"...\"> root block")

        raw_header = self.lines[:body_start]
        self.index = body_start
        root = self._parse_element(0)
        if root.tag.lower() != "check_type":
            raise AuditParseError("Audit root must be check_type", body_start + 1)
        if self.index < len(self.lines):
            trailing = [x for x in self.lines[self.index:] if x.strip() and not x.lstrip().startswith("#")]
            if trailing:
                raise AuditParseError("Unexpected content after check_type block", self.index + 1)

        syntax_family = root.attrs.get("value") or root.attrs.get("type") or "UNKNOWN"
        if not metadata.get("display_name"):
            metadata["display_name"] = Path(source_path).name

        return AuditDocument(
            source_path=source_path,
            file_hash=file_hash or hashlib.sha256(encoded).hexdigest(),
            syntax_family=syntax_family,
            metadata=metadata,
            variables=variables,
            nodes=root.children,
            raw_header=raw_header,
            warnings=metadata_warnings,
        )

    def _parse_element(self, depth: int) -> AuditASTNode:
        if depth > self.max_depth:
            raise AuditParseError(f"Maximum nesting depth exceeded ({self.max_depth})", self.index + 1)
        if self.index >= len(self.lines):
            raise AuditParseError("Unexpected end of file")
        start = self.index
        opening = OPEN_TAG_RE.match(self.lines[self.index])
        if not opening:
            raise AuditParseError("Expected opening tag", self.index + 1)
        tag = opening.group(1).lower()
        attrs = _parse_attrs(tag, opening.group(2))
        column = len(self.lines[start]) - len(self.lines[start].lstrip()) + 1
        node = AuditASTNode(tag=tag, attrs=attrs, source_location={"line": start + 1, "column": column})
        self.node_count += 1
        if self.node_count > self.max_nodes:
            raise AuditParseError(f"Maximum AST node count exceeded ({self.max_nodes})", start + 1)
        self.index += 1

        while self.index < len(self.lines):
            line = self.lines[self.index]
            stripped = line.strip()
            token = self.lexer.tokenize(line)
            if token.kind == "CLOSE_TAG":
                close_tag = token.tag
                if close_tag != tag:
                    raise AuditParseError(
                        f"Mismatched closing tag </{close_tag}>; expected </{tag}>",
                        self.index + 1
                    )
                self.index += 1
                node.raw_text = "\n".join(self.lines[start:self.index])
                return node

            if not stripped or stripped.startswith("#"):
                node.raw_lines.append(line)
                self.index += 1
                continue

            if token.kind == "OPEN_TAG":
                child = self._parse_element(depth + 1)
                node.children.append(child)
                continue

            if token.kind == "FIELD":
                key = token.field
                value = self._parse_field_value(token.value, self.index + 1)
                existing = node.fields.get(key)
                if existing is None:
                    node.fields[key] = value
                elif isinstance(existing, list):
                    existing.append(value)
                else:
                    node.fields[key] = [existing, value]
                continue

            node.raw_lines.append(line)
            self.index += 1

        raise AuditParseError(f"Unclosed tag <{tag}>", start + 1)

    def _parse_field_value(self, initial: str, field_line: int) -> str:
        value = initial.rstrip()
        self.index += 1
        if not value.startswith('"'):
            return value.strip()

        # Quoted values may span multiple physical lines. Structural-looking
        # lines inside a quoted value (e.g. <banner-text>) are plain text.
        content_parts: list[str] = []
        first = value[1:]
        close_at = _unescaped_quote_index(first)
        if close_at >= 0:
            content_parts.append(first[:close_at])
            return _decode_audit_string("\n".join(content_parts))

        content_parts.append(first)
        while self.index < len(self.lines):
            line = self.lines[self.index]
            self.index += 1
            close_at = _unescaped_quote_index(line)
            if close_at >= 0:
                content_parts.append(line[:close_at])
                return _decode_audit_string("\n".join(content_parts))
            content_parts.append(line)
        raise AuditParseError("Unterminated quoted field value", field_line)


    def _parse_metadata(self):
        return self.metadata_extractor.parse(self.lines)

