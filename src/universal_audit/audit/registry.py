
from __future__ import annotations

from universal_audit.audit.parser import AuditParser


class ParserRegistry:
    """Registry for syntax-family parser implementations."""

    def __init__(self):
        self._parsers = {}

    def register(self, syntax_family: str, parser_factory) -> None:
        key = syntax_family.strip().lower()
        if not key:
            raise ValueError("syntax_family is required")
        if key in self._parsers:
            raise ValueError(f"Parser already registered for {key}")
        self._parsers[key] = parser_factory

    def resolve(self, syntax_family: str):
        key = syntax_family.strip().lower()
        return self._parsers.get(key) or self._parsers.get("*")

    def families(self):
        return sorted(self._parsers)


def build_default_parser_registry() -> ParserRegistry:
    registry = ParserRegistry()
    # One tolerant parser handles the common Tenable pseudo-XML envelope;
    # normalization remains syntax-family specific.
    registry.register("*", AuditParser)
    return registry
