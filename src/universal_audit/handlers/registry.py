
from __future__ import annotations

from universal_audit.handlers.cisco_config import CiscoBannerCheckHandler, CiscoConfigCheckHandler
from universal_audit.handlers.fortigate_context_regex import (
    FortiGateBannerHandler, FortiGateCommandHandler, FortiGateContextRegexHandler
)
from universal_audit.handlers.unix_command import UnixCommandHandler
from universal_audit.handlers.unix_file_content import UnixFileContentHandler


class HandlerRegistry:
    def __init__(self):
        self._handlers = []

    def register(self, handler) -> None:
        if any(existing.handler_id == handler.handler_id for existing in self._handlers):
            raise ValueError(f"Handler already registered: {handler.handler_id}")
        self._handlers.append(handler)

    def resolve(self, check, adapter):
        matches = [h for h in self._handlers if h.can_handle(check, adapter)]
        if len(matches) > 1:
            raise RuntimeError(f"Multiple handlers match check {check.check_id}: {[h.handler_id for h in matches]}")
        return matches[0] if matches else None

    def handlers(self):
        return [h.handler_id for h in self._handlers]


def build_default_handler_registry() -> HandlerRegistry:
    registry = HandlerRegistry()
    for handler in (
        CiscoConfigCheckHandler(),
        CiscoBannerCheckHandler(),
        FortiGateContextRegexHandler(),
        FortiGateBannerHandler(),
        FortiGateCommandHandler(),
        UnixCommandHandler(),
        UnixFileContentHandler(),
    ):
        registry.register(handler)
    return registry
