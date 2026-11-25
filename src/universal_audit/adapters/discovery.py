
from __future__ import annotations

from universal_audit.adapters.registry import AdapterRegistry
from universal_audit.core.exceptions import PlatformDiscoveryError


class TargetDiscovery:
    def __init__(self, registry: AdapterRegistry):
        self.registry = registry

    def discover(self, target: str, transport, policy=None):
        try:
            return self.registry.discover(target, transport, policy)
        except Exception as exc:
            raise PlatformDiscoveryError(str(exc)) from exc
