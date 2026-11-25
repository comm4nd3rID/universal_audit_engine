
from __future__ import annotations

from typing import Callable

from universal_audit.adapters.base import BaseSSHAdapter
from universal_audit.adapters.cisco_iosxe.adapter import CiscoIOSXEAdapter
from universal_audit.adapters.fortigate.adapter import FortiGateAdapter
from universal_audit.adapters.ssh_transport import SSHTransport
from universal_audit.adapters.vmware_esxi.adapter import VMwareESXiAdapter
from universal_audit.security.command_policy import CommandPolicy


class AdapterRegistry:
    def __init__(self):
        self._factories: dict[str, Callable] = {}

    def register(self, platform_id: str, factory: Callable) -> None:
        if platform_id in self._factories:
            raise ValueError(f"Adapter already registered: {platform_id}")
        self._factories[platform_id] = factory

    def create(self, platform_id: str, transport: SSHTransport,
               policy: CommandPolicy | None = None) -> BaseSSHAdapter:
        try:
            factory = self._factories[platform_id]
        except KeyError as exc:
            raise KeyError(f"No adapter registered for platform {platform_id}") from exc
        return factory(transport, policy)

    def platforms(self) -> list[str]:
        return sorted(self._factories)

    def discover(self, ip_address: str, transport: SSHTransport,
                 policy: CommandPolicy | None = None):
        candidates = []
        for platform_id in self.platforms():
            adapter = self.create(platform_id, transport, policy)
            try:
                info = adapter.identify(ip_address)
            except Exception:
                info = None
            if info is not None:
                candidates.append((adapter, info))
        if len(candidates) == 1:
            return candidates[0]
        if not candidates:
            raise RuntimeError("Target platform could not be identified by any registered adapter")
        platforms = ", ".join(info.platform or "unknown" for _, info in candidates)
        raise RuntimeError(f"Target platform identification is ambiguous: {platforms}")


def build_default_adapter_registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register("cisco_ios_xe", CiscoIOSXEAdapter)
    registry.register("fortigate", FortiGateAdapter)
    registry.register("vmware_esxi", VMwareESXiAdapter)
    return registry
