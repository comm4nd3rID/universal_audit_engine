
from dataclasses import dataclass

from universal_audit.adapters.registry import AdapterRegistry, build_default_adapter_registry
from universal_audit.handlers.registry import HandlerRegistry, build_default_handler_registry


@dataclass
class RegistryHub:
    adapters: AdapterRegistry
    handlers: HandlerRegistry

    @classmethod
    def builtins(cls):
        return cls(
            adapters=build_default_adapter_registry(),
            handlers=build_default_handler_registry(),
        )
