
from __future__ import annotations

import re
from typing import Any

from universal_audit.core.models import CanonicalAudit


PLACEHOLDER_RE = re.compile(r"@([A-Za-z][A-Za-z0-9_]*)@")


def is_sensitive_name(name: str) -> bool:
    return bool(re.search(r"PASSWORD|PASSWD|SECRET|TOKEN|COMMUNITY|PRIVATE.?KEY|PSK", name, re.I))


def resolve_variables(audit: CanonicalAudit, overrides: dict[str, Any] | None = None) -> CanonicalAudit:
    overrides = {str(k).upper(): str(v) for k, v in (overrides or {}).items()}
    definitions = {v.name.upper(): v for v in audit.variables}
    values: dict[str, str | None] = {}

    for name, definition in definitions.items():
        value = overrides.get(name, definition.default)
        if value is not None and definition.value_type:
            kind = definition.value_type.upper()
            if kind == "INTEGER":
                try:
                    int(value)
                except ValueError:
                    audit.warnings.append(f"Variable {name} must be an integer; value was not applied")
                    value = None
        values[name] = value

    for name, value in overrides.items():
        if name not in definitions:
            audit.warnings.append(f"Override supplied for undefined variable {name}; it was ignored")

    def replace(value: Any, missing: set[str]) -> Any:
        if isinstance(value, str):
            def sub(match):
                name = match.group(1).upper()
                resolved = values.get(name)
                if resolved is None:
                    missing.add(name)
                    return match.group(0)
                return resolved
            return PLACEHOLDER_RE.sub(sub, value)
        if isinstance(value, list):
            return [replace(item, missing) for item in value]
        if isinstance(value, dict):
            return {k: replace(v, missing) for k, v in value.items()}
        return value

    def walk(nodes):
        for node in nodes:
            if node.check is not None:
                missing: set[str] = set()
                node.check.parameters = replace(node.check.parameters, missing)
                node.check.missing_variables = sorted(missing)
                params = node.check.parameters
                if node.check.canonical_check_type in {"CISCO_CONFIG_CHECK", "CISCO_CONFIG_CHECK_NOT"}:
                    node.check.expected = params.get("regex") or params.get("item")
                elif node.check.canonical_check_type in {
                    "CISCO_BANNER_CHECK", "FORTIGATE_BANNER_CHECK", "UNIX_BANNER"
                }:
                    node.check.expected = params.get("content") or params.get("expect")
                else:
                    node.check.expected = (
                        params.get("expect") or params.get("not_expect") or
                        params.get("content") or params.get("regex")
                    )
                node.check.context = node.check.parameters.get("context")
                node.check.remediation = node.check.parameters.get("solution")
                if node.check.missing_variables:
                    audit.warnings.append(
                        f"{node.check.check_id}: unresolved variables: {', '.join(node.check.missing_variables)}"
                    )
            walk(node.children)

    walk(audit.nodes)
    audit.secret_values = [
        value for name, value in values.items()
        if value and is_sensitive_name(name)
    ]
    audit.resolved_variables = {
        name: ("[REDACTED]" if is_sensitive_name(name) and value is not None else value)
        for name, value in values.items()
    }
    return audit
