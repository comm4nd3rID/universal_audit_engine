
from __future__ import annotations

from universal_audit.core.enums import Status


class ConditionEngine:
    """Evaluates IF conditions from already-collected check results."""

    def evaluate(self, condition_node, results: dict[str, object]) -> bool | None:
        values: list[bool | None] = []
        for child in condition_node.children:
            values.extend(self._node_values(child, results))
        if not values:
            return None

        operator = str(condition_node.attrs.get("type", "AND")).upper()
        if operator == "OR":
            if any(value is True for value in values):
                return True
            if any(value is None for value in values):
                return None
            return False
        # AND is the safe default for unknown operators.
        if any(value is False for value in values):
            return False
        if any(value is None for value in values):
            return None
        return True

    def _node_values(self, node, results) -> list[bool | None]:
        if node.check is not None:
            result = results.get(node.check.check_id)
            if result is None:
                return [None]
            status = result.status
            if status == Status.PASS.value:
                return [True]
            if status == Status.FAIL.value:
                return [False]
            return [None]
        values: list[bool | None] = []
        for child in node.children:
            values.extend(self._node_values(child, results))
        return values
