
from __future__ import annotations

from dataclasses import dataclass

from universal_audit.core.enums import Status
from universal_audit.core.models import CheckDefinition, Evidence
from universal_audit.security.regex_safety import UnsafeRegexError, find_lines, search


@dataclass
class Evaluation:
    status: str
    actual: str | None = None
    expected: str | None = None
    error: dict[str, str] | None = None
    note: str | None = None


def _is_yes(value) -> bool:
    return str(value).strip().upper() in {"YES", "TRUE", "1", "ON"}


def _manual_marker(value: str | None) -> bool:
    return bool(value and "manual review required" in value.lower())


class ComplianceEvaluator:
    """Pure evaluator: it never connects to a device or executes commands."""

    def evaluate(self, check: CheckDefinition, evidence: Evidence | None) -> Evaluation:
        if evidence is None:
            return Evaluation(Status.UNKNOWN.value, error={"code": "INSUFFICIENT_EVIDENCE", "message": "No evidence collected"})

        params = check.parameters
        output = evidence.raw_output or ""
        if evidence.truncated:
            # A positive match may still be meaningful, but a negative result
            # against a truncated body must never be treated as a confirmed failure.
            truncated = True
        else:
            truncated = False

        try:
            kind = check.canonical_check_type
            if kind in {"CISCO_CONFIG_CHECK", "CISCO_CONFIG_CHECK_NOT"}:
                return self._evaluate_cisco_config(check, output, truncated)
            if kind == "CISCO_BANNER_CHECK":
                return self._evaluate_banner(check, output, truncated)
            if kind == "FORTIGATE_CONTEXT_REGEX":
                return self._evaluate_fortigate_context(check, output, truncated)
            if kind == "FORTIGATE_BANNER_CHECK":
                return self._evaluate_banner(check, output, truncated)
            if kind in {"FORTIGATE_COMMAND", "UNIX_COMMAND"}:
                return self._evaluate_command(check, output, truncated)
            if kind in {"UNIX_FILE_CONTENT", "UNIX_BANNER"}:
                return self._evaluate_file(check, output, truncated)
            return Evaluation(
                Status.UNSUPPORTED.value,
                actual=output,
                expected=check.expected,
                error={"code": "UNSUPPORTED_CHECK", "message": f"No evaluator for {kind}"},
            )
        except UnsafeRegexError as exc:
            return Evaluation(
                Status.ERROR.value,
                actual=output,
                expected=check.expected,
                error={"code": "REGEX_REJECTED", "message": str(exc)},
            )

    def _evaluate_cisco_config(self, check: CheckDefinition, output: str, truncated: bool) -> Evaluation:
        params = check.parameters
        item = params.get("item")
        regex = params.get("regex")
        expected = regex or item
        if _manual_marker(str(regex or "")):
            return Evaluation(Status.MANUAL_REVIEW.value, output, str(expected), note="Audit explicitly requests manual review")
        if not expected:
            return Evaluation(Status.MANUAL_REVIEW.value, output, None, note="No comparison pattern is defined")
        if check.canonical_check_type == "CISCO_CONFIG_CHECK_NOT":
            found = search(str(item or expected), output)
            if found:
                return Evaluation(Status.FAIL.value, output, str(item or expected))
            if truncated:
                return Evaluation(Status.UNKNOWN.value, output, str(item or expected), note="Evidence was truncated")
            return Evaluation(Status.PASS.value, output, str(item or expected))

        pattern = str(expected)
        found = search(pattern, output)
        if found:
            if "min_occurrences" in params or "max_occurrences" in params:
                count = len(find_lines(pattern, output))
                minimum = int(params.get("min_occurrences", 0) or 0)
                maximum = params.get("max_occurrences")
                if count < minimum or (maximum is not None and count > int(maximum)):
                    return Evaluation(Status.FAIL.value, output, pattern, note=f"Matched {count} lines")
            return Evaluation(Status.PASS.value, output, pattern)
        if truncated:
            return Evaluation(Status.UNKNOWN.value, output, pattern, note="Evidence was truncated")
        return Evaluation(Status.FAIL.value, output, pattern)

    def _evaluate_fortigate_context(self, check: CheckDefinition, output: str, truncated: bool) -> Evaluation:
        params = check.parameters
        expect = params.get("expect")
        not_expect = params.get("not_expect")
        selector = params.get("regex")

        if _manual_marker(str(expect or "")):
            return Evaluation(Status.MANUAL_REVIEW.value, output, str(expect), note="Audit explicitly requests manual review")
        if not output.strip():
            if truncated:
                return Evaluation(Status.UNKNOWN.value, output, str(expect), note="Evidence was truncated")
            return Evaluation(Status.FAIL.value, output, str(expect), note="Configuration context was not found")

        selected = output
        if selector:
            selected_lines = find_lines(str(selector), output)
            selected = "\n".join(selected_lines)
            if not selected_lines and expect:
                if truncated:
                    return Evaluation(Status.UNKNOWN.value, output, str(expect), note="Evidence was truncated")
                return Evaluation(Status.FAIL.value, output, str(expect), note="Target setting was not found")

        if expect:
            expected_found = search(str(expect), selected)
            if not expected_found:
                if truncated:
                    return Evaluation(Status.UNKNOWN.value, selected, str(expect), note="Evidence was truncated")
                return Evaluation(Status.FAIL.value, selected, str(expect))
        if not_expect:
            prohibited_found = search(str(not_expect), selected)
            if prohibited_found:
                return Evaluation(Status.FAIL.value, selected, str(not_expect), note="Prohibited setting was found")
            if truncated:
                return Evaluation(Status.UNKNOWN.value, selected, str(not_expect), note="Evidence was truncated")
        if not expect and not not_expect:
            return Evaluation(Status.MANUAL_REVIEW.value, selected, None, note="No expect/not_expect rule is defined")
        return Evaluation(Status.PASS.value, selected, str(expect or not_expect))

    def _evaluate_command(self, check: CheckDefinition, output: str, truncated: bool) -> Evaluation:
        expected = check.parameters.get("expect")
        if _manual_marker(str(expected or "")):
            return Evaluation(Status.MANUAL_REVIEW.value, output, str(expected), note="Audit explicitly requests manual review")
        if not expected:
            return Evaluation(Status.MANUAL_REVIEW.value, output, None, note="Command check has no expected pattern")
        found = search(str(expected), output)
        if found:
            return Evaluation(Status.PASS.value, output, str(expected))
        if truncated:
            return Evaluation(Status.UNKNOWN.value, output, str(expected), note="Evidence was truncated")
        return Evaluation(Status.FAIL.value, output, str(expected))

    def _evaluate_file(self, check: CheckDefinition, output: str, truncated: bool) -> Evaluation:
        params = check.parameters
        content = params.get("content")
        if content is not None and _is_yes(params.get("is_substring", "NO")):
            if str(content) in output:
                return Evaluation(Status.PASS.value, output, str(content))
            if truncated:
                return Evaluation(Status.UNKNOWN.value, output, str(content), note="Evidence was truncated")
            return Evaluation(Status.FAIL.value, output, str(content))

        expected = params.get("expect")
        selector = params.get("regex")
        if _manual_marker(str(expected or "")):
            return Evaluation(Status.MANUAL_REVIEW.value, output, str(expected), note="Audit explicitly requests manual review")
        if not expected and not selector:
            return Evaluation(Status.MANUAL_REVIEW.value, output, None, note="File check has no comparison rule")

        selected = output
        if selector:
            selected_lines = find_lines(str(selector), output)
            selected = "\n".join(selected_lines)
            if not selected_lines and expected:
                if truncated:
                    return Evaluation(Status.UNKNOWN.value, output, str(expected), note="Evidence was truncated")
                return Evaluation(Status.FAIL.value, output, str(expected), note="Expected directive was not found")

        if expected:
            if search(str(expected), selected):
                return Evaluation(Status.PASS.value, selected, str(expected))
            if truncated:
                return Evaluation(Status.UNKNOWN.value, selected, str(expected), note="Evidence was truncated")
            return Evaluation(Status.FAIL.value, selected, str(expected))
        return Evaluation(Status.PASS.value, selected, str(selector))

    def _evaluate_banner(self, check: CheckDefinition, output: str, truncated: bool) -> Evaluation:
        params = check.parameters
        content = params.get("content")
        item = params.get("item")
        if content is None or str(content) == "":
            return Evaluation(Status.MANUAL_REVIEW.value, output, None, note="Banner content is not defined")
        if item and not search(str(item), output):
            if truncated:
                return Evaluation(Status.UNKNOWN.value, output, str(content), note="Evidence was truncated")
            return Evaluation(Status.FAIL.value, output, str(content), note="Banner directive was not found")
        if str(content) in output:
            return Evaluation(Status.PASS.value, output, str(content))
        if truncated:
            return Evaluation(Status.UNKNOWN.value, output, str(content), note="Evidence was truncated")
        return Evaluation(Status.FAIL.value, output, str(content))
