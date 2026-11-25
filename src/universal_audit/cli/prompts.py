
from __future__ import annotations

from universal_audit.core.enums import ExecutionStatus, ResultSource, Status
from universal_audit.core.models import OperatorDecision
from universal_audit.security.redaction import redact_text


class ReviewManager:
    def __init__(self, enabled: bool = True, max_retries: int = 2):
        self.enabled = enabled
        self.max_retries = max_retries
        self.secrets: list[str] = []

    def set_secrets(self, secrets: list[str]):
        self.secrets = [value for value in secrets if value]

    def _safe_text(self, value):
        text = str(value or "")
        for secret in self.secrets:
            text = text.replace(secret, "[REDACTED]")
        return redact_text(text)[0]

    def review(self, check, result, retry_callback):
        if not self.enabled:
            return result, False
        if result.status not in {
            Status.MANUAL_REVIEW.value,
            Status.ERROR.value,
            Status.UNSUPPORTED.value,
            Status.UNKNOWN.value,
        }:
            return result, False

        retries = 0
        while True:
            self._display(check, result)
            choice = input("Decision [p]ass / [f]ail / [n]a / [r]etry / [s]kip / [a]bort: ").strip().lower()
            if choice in {"p", "pass"}:
                justification = self._justification()
                result.status = Status.PASS.value
                result.execution_status = ExecutionStatus.MANUAL.value
                result.result_source = ResultSource.MANUAL.value
                result.operator_decision = OperatorDecision("PASS", justification)
                return result, False
            if choice in {"f", "fail"}:
                justification = self._justification()
                result.status = Status.FAIL.value
                result.execution_status = ExecutionStatus.MANUAL.value
                result.result_source = ResultSource.MANUAL.value
                result.operator_decision = OperatorDecision("FAIL", justification)
                return result, False
            if choice in {"n", "na", "n/a"}:
                justification = self._justification()
                result.status = Status.NA.value
                result.execution_status = ExecutionStatus.MANUAL.value
                result.result_source = ResultSource.MANUAL.value
                result.operator_decision = OperatorDecision("N/A", justification)
                return result, False
            if choice in {"r", "retry"}:
                if retries >= self.max_retries:
                    print(f"Retry limit reached ({self.max_retries}). Choose another action.")
                    continue
                retries += 1
                fresh = retry_callback(retries + 1)
                fresh.attempts = result.attempts + fresh.attempts
                fresh.evidence = result.evidence + fresh.evidence
                result = fresh
                if result.status not in {
                    Status.MANUAL_REVIEW.value,
                    Status.ERROR.value,
                    Status.UNSUPPORTED.value,
                    Status.UNKNOWN.value,
                }:
                    return result, False
                continue
            if choice in {"s", "skip"}:
                result.execution_status = ExecutionStatus.SKIPPED.value
                result.operator_decision = OperatorDecision("SKIP", "Operator skipped unresolved review")
                return result, False
            if choice in {"a", "abort"}:
                result.execution_status = ExecutionStatus.SKIPPED.value
                result.operator_decision = OperatorDecision("ABORT", "Operator aborted the assessment")
                return result, True
            print("Invalid choice. Select p, f, n, r, s, or a.")

    @staticmethod
    def _justification() -> str:
        while True:
            value = input("Justification (required): ").strip()
            if value:
                return value
            print("A justification is required for manual PASS/FAIL/N/A.")

    def _display(self, check, result):
        print("\n" + "=" * 78)
        print(f"[{result.status}] {check.check_id} — {self._safe_text(check.description)}")
        print(f"Type: {check.original_check_type or check.canonical_check_type} | Severity: {check.severity or 'N/A'}")
        if result.expected:
            print(f"Expected: {self._safe_text(result.expected)}")
        if result.error:
            print(f"Error: {result.error.get('code')}: {self._safe_text(result.error.get('message'))}")
        if result.notes:
            print("Notes: " + "; ".join(self._safe_text(item) for item in result.notes))
        if result.evidence:
            output = self._safe_text(result.evidence[-1].raw_output)
            print("Evidence (first 2500 chars; redacted):")
            print(output[:2500])
        if check.remediation:
            print("Remediation guidance:")
            print(self._safe_text(check.remediation)[:1500])
        if check.references:
            print("References: " + "; ".join(check.references))
