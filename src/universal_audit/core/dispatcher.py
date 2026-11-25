
from __future__ import annotations

from universal_audit.adapters.base import UnsupportedOperation
from universal_audit.adapters.ssh_transport import (
    SSHCommandTimeout, SSHConnectionError, SSHCommandFailure, SSHAuthenticationError
)
from universal_audit.core.enums import ExecutionStatus, ResultSource, Status
from universal_audit.core.evaluator import ComplianceEvaluator
from universal_audit.core.models import Attempt, CheckDefinition, CheckResult, utc_now
from universal_audit.handlers.registry import HandlerRegistry
from universal_audit.security.redaction import safe_exception_message


class CheckDispatcher:
    def __init__(self, handlers: HandlerRegistry, evaluator: ComplianceEvaluator | None = None):
        self.handlers = handlers
        self.evaluator = evaluator or ComplianceEvaluator()

    def execute(self, check: CheckDefinition, adapter, context: dict,
                attempt_number: int = 1) -> CheckResult:
        started = utc_now()
        result = CheckResult(
            check_id=check.check_id,
            description=check.description,
            original_check_type=check.original_check_type,
            canonical_check_type=check.canonical_check_type,
            expected=check.expected,
            raw_definition=check.raw_definition,
            source_location=check.source_location,
            execution_status=ExecutionStatus.RUNNING.value,
        )

        if check.missing_variables:
            result.status = Status.UNKNOWN.value
            result.execution_status = ExecutionStatus.BLOCKED.value
            result.error = {
                "code": "MISSING_VARIABLE",
                "message": "Unresolved required variables: " + ", ".join(check.missing_variables),
            }
            result.attempts.append(Attempt(
                attempt_number, started, utc_now(), ExecutionStatus.BLOCKED.value,
                error=result.error,
            ))
            return result

        handler = self.handlers.resolve(check, adapter)
        if handler is None:
            result.status = Status.UNSUPPORTED.value
            result.execution_status = ExecutionStatus.BLOCKED.value
            result.error = {
                "code": "UNSUPPORTED_CHECK",
                "message": f"No compatible handler for {check.canonical_check_type} on {adapter.platform_id}",
            }
            result.attempts.append(Attempt(
                attempt_number, started, utc_now(), ExecutionStatus.BLOCKED.value,
                error=result.error,
            ))
            return result

        try:
            evidence = handler.collect(check, adapter, context)
            result.evidence.append(evidence)
            if evidence.exit_code is not None and evidence.exit_code != 0:
                result.status = Status.ERROR.value
                result.execution_status = ExecutionStatus.FAILED.value
                result.result_source = ResultSource.NONE.value
                result.actual = evidence.raw_output
                permission_denied = "permission denied" in (
                    (evidence.stderr or "") + "\n" + (evidence.raw_output or "")
                ).lower()
                result.error = {
                    "code": "PERMISSION_DENIED" if permission_denied else "COMMAND_FAILED",
                    "message": (
                        "Read-only command was denied by the target"
                        if permission_denied
                        else f"Read-only command returned exit code {evidence.exit_code}"
                    ),
                }
                result.attempts.append(Attempt(
                    attempt_number, started, utc_now(), result.execution_status,
                    command_or_query=evidence.command_or_query,
                    error=result.error,
                ))
                return result
            evaluation = self.evaluator.evaluate(check, evidence)
            result.status = evaluation.status
            result.actual = evaluation.actual
            result.expected = evaluation.expected
            result.error = evaluation.error
            if evaluation.note:
                result.notes.append(evaluation.note)
            if evaluation.status == Status.MANUAL_REVIEW.value:
                result.execution_status = ExecutionStatus.MANUAL.value
                result.result_source = ResultSource.NONE.value
            elif evaluation.status in {Status.ERROR.value, Status.UNKNOWN.value, Status.UNSUPPORTED.value}:
                result.execution_status = ExecutionStatus.FAILED.value
                result.result_source = ResultSource.NONE.value
            else:
                result.execution_status = ExecutionStatus.COMPLETED.value
                result.result_source = ResultSource.AUTOMATIC.value
            result.attempts.append(Attempt(
                attempt_number, started, utc_now(), result.execution_status,
                command_or_query=evidence.command_or_query,
                error=result.error,
            ))
        except UnsupportedOperation as exc:
            result.status = Status.UNSUPPORTED.value
            result.execution_status = ExecutionStatus.BLOCKED.value
            result.error = {"code": "UNSUPPORTED_OPERATION", "message": safe_exception_message(exc)}
            result.attempts.append(Attempt(
                attempt_number, started, utc_now(), result.execution_status,
                command_or_query=check.parameters.get("cmd"),
                error=result.error,
            ))
        except (SSHCommandTimeout, TimeoutError) as exc:
            result.status = Status.ERROR.value
            result.execution_status = ExecutionStatus.FAILED.value
            result.error = {"code": "COMMAND_TIMEOUT", "message": safe_exception_message(exc)}
            result.attempts.append(Attempt(
                attempt_number, started, utc_now(), result.execution_status,
                command_or_query=check.parameters.get("cmd"),
                error=result.error,
            ))
        except PermissionError as exc:
            result.status = Status.ERROR.value
            result.execution_status = ExecutionStatus.FAILED.value
            result.error = {"code": "PERMISSION_DENIED", "message": safe_exception_message(exc)}
            result.attempts.append(Attempt(
                attempt_number, started, utc_now(), result.execution_status,
                command_or_query=check.parameters.get("cmd") or check.parameters.get("file"),
                error=result.error,
            ))
        except FileNotFoundError as exc:
            result.status = Status.ERROR.value
            result.execution_status = ExecutionStatus.FAILED.value
            result.error = {"code": "REMOTE_FILE_NOT_FOUND", "message": safe_exception_message(exc)}
            result.attempts.append(Attempt(
                attempt_number, started, utc_now(), result.execution_status,
                command_or_query=check.parameters.get("file"),
                error=result.error,
            ))
        except SSHCommandFailure as exc:
            result.status = Status.ERROR.value
            result.execution_status = ExecutionStatus.FAILED.value
            result.error = {"code": "COMMAND_FAILED", "message": safe_exception_message(exc)}
            result.attempts.append(Attempt(
                attempt_number, started, utc_now(), result.execution_status,
                command_or_query=check.parameters.get("cmd"),
                error=result.error,
            ))
        except SSHAuthenticationError as exc:
            result.status = Status.ERROR.value
            result.execution_status = ExecutionStatus.FAILED.value
            result.error = {"code": "AUTHENTICATION_FAILED", "message": safe_exception_message(exc)}
            result.attempts.append(Attempt(
                attempt_number, started, utc_now(), result.execution_status,
                command_or_query=check.parameters.get("cmd"),
                error=result.error,
            ))
        except SSHConnectionError as exc:
            result.status = Status.ERROR.value
            result.execution_status = ExecutionStatus.FAILED.value
            result.error = {"code": "CONNECTION_ERROR", "message": safe_exception_message(exc)}
            result.attempts.append(Attempt(
                attempt_number, started, utc_now(), result.execution_status,
                command_or_query=check.parameters.get("cmd"),
                error=result.error,
            ))
        except Exception as exc:
            result.status = Status.ERROR.value
            result.execution_status = ExecutionStatus.FAILED.value
            result.error = {
                "code": "CHECK_EXECUTION_ERROR",
                "message": f"{type(exc).__name__}: {safe_exception_message(exc)}",
            }
            result.attempts.append(Attempt(
                attempt_number, started, utc_now(), result.execution_status,
                command_or_query=check.parameters.get("cmd") or check.parameters.get("file"),
                error=result.error,
            ))
        return result
