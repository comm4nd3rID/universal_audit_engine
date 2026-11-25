
from enum import StrEnum


class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NA = "N/A"
    PENDING = "PENDING"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    ERROR = "ERROR"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"
    SKIPPED = "SKIPPED"


class ExecutionStatus(StrEnum):
    NOT_STARTED = "NOT_STARTED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    MANUAL = "MANUAL"
    SKIPPED = "SKIPPED"
    BLOCKED = "BLOCKED"


class ResultSource(StrEnum):
    AUTOMATIC = "AUTOMATIC"
    MANUAL = "MANUAL"
    NONE = "NONE"


class OverallStatus(StrEnum):
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_UNRESOLVED = "COMPLETED_WITH_UNRESOLVED"
    INTERRUPTED = "INTERRUPTED"
    FAILED = "FAILED"


UNRESOLVED_STATUSES = {
    Status.PENDING.value,
    Status.MANUAL_REVIEW.value,
    Status.ERROR.value,
    Status.UNSUPPORTED.value,
    Status.UNKNOWN.value,
}
