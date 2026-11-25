
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .enums import ExecutionStatus, ResultSource, Status


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class VariableDefinition:
    name: str
    default: str | None = None
    description: str | None = None
    info: str | None = None
    value_type: str | None = None


@dataclass
class AuditASTNode:
    tag: str
    attrs: dict[str, str] = field(default_factory=dict)
    fields: dict[str, Any] = field(default_factory=dict)
    children: list["AuditASTNode"] = field(default_factory=list)
    source_location: dict[str, int] = field(default_factory=dict)
    raw_text: str = ""
    raw_lines: list[str] = field(default_factory=list)


@dataclass
class AuditDocument:
    source_path: str
    file_hash: str
    syntax_family: str
    metadata: dict[str, Any]
    variables: list[VariableDefinition]
    nodes: list[AuditASTNode]
    raw_header: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class CheckDefinition:
    check_id: str
    description: str
    original_check_type: str | None
    canonical_check_type: str
    platform: str
    parameters: dict[str, Any]
    expected: str | None = None
    context: str | None = None
    severity: str | None = None
    references: list[str] = field(default_factory=list)
    remediation: str | None = None
    raw_fields: dict[str, Any] = field(default_factory=dict)
    raw_definition: dict[str, Any] = field(default_factory=dict)
    source_location: dict[str, int] = field(default_factory=dict)
    missing_variables: list[str] = field(default_factory=list)


@dataclass
class CanonicalNode:
    node_type: str
    attrs: dict[str, str] = field(default_factory=dict)
    children: list["CanonicalNode"] = field(default_factory=list)
    check: CheckDefinition | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    source_location: dict[str, int] = field(default_factory=dict)
    raw_text: str = ""


@dataclass
class CanonicalAudit:
    source_path: str
    file_hash: str
    syntax_family: str
    platform: str
    metadata: dict[str, Any]
    variables: list[VariableDefinition]
    nodes: list[CanonicalNode]
    raw_header: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    resolved_variables: dict[str, str | None] = field(default_factory=dict)
    secret_values: list[str] = field(default_factory=list, repr=False)

    def iter_checks(self):
        def walk(nodes):
            for node in nodes:
                if node.check is not None:
                    yield node.check
                yield from walk(node.children)
        yield from walk(self.nodes)


@dataclass
class Evidence:
    source: str
    command_or_query: str | None
    raw_output: str
    normalized_value: str | None = None
    collected_at: str = field(default_factory=utc_now)
    exit_code: int | None = None
    stderr: str | None = None
    redactions: list[str] = field(default_factory=list)
    truncated: bool = False


@dataclass
class Attempt:
    attempt_number: int
    started_at: str
    ended_at: str
    execution_status: str
    command_or_query: str | None = None
    error: dict[str, str] | None = None


@dataclass
class OperatorDecision:
    decision: str
    justification: str | None
    decided_at: str = field(default_factory=utc_now)


@dataclass
class CheckResult:
    check_id: str
    description: str
    original_check_type: str | None
    canonical_check_type: str
    status: str = Status.PENDING.value
    execution_status: str = ExecutionStatus.NOT_STARTED.value
    result_source: str = ResultSource.NONE.value
    expected: str | None = None
    actual: str | None = None
    evidence: list[Evidence] = field(default_factory=list)
    attempts: list[Attempt] = field(default_factory=list)
    operator_decision: OperatorDecision | None = None
    error: dict[str, str] | None = None
    raw_definition: dict[str, Any] = field(default_factory=dict)
    source_location: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


@dataclass
class DeviceInfo:
    ip_address: str
    hostname: str | None = None
    vendor: str | None = None
    platform: str | None = None
    software_version: str | None = None
    model: str | None = None
    identification_evidence: str | None = None


@dataclass
class AssessmentRun:
    assessment_id: str
    started_at: str
    target: DeviceInfo
    audit: CanonicalAudit
    results: dict[str, CheckResult] = field(default_factory=dict)
    ended_at: str | None = None
    overall_status: str = "INTERRUPTED"
    aborted: bool = False
    fatal_error: dict[str, str] | None = None
    execution_log: list[str] = field(default_factory=list)
    condition_evaluations: list[dict[str, Any]] = field(default_factory=list)
