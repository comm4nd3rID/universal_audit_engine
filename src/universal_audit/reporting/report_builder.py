
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from universal_audit.core.enums import Status
from universal_audit.core.models import AssessmentRun
from universal_audit.security.redaction import redact_text


def _redacted(value: Any, secrets: list[str] | None = None):
    if isinstance(value, str):
        text = value
        for secret in (secrets or []):
            if secret:
                text = text.replace(secret, "[REDACTED]")
        return redact_text(text)[0]
    if isinstance(value, list):
        return [_redacted(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: _redacted(item, secrets) for key, item in value.items()}
    return value


def _evidence_dict(evidence, secrets):
    output = _redacted(evidence.raw_output or "", secrets)
    _, redactions = redact_text(evidence.raw_output or "")
    if any(secret and secret in (evidence.raw_output or "") for secret in secrets):
        redactions.append("SENSITIVE_VARIABLE_VALUE")
    stderr = _redacted(evidence.stderr, secrets) if evidence.stderr else None
    return {
        "source": evidence.source,
        "command_or_query": _redacted(evidence.command_or_query, secrets),
        "raw_output": output,
        "normalized_value": _redacted(evidence.normalized_value, secrets),
        "collected_at": evidence.collected_at,
        "exit_code": evidence.exit_code,
        "stderr": stderr,
        "redactions": sorted(set(evidence.redactions + redactions)),
        "truncated": evidence.truncated,
    }


def _attempt_dict(attempt, secrets):
    return {
        "attempt_number": attempt.attempt_number,
        "started_at": attempt.started_at,
        "ended_at": attempt.ended_at,
        "execution_status": attempt.execution_status,
        "command_or_query": _redacted(attempt.command_or_query, secrets),
        "error": _redacted(attempt.error, secrets),
    }


def _decision_dict(decision, secrets):
    if decision is None:
        return None
    return {
        "decision": decision.decision,
        "justification": _redacted(decision.justification, secrets),
        "decided_at": decision.decided_at,
    }


def _check_dict(result, secrets):
    return {
        "check_id": result.check_id,
        "description": _redacted(result.description, secrets),
        "original_check_type": result.original_check_type,
        "canonical_check_type": result.canonical_check_type,
        "status": result.status,
        "execution_status": result.execution_status,
        "result_source": result.result_source,
        "expected": _redacted(result.expected, secrets),
        "actual": _redacted(result.actual, secrets),
        "evidence": [_evidence_dict(item, secrets) for item in result.evidence],
        "attempts": [_attempt_dict(item, secrets) for item in result.attempts],
        "operator_decision": _decision_dict(result.operator_decision, secrets),
        "error": _redacted(result.error, secrets),
        "raw_definition": _redacted(result.raw_definition, secrets),
        "source_location": result.source_location,
        "notes": [_redacted(item, secrets) for item in result.notes],
    }


def _walk_report_directives(nodes):
    directives = []
    for node in nodes:
        if node.node_type == "REPORT":
            directives.append({
                "type": node.attrs.get("type", "UNSPECIFIED"),
                "fields": node.fields,
                "source_location": node.source_location,
            })
        directives.extend(_walk_report_directives(node.children))
    return directives


class ReportBuilder:
    def build(self, run: AssessmentRun) -> dict[str, Any]:
        audit = run.audit
        ordered_results = []
        for check in audit.iter_checks():
            result = run.results.get(check.check_id)
            if result is not None:
                ordered_results.append(_check_dict(result, audit.secret_values))

        counts = Counter(item["status"] for item in ordered_results)
        summary = {
            "total_checks": len(ordered_results),
            "passed": counts[Status.PASS.value],
            "failed": counts[Status.FAIL.value],
            "not_applicable": counts[Status.NA.value],
            "manual_review": counts[Status.MANUAL_REVIEW.value],
            "errors": counts[Status.ERROR.value],
            "unsupported": counts[Status.UNSUPPORTED.value],
            "unknown": counts[Status.UNKNOWN.value],
            "skipped": counts[Status.SKIPPED.value],
            "pending": counts[Status.PENDING.value],
        }

        metadata = audit.metadata
        spec = metadata.get("spec", {}) if isinstance(metadata.get("spec"), dict) else {}
        report = {
            "schema_version": "1.0",
            "assessment": {
                "assessment_id": run.assessment_id,
                "started_at": run.started_at,
                "completed_at": run.ended_at,
                "overall_status": run.overall_status if run.ended_at else "RUNNING",
                "aborted": run.aborted,
                "fatal_error": _redacted(run.fatal_error, audit.secret_values),
            },
            "device": {
                "ip_address": run.target.ip_address,
                "hostname": run.target.hostname,
                "vendor": run.target.vendor,
                "platform": run.target.platform,
                "software_version": run.target.software_version,
                "model": run.target.model,
            },
            "audit": {
                "file_name": Path(audit.source_path).name,
                "source_path": audit.source_path,
                "sha256": audit.file_hash,
                "syntax_family": audit.syntax_family,
                "benchmark": spec.get("type", "CIS"),
                "benchmark_name": spec.get("name", metadata.get("display_name")),
                "benchmark_version": spec.get("version"),
                "profile": spec.get("profile"),
                "display_name": metadata.get("display_name"),
                "link": spec.get("link"),
            },
            "summary": summary,
            "resolved_variables": audit.resolved_variables,
            "warnings": _redacted(audit.warnings, audit.secret_values),
            "report_directives": _redacted(_walk_report_directives(audit.nodes), audit.secret_values),
            "condition_evaluations": run.condition_evaluations,
            "checks": ordered_results,
            "execution_log": _redacted(run.execution_log, audit.secret_values),
        }
        return report

    def to_json(self, report: dict, indent: int = 2) -> str:
        return json.dumps(report, ensure_ascii=False, indent=indent, sort_keys=False)
