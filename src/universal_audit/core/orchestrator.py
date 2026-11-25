
from __future__ import annotations

import uuid
from universal_audit.core.condition_engine import ConditionEngine
from universal_audit.core.dispatcher import CheckDispatcher
from universal_audit.core.enums import (
    ExecutionStatus, OverallStatus, Status, UNRESOLVED_STATUSES
)
from universal_audit.core.models import AssessmentRun, CheckResult, DeviceInfo, utc_now, OperatorDecision


class AssessmentOrchestrator:
    def __init__(self, dispatcher: CheckDispatcher, condition_engine: ConditionEngine | None = None,
                 review_manager=None):
        self.dispatcher = dispatcher
        self.condition_engine = condition_engine or ConditionEngine()
        self.review_manager = review_manager
        self._context = {}

    def run(self, audit, adapter, target: DeviceInfo, command_timeout: int = 45,
            on_checkpoint=None) -> AssessmentRun:
        run = AssessmentRun(
            assessment_id=str(uuid.uuid4()),
            started_at=utc_now(),
            target=target,
            audit=audit,
        )
        self._context = {"command_timeout": command_timeout, "assessment_id": run.assessment_id}
        if self.review_manager is not None and hasattr(self.review_manager, "set_secrets"):
            self.review_manager.set_secrets(audit.secret_values)
        try:
            self._run_nodes(audit.nodes, run, adapter, on_checkpoint)
        except KeyboardInterrupt:
            run.aborted = True
            run.execution_log.append(f"{utc_now()} Operator interrupt received")
        except Exception as exc:
            run.fatal_error = {"code": "ASSESSMENT_FATAL_ERROR", "message": f"{type(exc).__name__}: {str(exc)[:800]}"}
            run.execution_log.append(f"{utc_now()} Fatal assessment error: {type(exc).__name__}")

        self._fill_missing_results(run)
        run.ended_at = utc_now()
        if run.aborted:
            run.overall_status = OverallStatus.INTERRUPTED.value
        elif run.fatal_error:
            run.overall_status = OverallStatus.FAILED.value
        elif any(result.status in UNRESOLVED_STATUSES for result in run.results.values()):
            run.overall_status = OverallStatus.COMPLETED_WITH_UNRESOLVED.value
        else:
            run.overall_status = OverallStatus.COMPLETED.value
        return run

    def _fill_missing_results(self, run):
        if run.aborted:
            code = "OPERATOR_ABORT"
            message = "Check was not reached because the operator aborted the assessment"
        elif run.fatal_error:
            code = "ASSESSMENT_FATAL_ERROR"
            message = "Check was not reached because the assessment terminated unexpectedly"
        else:
            code = "INCOMPLETE_EXECUTION"
            message = "Check was not reached during assessment traversal"
        for check in run.audit.iter_checks():
            if check.check_id in run.results:
                continue
            run.results[check.check_id] = CheckResult(
                check_id=check.check_id,
                description=check.description,
                original_check_type=check.original_check_type,
                canonical_check_type=check.canonical_check_type,
                status=Status.SKIPPED.value,
                execution_status=ExecutionStatus.BLOCKED.value,
                expected=check.expected,
                raw_definition=check.raw_definition,
                source_location=check.source_location,
                error={"code": code, "message": message},
            )
            run.execution_log.append(f"{utc_now()} Check {check.check_id}: SKIPPED/BLOCKED ({code})")

        known_lines = {
            item.get("source_location", {}).get("line")
            for item in run.condition_evaluations
        }
        for node in self._walk_nodes(run.audit.nodes):
            if node.node_type != "IF":
                continue
            line = node.source_location.get("line")
            if line in known_lines:
                continue
            conditions = [child for child in node.children if child.node_type == "CONDITION"]
            then_nodes = [child for child in node.children if child.node_type == "THEN"]
            else_nodes = [child for child in node.children if child.node_type == "ELSE"]
            run.condition_evaluations.append({
                "source_location": node.source_location,
                "operator": conditions[0].attrs.get("type", "AND") if conditions else None,
                "auto_policy": conditions[0].attrs.get("auto") if conditions else None,
                "evaluated_check_ids": [],
                "result": None,
                "selected_branch": None,
                "branch_status": code,
                "then_check_ids": self._collect_check_ids(then_nodes),
                "else_check_ids": self._collect_check_ids(else_nodes),
            })

    @staticmethod
    def _walk_nodes(nodes):
        for node in nodes:
            yield node
            yield from AssessmentOrchestrator._walk_nodes(node.children)

    def _run_nodes(self, nodes, run, adapter, on_checkpoint=None):
        for node in nodes:
            if run.aborted:
                self._skip_node(node, run, "OPERATOR_ABORT", blocked=False)
                continue
            if node.node_type == "CHECK" and node.check is not None:
                self._run_check(node.check, run, adapter, on_checkpoint)
            elif node.node_type == "IF":
                self._run_if(node, run, adapter, on_checkpoint)
            elif node.node_type in {"CONTAINER", "THEN", "ELSE"}:
                self._run_nodes(node.children, run, adapter, on_checkpoint)
            elif node.node_type == "REPORT":
                directive = node.attrs.get("type", "UNSPECIFIED")
                description = node.fields.get("description", "")
                run.execution_log.append(
                    f"{utc_now()} Report directive preserved: type={directive}; description={str(description)[:240]}"
                )
            elif node.node_type == "CONDITION":
                self._run_nodes(node.children, run, adapter, on_checkpoint)
            elif node.node_type == "UNKNOWN":
                run.execution_log.append(
                    f"{utc_now()} Unknown audit node preserved at line {node.source_location.get('line')}"
                )
                if node.check is not None and node.check.check_id not in run.results:
                    check = node.check
                    run.results[check.check_id] = CheckResult(
                        check_id=check.check_id,
                        description=check.description,
                        original_check_type=check.original_check_type,
                        canonical_check_type="UNSUPPORTED",
                        status=Status.UNSUPPORTED.value,
                        execution_status=ExecutionStatus.BLOCKED.value,
                        expected=check.expected,
                        raw_definition=check.raw_definition,
                        source_location=check.source_location,
                        error={"code": "UNSUPPORTED_AUDIT_NODE", "message": "Unknown executable audit node"},
                    )
                for child in node.children:
                    self._skip_node(child, run, "UNKNOWN_PARENT_NODE", blocked=True)

    def _run_check(self, check, run, adapter, on_checkpoint=None):
        def execute(attempt_number):
            return self.dispatcher.execute(check, adapter, self._context, attempt_number)

        try:
            result = execute(1)
            if self.review_manager is not None:
                result, abort = self.review_manager.review(check, result, execute)
                if abort:
                    run.aborted = True
        except KeyboardInterrupt:
            run.aborted = True
            result = CheckResult(
                check_id=check.check_id,
                description=check.description,
                original_check_type=check.original_check_type,
                canonical_check_type=check.canonical_check_type,
                status=Status.UNKNOWN.value,
                execution_status=ExecutionStatus.SKIPPED.value,
                expected=check.expected,
                raw_definition=check.raw_definition,
                source_location=check.source_location,
                error={"code": "OPERATOR_ABORT", "message": "Operator interrupted the current check"},
                operator_decision=OperatorDecision("ABORT", "Keyboard interrupt"),
            )
        run.results[check.check_id] = result
        run.execution_log.append(
            f"{utc_now()} Check {check.check_id}: {result.status}/{result.execution_status}"
        )
        if on_checkpoint:
            on_checkpoint(run)

    def _run_if(self, if_node, run, adapter, on_checkpoint):
        condition_nodes = [n for n in if_node.children if n.node_type == "CONDITION"]
        then_nodes = [n for n in if_node.children if n.node_type == "THEN"]
        else_nodes = [n for n in if_node.children if n.node_type == "ELSE"]

        if not condition_nodes:
            for branch in then_nodes + else_nodes:
                self._skip_node(branch, run, "CONDITION_MISSING", blocked=True)
            run.condition_evaluations.append({
                "source_location": if_node.source_location,
                "operator": None,
                "auto_policy": None,
                "evaluated_check_ids": [],
                "result": None,
                "selected_branch": None,
                "branch_status": "BLOCKED_CONDITION_MISSING",
            })
            run.execution_log.append(f"{utc_now()} IF at line {if_node.source_location.get('line')} blocked: no condition")
            return

        # Eagerly evaluate every check in every condition node.
        condition_values = []
        for condition in condition_nodes:
            self._run_nodes(condition.children, run, adapter, on_checkpoint)
            if run.aborted:
                for branch in then_nodes + else_nodes:
                    self._skip_node(branch, run, "OPERATOR_ABORT", blocked=False)
                run.condition_evaluations.append({
                    "source_location": if_node.source_location,
                    "operator": condition_nodes[0].attrs.get("type", "AND"),
                    "auto_policy": condition_nodes[0].attrs.get("auto"),
                    "evaluated_check_ids": self._collect_check_ids(condition_nodes),
                    "result": None,
                    "selected_branch": None,
                    "branch_status": "ABORTED_DURING_CONDITION",
                })
                return
            condition_values.append(self.condition_engine.evaluate(condition, run.results))

        if len(condition_values) == 1:
            condition_value = condition_values[0]
        else:
            # Multiple condition blocks under one IF are conservatively ANDed.
            if any(value is False for value in condition_values):
                condition_value = False
            elif any(value is None for value in condition_values):
                condition_value = None
            else:
                condition_value = True

        auto_policy = condition_nodes[0].attrs.get("auto")
        selected_branch = "THEN" if condition_value is True else ("ELSE" if condition_value is False and else_nodes else None)
        branch_status = (
            "THEN_SELECTED" if condition_value is True
            else ("ELSE_SELECTED" if condition_value is False and else_nodes
                  else ("THEN_NOT_SELECTED_NO_ELSE" if condition_value is False
                        else "BLOCKED_CONDITION_UNRESOLVED"))
        )
        run.condition_evaluations.append({
            "source_location": if_node.source_location,
            "operator": condition_nodes[0].attrs.get("type", "AND"),
            "auto_policy": auto_policy,
            "evaluated_check_ids": self._collect_check_ids(condition_nodes),
            "result": condition_value,
            "selected_branch": selected_branch,
            "branch_status": branch_status,
            "then_check_ids": self._collect_check_ids(then_nodes),
            "else_check_ids": self._collect_check_ids(else_nodes),
        })
        run.execution_log.append(
            f"{utc_now()} IF at line {if_node.source_location.get('line')} evaluated={condition_value}; auto_policy={auto_policy}"
        )

        if condition_value is True:
            self._run_nodes(then_nodes, run, adapter, on_checkpoint)
            for branch in else_nodes:
                self._skip_node(branch, run, "CONDITIONAL_BRANCH_NOT_SELECTED", blocked=True)
        elif condition_value is False:
            for branch in then_nodes:
                self._skip_node(branch, run, "CONDITIONAL_BRANCH_NOT_SELECTED", blocked=True)
            self._run_nodes(else_nodes, run, adapter, on_checkpoint)
        else:
            for branch in then_nodes + else_nodes:
                self._skip_node(branch, run, "CONDITION_UNRESOLVED", blocked=True)

    @staticmethod
    def _collect_check_ids(nodes):
        ids = []
        for node in nodes:
            if node.check is not None:
                ids.append(node.check.check_id)
            ids.extend(AssessmentOrchestrator._collect_check_ids(node.children))
        return ids

    def _skip_node(self, node, run, reason: str, blocked: bool = True):
        if node.node_type == "IF":
            line = node.source_location.get("line")
            if not any(item.get("source_location", {}).get("line") == line for item in run.condition_evaluations):
                conditions = [child for child in node.children if child.node_type == "CONDITION"]
                then_nodes = [child for child in node.children if child.node_type == "THEN"]
                else_nodes = [child for child in node.children if child.node_type == "ELSE"]
                run.condition_evaluations.append({
                    "source_location": node.source_location,
                    "operator": conditions[0].attrs.get("type", "AND") if conditions else None,
                    "auto_policy": conditions[0].attrs.get("auto") if conditions else None,
                    "evaluated_check_ids": [],
                    "result": None,
                    "selected_branch": None,
                    "branch_status": reason,
                    "then_check_ids": self._collect_check_ids(then_nodes),
                    "else_check_ids": self._collect_check_ids(else_nodes),
                })
        if node.check is not None:
            check = node.check
            if check.check_id not in run.results:
                run.results[check.check_id] = CheckResult(
                    check_id=check.check_id,
                    description=check.description,
                    original_check_type=check.original_check_type,
                    canonical_check_type=check.canonical_check_type,
                    status=Status.SKIPPED.value,
                    execution_status=(
                        ExecutionStatus.BLOCKED.value if blocked else ExecutionStatus.SKIPPED.value
                    ),
                    expected=check.expected,
                    raw_definition=check.raw_definition,
                    source_location=check.source_location,
                    error={"code": reason, "message": reason.replace("_", " ").lower()},
                )
        for child in node.children:
            self._skip_node(child, run, reason, blocked)
