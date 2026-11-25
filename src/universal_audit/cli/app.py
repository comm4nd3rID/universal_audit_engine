
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

from universal_audit.adapters.discovery import TargetDiscovery
from universal_audit.adapters.ssh_transport import (
    SSHTransport, SSHAuthenticationError, SSHConnectionError, SSHCommandFailure, SSHCommandTimeout
)
from universal_audit.audit.normalizer import normalize
from universal_audit.audit.registry import build_default_parser_registry
from universal_audit.audit.variables import resolve_variables, is_sensitive_name
from universal_audit.core.dispatcher import CheckDispatcher
from universal_audit.core.enums import ExecutionStatus, OverallStatus, ResultSource, Status
from universal_audit.core.models import (
    AssessmentRun, CheckResult, DeviceInfo, utc_now
)
from universal_audit.core.exceptions import PlatformDiscoveryError
from universal_audit.core.orchestrator import AssessmentOrchestrator
from universal_audit.core.registry import RegistryHub
from universal_audit.reporting.report_builder import ReportBuilder, _redacted
from universal_audit.reporting.storage import ResultStorage
from universal_audit.cli.prompts import ReviewManager
from universal_audit.security.command_policy import CommandPolicy
from universal_audit.security.credential_provider import PromptCredentialProvider
from universal_audit.security.input_validator import InputValidator


def _load_overrides(path: str | None) -> dict:
    if not path:
        return {}
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        raise ValueError(f"Variable file does not exist: {file_path}")
    mode = file_path.stat().st_mode & 0o777
    if mode & 0o077:
        raise PermissionError(
            f"Variable file permissions are too broad ({oct(mode)}). Use chmod 600 {file_path}"
        )
    data = json.loads(file_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Variable file must contain a JSON object")
    return data


def _load_audit(path: str, variables_file: str | None = None):
    audit_path = InputValidator().validate_audit_file(path)
    parser_factory = build_default_parser_registry().resolve("tenable-pseudo-xml")
    parsed = parser_factory().parse_file(audit_path)
    canonical = normalize(parsed)
    overrides = _load_overrides(variables_file)
    resolve_variables(canonical, overrides)
    return canonical


def _count_types(audit):
    counts = {}
    for check in audit.iter_checks():
        counts[check.canonical_check_type] = counts.get(check.canonical_check_type, 0) + 1
    return counts


def _print_audit_summary(audit):
    print(f"Audit: {audit.metadata.get('display_name', Path(audit.source_path).name)}")
    print(f"Platform: {audit.platform} | Syntax family: {audit.syntax_family}")
    print(f"Profile: {audit.metadata.get('spec', {}).get('profile', 'N/A')}")
    print(f"SHA-256: {audit.file_hash}")
    print(f"Checks: {sum(_count_types(audit).values())}")
    for check_type, count in sorted(_count_types(audit).items()):
        print(f"  {check_type:<28} {count}")
    if audit.warnings:
        print("Warnings:")
        for warning in audit.warnings:
            print(f"  - {warning}")


def _cmd_parse(args):
    audit = _load_audit(args.audit, args.variables_file)
    _print_audit_summary(audit)
    if getattr(args, "output", None):
        payload = {
            "source_path": audit.source_path,
            "sha256": audit.file_hash,
            "syntax_family": audit.syntax_family,
            "platform": audit.platform,
            "metadata": audit.metadata,
            "variables": [
                {
                    "name": item.name,
                    "default": "[REDACTED]" if is_sensitive_name(item.name) and item.default is not None else item.default,
                    "description": item.description,
                    "value_type": item.value_type,
                } for item in audit.variables
            ],
            "resolved_variables": audit.resolved_variables,
            "checks": [
                {
                    "check_id": check.check_id,
                    "description": check.description,
                    "original_check_type": check.original_check_type,
                    "canonical_check_type": check.canonical_check_type,
                    "parameters": _redacted(check.parameters, audit.secret_values),
                    "source_location": check.source_location,
                    "raw_definition": _redacted(check.raw_definition, audit.secret_values),
                } for check in audit.iter_checks()
            ],
            "warnings": audit.warnings,
        }
        output_path = Path(args.output).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False, indent=2))
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        print(f"Canonical audit model written to: {output_path}")
    return 0


def _compatible_version(platform: str, version: str | None, audit) -> bool:
    if not version:
        return False
    name = str(audit.metadata.get("spec", {}).get("name", "")).lower()
    if platform == "cisco_ios_xe":
        return version.startswith("17.")
    if platform == "fortigate":
        return version.startswith("7.4.")
    if platform == "vmware_esxi":
        return version.startswith("9.")
    return False



def _save_preflight_failure(audit, target_ip: str, output_dir: str, code: str,
                            message: str, status: str, overall_status: str,
                            device: DeviceInfo | None = None) -> int:
    started = utc_now()
    error = {"code": code, "message": message}
    run = AssessmentRun(
        assessment_id=str(uuid.uuid4()),
        started_at=started,
        target=device or DeviceInfo(ip_address=target_ip),
        audit=audit,
        ended_at=utc_now(),
        overall_status=overall_status,
        fatal_error=error if overall_status == OverallStatus.FAILED.value else None,
        execution_log=[f"{started} Preflight stopped: {code}: {message}"],
    )
    for check in audit.iter_checks():
        run.results[check.check_id] = CheckResult(
            check_id=check.check_id,
            description=check.description,
            original_check_type=check.original_check_type,
            canonical_check_type=check.canonical_check_type,
            status=status,
            execution_status=ExecutionStatus.BLOCKED.value,
            result_source=ResultSource.NONE.value,
            expected=check.expected,
            raw_definition=check.raw_definition,
            source_location=check.source_location,
            error=error,
        )

    def walk(nodes):
        for node in nodes:
            yield node
            yield from walk(node.children)

    for node in walk(audit.nodes):
        if node.node_type == "IF":
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
                "then_check_ids": [c.check_id for branch in then_nodes for c in _checks_in_nodes([branch])],
                "else_check_ids": [c.check_id for branch in else_nodes for c in _checks_in_nodes([branch])],
            })

    saved = ResultStorage(output_dir).save(run)
    print(f"Assessment was not started: {code}")
    print(f"Report: {saved['report']}")
    print(f"Execution log: {saved['log']}")
    return 2


def _checks_in_nodes(nodes):
    for node in nodes:
        if node.check is not None:
            yield node.check
        yield from _checks_in_nodes(node.children)


def _cmd_run(args):
    target_ip = InputValidator().validate_target_ipv4(args.target)
    audit = _load_audit(args.audit, args.variables_file)
    if audit.platform not in {"cisco_ios_xe", "fortigate", "vmware_esxi"}:
        raise ValueError(f"No runtime adapter is available for audit platform {audit.platform}")

    credentials = PromptCredentialProvider().obtain(
        username=args.username,
        key_filename=args.key_file,
    )
    transport = SSHTransport()
    adapter = None
    try:
        try:
            transport.connect(
                host=target_ip,
                port=args.port,
                username=credentials.username,
                password=credentials.password,
                known_hosts=args.known_hosts,
                timeout=args.connect_timeout,
                key_filename=credentials.key_filename,
            )
        except SSHAuthenticationError as exc:
            return _save_preflight_failure(
                audit, target_ip, args.output_dir, "AUTHENTICATION_FAILED",
                str(exc), Status.ERROR.value, OverallStatus.FAILED.value,
            )
        except SSHConnectionError as exc:
            return _save_preflight_failure(
                audit, target_ip, args.output_dir, "CONNECTION_ERROR",
                str(exc), Status.ERROR.value, OverallStatus.FAILED.value,
            )
        except Exception as exc:
            return _save_preflight_failure(
                audit, target_ip, args.output_dir, "SSH_TRANSPORT_ERROR",
                f"{type(exc).__name__}: {str(exc)[:500]}",
                Status.ERROR.value, OverallStatus.FAILED.value,
            )

        registries = RegistryHub.builtins()
        adapter_registry = registries.adapters
        policy = CommandPolicy()

        if args.platform == "auto":
            try:
                adapter, device = TargetDiscovery(adapter_registry).discover(target_ip, transport, policy)
            except PlatformDiscoveryError as exc:
                return _save_preflight_failure(
                    audit, target_ip, args.output_dir, "PLATFORM_UNIDENTIFIED",
                    str(exc), Status.UNKNOWN.value, OverallStatus.COMPLETED_WITH_UNRESOLVED.value,
                )
        else:
            adapter = adapter_registry.create(args.platform, transport, policy)
            try:
                device = adapter.identify(target_ip)
            except PermissionError as exc:
                return _save_preflight_failure(
                    audit, target_ip, args.output_dir, "PERMISSION_DENIED",
                    str(exc), Status.ERROR.value, OverallStatus.COMPLETED_WITH_UNRESOLVED.value,
                )
            except SSHCommandFailure as exc:
                return _save_preflight_failure(
                    audit, target_ip, args.output_dir, "COMMAND_FAILED",
                    str(exc), Status.ERROR.value, OverallStatus.COMPLETED_WITH_UNRESOLVED.value,
                )
            except SSHCommandTimeout as exc:
                return _save_preflight_failure(
                    audit, target_ip, args.output_dir, "COMMAND_TIMEOUT",
                    str(exc), Status.ERROR.value, OverallStatus.COMPLETED_WITH_UNRESOLVED.value,
                )
            except SSHConnectionError as exc:
                return _save_preflight_failure(
                    audit, target_ip, args.output_dir, "CONNECTION_ERROR",
                    str(exc), Status.ERROR.value, OverallStatus.COMPLETED_WITH_UNRESOLVED.value,
                )
            except Exception as exc:
                return _save_preflight_failure(
                    audit, target_ip, args.output_dir, "PLATFORM_IDENTIFICATION_ERROR",
                    f"{type(exc).__name__}: {str(exc)[:500]}",
                    Status.ERROR.value, OverallStatus.COMPLETED_WITH_UNRESOLVED.value,
                )
            if device is None:
                return _save_preflight_failure(
                    audit, target_ip, args.output_dir, "PLATFORM_UNIDENTIFIED",
                    f"Target did not identify as {args.platform}",
                    Status.UNKNOWN.value, OverallStatus.COMPLETED_WITH_UNRESOLVED.value,
                )

        if device.platform != audit.platform:
            return _save_preflight_failure(
                audit, target_ip, args.output_dir, "PLATFORM_MISMATCH",
                f"Audit expects {audit.platform}; target identified as {device.platform}",
                Status.UNSUPPORTED.value, OverallStatus.COMPLETED_WITH_UNRESOLVED.value,
                device=device,
            )
        if not _compatible_version(device.platform, device.software_version, audit) and not args.allow_version_mismatch:
            return _save_preflight_failure(
                audit, target_ip, args.output_dir, "VERSION_NOT_CONFIRMED",
                f"Target version {device.software_version or 'unknown'} is not confirmed compatible with this benchmark",
                Status.UNKNOWN.value, OverallStatus.COMPLETED_WITH_UNRESOLVED.value,
                device=device,
            )

        print(f"Target identified: {device.vendor} {device.platform} {device.software_version or 'unknown'}")
        dispatcher = CheckDispatcher(registries.handlers)
        review_enabled = not args.no_review and sys.stdin.isatty()
        review_manager = ReviewManager(enabled=review_enabled, max_retries=args.max_retries)
        orchestrator = AssessmentOrchestrator(
            dispatcher=dispatcher,
            review_manager=review_manager,
        )
        storage = ResultStorage(args.output_dir)

        def checkpoint(run):
            storage.checkpoint(run)

        run = orchestrator.run(
            audit, adapter, device,
            command_timeout=args.command_timeout,
            on_checkpoint=checkpoint,
        )
        saved = storage.save(run)
        report = ReportBuilder().build(run)

        print("\nAssessment finished")
        print(f"Overall status: {run.overall_status}")
        print(f"Checks: {report['summary']['total_checks']} | PASS: {report['summary']['passed']} | "
              f"FAIL: {report['summary']['failed']} | Unresolved: "
              f"{report['summary']['manual_review'] + report['summary']['errors'] + report['summary']['unsupported'] + report['summary']['unknown']}")
        print(f"Report: {saved['report']}")
        print(f"Execution log: {saved['log']}")
        return 0 if run.overall_status in {
            OverallStatus.COMPLETED.value,
            OverallStatus.COMPLETED_WITH_UNRESOLVED.value,
        } else 2
    finally:
        if adapter is not None:
            adapter.close()
        else:
            transport.close()


def build_parser():
    parser = argparse.ArgumentParser(
        prog="uaudit",
        description="Universal Audit & Compliance Assessment Engine (read-only MVP)"
    )
    parser.add_argument("--version", action="version", version="Universal Audit Engine 1.0.0")
    sub = parser.add_subparsers(dest="command", required=True)

    parse_cmd = sub.add_parser("parse", help="Parse an audit file without connecting to a target")
    parse_cmd.add_argument("--audit", required=True)
    parse_cmd.add_argument("--variables-file")
    parse_cmd.add_argument("--output", help="Write canonical audit model as JSON")
    parse_cmd.set_defaults(func=_cmd_parse)

    validate_cmd = sub.add_parser("validate", help="Validate syntax and check coverage without SSH")
    validate_cmd.add_argument("--audit", required=True)
    validate_cmd.add_argument("--variables-file")
    validate_cmd.set_defaults(func=_cmd_parse)

    run_cmd = sub.add_parser("run", help="Run a read-only assessment against one IPv4 target")
    run_cmd.add_argument("--target", required=True, help="Target IPv4 address")
    run_cmd.add_argument("--audit", required=True, help="Path to a Tenable-compatible .audit file")
    run_cmd.add_argument("--username")
    run_cmd.add_argument("--port", type=int, default=22)
    run_cmd.add_argument("--platform", choices=["auto", "cisco_ios_xe", "fortigate", "vmware_esxi"], default="auto")
    run_cmd.add_argument("--known-hosts", help="Additional known_hosts file; unknown host keys are always rejected")
    run_cmd.add_argument("--key-file", help="SSH private key path (optional)")
    run_cmd.add_argument("--connect-timeout", type=int, default=15)
    run_cmd.add_argument("--command-timeout", type=int, default=45)
    run_cmd.add_argument("--max-retries", type=int, default=2)
    run_cmd.add_argument("--no-review", action="store_true", help="Do not prompt for manual/error/unsupported checks")
    run_cmd.add_argument("--allow-version-mismatch", action="store_true")
    run_cmd.add_argument("--variables-file", help="JSON variable overrides file (chmod 600)")
    run_cmd.add_argument("--output-dir", default="results")
    run_cmd.set_defaults(func=_cmd_run)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted by operator", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
