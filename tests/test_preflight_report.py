
import json
from pathlib import Path

from universal_audit.audit.normalizer import normalize
from universal_audit.audit.parser import AuditParser
from universal_audit.audit.variables import resolve_variables
from universal_audit.cli.app import _save_preflight_failure
from universal_audit.core.enums import OverallStatus, Status


ROOT = Path(__file__).resolve().parents[1]


def test_connection_failure_generates_report_for_every_check(tmp_path, capsys):
    audit = normalize(AuditParser().parse_file(
        ROOT / "audit_profiles" / "CIS_VMware_ESXi_9.0_v1.0.0_L1_Unix.audit"
    ))
    resolve_variables(audit, {})
    result = _save_preflight_failure(
        audit=audit,
        target_ip="192.0.2.55",
        output_dir=str(tmp_path),
        code="CONNECTION_ERROR",
        message="SSH connection failed",
        status=Status.ERROR.value,
        overall_status=OverallStatus.FAILED.value,
    )
    assert result == 2
    report_path = next(tmp_path.rglob("report.json"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["assessment"]["overall_status"] == "FAILED"
    assert report["summary"]["total_checks"] == 52
    assert report["summary"]["errors"] == 52
    assert len(report["checks"]) == 52
    assert report["condition_evaluations"]
    assert all(item["execution_status"] == "BLOCKED" for item in report["checks"])
