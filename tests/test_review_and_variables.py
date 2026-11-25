
from unittest.mock import patch

from universal_audit.audit.normalizer import normalize
from universal_audit.audit.parser import AuditParser
from universal_audit.audit.variables import resolve_variables
from universal_audit.cli.prompts import ReviewManager
from universal_audit.core.models import (
    AssessmentRun, CheckDefinition, CheckResult, DeviceInfo, Evidence, utc_now
)
from universal_audit.reporting.report_builder import ReportBuilder
from universal_audit.core.enums import ExecutionStatus, ResultSource


def test_review_manual_pass_requires_and_records_justification():
    check = CheckDefinition(
        check_id="manual-1",
        description="Manual control",
        original_check_type="CMD_EXEC",
        canonical_check_type="UNIX_COMMAND",
        platform="vmware_esxi",
        parameters={},
    )
    result = CheckResult(
        check_id="manual-1",
        description="Manual control",
        original_check_type="CMD_EXEC",
        canonical_check_type="UNIX_COMMAND",
        status="MANUAL_REVIEW",
        execution_status="MANUAL",
    )
    with patch("builtins.input", side_effect=["p", "Verified in vCenter UI"]):
        reviewed, abort = ReviewManager(enabled=True).review(check, result, lambda _: result)
    assert not abort
    assert reviewed.status == "PASS"
    assert reviewed.execution_status == ExecutionStatus.MANUAL.value
    assert reviewed.result_source == ResultSource.MANUAL.value
    assert reviewed.operator_decision.justification == "Verified in vCenter UI"


def test_variable_override_takes_precedence_and_sensitive_values_are_masked():
    source = '''
#<ui_metadata>
#<display_name>Variable test</display_name>
#<spec><type>CIS</type><name>Test</name><profile>L1</profile><version>1</version></spec>
#<variables>
#  <variable><name>ADMIN_PASSWORD</name><default>default-password</default><value_type>STRING</value_type></variable>
#</variables>
#</ui_metadata>
<check_type:"Cisco">
  <item>
    type : CONFIG_CHECK
    description : "Check secret placeholder"
    item : "secret @ADMIN_PASSWORD@"
  </item>
</check_type>
'''
    audit = normalize(AuditParser().parse_text(source))
    resolve_variables(audit, {"ADMIN_PASSWORD": "override-secret"})
    check = next(audit.iter_checks())
    assert check.parameters["item"] == "secret override-secret"
    assert audit.resolved_variables["ADMIN_PASSWORD"] == "[REDACTED]"
    assert "override-secret" in audit.secret_values

def test_report_redacts_sensitive_variable_values_from_all_evidence_fields():
    source = '''
#<ui_metadata>
#<display_name>Variable report test</display_name>
#<spec><type>CIS</type><name>Test</name><profile>L1</profile><version>1</version></spec>
#<variables>
#  <variable><name>ADMIN_PASSWORD</name><default>default-password</default><value_type>STRING</value_type></variable>
#</variables>
#</ui_metadata>
<check_type:"Cisco">
  <item>
    type : CONFIG_CHECK
    description : "Secret check"
    item : "secret @ADMIN_PASSWORD@"
  </item>
</check_type>
'''
    audit = normalize(AuditParser().parse_text(source))
    resolve_variables(audit, {"ADMIN_PASSWORD": "override-secret"})
    check = next(audit.iter_checks())
    result = CheckResult(
        check_id=check.check_id,
        description=check.description,
        original_check_type=check.original_check_type,
        canonical_check_type=check.canonical_check_type,
        status="PASS",
        execution_status="COMPLETED",
        result_source="AUTOMATIC",
        expected="secret override-secret",
        actual="secret override-secret",
        evidence=[Evidence("MOCK", "mock", "secret override-secret\nset password override-secret")],
        raw_definition=check.raw_definition,
        source_location=check.source_location,
    )
    run = AssessmentRun(
        assessment_id="assessment-secret",
        started_at=utc_now(),
        target=DeviceInfo("192.0.2.10", platform="cisco_ios_xe"),
        audit=audit,
        results={check.check_id: result},
        ended_at=utc_now(),
        overall_status="COMPLETED",
    )
    import json
    serialized = json.dumps(ReportBuilder().build(run))
    assert "override-secret" not in serialized
    assert "[REDACTED]" in serialized
