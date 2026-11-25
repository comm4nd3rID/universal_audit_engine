
import json
import tempfile

from universal_audit.adapters.ssh_transport import CommandResult
from universal_audit.audit.normalizer import normalize
from universal_audit.audit.parser import AuditParser
from universal_audit.cli.prompts import ReviewManager
from universal_audit.core.dispatcher import CheckDispatcher
from universal_audit.core.models import DeviceInfo
from universal_audit.core.orchestrator import AssessmentOrchestrator
from universal_audit.handlers.registry import build_default_handler_registry
from universal_audit.reporting.storage import ResultStorage


SYNTHETIC_AUDIT = r'''
#<ui_metadata>
#<display_name>Unit test audit</display_name>
#<spec>
#  <type>CIS</type>
#  <name>Cisco IOS XE 17.x</name>
#  <profile>L1</profile>
#  <version>1.0</version>
#</spec>
#</ui_metadata>
<check_type:"Cisco">
<if>
  <condition type:"AND">
    <item>
      type : CONFIG_CHECK
      description : "Gate check"
      item : "^aaa new-model$"
    </item>
  </condition>
  <then>
    <item>
      type : CONFIG_CHECK
      description : "Then check"
      item : "^logging buffered 64000$"
    </item>
  </then>
  <else>
    <item>
      type : CONFIG_CHECK
      description : "Else check"
      item : "^hostname forbidden$"
    </item>
  </else>
</if>
</check_type>
'''


class MockCiscoAdapter:
    platform_id = "cisco_ios_xe"

    def get_config(self, timeout=60):
        return CommandResult("show running-config", "aaa new-model\nlogging buffered 64000\nhostname edge\n")

    def execute_readonly(self, command, timeout=30):
        return CommandResult(command, "")

    def read_file(self, path, timeout=30):
        return CommandResult(f"read {path}", "")

    def close(self):
        pass


def test_condition_branch_skip_and_json_report_storage():
    parsed = AuditParser().parse_text(SYNTHETIC_AUDIT)
    audit = normalize(parsed)
    adapter = MockCiscoAdapter()
    dispatcher = CheckDispatcher(build_default_handler_registry())
    orchestrator = AssessmentOrchestrator(
        dispatcher,
        review_manager=ReviewManager(enabled=False),
    )
    device = DeviceInfo(
        ip_address="192.0.2.10",
        hostname="edge",
        vendor="Cisco",
        platform="cisco_ios_xe",
        software_version="17.12.1",
    )
    run = orchestrator.run(audit, adapter, device)
    assert len(run.results) == 3
    statuses = {result.description: result.status for result in run.results.values()}
    assert statuses["Gate check"] == "PASS"
    assert statuses["Then check"] == "PASS"
    assert statuses["Else check"] == "SKIPPED"

    with tempfile.TemporaryDirectory() as temp:
        storage = ResultStorage(temp)
        saved = storage.save(run)
        report = json.loads(saved["report"].read_text(encoding="utf-8"))
        assert report["summary"]["total_checks"] == 3
        assert report["summary"]["passed"] == 2
        assert report["summary"]["skipped"] == 1
        assert len(report["condition_evaluations"]) == 1
        assert report["condition_evaluations"][0]["result"] is True
        assert report["condition_evaluations"][0]["selected_branch"] == "THEN"
        assert saved["report"].is_file()
        assert saved["log"].is_file()
        try:
            storage._atomic_write(saved["report"], "overwrite", replace=False)
        except FileExistsError:
            pass
        else:
            raise AssertionError("Storage overwrote an existing final report")


def test_fatal_interruption_still_reports_every_audit_check_as_skipped():
    parsed = AuditParser().parse_text(SYNTHETIC_AUDIT)
    audit = normalize(parsed)
    adapter = MockCiscoAdapter()
    dispatcher = CheckDispatcher(build_default_handler_registry())
    orchestrator = AssessmentOrchestrator(
        dispatcher,
        review_manager=ReviewManager(enabled=False),
    )
    device = DeviceInfo(
        ip_address="192.0.2.10",
        hostname="edge",
        vendor="Cisco",
        platform="cisco_ios_xe",
        software_version="17.12.1",
    )

    def broken_checkpoint(run):
        raise RuntimeError("simulated checkpoint storage failure")

    run = orchestrator.run(audit, adapter, device, on_checkpoint=broken_checkpoint)
    assert run.overall_status == "FAILED"
    assert len(run.results) == len(list(audit.iter_checks())) == 3
    assert sum(1 for item in run.results.values() if item.status == "SKIPPED") == 2
    assert len(run.condition_evaluations) == 1
    assert run.condition_evaluations[0]["branch_status"] == "ASSESSMENT_FATAL_ERROR"
