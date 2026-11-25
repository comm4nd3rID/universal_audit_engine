
from pathlib import Path

from universal_audit.adapters.ssh_transport import CommandResult
from universal_audit.audit.normalizer import normalize
from universal_audit.audit.parser import AuditParser
from universal_audit.audit.variables import resolve_variables
from universal_audit.core.evaluator import ComplianceEvaluator
from universal_audit.handlers.fortigate_context_regex import FortiGateContextRegexHandler
from universal_audit.handlers.config_extractors import extract_cisco_banner
from universal_audit.security.command_policy import CommandPolicy


ROOT = Path(__file__).resolve().parents[1]
AUDITS = ROOT / "audit_profiles"


def test_every_esxi_command_is_either_allowlisted_or_explicitly_unsupported():
    policy = CommandPolicy()
    audit = normalize(AuditParser().parse_file(
        AUDITS / "CIS_VMware_ESXi_9.0_v1.0.0_L1_Unix.audit"
    ))
    denied = []
    for check in audit.iter_checks():
        if check.canonical_check_type == "UNIX_COMMAND":
            decision = policy.authorize("vmware_esxi", check.parameters["cmd"])
            if not decision.allowed:
                denied.append(check.description)
    assert len(denied) == 2
    assert any("diagnostic logging" in item.lower() for item in denied)
    assert any("vmware.log" in item for item in denied)


def test_esxi_l2_command_policy_allows_simple_grep_pipelines():
    policy = CommandPolicy()
    audit = normalize(AuditParser().parse_file(
        AUDITS / "CIS_VMware_ESXi_9.0_v1.0.0_L2_Unix.audit"
    ))
    decisions = [
        policy.authorize("vmware_esxi", check.parameters["cmd"])
        for check in audit.iter_checks()
        if check.canonical_check_type == "UNIX_COMMAND"
    ]
    assert len(decisions) == 3
    assert all(item.allowed for item in decisions)


class MockFortiGateAdapter:
    platform_id = "fortigate"

    def get_config(self, timeout=120):
        return CommandResult(
            "show full-configuration",
            'config system dns\n    set primary 10.0.0.1\n    set secondary 10.0.0.2\nend\n'
            'config system global\n    set hostname edge-fw\nend\n',
        )


def test_fortigate_handler_extracts_context_and_evaluator_passes():
    audit = normalize(AuditParser().parse_file(
        AUDITS / "CIS_FortiGate_7.4.x_v1.0.1_L1.audit"
    ))
    resolve_variables(audit, {})
    check = next(c for c in audit.iter_checks() if c.description == "dns server 1")
    evidence = FortiGateContextRegexHandler().collect(check, MockFortiGateAdapter(), {})
    assert "config system dns" in evidence.raw_output
    assert "config system global" not in evidence.raw_output
    assert ComplianceEvaluator().evaluate(check, evidence).status == "PASS"


def test_unknown_tag_becomes_explicit_unsupported_check():
    source = '''
#<ui_metadata>
#<display_name>Unknown tag test</display_name>
#<spec><type>CIS</type><name>Test</name><profile>L1</profile><version>1</version></spec>
#</ui_metadata>
<check_type:"Cisco">
  <future_check>
    description : "Future executable node"
    command : "some command"
  </future_check>
</check_type>
'''
    audit = normalize(AuditParser().parse_text(source))
    checks = list(audit.iter_checks())
    assert len(checks) == 1
    assert checks[0].canonical_check_type == "UNSUPPORTED"
    assert checks[0].description == "Future executable node"


def test_cisco_banner_extraction_is_scoped_to_the_requested_banner():
    config = """banner exec ^C
EXEC NOTICE
^C
banner login ^C
LOGIN NOTICE
^C
"""
    exec_banner = extract_cisco_banner(config, r"^banner exec")
    login_banner = extract_cisco_banner(config, r"^banner login")
    assert "EXEC NOTICE" in exec_banner
    assert "LOGIN NOTICE" not in exec_banner
    assert "LOGIN NOTICE" in login_banner
    assert "EXEC NOTICE" not in login_banner
