
from universal_audit.core.evaluator import ComplianceEvaluator
from universal_audit.core.models import CheckDefinition, Evidence
from universal_audit.core.enums import Status
from universal_audit.security.command_policy import CommandPolicy
from universal_audit.adapters.ssh_transport import CommandResult
from universal_audit.core.dispatcher import CheckDispatcher
from universal_audit.handlers.registry import build_default_handler_registry


def check(kind, **params):
    return CheckDefinition(
        check_id="test-id",
        description="test",
        original_check_type=kind,
        canonical_check_type=kind,
        platform="test",
        parameters=params,
        expected=params.get("expect"),
    )


def evidence(text, truncated=False):
    return Evidence("MOCK", "mock-command", text, truncated=truncated)


def test_cisco_config_check_pass_and_fail():
    evaluator = ComplianceEvaluator()
    c = check("CISCO_CONFIG_CHECK", item="^aaa new-model$")
    assert evaluator.evaluate(c, evidence("aaa new-model")).status == Status.PASS.value
    assert evaluator.evaluate(c, evidence("no aaa new-model")).status == Status.FAIL.value


def test_cisco_config_check_not():
    evaluator = ComplianceEvaluator()
    c = check("CISCO_CONFIG_CHECK_NOT", item="^ip http server$")
    assert evaluator.evaluate(c, evidence("hostname edge")).status == Status.PASS.value
    assert evaluator.evaluate(c, evidence("ip http server")).status == Status.FAIL.value


def test_fortigate_expect_and_not_expect():
    evaluator = ComplianceEvaluator()
    c = check(
        "FORTIGATE_CONTEXT_REGEX",
        regex=r"set\s+primary\s+",
        expect=r"set\s+primary\s+10\.0\.0\.1",
    )
    assert evaluator.evaluate(c, evidence("config system dns\n set primary 10.0.0.1\nend")).status == Status.PASS.value
    assert evaluator.evaluate(c, evidence("config system dns\n set primary 8.8.8.8\nend")).status == Status.FAIL.value


def test_manual_review_marker_is_not_a_failure():
    evaluator = ComplianceEvaluator()
    c = check("UNIX_COMMAND", expect="^Manual Review Required$")
    assert evaluator.evaluate(c, evidence("Manual Review Required")).status == Status.MANUAL_REVIEW.value


def test_truncated_negative_evidence_is_unknown():
    evaluator = ComplianceEvaluator()
    c = check("UNIX_COMMAND", expect="^VMkernel$")
    assert evaluator.evaluate(c, evidence("partial", truncated=True)).status == Status.UNKNOWN.value


def test_command_policy_is_deny_by_default_and_supports_local_grep():
    policy = CommandPolicy()
    allowed = policy.authorize("vmware_esxi", "/bin/esxcli system ntp get")
    assert allowed.allowed
    pipeline = policy.authorize(
        "vmware_esxi", "/bin/esxcli system process list | /bin/grep -i ntp"
    )
    assert pipeline.allowed
    assert pipeline.command_to_execute == "/bin/esxcli system process list"
    assert pipeline.local_filter["pattern"] == "ntp"
    denied = policy.authorize("vmware_esxi", "esxcli system ntp set")
    assert not denied.allowed
    assert not policy.authorize("cisco_ios_xe", "write memory").allowed
    assert not policy.authorize("fortigate", "config system global").allowed


def test_file_read_policy_blocks_path_traversal():
    policy = CommandPolicy()
    assert policy.authorize_file_read("vmware_esxi", "/etc/ssh/sshd_config").allowed
    assert not policy.authorize_file_read("vmware_esxi", "/etc/../bootbank").allowed
    assert not policy.authorize_file_read("vmware_esxi", "/vmfs/volumes/a.vmx").allowed


def test_fortigate_absence_check_on_truncated_evidence_is_unknown():
    evaluator = ComplianceEvaluator()
    c = check("FORTIGATE_CONTEXT_REGEX", not_expect=r"set\s+allowaccess\s+.*http")
    result = evaluator.evaluate(c, evidence("config system interface\n set allowaccess ping\n", truncated=True))
    assert result.status == Status.UNKNOWN.value


def test_nonzero_command_exit_is_error_not_compliance_fail():
    class FailedEsxiAdapter:
        platform_id = "vmware_esxi"

        def execute_readonly(self, command, timeout=30):
            return CommandResult(command, "", stderr="Permission denied", exit_code=126)

    definition = CheckDefinition(
        check_id="esxi-error-1",
        description="ESXi read-only command",
        original_check_type="CMD_EXEC",
        canonical_check_type="UNIX_COMMAND",
        platform="vmware_esxi",
        parameters={"cmd": "uname -a", "expect": "VMkernel"},
        expected="VMkernel",
    )
    result = CheckDispatcher(build_default_handler_registry()).execute(
        definition, FailedEsxiAdapter(), {"command_timeout": 10}
    )
    assert result.status == Status.ERROR.value
    assert result.error["code"] == "PERMISSION_DENIED"
    assert result.evidence[0].stderr == "Permission denied"
    assert result.evidence[0].exit_code == 126
