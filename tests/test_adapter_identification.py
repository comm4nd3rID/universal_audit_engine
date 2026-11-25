
from universal_audit.adapters.cisco_iosxe.adapter import CiscoIOSXEAdapter
from universal_audit.adapters.fortigate.adapter import FortiGateAdapter
from universal_audit.adapters.vmware_esxi.adapter import VMwareESXiAdapter
from universal_audit.adapters.ssh_transport import CommandResult


class FakeTransport:
    def __init__(self, output):
        self.output = output
        self.commands = []

    def execute(self, command, timeout=30):
        self.commands.append(command)
        return CommandResult(command, self.output)

    def execute_exec(self, command, timeout=30):
        self.commands.append(command)
        return CommandResult(command, self.output, exit_code=0)

    def close(self):
        pass


def test_cisco_iosxe_identification_extracts_version():
    transport = FakeTransport("Cisco IOS XE Software, Version 17.12.4\n")
    info = CiscoIOSXEAdapter(transport).identify("192.0.2.1")
    assert info.platform == "cisco_ios_xe"
    assert info.software_version == "17.12.4"


def test_fortigate_identification_extracts_hostname_and_version():
    transport = FakeTransport("Version: FortiGate-100F v7.4.3,build2573\nHostname: edge-fw\n")
    info = FortiGateAdapter(transport).identify("192.0.2.2")
    assert info.platform == "fortigate"
    assert info.hostname == "edge-fw"
    assert info.software_version == "7.4.3"


def test_esxi_identification_extracts_hostname_and_version():
    transport = FakeTransport("VMkernel esxi-lab 9.0.0 #1 SMP Release build-123456 x86_64\n")
    info = VMwareESXiAdapter(transport).identify("192.0.2.3")
    assert info.platform == "vmware_esxi"
    assert info.hostname == "esxi-lab"
    assert info.software_version == "9.0.0"


def test_interactive_cli_permission_denial_is_not_misclassified_as_compliance_fail():
    import pytest

    adapter = CiscoIOSXEAdapter(FakeTransport("% Authorization failed\n"))
    with pytest.raises(PermissionError):
        adapter.execute_readonly("show version")
