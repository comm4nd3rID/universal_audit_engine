
from __future__ import annotations

import re

from universal_audit.adapters.base import BaseSSHAdapter, UnsupportedOperation
from universal_audit.adapters.ssh_transport import CommandResult
from universal_audit.core.models import DeviceInfo


class VMwareESXiAdapter(BaseSSHAdapter):
    platform_id = "vmware_esxi"
    vendor = "VMware"

    def execute_readonly(self, command: str, timeout: int = 30) -> CommandResult:
        decision = self.policy.authorize(self.platform_id, command)
        if not decision.allowed or not decision.command_to_execute:
            raise UnsupportedOperation(decision.reason or "Command rejected by read-only policy")
        result = self.transport.execute_exec(decision.command_to_execute, timeout=timeout)
        if decision.local_filter:
            result.stdout = self._apply_local_filter(result.stdout, decision.local_filter)
            result.command = command
        return result

    def identify(self, ip_address: str) -> DeviceInfo | None:
        output = self.execute_readonly("uname -a", timeout=20).stdout
        if not re.search(r"VMkernel", output, re.I):
            return None
        identity_match = re.search(r"VMkernel\s+(\S+)\s+([0-9][A-Za-z0-9._-]*)", output, re.I)
        self._hostname = identity_match.group(1) if identity_match else None
        self._version = identity_match.group(2) if identity_match else None
        return DeviceInfo(
            ip_address=ip_address,
            hostname=self._hostname,
            vendor=self.vendor,
            platform=self.platform_id,
            software_version=self._version,
            identification_evidence=output[:2000],
        )

    def get_config(self, timeout: int = 60) -> CommandResult:
        raise UnsupportedOperation("ESXi checks use explicit CMD_EXEC or SFTP file reads; no generic config dump is used")
