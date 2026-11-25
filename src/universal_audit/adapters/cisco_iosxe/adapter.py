
from __future__ import annotations

import re

from universal_audit.adapters.base import BaseSSHAdapter
from universal_audit.adapters.ssh_transport import CommandResult
from universal_audit.core.models import DeviceInfo


class CiscoIOSXEAdapter(BaseSSHAdapter):
    platform_id = "cisco_ios_xe"
    vendor = "Cisco"

    def identify(self, ip_address: str) -> DeviceInfo | None:
        output = self.execute_readonly("show version", timeout=30).stdout
        if not re.search(r"Cisco IOS XE Software|Cisco IOS Software|Cisco IOS XE", output, re.I):
            return None
        version_match = re.search(r"(?:Version|version)\s+([0-9][A-Za-z0-9()._-]+)", output)
        hostname_match = re.search(r"(?im)^([A-Za-z0-9_.-]+)\s+uptime is", output)
        self._version = version_match.group(1) if version_match else None
        self._hostname = hostname_match.group(1) if hostname_match else None
        return DeviceInfo(
            ip_address=ip_address,
            hostname=self._hostname,
            vendor=self.vendor,
            platform=self.platform_id,
            software_version=self._version,
            identification_evidence=output[:2000],
        )

    def get_config(self, timeout: int = 90) -> CommandResult:
        if self._config_cache is None:
            self.execute_readonly("terminal length 0", timeout=15)
            result = self.execute_readonly("show running-config", timeout=timeout)
            self._config_cache = result
            if self._hostname is None:
                match = re.search(r"(?im)^hostname\s+(\S+)", result.stdout)
                if match:
                    self._hostname = match.group(1)
        return self._config_cache
