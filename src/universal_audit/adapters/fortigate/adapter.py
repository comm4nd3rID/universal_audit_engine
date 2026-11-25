
from __future__ import annotations

import re

from universal_audit.adapters.base import BaseSSHAdapter
from universal_audit.adapters.ssh_transport import CommandResult
from universal_audit.core.models import DeviceInfo


class FortiGateAdapter(BaseSSHAdapter):
    platform_id = "fortigate"
    vendor = "Fortinet"

    def identify(self, ip_address: str) -> DeviceInfo | None:
        output = self.execute_readonly("get system status", timeout=30).stdout
        if not re.search(r"(?im)^Version:\s*.*(?:FortiGate|FortiOS)", output):
            return None
        hostname_match = re.search(r"(?im)^Hostname:\s*(.+?)\s*$", output)
        version_match = re.search(r"(?im)^Version:\s*.*?\bv?(\d+\.\d+(?:\.\d+)?)", output)
        self._hostname = hostname_match.group(1).strip() if hostname_match else None
        self._version = version_match.group(1) if version_match else None
        return DeviceInfo(
            ip_address=ip_address,
            hostname=self._hostname,
            vendor=self.vendor,
            platform=self.platform_id,
            software_version=self._version,
            identification_evidence=output[:2000],
        )

    def get_config(self, timeout: int = 120) -> CommandResult:
        if self._config_cache is None:
            self._config_cache = self.execute_readonly("show full-configuration", timeout=timeout)
            if self._hostname is None:
                match = re.search(r"(?im)^set hostname\s+(.+)$", self._config_cache.stdout)
                if match:
                    self._hostname = match.group(1).strip().strip('"')
        return self._config_cache
