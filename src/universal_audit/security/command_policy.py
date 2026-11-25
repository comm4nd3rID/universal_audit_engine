
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PolicyDecision:
    allowed: bool
    command_to_execute: str | None = None
    local_filter: dict[str, str | bool] | None = None
    reason: str | None = None


CISCO_COMMANDS = {
    "show version",
    "terminal length 0",
    "show running-config",
    "show snmp user",
    "show crypto key mypubkey rsa",
}

FORTIGATE_COMMANDS = {
    "get system status",
    "show full-configuration",
}

ESXI_SIMPLE_COMMANDS = {
    "uname -a",
    "/usr/lib/vmware/secureboot/bin/secureBoot.py -s",
    "/bin/esxcli hardware trustedboot get",
    "/bin/esxcli hardware cpu list",
    "/bin/esxcfg-info",
    "/bin/esxcli network firewall get",
    "/bin/esxcli network firewall ruleset list",
    "/bin/esxcli network ip interface list",
    "/bin/esxcli software profile get",
    "/bin/esxcli software vib list",
    "/bin/esxcli storage filesystem list",
    "/bin/esxcli system account list",
    "/bin/esxcli system auditrecords get",
    "/bin/esxcli system ntp config get",
    "/bin/esxcli system ntp get",
    "/bin/esxcli system process list",
    "/bin/esxcli system settings encryption get",
    "/bin/esxcli system settings kernel list -o disableHwrng",
    "/bin/esxcli system settings kernel list -o entropySources",
    "/bin/esxcli system settings kernel list -o execInstalledOnly",
    "/bin/esxcli system snmp get",
    "/bin/esxcli system syslog config get",
    "/bin/esxcli system syslog config logfilter get",
    "/bin/esxcli system syslog config logger list",
    "/bin/esxcli system version get",
    "esxcli software acceptance get",
}

# Only the exact read-only pipelines present in the supplied ESXi audit files
# are supported. The grep stage is applied locally; it is not sent to the shell.
ESXI_PIPELINES = {
    "/bin/esxcli system process list | /bin/grep -i ntp": (
        "/bin/esxcli system process list", {"pattern": "ntp", "ignore_case": True, "invert": False}
    ),
    "/bin/esxcli system syslog config logger list | /bin/grep 'ID:'": (
        "/bin/esxcli system syslog config logger list", {"pattern": "ID:", "ignore_case": False, "invert": False}
    ),
    "/bin/esxcli system syslog config get | /bin/grep 'Log Level'": (
        "/bin/esxcli system syslog config get", {"pattern": "Log Level", "ignore_case": False, "invert": False}
    ),
    "/bin/esxcli system auditrecords get | /bin/grep 'Storage Active'": (
        "/bin/esxcli system auditrecords get", {"pattern": "Storage Active", "ignore_case": False, "invert": False}
    ),
    "/bin/esxcli system auditrecords get | /bin/grep 'Audit Record'": (
        "/bin/esxcli system auditrecords get", {"pattern": "Audit Record", "ignore_case": False, "invert": False}
    ),
    "/bin/esxcli system auditrecords get | /bin/grep 'Storage Capacity'": (
        "/bin/esxcli system auditrecords get", {"pattern": "Storage Capacity", "ignore_case": False, "invert": False}
    ),
    "/bin/esxcli hardware cpu list | /bin/grep 'Brand:'": (
        "/bin/esxcli hardware cpu list", {"pattern": "Brand:", "ignore_case": False, "invert": False}
    ),
    "/bin/esxcfg-info 2>/dev/null | /bin/grep -E 'HV Support[.]+'": (
        "/bin/esxcfg-info", {"pattern": "HV Support[.]+", "ignore_case": False, "invert": False}
    ),
}


class CommandPolicy:
    """Platform-aware, deny-by-default read-only command policy."""

    def authorize(self, platform: str, command: str) -> PolicyDecision:
        command = command.strip()
        if not command or len(command) > 2048 or "\n" in command or "\r" in command:
            return PolicyDecision(False, reason="Empty, multiline, or oversized command")
        if platform == "cisco_ios_xe":
            if command in CISCO_COMMANDS:
                return PolicyDecision(True, command_to_execute=command)
            return PolicyDecision(False, reason="Command is not in the Cisco read-only allowlist")
        if platform == "fortigate":
            if command in FORTIGATE_COMMANDS:
                return PolicyDecision(True, command_to_execute=command)
            return PolicyDecision(False, reason="Command is not in the FortiGate read-only allowlist")
        if platform == "vmware_esxi":
            if command in ESXI_SIMPLE_COMMANDS:
                return PolicyDecision(True, command_to_execute=command)
            if command in ESXI_PIPELINES:
                base, local_filter = ESXI_PIPELINES[command]
                return PolicyDecision(True, command_to_execute=base, local_filter=local_filter)
            return PolicyDecision(False, reason="Command is not in the ESXi read-only allowlist")
        return PolicyDecision(False, reason=f"No command policy registered for platform {platform}")

    def authorize_file_read(self, platform: str, path: str) -> PolicyDecision:
        if platform != "vmware_esxi":
            return PolicyDecision(False, reason="Remote file reads are not enabled for this platform")
        if not path.startswith("/") or ".." in path.split("/") or "\x00" in path:
            return PolicyDecision(False, reason="Unsafe file path")
        allowed_files = {
            "/etc/passwd",
            "/etc/ssh/sshd_config",
            "/etc/issue",
        }
        if path not in allowed_files:
            return PolicyDecision(False, reason="File path is not in the ESXi file-read allowlist")
        return PolicyDecision(True, command_to_execute=path)
