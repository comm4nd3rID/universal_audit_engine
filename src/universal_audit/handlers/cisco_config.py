
from __future__ import annotations

from universal_audit.handlers.base import BaseHandler
from universal_audit.handlers.config_extractors import extract_cisco_context, extract_cisco_banner


class CiscoConfigCheckHandler(BaseHandler):
    handler_id = "cisco.config"
    supported_check_types = {"CISCO_CONFIG_CHECK", "CISCO_CONFIG_CHECK_NOT"}

    def collect(self, check, adapter, context):
        command = check.parameters.get("cmd")
        if command:
            result = adapter.execute_readonly(str(command), timeout=context.get("command_timeout", 45))
            output = result.stdout
            source = "SSH_COMMAND"
            query = str(command)
        else:
            result = adapter.get_config(timeout=context.get("command_timeout", 90))
            output = result.stdout
            source = "RUNNING_CONFIG"
            query = "show running-config"
        selected = extract_cisco_context(output, check.parameters.get("context"))
        return self.evidence(
            source=source, command=query, output=selected,
            exit_code=result.exit_code, stderr=result.stderr,
            truncated=result.truncated,
        )


class CiscoBannerCheckHandler(BaseHandler):
    handler_id = "cisco.banner"
    supported_check_types = {"CISCO_BANNER_CHECK"}

    def collect(self, check, adapter, context):
        result = adapter.get_config(timeout=context.get("command_timeout", 90))
        selected = extract_cisco_banner(result.stdout, check.parameters.get("item"))
        return self.evidence(
            source="RUNNING_CONFIG", command="show running-config",
            output=selected, exit_code=result.exit_code,
            stderr=result.stderr, truncated=result.truncated,
        )
