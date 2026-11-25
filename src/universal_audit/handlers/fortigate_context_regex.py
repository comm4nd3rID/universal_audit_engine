
from __future__ import annotations

from universal_audit.handlers.base import BaseHandler
from universal_audit.handlers.config_extractors import extract_fortigate_context


class FortiGateContextRegexHandler(BaseHandler):
    handler_id = "fortigate.context_regex"
    supported_check_types = {"FORTIGATE_CONTEXT_REGEX"}

    def collect(self, check, adapter, context):
        result = adapter.get_config(timeout=context.get("command_timeout", 120))
        selected = extract_fortigate_context(result.stdout, check.parameters.get("context"))
        return self.evidence(
            source="FULL_CONFIGURATION",
            command="show full-configuration",
            output=selected,
            exit_code=result.exit_code,
            stderr=result.stderr,
            truncated=result.truncated,
        )


class FortiGateBannerHandler(BaseHandler):
    handler_id = "fortigate.banner"
    supported_check_types = {"FORTIGATE_BANNER_CHECK"}

    def collect(self, check, adapter, context):
        result = adapter.get_config(timeout=context.get("command_timeout", 120))
        selected = extract_fortigate_context(result.stdout, check.parameters.get("context"))
        return self.evidence(
            source="FULL_CONFIGURATION",
            command="show full-configuration",
            output=selected,
            exit_code=result.exit_code,
            stderr=result.stderr,
            truncated=result.truncated,
        )


class FortiGateCommandHandler(BaseHandler):
    handler_id = "fortigate.command"
    supported_check_types = {"FORTIGATE_COMMAND"}

    def collect(self, check, adapter, context):
        command = str(check.parameters.get("cmd", ""))
        result = adapter.execute_readonly(command, timeout=context.get("command_timeout", 45))
        return self.evidence(
            source="SSH_COMMAND", command=command, output=result.stdout,
            exit_code=result.exit_code, stderr=result.stderr,
            truncated=result.truncated,
        )
