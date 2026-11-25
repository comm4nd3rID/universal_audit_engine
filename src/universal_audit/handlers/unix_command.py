
from __future__ import annotations

from universal_audit.handlers.base import BaseHandler


class UnixCommandHandler(BaseHandler):
    handler_id = "unix.command"
    supported_check_types = {"UNIX_COMMAND"}

    def collect(self, check, adapter, context):
        command = str(check.parameters.get("cmd", ""))
        result = adapter.execute_readonly(command, timeout=context.get("command_timeout", 45))
        return self.evidence(
            source="SSH_COMMAND", command=command, output=result.stdout,
            exit_code=result.exit_code, stderr=result.stderr,
            truncated=result.truncated,
        )
