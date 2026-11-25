
from __future__ import annotations

from universal_audit.handlers.base import BaseHandler


class UnixFileContentHandler(BaseHandler):
    handler_id = "unix.file_content"
    supported_check_types = {"UNIX_FILE_CONTENT", "UNIX_BANNER"}

    def collect(self, check, adapter, context):
        path = str(check.parameters.get("file", ""))
        result = adapter.read_file(path, timeout=context.get("command_timeout", 30))
        return self.evidence(
            source="SFTP_FILE", command=f"read {path}", output=result.stdout,
            exit_code=result.exit_code, stderr=result.stderr,
            truncated=result.truncated,
        )
