
from __future__ import annotations

import getpass
from dataclasses import dataclass


@dataclass
class Credentials:
    username: str
    password: str | None = None
    key_filename: str | None = None


class PromptCredentialProvider:
    """Interactive credential provider; never echoes or persists passwords."""

    def obtain(self, username: str | None = None, key_filename: str | None = None) -> Credentials:
        username = username or input("SSH username: ").strip()
        if not username:
            raise ValueError("SSH username is required")
        password = getpass.getpass("SSH password (leave empty to use SSH key/agent): ") or None
        return Credentials(username=username, password=password, key_filename=key_filename)
