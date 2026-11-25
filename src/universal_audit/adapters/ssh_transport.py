
from __future__ import annotations

import socket
import time
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CommandResult:
    command: str
    stdout: str
    stderr: str = ""
    exit_code: int | None = None
    truncated: bool = False


class SSHConnectionError(RuntimeError):
    pass


class SSHAuthenticationError(SSHConnectionError):
    pass


class SSHCommandTimeout(TimeoutError):
    pass


class SSHCommandFailure(RuntimeError):
    pass


class SSHTransport:
    """Strict-host-key SSH transport with an interactive command channel.

    It does not auto-trust host keys. Add the target key to known_hosts out of band.
    """

    _ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")

    @classmethod
    def _clean_text(cls, value: str) -> str:
        value = cls._ANSI_RE.sub("", value)
        return value.replace("\r\n", "\n").replace("\r", "\n").replace("\x08", "")

    def __init__(self, max_output_bytes: int = 5_000_000):
        self.max_output_bytes = max_output_bytes
        self.client = None
        self.channel = None
        self.host = None
        self.username = None
        self._sftp = None

    def connect(self, host: str, username: str, password: str | None = None,
                port: int = 22, known_hosts: str | None = None,
                timeout: int = 15, key_filename: str | None = None) -> None:
        try:
            import paramiko
        except ImportError as exc:
            raise SSHConnectionError(
                "Paramiko is required for SSH execution. Install project dependencies first."
            ) from exc

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if known_hosts:
            kh = Path(known_hosts).expanduser()
            if not kh.is_file():
                raise SSHConnectionError(f"Known-hosts file does not exist: {kh}")
            client.load_host_keys(str(kh))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        try:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                key_filename=key_filename,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                look_for_keys=True,
                allow_agent=True,
            )
            self.client = client
            self.host = host
            self.username = username
        except paramiko.AuthenticationException as exc:
            try:
                client.close()
            except Exception:
                pass
            raise SSHAuthenticationError("SSH authentication failed") from exc
        except Exception as exc:
            try:
                client.close()
            except Exception:
                pass
            raise SSHConnectionError(f"SSH connection failed: {type(exc).__name__}: {exc}") from exc

    def _ensure_shell(self) -> None:
        if self.client is None:
            raise SSHConnectionError("SSH is not connected")
        if self.channel is None or self.channel.closed:
            self.channel = self.client.invoke_shell(term="vt100", width=240, height=1000)
            self.channel.settimeout(0.25)
            self._drain_startup()

    def _reset_shell(self) -> None:
        if self.client is None:
            self.channel = None
            return
        try:
            if self.channel is not None:
                self.channel.close()
        except Exception:
            pass
        self.channel = None
        self._ensure_shell()

    def _drain_startup(self) -> None:
        if self.channel is None:
            return
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                if self.channel.recv_ready():
                    self.channel.recv(65536)
                else:
                    time.sleep(0.05)
            except socket.timeout:
                continue
            except Exception:
                break

    def execute(self, command: str, timeout: int = 30, quiet_period: float = 1.0) -> CommandResult:
        self._ensure_shell()
        if "\n" in command or "\r" in command:
            raise ValueError("Multiline remote commands are prohibited")
        try:
            self.channel.send(command + "\n")
        except Exception as exc:
            raise SSHConnectionError(f"Unable to send remote command: {type(exc).__name__}") from exc

        chunks: list[bytes] = []
        size = 0
        truncated = False
        started = time.monotonic()
        last_data = started
        saw_data = False

        while time.monotonic() - started < timeout:
            try:
                if self.channel.recv_ready():
                    chunk = self.channel.recv(min(65536, self.max_output_bytes - size + 1))
                    if chunk:
                        saw_data = True
                        last_data = time.monotonic()
                        size += len(chunk)
                        if size <= self.max_output_bytes:
                            chunks.append(chunk)
                        else:
                            truncated = True
                            remaining = self.max_output_bytes - (size - len(chunk))
                            if remaining > 0:
                                chunks.append(chunk[:remaining])
                            self._reset_shell()
                            break
                else:
                    if saw_data and time.monotonic() - last_data >= quiet_period:
                        break
                    if not saw_data and time.monotonic() - started >= min(3.0, float(timeout)):
                        break
                    time.sleep(0.05)
            except socket.timeout:
                if saw_data and time.monotonic() - last_data >= quiet_period:
                    break
            except Exception as exc:
                raise SSHConnectionError(f"SSH read failed: {type(exc).__name__}") from exc

        else:
            self._reset_shell()
            raise SSHCommandTimeout(f"Remote command exceeded {timeout} seconds")

        output = self._clean_text(b"".join(chunks).decode("utf-8", errors="replace"))
        return CommandResult(command=command, stdout=output, truncated=truncated)

    def execute_exec(self, command: str, timeout: int = 30) -> CommandResult:
        """Execute one already-authorized non-interactive command and keep stdout/stderr separate."""
        if self.client is None:
            raise SSHConnectionError("SSH is not connected")
        if "\n" in command or "\r" in command:
            raise ValueError("Multiline remote commands are prohibited")
        transport = self.client.get_transport()
        if transport is None or not transport.is_active():
            raise SSHConnectionError("SSH transport is not active")
        channel = transport.open_session(timeout=timeout)
        channel.settimeout(0.25)
        try:
            channel.exec_command(command)
            stdout_chunks: list[bytes] = []
            stderr_chunks: list[bytes] = []
            stdout_size = 0
            stderr_size = 0
            truncated = False
            started = time.monotonic()

            while True:
                received = False
                while channel.recv_ready():
                    chunk = channel.recv(65536)
                    if not chunk:
                        break
                    received = True
                    stdout_size += len(chunk)
                    if stdout_size <= self.max_output_bytes:
                        stdout_chunks.append(chunk)
                    else:
                        truncated = True
                        remaining = self.max_output_bytes - (stdout_size - len(chunk))
                        if remaining > 0:
                            stdout_chunks.append(chunk[:remaining])

                while channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(65536)
                    if not chunk:
                        break
                    received = True
                    stderr_size += len(chunk)
                    if stderr_size <= 500_000:
                        stderr_chunks.append(chunk)
                    else:
                        truncated = True

                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    break
                if time.monotonic() - started >= timeout:
                    raise SSHCommandTimeout(f"Remote command exceeded {timeout} seconds")
                if not received:
                    time.sleep(0.03)

            exit_code = channel.recv_exit_status()
            return CommandResult(
                command=command,
                stdout=self._clean_text(b"".join(stdout_chunks).decode("utf-8", errors="replace")),
                stderr=self._clean_text(b"".join(stderr_chunks).decode("utf-8", errors="replace")),
                exit_code=exit_code,
                truncated=truncated,
            )
        except SSHCommandTimeout:
            raise
        except Exception as exc:
            raise SSHConnectionError(f"SSH exec channel failed: {type(exc).__name__}: {exc}") from exc
        finally:
            try:
                channel.close()
            except Exception:
                pass

    def read_file(self, path: str, max_bytes: int = 2_000_000, timeout: int = 30) -> CommandResult:
        if self.client is None:
            raise SSHConnectionError("SSH is not connected")
        try:
            if self._sftp is None:
                self._sftp = self.client.open_sftp()
                try:
                    self._sftp.get_channel().settimeout(timeout)
                except Exception:
                    pass
            with self._sftp.open(path, "rb") as handle:
                data = handle.read(max_bytes + 1)
            truncated = len(data) > max_bytes
            if truncated:
                data = data[:max_bytes]
            return CommandResult(
                command=f"SFTP READ {path}",
                stdout=self._clean_text(data.decode("utf-8", errors="replace")),
                truncated=truncated,
            )
        except FileNotFoundError:
            raise
        except PermissionError:
            raise
        except Exception as exc:
            raise SSHConnectionError(f"Remote file read failed: {type(exc).__name__}: {exc}") from exc

    def close(self) -> None:
        try:
            if self._sftp is not None:
                self._sftp.close()
        except Exception:
            pass
        try:
            if self.channel is not None:
                self.channel.close()
        except Exception:
            pass
        try:
            if self.client is not None:
                self.client.close()
        except Exception:
            pass
        self.channel = None
        self.client = None
        self._sftp = None
