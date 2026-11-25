
from universal_audit.adapters.ssh_transport import SSHTransport


class FakeChannel:
    def __init__(self, stdout=b"out\n", stderr=b"warning\n", exit_code=0):
        self.stdout = [stdout] if stdout else []
        self.stderr = [stderr] if stderr else []
        self.exit_code = exit_code
        self.closed = False
        self.command = None

    def settimeout(self, timeout):
        pass

    def exec_command(self, command):
        self.command = command

    def recv_ready(self):
        return bool(self.stdout)

    def recv(self, size):
        return self.stdout.pop(0)

    def recv_stderr_ready(self):
        return bool(self.stderr)

    def recv_stderr(self, size):
        return self.stderr.pop(0)

    def exit_status_ready(self):
        return not self.stdout and not self.stderr

    def recv_exit_status(self):
        return self.exit_code

    def close(self):
        self.closed = True


class FakeSSHTransport:
    def __init__(self, channel):
        self.channel = channel

    def is_active(self):
        return True

    def open_session(self, timeout=None):
        return self.channel


class FakeSSHClient:
    def __init__(self, channel):
        self.transport = FakeSSHTransport(channel)

    def get_transport(self):
        return self.transport


def test_exec_channel_keeps_stdout_stderr_and_exit_code_separate():
    channel = FakeChannel(b"VMkernel esx01 9.0.0\n", b"non-fatal warning\n", 0)
    transport = SSHTransport()
    transport.client = FakeSSHClient(channel)
    result = transport.execute_exec("uname -a", timeout=2)
    assert result.stdout == "VMkernel esx01 9.0.0\n"
    assert result.stderr == "non-fatal warning\n"
    assert result.exit_code == 0
    assert not result.truncated
    assert channel.command == "uname -a"


def test_exec_channel_marks_oversized_output_as_truncated():
    channel = FakeChannel(b"0123456789", b"", 0)
    transport = SSHTransport(max_output_bytes=4)
    transport.client = FakeSSHClient(channel)
    result = transport.execute_exec("uname -a", timeout=2)
    assert result.stdout == "0123"
    assert result.truncated


def test_terminal_output_strips_ansi_and_normalizes_newlines():
    value = "\x1b[31mPASS\x1b[0m\r\nnext\rline"
    assert SSHTransport._clean_text(value) == "PASS\nnext\nline"
