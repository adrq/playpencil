"""Integration tests for playpencil-init multiplexed exec protocol via PLAYPENCIL_EXEC_FD."""

import base64
import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
# Use debug binary for tests (faster build), fall back to release
INIT_BIN = REPO_ROOT / "target" / "debug" / "playpencil-init"
if not INIT_BIN.exists():
    INIT_BIN = REPO_ROOT / "bin" / "playpencil-init"


@pytest.fixture
def init_process():
    """Start playpencil-init with a socketpair for the exec channel.

    Yields (process, our_socket) where our_socket is the host side
    of the exec channel.
    """
    host_sock, guest_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    guest_fd = guest_sock.fileno()

    env = {
        "PLAYPENCIL_EXEC_FD": str(guest_fd),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }

    proc = subprocess.Popen(
        [str(INIT_BIN)],
        env=env,
        pass_fds=(guest_fd,),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    guest_sock.close()

    host_sock.settimeout(10)

    yield proc, host_sock

    host_sock.close()
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


class ExecHelper:
    """Helper to send multiplexed exec messages and collect streaming responses."""

    def __init__(self, sock):
        self.sock = sock
        self._buf = b""

    def _readline(self):
        while b"\n" not in self._buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("init process closed connection")
            self._buf += chunk
        idx = self._buf.index(b"\n")
        line = self._buf[:idx]
        self._buf = self._buf[idx + 1 :]
        return json.loads(line)

    def send_raw(self, obj):
        """Send a raw JSON message."""
        self.sock.sendall((json.dumps(obj) + "\n").encode())

    def run(self, exec_id, cmd, env=None, workdir=None):
        """Send an exec message and collect all events until exit.

        Returns dict with keys: exit_code, stdout (bytes), stderr (bytes).
        """
        msg = {"type": "exec", "id": exec_id, "cmd": cmd}
        if env:
            msg["env"] = env
        if workdir:
            msg["workdir"] = workdir
        self.send_raw(msg)

        stdout_parts = []
        stderr_parts = []
        exit_code = None

        while exit_code is None:
            event = self._readline()
            if event.get("id") != exec_id:
                continue
            t = event["type"]
            if t == "stdout":
                stdout_parts.append(base64.b64decode(event["data"]))
            elif t == "stderr":
                stderr_parts.append(base64.b64decode(event["data"]))
            elif t == "exit":
                exit_code = event["code"]

        return {
            "exit_code": exit_code,
            "stdout": b"".join(stdout_parts),
            "stderr": b"".join(stderr_parts),
        }


def test_basic_echo(init_process):
    proc, sock = init_process
    h = ExecHelper(sock)
    result = h.run("e1", ["echo", "hello world"])
    assert result["exit_code"] == 0
    assert result["stdout"] == b"hello world\n"
    assert result["stderr"] == b""


def test_nonzero_exit_code(init_process):
    proc, sock = init_process
    h = ExecHelper(sock)
    result = h.run("e1", ["sh", "-c", "exit 42"])
    assert result["exit_code"] == 42


def test_stdout_stderr_separation(init_process):
    proc, sock = init_process
    h = ExecHelper(sock)
    result = h.run("e1", ["sh", "-c", "echo out; echo err >&2"])
    assert result["exit_code"] == 0
    assert result["stdout"] == b"out\n"
    assert result["stderr"] == b"err\n"


def test_base64_binary_output(init_process):
    proc, sock = init_process
    h = ExecHelper(sock)
    result = h.run("e1", ["printf", "\\x00\\x01\\x02\\xff"])
    assert result["exit_code"] == 0
    assert result["stdout"] == b"\x00\x01\x02\xff"


def test_invalid_json_is_non_fatal(init_process):
    """Init should log the error and continue — no response is sent for bad JSON."""
    proc, sock = init_process
    h = ExecHelper(sock)
    sock.sendall(b"this is not json\n")
    # After the garbage, a valid exec should still work.
    result = h.run("e2", ["echo", "still alive"])
    assert result["exit_code"] == 0
    assert result["stdout"] == b"still alive\n"


def test_empty_cmd(init_process):
    proc, sock = init_process
    h = ExecHelper(sock)
    result = h.run("e1", [])
    assert result["exit_code"] == -1
    assert b"empty command" in result["stderr"]


def test_workdir(init_process):
    proc, sock = init_process
    h = ExecHelper(sock)
    result = h.run("e1", ["pwd"], workdir="/tmp")
    assert result["exit_code"] == 0
    assert result["stdout"].strip() == b"/tmp"


def test_env_vars(init_process):
    proc, sock = init_process
    h = ExecHelper(sock)
    result = h.run("e1", ["sh", "-c", "echo $MY_VAR"], env=["MY_VAR=test_value"])
    assert result["exit_code"] == 0
    assert result["stdout"].strip() == b"test_value"


def test_command_not_found(init_process):
    proc, sock = init_process
    h = ExecHelper(sock)
    result = h.run("e1", ["nonexistent_command_xyz"])
    # execvp fails → child exits 127
    assert result["exit_code"] == 127


def test_multiple_sequential_execs(init_process):
    proc, sock = init_process
    h = ExecHelper(sock)
    for i in range(5):
        result = h.run(f"e{i}", ["echo", str(i)])
        assert result["exit_code"] == 0
        assert result["stdout"].strip() == str(i).encode()


def test_large_output(init_process):
    """Verify large output is fully streamed and reassembled."""
    proc, sock = init_process
    h = ExecHelper(sock)
    result = h.run(
        "e1",
        ["sh", "-c", "dd if=/dev/zero bs=1024 count=1024 2>/dev/null | base64"],
    )
    assert result["exit_code"] == 0
    # base64 of 1 MB zeros ≈ 1.37 MB
    assert len(result["stdout"]) > 1_000_000


def test_concurrent_execs(init_process):
    """Send two execs back-to-back; both should complete independently."""
    proc, sock = init_process
    h = ExecHelper(sock)

    # Send both exec messages before consuming any responses.
    h.send_raw({"type": "exec", "id": "a", "cmd": ["sh", "-c", "sleep 0.05; echo A"]})
    h.send_raw({"type": "exec", "id": "b", "cmd": ["echo", "B"]})

    results: dict = {}
    pending = {"a", "b"}
    while pending:
        event = h._readline()
        eid = event.get("id")
        if eid not in pending:
            continue
        t = event["type"]
        if t == "stdout":
            results.setdefault(eid, {}).setdefault("stdout", b"")
            results[eid]["stdout"] += base64.b64decode(event["data"])
        elif t == "exit":
            results.setdefault(eid, {})["exit_code"] = event["code"]
            pending.discard(eid)

    assert results["a"]["exit_code"] == 0
    assert results["a"]["stdout"].strip() == b"A"
    assert results["b"]["exit_code"] == 0
    assert results["b"]["stdout"].strip() == b"B"


def test_stdin_forwarding(init_process):
    """Send stdin data to a running process and close stdin via empty-data EOF."""
    proc, sock = init_process
    h = ExecHelper(sock)

    exec_id = "e1"
    h.send_raw({"type": "exec", "id": exec_id, "cmd": ["cat"]})

    data = b"hello from stdin\n"
    h.send_raw(
        {
            "type": "stdin",
            "id": exec_id,
            "data": base64.b64encode(data).decode(),
        }
    )
    # Empty data = EOF: init closes the write end of the stdin pipe.
    # cat sees EOF, flushes and exits with code 0.
    h.send_raw({"type": "stdin", "id": exec_id, "data": ""})

    stdout_parts = []
    exit_code = None
    while exit_code is None:
        event = h._readline()
        if event.get("id") != exec_id:
            continue
        t = event["type"]
        if t == "stdout":
            stdout_parts.append(base64.b64decode(event["data"]))
        elif t == "exit":
            exit_code = event["code"]

    stdout = b"".join(stdout_parts)
    assert exit_code == 0
    assert data in stdout
