"""Integration tests for playpencil-init exec protocol via PLAYPENCIL_EXEC_FD."""

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


def send_request(sock, request):
    """Send a JSON request and read the JSON response."""
    line = json.dumps(request) + "\n"
    sock.sendall(line.encode())

    # Read response line
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("init process closed connection")
        buf += chunk

    line_end = buf.index(b"\n")
    return json.loads(buf[:line_end])


def decode_field(b64_str):
    """Decode a base64-encoded response field."""
    return base64.b64decode(b64_str)


def test_basic_echo(init_process):
    proc, sock = init_process
    resp = send_request(sock, {"cmd": ["echo", "hello world"]})
    assert resp["exit_code"] == 0
    assert decode_field(resp["stdout"]) == b"hello world\n"
    assert decode_field(resp["stderr"]) == b""


def test_nonzero_exit_code(init_process):
    proc, sock = init_process
    resp = send_request(sock, {"cmd": ["sh", "-c", "exit 42"]})
    assert resp["exit_code"] == 42


def test_stdout_stderr_separation(init_process):
    proc, sock = init_process
    resp = send_request(
        sock,
        {
            "cmd": ["sh", "-c", "echo out; echo err >&2"],
        },
    )
    assert resp["exit_code"] == 0
    assert decode_field(resp["stdout"]) == b"out\n"
    assert decode_field(resp["stderr"]) == b"err\n"


def test_base64_binary_output(init_process):
    proc, sock = init_process
    resp = send_request(
        sock,
        {
            "cmd": ["printf", "\\x00\\x01\\x02\\xff"],
        },
    )
    assert resp["exit_code"] == 0
    decoded = decode_field(resp["stdout"])
    assert decoded == b"\x00\x01\x02\xff"


def test_invalid_json_request(init_process):
    proc, sock = init_process
    sock.sendall(b"this is not json\n")

    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk

    resp = json.loads(buf.split(b"\n")[0])
    assert resp["exit_code"] == -1
    stderr_text = decode_field(resp["stderr"]).decode()
    assert "invalid request" in stderr_text


def test_empty_cmd(init_process):
    proc, sock = init_process
    resp = send_request(sock, {"cmd": []})
    assert resp["exit_code"] == -1
    stderr_text = decode_field(resp["stderr"]).decode()
    assert "empty command" in stderr_text


def test_workdir(init_process):
    proc, sock = init_process
    resp = send_request(sock, {"cmd": ["pwd"], "workdir": "/tmp"})
    assert resp["exit_code"] == 0
    assert decode_field(resp["stdout"]).strip() == b"/tmp"


def test_env_vars(init_process):
    proc, sock = init_process
    resp = send_request(
        sock,
        {
            "cmd": ["sh", "-c", "echo $MY_VAR"],
            "env": ["MY_VAR=test_value"],
        },
    )
    assert resp["exit_code"] == 0
    assert decode_field(resp["stdout"]).strip() == b"test_value"


def test_command_not_found(init_process):
    proc, sock = init_process
    resp = send_request(sock, {"cmd": ["nonexistent_command_xyz"]})
    # execvp fails -> child exits 127
    assert resp["exit_code"] == 127


def test_multiple_sequential_execs(init_process):
    proc, sock = init_process
    for i in range(5):
        resp = send_request(sock, {"cmd": ["echo", str(i)]})
        assert resp["exit_code"] == 0
        assert decode_field(resp["stdout"]).strip() == str(i).encode()


def test_large_output(init_process):
    """Verify large output is captured up to the 16MB cap."""
    proc, sock = init_process
    # Generate ~1MB of output
    resp = send_request(
        sock,
        {
            "cmd": [
                "sh",
                "-c",
                "dd if=/dev/zero bs=1024 count=1024 2>/dev/null | base64",
            ],
        },
    )
    assert resp["exit_code"] == 0
    stdout = decode_field(resp["stdout"])
    # base64 of 1MB zero = ~1.37MB, should be fully captured
    assert len(stdout) > 1_000_000
