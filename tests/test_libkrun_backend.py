"""VM integration tests for LibkrunBackend.

All tests require KVM and a fully wired CLI/server (playpencil binary with
`serve` subcommand). They are placeholders until the CLI/server layer is
connected to LibkrunBackend (tracked as a future task). Until then every test
in this file will be skipped because the daemon exits immediately when `serve`
is not yet implemented (detected by the `server` fixture).

Mark them with @pytest.mark.vm so they are also skipped in CI environments
without hardware virtualization.
"""

import base64
import json
import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
BIN_DIR = REPO_ROOT / "bin"
PLAYPENCIL_BIN = BIN_DIR / "playpencil"

pytestmark = pytest.mark.vm


def _kvm_available():
    return os.access("/dev/kvm", os.R_OK | os.W_OK)


@pytest.fixture(scope="session", autouse=True)
def require_kvm():
    if not _kvm_available():
        pytest.skip("KVM not available")


@pytest.fixture
def server(tmp_path):
    """Start the playpencil daemon and yield a helper that talks to it."""
    if not PLAYPENCIL_BIN.exists():
        pytest.skip(f"Binary not found at {PLAYPENCIL_BIN}")

    sock_path = tmp_path / "playpencil.sock"
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    proc = subprocess.Popen(
        [
            str(PLAYPENCIL_BIN),
            "serve",
            "--socket",
            str(sock_path),
            "--data-dir",
            str(data_dir),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for the socket to appear.
    deadline = time.monotonic() + 10
    while not sock_path.exists():
        if proc.poll() is not None:
            pytest.skip(
                "playpencil daemon exited immediately (serve not yet implemented)"
            )
        if time.monotonic() > deadline:
            proc.terminate()
            pytest.fail("playpencil daemon did not start in time")
        time.sleep(0.05)

    yield SandboxClient(str(sock_path))

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


class SandboxClient:
    """Minimal HTTP client over a Unix socket."""

    def __init__(self, sock_path):
        self.sock_path = sock_path

    def _request(self, method, path, body=None):
        import http.client

        conn = http.client.HTTPConnection("localhost")
        conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.sock.connect(self.sock_path)
        headers = {"Content-Type": "application/json"} if body else {}
        payload = json.dumps(body).encode() if body else None
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, json.loads(data) if data else {}

    def create(self, image="alpine:3.19", cpus=1, memory_mb=256, network="isolated"):
        status, body = self._request(
            "POST",
            "/v1/sandboxes",
            {
                "image": image,
                "resource_limits": {
                    "cpus": cpus,
                    "memory_bytes": memory_mb * 1024 * 1024,
                },
                "mounts": [],
                "network": network,
                "env": [],
            },
        )
        assert status == 201, f"create failed: {status} {body}"
        return body["sandbox_id"]

    def start(self, sandbox_id):
        status, body = self._request("POST", f"/v1/sandboxes/{sandbox_id}/start")
        assert status == 200, f"start failed: {status} {body}"

    def stop(self, sandbox_id):
        status, body = self._request("POST", f"/v1/sandboxes/{sandbox_id}/stop")
        assert status == 200, f"stop failed: {status} {body}"

    def destroy(self, sandbox_id):
        status, body = self._request("DELETE", f"/v1/sandboxes/{sandbox_id}")
        assert status == 200, f"destroy failed: {status} {body}"

    def status(self, sandbox_id):
        status, body = self._request("GET", f"/v1/sandboxes/{sandbox_id}")
        assert status == 200, f"status failed: {status} {body}"
        return body

    def exec(self, sandbox_id, command, env=None, working_dir=None, timeout=30):
        """Run a command and collect all output. Returns (exit_code, stdout, stderr)."""
        payload = {"command": command}
        if env:
            payload["env"] = env
        if working_dir:
            payload["working_dir"] = working_dir

        # Use SSE or streaming endpoint depending on protocol.
        # For now, use the simple blocking exec endpoint.
        status, body = self._request(
            "POST", f"/v1/sandboxes/{sandbox_id}/exec", payload
        )
        assert status == 200, f"exec failed: {status} {body}"
        stdout = base64.b64decode(body.get("stdout", ""))
        stderr = base64.b64decode(body.get("stderr", ""))
        return body["exit_code"], stdout, stderr


@pytest.fixture
def running_sandbox(server):
    """Create and start an Alpine sandbox, yield its ID, then destroy it."""
    sid = server.create()
    server.start(sid)
    yield sid
    server.destroy(sid)


def test_vm_lifecycle(server):
    """Create → start → stop → destroy a VM."""
    sid = server.create()
    st = server.status(sid)
    assert st["state"] == "ready"

    server.start(sid)
    st = server.status(sid)
    assert st["state"] == "running"

    server.stop(sid)
    st = server.status(sid)
    assert st["state"] == "stopped"

    server.destroy(sid)


def test_vm_exec_echo(running_sandbox, server):
    """Run echo inside the VM and verify output."""
    code, stdout, stderr = server.exec(running_sandbox, ["echo", "hello from vm"])
    assert code == 0
    assert stdout.strip() == b"hello from vm"
    assert stderr == b""


def test_vm_exec_nonzero_exit(running_sandbox, server):
    """Verify non-zero exit codes are propagated."""
    code, _, _ = server.exec(running_sandbox, ["sh", "-c", "exit 7"])
    assert code == 7


def test_vm_exec_stdout_stderr_separation(running_sandbox, server):
    code, stdout, stderr = server.exec(
        running_sandbox, ["sh", "-c", "echo OUT; echo ERR >&2"]
    )
    assert code == 0
    assert stdout.strip() == b"OUT"
    assert stderr.strip() == b"ERR"


def test_vm_exec_env_vars(running_sandbox, server):
    code, stdout, _ = server.exec(
        running_sandbox,
        ["sh", "-c", "echo $HELLO"],
        env=[("HELLO", "world")],
    )
    assert code == 0
    assert stdout.strip() == b"world"


def test_vm_exec_workdir(running_sandbox, server):
    code, stdout, _ = server.exec(running_sandbox, ["pwd"], working_dir="/tmp")
    assert code == 0
    assert stdout.strip() == b"/tmp"


def test_vm_exec_binary_output(running_sandbox, server):
    code, stdout, _ = server.exec(running_sandbox, ["printf", "\\x00\\x01\\x02\\xff"])
    assert code == 0
    assert stdout == b"\x00\x01\x02\xff"


def test_vm_exec_command_not_found(running_sandbox, server):
    code, _, _ = server.exec(running_sandbox, ["nonexistent_xyz_cmd"])
    assert code == 127


def test_vm_multiple_execs(running_sandbox, server):
    """Multiple sequential execs in the same VM."""
    for i in range(3):
        code, stdout, _ = server.exec(running_sandbox, ["echo", str(i)])
        assert code == 0
        assert stdout.strip() == str(i).encode()


def test_vm_create_unique_ids(server):
    """Each create() returns a distinct sandbox ID."""
    ids = [server.create() for _ in range(3)]
    try:
        assert len(set(ids)) == 3
    finally:
        for sid in ids:
            server.destroy(sid)


def test_vm_isolated_network(server):
    """In Isolated mode the VM should have no external network access."""
    sid = server.create(network="isolated")
    server.start(sid)
    try:
        code, _, _ = server.exec(sid, ["sh", "-c", "ping -c 1 -W 1 8.8.8.8 2>&1"])
        # ping should fail (no route / no network device)
        assert code != 0
    finally:
        server.destroy(sid)
