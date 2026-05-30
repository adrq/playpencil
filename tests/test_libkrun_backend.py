"""VM integration tests for LibkrunBackend via HTTP API.

All tests require KVM and a built playpencil binary with `serve` subcommand.
Mark them with @pytest.mark.vm so they are skipped in CI without KVM.
"""

import http.client
import json
import os
import queue
import subprocess
import threading
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
    """Start the playpencil daemon on a random TCP port and yield a client."""
    if not PLAYPENCIL_BIN.exists():
        pytest.skip(f"Binary not found at {PLAYPENCIL_BIN}")

    data_dir = tmp_path / "data"
    data_dir.mkdir()

    proc = subprocess.Popen(
        [
            str(PLAYPENCIL_BIN),
            "serve",
            "--port",
            "0",
            "--bind",
            "127.0.0.1",
            "--data-dir",
            str(data_dir),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for the "listening on ..." line to discover the port.
    # Use threads to avoid blocking indefinitely on readline, and to drain
    # stderr continuously so the daemon never blocks on a full pipe buffer.
    line_queue = queue.Queue()
    stderr_chunks = []

    def _read_stdout():
        for raw_line in proc.stdout:
            line_queue.put(raw_line.decode().strip())

    def _read_stderr():
        for raw_line in proc.stderr:
            stderr_chunks.append(raw_line.decode())

    reader_thread = threading.Thread(target=_read_stdout, daemon=True)
    stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
    reader_thread.start()
    stderr_thread.start()

    def _captured_stderr():
        # Give the drainer a moment to flush; read the buffer it fills rather
        # than proc.stderr directly (which would race the drainer thread).
        stderr_thread.join(timeout=1)
        return "".join(stderr_chunks)

    port = None
    deadline = time.monotonic() + 10
    while port is None:
        if proc.poll() is not None:
            pytest.fail(f"playpencil daemon failed to start: {_captured_stderr()}")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            proc.terminate()
            pytest.fail(
                "playpencil daemon did not print listening line in time. "
                f"stderr: {_captured_stderr()}"
            )
        try:
            line = line_queue.get(timeout=min(remaining, 0.5))
        except queue.Empty:
            continue
        if line.startswith("listening on "):
            addr = line[len("listening on ") :]
            port = int(addr.rsplit(":", 1)[1])

    yield SandboxClient("127.0.0.1", port)

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


class SandboxClient:
    """Minimal HTTP client for the playpencil API."""

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def _request(self, method, path, body=None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=30)
        headers = {"Content-Type": "application/json"} if body else {}
        payload = json.dumps(body).encode() if body else None
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        if data:
            return resp.status, json.loads(data)
        return resp.status, None

    def create(self, image="alpine:3.19", cpus=1, memory_mb=256, network="isolated"):
        status, body = self._request(
            "POST",
            "/v1/sandboxes",
            {
                "image": {"uri": image},
                "resource_limits": {
                    "cpus": cpus,
                    "memory_bytes": memory_mb * 1024 * 1024,
                },
                "mounts": [],
                "network": network,
                "env": {},
            },
        )
        assert status == 201, f"create failed: {status} {body}"
        return body["id"]

    def start(self, sandbox_id):
        status, body = self._request("POST", f"/v1x/sandboxes/{sandbox_id}/start")
        assert status == 200, f"start failed: {status} {body}"

    def stop(self, sandbox_id):
        status, body = self._request("POST", f"/v1x/sandboxes/{sandbox_id}/stop")
        assert status == 200, f"stop failed: {status} {body}"

    def destroy(self, sandbox_id):
        status, body = self._request("DELETE", f"/v1/sandboxes/{sandbox_id}")
        assert status == 204, f"destroy failed: {status} {body}"

    def status(self, sandbox_id):
        status, body = self._request("GET", f"/v1/sandboxes/{sandbox_id}")
        assert status == 200, f"status failed: {status} {body}"
        return body


@pytest.fixture
def running_sandbox(server):
    """Create a sandbox (auto-started by create), yield its ID, then destroy."""
    sid = server.create()
    yield sid
    server.destroy(sid)


def test_vm_lifecycle(server):
    """Create (auto-starts → running) → stop → destroy.

    The HTTP lifecycle is synchronous: start() blocks until the reconciler
    converges to Running and the record stays Running until a later transition,
    so a separate GET deterministically reports the new state. No polling needed.
    """
    sid = server.create()
    st = server.status(sid)
    assert st["status"]["state"] == "Running"

    server.stop(sid)
    st = server.status(sid)
    assert st["status"]["state"] == "Stopped"

    server.destroy(sid)
    st = server.status(sid)
    assert st["status"]["state"] == "Terminated"


def test_vm_create_unique_ids(server):
    """Each create() returns a distinct sandbox ID."""
    ids = [server.create() for _ in range(3)]
    try:
        assert len(set(ids)) == 3
    finally:
        for sid in ids:
            server.destroy(sid)


def test_get_nonexistent_sandbox(server):
    status, body = server._request("GET", "/v1/sandboxes/bogus-id-does-not-exist")
    assert status == 404
    assert body["error"] == "not_found"


def test_destroy_nonexistent_sandbox(server):
    status, body = server._request("DELETE", "/v1/sandboxes/bogus-id-does-not-exist")
    assert status == 404
    assert body["error"] == "not_found"


def test_list_sandboxes(server):
    sid = server.create()
    try:
        status, body = server._request("GET", "/v1/sandboxes")
        assert status == 200
        ids = [s["id"] for s in body["items"]]
        assert sid in ids
        match = [s for s in body["items"] if s["id"] == sid][0]
        assert match["status"]["state"] == "Running"
    finally:
        server.destroy(sid)


def test_list_filter_by_state(server):
    sid = server.create()
    try:
        status, body = server._request("GET", "/v1/sandboxes?state=Terminated")
        assert status == 200
        ids = [s["id"] for s in body["items"]]
        assert sid not in ids

        status, body = server._request("GET", "/v1/sandboxes?state=Running")
        assert status == 200
        ids = [s["id"] for s in body["items"]]
        assert sid in ids

        # An empty state param is treated as unset (returns all), not as a
        # filter matching nothing.
        status, body = server._request("GET", "/v1/sandboxes?state=")
        assert status == 200
        ids = [s["id"] for s in body["items"]]
        assert sid in ids
    finally:
        server.destroy(sid)


def test_pause_returns_501(running_sandbox, server):
    status, body = server._request("POST", f"/v1/sandboxes/{running_sandbox}/pause")
    assert status == 501
    assert body["error"] == "not_implemented"


def test_pause_nonexistent_returns_404(server):
    status, body = server._request("POST", "/v1/sandboxes/bogus-id/pause")
    assert status == 404
    assert body["error"] == "not_found"


def test_resume_returns_501(running_sandbox, server):
    status, body = server._request("POST", f"/v1/sandboxes/{running_sandbox}/resume")
    assert status == 501
    assert body["error"] == "not_implemented"


def test_resume_nonexistent_returns_404(server):
    status, body = server._request("POST", "/v1/sandboxes/bogus-id/resume")
    assert status == 404
    assert body["error"] == "not_found"


def test_create_invalid_mount_returns_422(server):
    """A bad mount is rejected as user input (422), not a server fault (500).

    Mount validation runs before VM provisioning, so create fails fast without
    booting a VM.
    """
    status, body = server._request(
        "POST",
        "/v1/sandboxes",
        {
            "image": {"uri": "alpine:3.19"},
            "resource_limits": {"cpus": 1, "memory_bytes": 256 * 1024 * 1024},
            "mounts": [
                {
                    "host_path": "relative/path",
                    "guest_path": "/mnt",
                    "read_only": True,
                }
            ],
            "network": "isolated",
            "env": {},
        },
    )
    assert status == 422
    assert body["error"] == "validation_error"
    assert "must be absolute" in body["detail"]
