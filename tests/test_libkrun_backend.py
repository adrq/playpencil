"""VM integration tests for LibkrunBackend via HTTP API.

All tests require KVM and a built playpencil binary with `serve` subcommand.
Mark them with @pytest.mark.vm so they are skipped in CI without KVM.
"""

import base64
import http.client
import json
import os
import queue
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

import pytest

from conftest import ALPINE_IMAGE_BACKEND, seed_image_cache


class WSConn:
    """A minimal raw WebSocket client (RFC 6455) — enough to drive the duplex
    exec face without an external dependency. Client frames are masked; server
    frames are not."""

    def __init__(self, host, port, path, timeout=30):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {key}\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        self._buf = b""
        header = self._read_until(b"\r\n\r\n")
        status = header.split(b"\r\n", 1)[0]
        assert b"101" in status, f"upgrade failed: {status!r}"

    def _read_until(self, marker):
        while marker not in self._buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("closed during handshake")
            self._buf += chunk
        idx = self._buf.index(marker) + len(marker)
        out, self._buf = self._buf[:idx], self._buf[idx:]
        return out

    def _recv_exact(self, n):
        while len(self._buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("closed")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def send(self, opcode, payload):
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        header = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", n)
        self.sock.sendall(header + mask + masked)

    def send_text(self, obj):
        self.send(0x1, json.dumps(obj).encode())

    def send_binary(self, data):
        self.send(0x2, data)

    def recv(self):
        """Return (opcode, payload) for the next frame, or (0x8, b'') on close."""
        b0, b1 = self._recv_exact(2)
        opcode = b0 & 0x0F
        n = b1 & 0x7F
        if n == 126:
            n = struct.unpack(">H", self._recv_exact(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", self._recv_exact(8))[0]
        payload = self._recv_exact(n) if n else b""
        return opcode, payload

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


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
    seed_image_cache(data_dir)

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

    def create(
        self, image=ALPINE_IMAGE_BACKEND, cpus=1, memory_mb=256, network="isolated"
    ):
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
        assert status == 202, f"create failed: {status} {body}"
        return body["id"]

    def wait_state(self, sandbox_id, wanted, timeout=90):
        """Poll GET until the sandbox reaches `wanted` (accepted-not-converged)."""
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = self.status(sandbox_id)["status"]["state"]
            if last == wanted:
                return
            time.sleep(0.2)
        raise AssertionError(
            f"sandbox {sandbox_id} did not reach {wanted}; last was {last}"
        )

    def start(self, sandbox_id):
        status, body = self._request("POST", f"/v1x/sandboxes/{sandbox_id}/start")
        assert status == 202, f"start failed: {status} {body}"

    def stop(self, sandbox_id):
        status, body = self._request("POST", f"/v1x/sandboxes/{sandbox_id}/stop")
        assert status == 202, f"stop failed: {status} {body}"

    def destroy(self, sandbox_id):
        status, body = self._request("DELETE", f"/v1/sandboxes/{sandbox_id}")
        assert status == 204, f"destroy failed: {status} {body}"

    def status(self, sandbox_id):
        status, body = self._request("GET", f"/v1/sandboxes/{sandbox_id}")
        assert status == 200, f"status failed: {status} {body}"
        return body

    def command(self, sandbox_id, command, timeout=60, **extra):
        """POST a foreground command and collect the SSE events until the stream
        closes (the command terminal closes it)."""
        conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        body = {"command": command}
        body.update(extra)
        conn.request(
            "POST",
            f"/v1x/sandboxes/{sandbox_id}/execd/command",
            body=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        status = resp.status
        data = resp.read()
        conn.close()
        events = []
        for chunk in data.split(b"\n\n"):
            chunk = chunk.strip()
            if chunk:
                events.append(json.loads(chunk))
        return status, events

    def discover(self, sandbox_id, port):
        return self._request("GET", f"/v1/sandboxes/{sandbox_id}/endpoints/{port}")


@pytest.fixture
def running_sandbox(server):
    """Create a sandbox (auto-started by create), yield its ID, then destroy."""
    sid = server.create()
    server.wait_state(sid, "Running")
    yield sid
    server.destroy(sid)


def test_vm_lifecycle(server):
    """Create (accepted, reconciles to running) → stop → destroy.

    Lifecycle calls are accepted-not-converged, so each transition is observed
    by polling GET until the sandbox reaches the expected state.
    """
    sid = server.create()
    server.wait_state(sid, "Running")

    server.stop(sid)
    server.wait_state(sid, "Stopped")

    server.destroy(sid)
    server.wait_state(sid, "Terminated")


def test_vm_survives_past_fork_keepalive(server):
    """A running VM must outlive the fork thread's idle keep-alive window of 10s"""
    sid = server.create()
    server.wait_state(sid, "Running")
    try:
        time.sleep(15)
        state = server.status(sid)["status"]["state"]
        assert state == "Running", (
            f"VM did not survive past the fork keep-alive window; "
            f"state is {state} (expected Running)"
        )
    finally:
        server.destroy(sid)


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
        server.wait_state(sid, "Running")
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
        server.wait_state(sid, "Running")
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
            "image": {"uri": ALPINE_IMAGE_BACKEND},
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


def test_command_face_echo(running_sandbox, server):
    """End-to-end: POST a foreground command, stream init → stdout → terminal."""
    status, events = server.command(running_sandbox, "echo hi")
    assert status == 200
    types = [e["type"] for e in events]
    assert types[0] == "init"
    assert "execution_complete" in types
    stdout = "".join(e.get("text", "") for e in events if e["type"] == "stdout")
    assert stdout.strip() == "hi"


def test_command_face_nonzero_exit_is_error(running_sandbox, server):
    status, events = server.command(running_sandbox, "exit 3")
    assert status == 200
    errs = [e for e in events if e["type"] == "error"]
    assert errs, f"expected an error terminal, got {events}"
    assert errs[-1]["error"]["evalue"] == "3"


def test_command_face_start_error_for_bad_cwd(running_sandbox, server):
    status, events = server.command(running_sandbox, "echo hi", cwd="/no/such/dir")
    assert status == 200
    errs = [e for e in events if e["type"] == "error"]
    assert errs, f"expected a start-error terminal, got {events}"


def test_command_face_empty_command_is_422(running_sandbox, server):
    status, _ = server._request(
        "POST",
        f"/v1x/sandboxes/{running_sandbox}/execd/command",
        {"command": ""},
    )
    assert status == 422


def test_command_face_unknown_sandbox_is_404(server):
    status, _ = server._request(
        "POST",
        "/v1x/sandboxes/bogus-id/execd/command",
        {"command": "echo hi"},
    )
    assert status == 404


def test_command_face_oversize_command_is_422(running_sandbox, server):
    """A command frame exceeding the 1 MiB console wire limit is malformed input
    (422 validation_error), not a server fault (500). Rejected before any guest
    dispatch, so the sandbox stays usable afterward."""
    big = "x" * (1024 * 1024 + 64)  # exceeds the 1 MiB frame cap once serialized
    status, body = server._request(
        "POST",
        f"/v1x/sandboxes/{running_sandbox}/execd/command",
        {"command": big},
    )
    assert status == 422, (status, body)
    assert body["error"] == "validation_error", body

    # No session/forwarder was leaked: a normal command still runs.
    status, events = server.command(running_sandbox, "echo ok")
    assert status == 200
    assert any(e.get("type") == "execution_complete" for e in events), events


def test_discovery_command_port(running_sandbox, server):
    status, body = server.discover(running_sandbox, 44772)
    assert status == 200
    assert body["endpoint"].endswith(f"/v1x/sandboxes/{running_sandbox}/execd")
    assert body["headers"]["X-EXECD-ACCESS-TOKEN"]


def test_discovery_other_port_is_404(running_sandbox, server):
    status, _ = server.discover(running_sandbox, 8080)
    assert status == 404


def test_discovery_unknown_sandbox_is_404(server):
    status, _ = server.discover("bogus-id", 44772)
    assert status == 404


def test_duplex_cat_echo(running_sandbox, server):
    """End-to-end duplex WebSocket: open `cat`, send stdin, read the echoed
    binary stdout, then the exit control frame."""
    ws = WSConn(server.host, server.port, f"/v1x/sandboxes/{running_sandbox}/exec")
    try:
        ws.send_text({"command": ["cat"]})
        ws.send_binary(bytes([2]) + b"hello\n")  # tag 2 = stdin
        ws.send_text({"type": "stdin_eof"})

        stdout = b""
        exit_code = None
        deadline = time.monotonic() + 30
        while exit_code is None and time.monotonic() < deadline:
            opcode, payload = ws.recv()
            if opcode == 0x2:  # binary data frame
                tag, data = payload[0], payload[1:]
                if tag == 0:  # stdout
                    stdout += data
            elif opcode == 0x1:  # text control
                msg = json.loads(payload)
                if msg["type"] == "exit":
                    exit_code = msg["code"]
            elif opcode == 0x8:  # close
                break
        assert exit_code == 0, f"stdout so far: {stdout!r}"
        assert b"hello" in stdout
    finally:
        ws.close()


def test_duplex_oversize_stdin_frame_is_rejected(running_sandbox, server):
    """An inbound stdin frame larger than STDIN_FRAME_RAW_MAX (64 KiB) is a
    protocol violation: it is rejected (never echoed/forwarded) and the exec is
    torn down, rather than buffered as a per-connection memory vector."""
    ws = WSConn(server.host, server.port, f"/v1x/sandboxes/{running_sandbox}/exec")
    try:
        ws.send_text({"command": ["cat"]})
        big = b"z" * (64 * 1024 + 1)  # one byte over the per-frame stdin cap
        ws.send_binary(bytes([2]) + big)  # tag 2 = stdin

        stdout = b""
        torn_down = False
        deadline = time.monotonic() + 30
        try:
            while not torn_down and time.monotonic() < deadline:
                opcode, payload = ws.recv()
                if opcode == 0x2:
                    tag, data = payload[0], payload[1:]
                    if tag == 0:
                        stdout += data
                elif opcode == 0x1:
                    msg = json.loads(payload)
                    if msg["type"] in ("exit", "start_error"):
                        torn_down = True
                elif opcode == 0x8:
                    torn_down = True
        except (ConnectionError, OSError):
            torn_down = True
        assert torn_down, "an oversize stdin frame must tear the exec down"
        assert b"z" not in stdout, "oversize stdin must not be echoed/forwarded"
    finally:
        ws.close()


def test_duplex_invalid_open_is_start_error(running_sandbox, server):
    """An empty open command yields a start_error control frame, not a hang."""
    ws = WSConn(server.host, server.port, f"/v1x/sandboxes/{running_sandbox}/exec")
    try:
        ws.send_text({"command": []})
        opcode, payload = ws.recv()
        assert opcode == 0x1, f"expected text control, got opcode {opcode}"
        msg = json.loads(payload)
        assert msg["type"] == "start_error"
    finally:
        ws.close()


def test_duplex_gid_without_uid_is_start_error(running_sandbox, server):
    """Open params with gid but no uid are rejected in-band (gid requires uid),
    matching the command face's semantics."""
    ws = WSConn(server.host, server.port, f"/v1x/sandboxes/{running_sandbox}/exec")
    try:
        ws.send_text({"command": ["echo", "hi"], "gid": 5})
        opcode, payload = ws.recv()
        assert opcode == 0x1, f"expected text control, got opcode {opcode}"
        msg = json.loads(payload)
        assert msg["type"] == "start_error"
        assert "gid requires uid" in msg.get("message", "")
    finally:
        ws.close()


def test_duplex_unknown_sandbox_is_404_before_upgrade(server):
    """An unknown sandbox is rejected with HTTP 404 before the WS upgrade, not a
    101 followed by an in-band error."""
    conn = http.client.HTTPConnection(server.host, server.port, timeout=30)
    conn.request(
        "GET",
        "/v1x/sandboxes/does-not-exist/exec",
        headers={
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        },
    )
    resp = conn.getresponse()
    conn.close()
    assert resp.status == 404


def test_duplex_not_running_sandbox_is_409_before_upgrade(server):
    """A stopped sandbox is rejected with HTTP 409 before the WS upgrade,
    matching the command face."""
    sid = server.create()
    server.wait_state(sid, "Running")
    server.stop(sid)
    server.wait_state(sid, "Stopped")
    conn = http.client.HTTPConnection(server.host, server.port, timeout=30)
    conn.request(
        "GET",
        f"/v1x/sandboxes/{sid}/exec",
        headers={
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        },
    )
    resp = conn.getresponse()
    conn.close()
    assert resp.status == 409
