"""Daemon operations: the exclusive data-directory lease, readiness health, and
the SIGTERM drain."""

import json
import os
import signal
import socket
import time

import httpx
import psutil
import pytest

from conftest import ALPINE_IMAGE_BACKEND, seed_image_cache
from testhelpers import spawn_serve, start_serve

# One retained destroyed record: recovery leaves it unchanged.
DESTROYED_STORE = {
    "sb-1": {
        "id": "sb-1",
        "config": {
            "name": None,
            "image": "alpine",
            "resource_limits": {"cpus": None, "memory_bytes": None, "disk_bytes": None},
            "mounts": [],
            "network": "Isolated",
            "env": [],
            "entrypoint": None,
        },
        "desired": "destroyed",
        "generation": 1,
        "state": "destroyed",
        "observed_generation": 1,
        "pid": None,
        "pid_start_time": None,
        "rootfs_path": None,
        "reason": None,
        "message": None,
        "entrypoint_exit": None,
        "created_at": "2026-01-01T00:00:00Z",
        "last_transition_at": "2026-01-01T00:00:00Z",
    }
}


def _data_dir(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return data_dir


def _health(daemon):
    resp = httpx.get(f"http://127.0.0.1:{daemon.port}/v1/health", timeout=10)
    return resp.status_code, resp.content


def _wait_health(daemon, wanted, timeout=10):
    deadline = time.monotonic() + timeout
    while True:
        status, _ = _health(daemon)
        if status == wanted:
            return
        assert time.monotonic() < deadline, f"health stayed {status}, wanted {wanted}"
        time.sleep(0.05)


def _assert_refused(data_dir, holder_pid):
    """Starts a daemon on `data_dir` and asserts it exits refusing the lease."""
    contender = spawn_serve(data_dir)
    try:
        code = contender.wait_exit(timeout=5)
    finally:
        contender.stop()
    stderr = contender.stderr()
    assert code != 0, stderr
    assert f"lock file {data_dir / 'daemon.lock'}" in stderr, stderr
    assert f"(last recorded pid {holder_pid})" in stderr, stderr


def _fd_targets(pid):
    """Resolved targets of every open descriptor of `pid`."""
    targets = []
    fd_dir = f"/proc/{pid}/fd"
    for fd in os.listdir(fd_dir):
        try:
            targets.append(os.readlink(os.path.join(fd_dir, fd)))
        except OSError:
            continue
    return targets


def _wait_state(base, sandbox_id, wanted, timeout=90):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        resp = httpx.get(f"{base}/v1/sandboxes/{sandbox_id}", timeout=10)
        last = resp.json()["status"]["state"]
        if last == wanted:
            return
        time.sleep(0.2)
    raise AssertionError(f"sandbox {sandbox_id} did not reach {wanted}; last {last}")


def test_lease_released_after_daemon_sigkill(tmp_path):
    data_dir = _data_dir(tmp_path)
    first = start_serve(data_dir)
    first.proc.send_signal(signal.SIGKILL)
    assert first.wait_exit() == -signal.SIGKILL

    second = start_serve(data_dir)
    second.stop()


@pytest.mark.vm
def test_sandbox_processes_do_not_hold_lease_fd(tmp_path):
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        pytest.skip("KVM not available")
    data_dir = _data_dir(tmp_path)
    seed_image_cache(data_dir)
    lock_path = str(data_dir / "daemon.lock")

    daemon = start_serve(data_dir)
    base = f"http://127.0.0.1:{daemon.port}"
    try:
        resp = httpx.post(
            f"{base}/v1/sandboxes",
            json={
                "image": {"uri": ALPINE_IMAGE_BACKEND},
                "resource_limits": {"cpus": 1, "memory_bytes": 256 * 1024 * 1024},
                "mounts": [],
                "network": "isolated",
                "env": {},
            },
            timeout=30,
        )
        assert resp.status_code == 202, resp.text
        _wait_state(base, resp.json()["id"], "Running")

        # VM children are forked by the daemon; detached helpers (e.g. an
        # overlay mount process) are found by the data dir in their cmdline.
        helpers = set(psutil.Process(daemon.pid).children(recursive=True))
        for proc in psutil.process_iter(["cmdline"]):
            if proc.pid != daemon.pid and str(data_dir) in " ".join(
                proc.info["cmdline"] or []
            ):
                helpers.add(proc)
        assert helpers, "expected at least the VM child process"
        for proc in helpers:
            assert lock_path not in _fd_targets(proc.pid), (
                f"pid {proc.pid} ({proc.name()}) holds the lease descriptor"
            )
        assert lock_path in _fd_targets(daemon.pid)
    finally:
        daemon.proc.send_signal(signal.SIGKILL)
        daemon.wait_exit()

    successor = start_serve(data_dir)
    successor.stop()


def test_second_daemon_refuses_shared_data_dir(tmp_path):
    data_dir = _data_dir(tmp_path)
    state_file = data_dir / "state.json"
    seed = json.dumps(DESTROYED_STORE, indent=2).encode()
    state_file.write_bytes(seed)

    holder = start_serve(data_dir)
    try:
        assert state_file.read_bytes() == seed
        sentinel = data_dir / "images" / "tmp" / "sentinel"
        sentinel.mkdir(parents=True)
        two_hours_ago = time.time() - 7200
        os.utime(sentinel, (two_hours_ago, two_hours_ago))

        _assert_refused(data_dir, holder.pid)
        assert _health(holder) == (200, b"")
        assert state_file.read_bytes() == seed
        assert sentinel.is_dir()
    finally:
        holder.stop()

    successor = start_serve(data_dir)
    try:
        assert not sentinel.exists()
    finally:
        successor.stop()


def test_health_reports_store_failure(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root bypasses directory permissions")
    data_dir = _data_dir(tmp_path)
    daemon = start_serve(data_dir)
    try:
        assert _health(daemon) == (200, b"")
        data_dir.chmod(0o500)
        try:
            assert _health(daemon) == (503, b"")
        finally:
            data_dir.chmod(0o700)
        assert _health(daemon) == (200, b"")
    finally:
        daemon.stop()


def test_health_reports_corrupt_state_file(tmp_path):
    data_dir = _data_dir(tmp_path)
    daemon = start_serve(data_dir)
    try:
        assert _health(daemon) == (200, b"")
        (data_dir / "state.json").write_bytes(b"{not json")
        assert _health(daemon) == (503, b"")
    finally:
        daemon.stop()


def test_sigterm_exits_and_releases_lease(tmp_path):
    data_dir = _data_dir(tmp_path)
    daemon = start_serve(data_dir)
    assert _health(daemon) == (200, b"")
    daemon.proc.send_signal(signal.SIGTERM)
    assert daemon.wait_exit() == 0

    successor = start_serve(data_dir)
    successor.stop()


def test_sigterm_right_after_readiness_drains(tmp_path):
    data_dir = _data_dir(tmp_path)
    daemon = spawn_serve(data_dir)
    try:
        daemon.wait_ready()
        daemon.proc.send_signal(signal.SIGTERM)
        assert daemon.wait_exit() == 0, daemon.stderr()
    finally:
        daemon.stop()

    successor = start_serve(data_dir)
    successor.stop()


def _recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        assert chunk, f"connection closed before {marker!r}; got {data!r}"
        data += chunk
    return data


def test_lease_held_through_drain(tmp_path):
    data_dir = _data_dir(tmp_path)
    holder = start_serve(data_dir)
    try:
        body = b"{}"
        sock = socket.create_connection(("127.0.0.1", holder.port), timeout=10)
        with sock:
            sock.sendall(
                b"POST /v1/sandboxes HTTP/1.1\r\n"
                b"Host: test\r\n"
                b"Content-Type: application/json\r\n"
                b"Expect: 100-continue\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode()
            )
            # 100 Continue is sent once the handler reads the body, after
            # the request was admitted.
            _recv_until(sock, b"HTTP/1.1 100 Continue\r\n\r\n")

            holder.proc.send_signal(signal.SIGTERM)
            _wait_health(holder, 503)
            _assert_refused(data_dir, holder.pid)
            assert _health(holder) == (503, b"")

            sock.sendall(body)
            response = _recv_until(sock, b"\r\n\r\n")
            status_line = response.split(b"\r\n", 1)[0]
            assert status_line.startswith(b"HTTP/1.1 422 "), response
        assert holder.wait_exit() == 0, holder.stderr()
    finally:
        holder.stop()

    successor = start_serve(data_dir)
    successor.stop()
