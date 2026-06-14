"""Tests for the playpencil C ABI (FFI layer)."""

import base64
import ctypes
import json
import tempfile
import time

import pytest

from conftest import (
    ALPINE_IMAGE_FFI,
    REPO_ROOT,
    get_last_error,
    read_pp_string,
    seed_image_cache,
)


def _wait_state(pplib, sb, want, timeout=90):
    """Poll pp_sandbox_status until `state` equals `want` (accepted-not-converged)."""
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        status_json = read_pp_string(pplib, pplib.pp_sandbox_status(sb))
        assert status_json is not None, f"status failed: {get_last_error(pplib)}"
        last = json.loads(status_json)["state"]
        if last == want:
            return
        time.sleep(0.2)
    raise AssertionError(f"sandbox did not reach {want!r}; last was {last!r}")


# ---------------------------------------------------------------------------
# FFI mechanics (no runtime needed)
# ---------------------------------------------------------------------------


def test_version(pplib):
    ptr = pplib.pp_version()
    assert ptr is not None
    version = ctypes.string_at(ptr).decode("utf-8")
    assert len(version) > 0


def test_last_error_initially_null(pplib):
    assert pplib.pp_last_error() is None


def test_string_free_null(pplib):
    pplib.pp_string_free(None)


def test_runtime_free_null(pplib):
    pplib.pp_runtime_free(None)


def test_sandbox_free_null(pplib):
    pplib.pp_sandbox_free(None)


def test_exec_free_null(pplib):
    pplib.pp_exec_free(None)


def test_create_null_runtime(pplib):
    sb = pplib.pp_sandbox_create(None, None)
    assert sb is None
    assert get_last_error(pplib) == "runtime handle is NULL"


def test_start_null_sandbox(pplib):
    assert pplib.pp_sandbox_start(None) == -1
    assert get_last_error(pplib) == "sandbox handle is NULL"


def test_create_invalid_json(pplib):
    """Pass invalid JSON as config_json to pp_runtime_new."""
    rt = pplib.pp_runtime_new(b"{bad json")
    assert rt is None
    err = get_last_error(pplib)
    assert err is not None
    assert "invalid config JSON" in err


def test_null_json_input(pplib):
    """Pass NULL as config_json to pp_runtime_new."""
    rt = pplib.pp_runtime_new(None)
    assert rt is None
    assert get_last_error(pplib) == "config_json is NULL"


def test_error_cleared_on_entry(pplib):
    """Result-returning calls clear last_error on entry."""
    pplib.pp_sandbox_start(None)
    assert pplib.pp_last_error() is not None
    pplib.pp_sandbox_stop(None)  # clears stale error, sets new one
    assert get_last_error(pplib) == "sandbox handle is NULL"


def test_free_preserves_last_error(pplib):
    """Free functions must not clear last_error (UAF prevention)."""
    pplib.pp_sandbox_create(None, None)  # sets error
    err_before = get_last_error(pplib)
    assert err_before == "runtime handle is NULL"

    pplib.pp_sandbox_free(None)  # should NOT clear
    assert get_last_error(pplib) == err_before


# ---------------------------------------------------------------------------
# VM lifecycle tests (require KVM + built init binary)
# ---------------------------------------------------------------------------

INIT_BINARY = REPO_ROOT / "bin" / "playpencil-init"


def _make_runtime_config(data_dir):
    """Build runtime config JSON pointing at a temp data_dir."""
    return json.dumps(
        {
            "data_dir": str(data_dir),
            "init_binary": str(INIT_BINARY),
        }
    ).encode("utf-8")


def _sandbox_config(image=ALPINE_IMAGE_FFI, entrypoint=None):
    cfg = {
        "image": image,
        "resource_limits": {
            "cpus": 1,
            "memory_bytes": 256 * 1024 * 1024,
            "disk_bytes": None,
        },
        "mounts": [],
        "network": "Isolated",
        "env": [],
    }
    if entrypoint is not None:
        cfg["entrypoint"] = entrypoint
    return json.dumps(cfg).encode("utf-8")


@pytest.fixture
def ffi_runtime(pplib):
    """Create a real FFI runtime with a temp data_dir. Requires KVM."""
    if not INIT_BINARY.exists():
        pytest.fail(f"Init binary not found at {INIT_BINARY}. Run 'make all' first.")
    with tempfile.TemporaryDirectory() as tmpdir:
        seed_image_cache(tmpdir)
        cfg = _make_runtime_config(tmpdir)
        rt = pplib.pp_runtime_new(cfg)
        assert rt is not None, f"pp_runtime_new failed: {get_last_error(pplib)}"
        yield rt
        pplib.pp_runtime_free(rt)


@pytest.mark.vm
def test_ffi_lifecycle(pplib, ffi_runtime):
    sb = pplib.pp_sandbox_create(ffi_runtime, _sandbox_config())
    assert sb is not None, f"create failed: {get_last_error(pplib)}"

    # create provisions toward the stopped state.
    _wait_state(pplib, sb, "stopped")

    # start/stop/destroy are accepted, then reconcile asynchronously.
    assert pplib.pp_sandbox_start(sb) == 0
    _wait_state(pplib, sb, "running")

    assert pplib.pp_sandbox_stop(sb) == 0
    _wait_state(pplib, sb, "stopped")

    assert pplib.pp_sandbox_destroy(sb) == 0
    _wait_state(pplib, sb, "destroyed")
    pplib.pp_sandbox_free(sb)


@pytest.mark.vm
def test_ffi_create_and_start(pplib, ffi_runtime):
    sb = pplib.pp_sandbox_create_and_start(ffi_runtime, _sandbox_config())
    assert sb is not None, f"create_and_start failed: {get_last_error(pplib)}"
    _wait_state(pplib, sb, "running")
    assert pplib.pp_sandbox_destroy(sb) == 0
    _wait_state(pplib, sb, "destroyed")
    pplib.pp_sandbox_free(sb)


def test_ffi_exec_gid_without_uid_is_invalid_input(pplib, ffi_runtime):
    """The credential invariant is enforced at the core/FFI boundary, not only in
    the HTTP/WS adapters: a gid with no uid is rejected as invalid input before
    the running-state gate or any guest dispatch, so a C-ABI caller cannot request
    a credential drop that silently runs with the default (typically root) creds.

    No VM boot needed — the rejection happens on a provisioned-but-stopped
    sandbox, before exec would require the running state.
    """
    sb = pplib.pp_sandbox_create(ffi_runtime, _sandbox_config())
    assert sb is not None, f"create failed: {get_last_error(pplib)}"
    _wait_state(pplib, sb, "stopped")

    cmd = json.dumps({"command": ["id"], "env": [], "gid": 5}).encode("utf-8")
    exec_h = pplib.pp_sandbox_exec(sb, cmd)
    assert exec_h is None, "exec must be refused when gid is set without uid"
    err = get_last_error(pplib)
    assert err is not None and "gid requires uid" in err, err

    pplib.pp_sandbox_destroy(sb)
    _wait_state(pplib, sb, "destroyed")
    pplib.pp_sandbox_free(sb)


def test_ffi_exec_invalid_env_is_invalid_input(pplib, ffi_runtime):
    """Env is validated at the core/FFI boundary (not only at sandbox creation):
    a key containing '=' is rejected as invalid input before guest dispatch, so it
    can't become a guest-side start error or be re-split by putenv. No VM boot
    needed — rejection happens on a provisioned-but-stopped sandbox."""
    sb = pplib.pp_sandbox_create(ffi_runtime, _sandbox_config())
    assert sb is not None, f"create failed: {get_last_error(pplib)}"
    _wait_state(pplib, sb, "stopped")

    cmd = json.dumps({"command": ["env"], "env": [["BAD=KEY", "v"]]}).encode("utf-8")
    exec_h = pplib.pp_sandbox_exec(sb, cmd)
    assert exec_h is None, "exec must be refused for an invalid env entry"
    err = get_last_error(pplib)
    assert err is not None and "env key" in err, err

    pplib.pp_sandbox_destroy(sb)
    _wait_state(pplib, sb, "destroyed")
    pplib.pp_sandbox_free(sb)


def test_ffi_create_rejects_invalid_entrypoint(pplib, ffi_runtime):
    """A malformed main-process command is rejected as invalid input at the
    core/FFI boundary (an empty program), before any provisioning — the same
    validation the HTTP path and the durable store enforce."""
    sb = pplib.pp_sandbox_create(ffi_runtime, _sandbox_config(entrypoint=[""]))
    assert sb is None, "create must reject an empty entrypoint program"
    err = get_last_error(pplib)
    assert err is not None and "entrypoint" in err, err


@pytest.mark.vm
def test_ffi_entrypoint_exit_reaches_terminal_without_leaking_carrier(
    pplib, ffi_runtime
):
    """A create-supplied entrypoint runs as the main process; when it exits the VM
    is driven to a terminal state. The exit carrier is backend-internal and must
    NOT appear in the C-ABI status JSON."""
    sb = pplib.pp_sandbox_create_and_start(
        ffi_runtime, _sandbox_config(entrypoint=["sh", "-c", "exit 0"])
    )
    assert sb is not None, f"create failed: {get_last_error(pplib)}"
    _wait_state(pplib, sb, "failed")
    status_json = read_pp_string(pplib, pplib.pp_sandbox_status(sb))
    assert "entrypoint_exit" not in status_json, status_json
    assert "exit_code" not in status_json, status_json
    pplib.pp_sandbox_destroy(sb)
    _wait_state(pplib, sb, "destroyed")
    pplib.pp_sandbox_free(sb)


@pytest.mark.vm
def test_ffi_exec_echo(pplib, ffi_runtime):
    sb = pplib.pp_sandbox_create_and_start(ffi_runtime, _sandbox_config())
    _wait_state(pplib, sb, "running")

    cmd = json.dumps({"command": ["echo", "hello"], "env": []}).encode("utf-8")
    exec_h = pplib.pp_sandbox_exec(sb, cmd)
    assert exec_h is not None, f"exec failed: {get_last_error(pplib)}"

    stdout_bytes = b""
    got_exit = False
    while True:
        event_ptr = pplib.pp_exec_next_event(exec_h)
        if event_ptr is None:
            break
        event = json.loads(read_pp_string(pplib, event_ptr))
        if event["type"] == "stdout":
            stdout_bytes += base64.b64decode(event["data"])
        elif event["type"] == "exit":
            assert event["code"] == 0
            got_exit = True

    assert b"hello" in stdout_bytes
    assert got_exit
    assert pplib.pp_last_error() is None  # EOF, not error

    pplib.pp_exec_free(exec_h)
    pplib.pp_sandbox_destroy(sb)
    _wait_state(pplib, sb, "destroyed")
    pplib.pp_sandbox_free(sb)


@pytest.mark.vm
def test_ffi_exec_after_fork_keepalive(pplib, ffi_runtime):
    """A VM must still be genuinely executable past the fork keep-alive window of 10s"""
    sb = pplib.pp_sandbox_create_and_start(ffi_runtime, _sandbox_config())
    assert sb is not None, f"create_and_start failed: {get_last_error(pplib)}"
    _wait_state(pplib, sb, "running")

    time.sleep(15)

    # Sandbox record still reports running, AND a real exec round-trips.
    status = json.loads(read_pp_string(pplib, pplib.pp_sandbox_status(sb)))
    assert status["state"] == "running", (
        f"VM did not survive the fork keep-alive window; state is {status['state']}"
    )

    cmd = json.dumps({"command": ["echo", "alive"], "env": []}).encode("utf-8")
    exec_h = pplib.pp_sandbox_exec(sb, cmd)
    assert exec_h is not None, f"exec failed (VM not alive?): {get_last_error(pplib)}"

    stdout_bytes = b""
    got_exit = False
    while True:
        event_ptr = pplib.pp_exec_next_event(exec_h)
        if event_ptr is None:
            break
        event = json.loads(read_pp_string(pplib, event_ptr))
        if event["type"] == "stdout":
            stdout_bytes += base64.b64decode(event["data"])
        elif event["type"] == "exit":
            assert event["code"] == 0
            got_exit = True

    assert b"alive" in stdout_bytes
    assert got_exit

    pplib.pp_exec_free(exec_h)
    pplib.pp_sandbox_destroy(sb)
    _wait_state(pplib, sb, "destroyed")
    pplib.pp_sandbox_free(sb)


@pytest.mark.vm
def test_ffi_write_stdin_null_data(pplib, ffi_runtime):
    """pp_exec_write_stdin with NULL data and nonzero len returns -1."""
    sb = pplib.pp_sandbox_create_and_start(ffi_runtime, _sandbox_config())
    _wait_state(pplib, sb, "running")

    cmd = json.dumps({"command": ["cat"], "env": []}).encode("utf-8")
    exec_h = pplib.pp_sandbox_exec(sb, cmd)
    assert exec_h is not None

    assert pplib.pp_exec_write_stdin(exec_h, None, 10) == -1
    assert get_last_error(pplib) == "data is NULL"

    pplib.pp_exec_free(exec_h)
    pplib.pp_sandbox_destroy(sb)
    _wait_state(pplib, sb, "destroyed")
    pplib.pp_sandbox_free(sb)


@pytest.mark.vm
def test_ffi_write_stdin_after_destroy_fails(pplib, ffi_runtime):
    """Destroying a sandbox closes its exec channels: a later stdin write fails.

    Guards the C-ABI contract that teardown closes exec channels (a post-destroy
    pp_exec_write_stdin must not silently succeed into a gone guest console).
    """
    sb = pplib.pp_sandbox_create_and_start(ffi_runtime, _sandbox_config())
    _wait_state(pplib, sb, "running")

    cmd = json.dumps({"command": ["cat"], "env": []}).encode("utf-8")
    exec_h = pplib.pp_sandbox_exec(sb, cmd)
    assert exec_h is not None, f"exec failed: {get_last_error(pplib)}"

    data = b"hello\n"
    buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    # While the VM is running, the write is accepted.
    assert pplib.pp_exec_write_stdin(exec_h, buf, len(data)) == 0

    # Destroy the sandbox; its exec channels must close. Teardown aborts and
    # awaits the relay tasks before completing, so by the time the sandbox is
    # observed destroyed the stdin channel is already closed.
    assert pplib.pp_sandbox_destroy(sb) == 0
    _wait_state(pplib, sb, "destroyed")

    # The FIRST write after destroy fails synchronously: the relay receiver is
    # dropped (channel closed) by teardown, so no polling/retry is needed.
    assert pplib.pp_exec_write_stdin(exec_h, buf, len(data)) == -1, (
        "stdin write after destroy must fail synchronously"
    )

    pplib.pp_exec_free(exec_h)
    pplib.pp_sandbox_free(sb)
