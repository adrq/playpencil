"""Tests for the playpencil C ABI (FFI layer)."""

import base64
import ctypes
import json
import tempfile

import pytest

from conftest import REPO_ROOT, get_last_error, read_pp_string


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


def _sandbox_config(image="alpine:3.21"):
    return json.dumps(
        {
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
    ).encode("utf-8")


@pytest.fixture
def ffi_runtime(pplib):
    """Create a real FFI runtime with a temp data_dir. Requires KVM."""
    if not INIT_BINARY.exists():
        pytest.fail(f"Init binary not found at {INIT_BINARY}. Run 'make all' first.")
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = _make_runtime_config(tmpdir)
        rt = pplib.pp_runtime_new(cfg)
        assert rt is not None, f"pp_runtime_new failed: {get_last_error(pplib)}"
        yield rt
        pplib.pp_runtime_free(rt)


@pytest.mark.vm
def test_ffi_lifecycle(pplib, ffi_runtime):
    sb = pplib.pp_sandbox_create(ffi_runtime, _sandbox_config())
    assert sb is not None, f"create failed: {get_last_error(pplib)}"

    assert pplib.pp_sandbox_start(sb) == 0

    status_json = read_pp_string(pplib, pplib.pp_sandbox_status(sb))
    assert status_json is not None
    status = json.loads(status_json)
    assert status["state"] == "running"

    assert pplib.pp_sandbox_stop(sb) == 0
    assert pplib.pp_sandbox_destroy(sb) == 0
    pplib.pp_sandbox_free(sb)


@pytest.mark.vm
def test_ffi_exec_echo(pplib, ffi_runtime):
    sb = pplib.pp_sandbox_create(ffi_runtime, _sandbox_config())
    assert pplib.pp_sandbox_start(sb) == 0

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
    pplib.pp_sandbox_free(sb)


@pytest.mark.vm
def test_ffi_write_stdin_null_data(pplib, ffi_runtime):
    """pp_exec_write_stdin with NULL data and nonzero len returns -1."""
    sb = pplib.pp_sandbox_create(ffi_runtime, _sandbox_config())
    assert pplib.pp_sandbox_start(sb) == 0

    cmd = json.dumps({"command": ["cat"], "env": []}).encode("utf-8")
    exec_h = pplib.pp_sandbox_exec(sb, cmd)
    assert exec_h is not None

    assert pplib.pp_exec_write_stdin(exec_h, None, 10) == -1
    assert get_last_error(pplib) == "data is NULL"

    pplib.pp_exec_free(exec_h)
    pplib.pp_sandbox_destroy(sb)
    pplib.pp_sandbox_free(sb)
