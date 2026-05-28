"""Shared fixtures for playpencil tests."""

import ctypes
from ctypes import c_char_p, c_int, c_void_p, c_uint16, c_size_t, POINTER, c_ubyte
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
BIN_DIR = REPO_ROOT / "bin"
PLAYPENCIL_BIN = BIN_DIR / "playpencil"


@pytest.fixture
def playpencil_bin():
    """Path to the playpencil binary. Fails if not built."""
    if not PLAYPENCIL_BIN.exists():
        pytest.fail(f"Binary not found at {PLAYPENCIL_BIN}. Run 'make all' first.")
    return PLAYPENCIL_BIN


def _find_lib():
    """Locate the libplaypencil_core shared library in bin/."""
    candidate = BIN_DIR / "libplaypencil_core.so"
    if candidate.exists():
        return str(candidate)
    return None


def _load_lib():
    """Load libplaypencil_core and configure function signatures."""
    path = _find_lib()
    if path is None:
        return None

    lib = ctypes.CDLL(path)

    # Runtime
    lib.pp_runtime_new.argtypes = [c_char_p]
    lib.pp_runtime_new.restype = c_void_p
    lib.pp_runtime_free.argtypes = [c_void_p]
    lib.pp_runtime_free.restype = None

    # Sandbox
    lib.pp_sandbox_create.argtypes = [c_void_p, c_char_p]
    lib.pp_sandbox_create.restype = c_void_p
    lib.pp_sandbox_start.argtypes = [c_void_p]
    lib.pp_sandbox_start.restype = c_int
    lib.pp_sandbox_stop.argtypes = [c_void_p]
    lib.pp_sandbox_stop.restype = c_int
    lib.pp_sandbox_destroy.argtypes = [c_void_p]
    lib.pp_sandbox_destroy.restype = c_int
    lib.pp_sandbox_status.argtypes = [c_void_p]
    lib.pp_sandbox_status.restype = c_void_p
    lib.pp_sandbox_free.argtypes = [c_void_p]
    lib.pp_sandbox_free.restype = None

    # Exec
    lib.pp_sandbox_exec.argtypes = [c_void_p, c_char_p]
    lib.pp_sandbox_exec.restype = c_void_p
    lib.pp_exec_next_event.argtypes = [c_void_p]
    lib.pp_exec_next_event.restype = c_void_p
    lib.pp_exec_write_stdin.argtypes = [c_void_p, POINTER(c_ubyte), c_size_t]
    lib.pp_exec_write_stdin.restype = c_int
    lib.pp_exec_close_stdin.argtypes = [c_void_p]
    lib.pp_exec_close_stdin.restype = c_int
    lib.pp_exec_signal.argtypes = [c_void_p, c_int]
    lib.pp_exec_signal.restype = c_int
    lib.pp_exec_resize.argtypes = [c_void_p, c_uint16, c_uint16]
    lib.pp_exec_resize.restype = c_int
    lib.pp_exec_free.argtypes = [c_void_p]
    lib.pp_exec_free.restype = None

    # Error / utility
    lib.pp_last_error.argtypes = []
    lib.pp_last_error.restype = c_void_p
    lib.pp_string_free.argtypes = [c_void_p]
    lib.pp_string_free.restype = None
    lib.pp_version.argtypes = []
    lib.pp_version.restype = c_void_p

    return lib


@pytest.fixture(scope="session")
def pplib():
    """Load the playpencil C library. Skips if not built."""
    lib = _load_lib()
    if lib is None:
        pytest.skip("libplaypencil_core.so not found. Run 'make all' first.")
    return lib


def read_pp_string(lib, ptr):
    """Read a C string from a pp_* return value and free it."""
    if not ptr:
        return None
    s = ctypes.string_at(ptr).decode("utf-8")
    lib.pp_string_free(ptr)
    return s


def get_last_error(lib):
    """Read pp_last_error as a Python string, or None."""
    ptr = lib.pp_last_error()
    if not ptr:
        return None
    return ctypes.string_at(ptr).decode("utf-8")
