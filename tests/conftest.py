"""Shared fixtures for playpencil tests."""

import ctypes
import os
import shutil
from ctypes import c_char_p, c_int, c_void_p, c_uint16, c_size_t, POINTER, c_ubyte
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
BIN_DIR = REPO_ROOT / "bin"
PLAYPENCIL_BIN = BIN_DIR / "playpencil"

# Digest-pinned test images. A digest is immutable, so the image cache can serve
# it from the local seed without any registry round-trip (see seed_image_cache).
# These digests are the platform-specific (host-arch) manifest digests, which is
# the cache key the rootfs is stored under.
ALPINE_IMAGE_BACKEND = (
    "alpine@sha256:b58899f069c47216f6002a6850143dc6fae0d35eb8b0df9300bbe6327b9c2171"
)
ALPINE_IMAGE_FFI = (
    "alpine@sha256:f27cad9117495d32d067133afff942cb2dc745dfe9163e949f6bfe8a6a245339"
)

# Shared, pre-extracted image cache. Override with PLAYPENCIL_TEST_IMAGE_CACHE.
# This is an interim known location, not a blessed production path.
DEFAULT_TEST_IMAGE_CACHE = Path.home() / ".cache" / "playpencil" / "test-images"


def test_image_cache_dir():
    """Resolve the seed image-cache directory (env override or default)."""
    env = os.environ.get("PLAYPENCIL_TEST_IMAGE_CACHE")
    return Path(env) if env else DEFAULT_TEST_IMAGE_CACHE


def seed_image_cache(data_dir):
    """Point ``<data_dir>/images`` at the shared seed cache so digest-pinned
    images resolve fully offline.

    No-op if the seed directory is absent, so tests gracefully fall back to a
    normal registry pull on a machine without the seed.
    """
    seed = test_image_cache_dir()
    if not seed.is_dir():
        return
    images = Path(data_dir) / "images"
    if images.exists() or images.is_symlink():
        return
    try:
        images.symlink_to(seed, target_is_directory=True)
    except OSError:
        # Symlink unavailable (e.g. cross-device under xdist): copy the seed.
        shutil.copytree(seed, images)


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
    lib.pp_sandbox_create_and_start.argtypes = [c_void_p, c_char_p]
    lib.pp_sandbox_create_and_start.restype = c_void_p
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
