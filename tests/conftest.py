"""Shared fixtures for playpencil tests."""

import os
import shutil
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
# A minimal image that ships NO shell/coreutils (no `tail`), pinned by its
# amd64 platform-manifest digest — used to prove image-independent idle mode
# (init is injected regardless, so an idle box needs no image-provided binary).
DISTROLESS_IMAGE = (
    "gcr.io/distroless/static-debian12"
    "@sha256:7d14daf425206f9e79b463e57226c1d6500a6b42f4923d5f0a9a413657f5774f"
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
