"""Shared fixtures for playpencil tests."""

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
