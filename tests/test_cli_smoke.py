"""Smoke test: CLI binary prints version."""

import subprocess


def test_cli_prints_version(playpencil_bin):
    result = subprocess.run(
        [str(playpencil_bin)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "playpencil v" in result.stdout
