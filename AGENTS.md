# Playpencil — Developer Guide

Compute isolation layer. Cross-platform VM sandbox for running untrusted code (Linux + macOS, no root).

## Common Commands

```bash
make all        # Build everything (release)
make check      # cargo check + clippy
make test       # Run all tests (cargo + pytest, needs KVM)
make test-rust  # Rust unit tests only
make test-vm    # VM tests only (needs KVM)
make test-ci    # CI suite (check + rust tests + non-VM pytest)
make clean      # Clean build artifacts
```

## Project Structure

- **playpencil-core/** — Core library crate (lifecycle, policy, backends, network backend, C ABI)
- **playpencil-server/** — HTTP server crate (OpenSandbox protocol, daemon runtime)
- **playpencil-cli/** — CLI binary crate (`playpencil` — serve + client subcommands)
- **playpencil-init/** — Guest init binary (PID 1 inside VMs, exec handler). Built as musl static.
- **tests/** — Integration tests (Python)
- **scripts/** — Build/publish/e2e

## Code Style

- **Comments**: Explain why, not what. No fluff.
- **Python imports**: Always at top level, never inside functions.
- **Tests**: Flat `def test_*()` functions (Python), not class groupings.
- **Test assertions**: Precise comparisons, exact error codes + message fragments.
