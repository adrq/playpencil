# Playpencil — Developer Guide

Compute isolation layer. Cross-platform VM sandbox for running untrusted code (Linux + macOS, no root).

## Prerequisites

- **libkrun**: Required for building the core crate. Run `make setup-libkrun` to download and set up `vendor/libkrun/` with headers and pkg-config files. The build system and pre-commit hooks expect `vendor/libkrun/lib64/pkgconfig/libkrun.pc` to exist.

## Common Commands

```bash
make all        # Build everything (release)
make check      # cargo check + clippy
make test       # Run all tests (cargo + pytest, needs KVM)
make test-rust  # Rust unit tests only
make test-vm    # VM tests only (needs KVM)
make test-ci    # CI suite (check + rust tests + non-VM pytest)
make pre-commit  # Run pre-commit hooks on staged files
make clean      # Clean build artifacts
```

## Project Structure

- **core/** — Core library crate (`playpencil-core`: lifecycle, policy, backends, network backend, C ABI)
- **server/** — HTTP server crate (`playpencil-server`: OpenSandbox protocol, daemon runtime)
- **cli/** — CLI binary crate (`playpencil-cli`: serve + client subcommands)
- **init/** — Guest init binary (`playpencil-init`: PID 1 inside VMs, exec handler). Built as musl static.
- **tests/** — Integration tests (Python)
- **scripts/** — Build/publish/e2e

## Code Style

- **Comments**: Explain why, not what. No fluff.
- **Python imports**: Always at top level, never inside functions.
- **Tests**: Flat `def test_*()` functions (Python), not class groupings.
- **Test assertions**: Precise comparisons, exact error codes + message fragments.
