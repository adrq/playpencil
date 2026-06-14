LIBKRUN_DIR ?= vendor/libkrun
ifneq ($(wildcard $(LIBKRUN_DIR)/lib64/pkgconfig/libkrun.pc),)
  export PKG_CONFIG_PATH := $(abspath $(LIBKRUN_DIR))/lib64/pkgconfig:$(PKG_CONFIG_PATH)
  export LD_LIBRARY_PATH := $(abspath $(LIBKRUN_DIR))/lib64:$(LD_LIBRARY_PATH)
endif

.PHONY: all build check check-exec-features test test-rust test-vm test-ci pre-commit clean setup-libkrun

all: build

build:
	cargo build --release
	cargo build --release --target x86_64-unknown-linux-musl -p playpencil-init
	mkdir -p bin
	cp target/release/playpencil bin/
	cp target/x86_64-unknown-linux-musl/release/playpencil-init bin/
	cp target/release/libplaypencil_core.so bin/
	cp target/release/libplaypencil_core.a bin/

# `check` also validates the playpencil-exec feature firewall (check-exec-features
# is a prerequisite) so the dependency-isolation property this crate introduces is
# guarded by the mandated `make check` gate, not a manual target. The whole-
# workspace `cargo check`/`clippy` below cannot catch a stray producer-only tokio
# (feature unification turns tokio on for the whole build) — check-exec-features
# can.
check: check-exec-features
	cargo check
	cargo clippy -- -D warnings

# Build playpencil-exec under every feature combo (with --all-targets so the
# tests are compiled too) and assert the dependency-graph exclusions that keep
# the capabilities clean: tokio must be ABSENT from the producer-only graph (the
# producer firewall), and the exec crate must not DIRECTLY depend on libc under
# relay or consumer (their signal handling uses crate-owned consts, not libc — so
# the relay/consumer code literally cannot `use libc`). libc still appears in the
# relay/consumer graphs TRANSITIVELY via tokio (tokio -> mio/socket2 -> libc on
# unix), which is unavoidable and not our concern; we assert only that
# playpencil-exec is never a DIRECT depender of libc. --all-targets makes this
# meaningful: a relay/consumer TEST reaching for `libc::` would fail to compile
# here, since neither combo enables the optional libc dependency. Finally build
# init for the musl target — the only build that compiles `producer` WITHOUT tokio.
check-exec-features:
	@set -e; \
	for f in "" producer relay consumer relay,consumer host; do \
	  if [ -z "$$f" ]; then \
	    echo "== exec features: (default) =="; \
	    cargo check -p playpencil-exec --all-targets --no-default-features; \
	  else \
	    echo "== exec features: $$f =="; \
	    cargo check -p playpencil-exec --all-targets --no-default-features --features $$f; \
	  fi; \
	done
	@echo "== assert tokio ABSENT from producer-only graph =="
	@if cargo tree -p playpencil-exec --no-default-features --features producer -e no-dev,no-build --prefix none | grep -qE '^tokio v'; then \
	  echo "FAIL: tokio reachable from the producer-only graph (firewall breach)"; exit 1; \
	else echo "ok: no tokio"; fi
	@echo "== assert exec is not a DIRECT depender of libc under relay =="
	@if cargo tree -p playpencil-exec --no-default-features --features relay -e no-dev,no-build -i libc --prefix depth | grep -qE '^1playpencil-exec '; then \
	  echo "FAIL: playpencil-exec directly depends on libc under relay"; exit 1; \
	else echo "ok: libc only transitive (via tokio)"; fi
	@echo "== assert exec is not a DIRECT depender of libc under consumer =="
	@if cargo tree -p playpencil-exec --no-default-features --features consumer -e no-dev,no-build -i libc --prefix depth | grep -qE '^1playpencil-exec '; then \
	  echo "FAIL: playpencil-exec directly depends on libc under consumer"; exit 1; \
	else echo "ok: libc only transitive (via tokio)"; fi
	@echo "== init musl build (producer without tokio) =="
	cargo build --target x86_64-unknown-linux-musl -p playpencil-init

test: all test-rust
	cargo build
	uv run pytest -n4 -v tests

test-rust:
	cargo test

test-vm: all
	uv run pytest -v -m vm tests

# check-exec-features is listed explicitly (it also rides in via `check`) so CI
# guards the feature/dependency firewall without KVM, robustly of `check`'s deps.
test-ci: all check check-exec-features test-rust
	uv run pytest -v -m 'not vm' tests

pre-commit:
	uv run pre-commit run

setup-libkrun:
	scripts/setup-libkrun.sh

clean:
	cargo clean
	rm -rf bin/
