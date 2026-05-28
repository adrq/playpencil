LIBKRUN_DIR ?= vendor/libkrun
ifneq ($(wildcard $(LIBKRUN_DIR)/lib64/pkgconfig/libkrun.pc),)
  export PKG_CONFIG_PATH := $(abspath $(LIBKRUN_DIR))/lib64/pkgconfig:$(PKG_CONFIG_PATH)
  export LD_LIBRARY_PATH := $(abspath $(LIBKRUN_DIR))/lib64:$(LD_LIBRARY_PATH)
endif

.PHONY: all build check test test-rust test-vm test-ci pre-commit clean setup-libkrun

all: build

build:
	cargo build --release
	cargo build --release --target x86_64-unknown-linux-musl -p playpencil-init
	mkdir -p bin
	cp target/release/playpencil bin/
	cp target/x86_64-unknown-linux-musl/release/playpencil-init bin/
	cp target/release/libplaypencil_core.so bin/
	cp target/release/libplaypencil_core.a bin/

check:
	cargo check
	cargo clippy -- -D warnings

test: all test-rust
	cargo build
	uv run pytest -v tests

test-rust:
	cargo test

test-vm: all
	uv run pytest -v -m vm tests

test-ci: all check test-rust
	uv run pytest -v -m 'not vm' tests

pre-commit:
	uv run pre-commit run

setup-libkrun:
	scripts/setup-libkrun.sh

clean:
	cargo clean
	rm -rf bin/
