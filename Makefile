.PHONY: all build check test test-rust test-vm test-ci clean

all: build

build:
	cargo build --release
	mkdir -p bin
	cp target/release/playpencil bin/

check:
	cargo check
	cargo clippy -- -D warnings

test: all test-rust
	uv run pytest -v tests

test-rust:
	cargo test

test-vm: all
	uv run pytest -v -m vm tests

test-ci: check test-rust
	uv run pytest -v -m 'not vm' tests

clean:
	cargo clean
	rm -rf bin/
