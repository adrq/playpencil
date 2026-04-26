.PHONY: all build check test clean

all: build

build:
	cargo build --release
	mkdir -p bin
	cp target/release/playpencil bin/

check:
	cargo check
	cargo clippy -- -D warnings

test:
	cargo test

clean:
	cargo clean
	rm -rf bin/
