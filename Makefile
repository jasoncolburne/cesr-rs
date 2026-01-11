.PHONY: all build clippy deny fmt-check fmt install-deny test

all: fmt-check deny clippy test build

build:
	cargo build --release

clippy:
	cargo clippy -- -D warnings

deny:
	cargo deny check -A no-license-field

fmt-check:
	cargo fmt --check

fmt:
	cargo fmt

install-deny:
	cargo install cargo-deny

test:
	cargo test
