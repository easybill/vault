build-linux:
	docker run -v "$(CURDIR)":/volume -w /volume -e RUSTFLAGS='-C link-args=-s' -t clux/muslrust cargo build --target=x86_64-unknown-linux-musl --release

build: build-linux

clippy:
	cargo clippy

test:
	cargo test -- --nocapture --test-threads=1
