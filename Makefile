.PHONY: build build-maxperf lint fmt clippy deny udeps docs test pr pr-fix

build:
	cargo build --release

build-maxperf:
	cargo build --profile maxperf

## Run all checks that CI runs on pull requests
pr: fmt clippy deny udeps docs test
	@echo "All PR checks passed!"

## Auto-fix formatting issues
pr-fix:
	cargo +nightly fmt --all
	@echo "Formatting fixed!"

fmt:
	@echo "Checking formatting..."
	cargo +nightly fmt --all --check

clippy:
	@echo "Running clippy..."
	cargo clippy --workspace --all-targets -- -D warnings

deny:
	@echo "Running security audit..."
	cargo deny check

udeps:
	@echo "Checking unused dependencies..."
	cargo machete

docs:
	@echo "Checking documentation..."
	RUSTDOCFLAGS="-D warnings" cargo doc --all --no-deps --document-private-items

test:
	@echo "Running tests..."
	cargo test --workspace
