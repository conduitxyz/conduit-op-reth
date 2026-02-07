.PHONY: lint fmt clippy test pr pr-fix

## Run all checks that CI runs on pull requests
pr: fmt clippy test
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

test:
	@echo "Running tests..."
	cargo test --workspace -- --test-threads=1
