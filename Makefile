# 1SEC — Development & Testing
#
# Usage:
#   make test          Run all tests (Go + Rust)
#   make test-go       Run Go tests only
#   make test-rust     Run Rust tests only
#   make lint          Run all linters
#   make fmt           Format all code
#   make build         Build all binaries
#   make check         Full CI check (fmt + lint + test)

.PHONY: test test-go test-rust lint lint-go lint-rust fmt fmt-go fmt-rust build build-go build-rust check

# ─── Test ─────────────────────────────────────────────────────────────────────

test: test-go test-rust

test-go:
	@echo "==> Running Go tests..."
	go test -timeout 120s ./...

test-go-race:
	@echo "==> Running Go tests with race detector..."
	CGO_ENABLED=1 go test -race -timeout 120s ./...

test-rust:
	@echo "==> Running Rust tests..."
	cd rust/1sec-engine && cargo test --no-default-features

test-rust-all:
	@echo "==> Running Rust tests (all features, requires libpcap)..."
	cd rust/1sec-engine && cargo test --all-features

# ─── Lint ─────────────────────────────────────────────────────────────────────

lint: lint-go lint-rust

lint-go:
	@echo "==> Go vet..."
	go vet ./...

lint-rust:
	@echo "==> Rust clippy..."
	cd rust/1sec-engine && cargo clippy --no-default-features -- -A dead-code -D warnings

# ─── Format ───────────────────────────────────────────────────────────────────

fmt: fmt-go fmt-rust

fmt-go:
	@echo "==> Formatting Go..."
	gofmt -w .

fmt-rust:
	@echo "==> Formatting Rust..."
	cd rust/1sec-engine && cargo fmt

fmt-check: fmt-check-go fmt-check-rust

fmt-check-go:
	@echo "==> Checking Go formatting..."
	@test -z "$$(gofmt -l .)" || (echo "Files not formatted:"; gofmt -l .; exit 1)

fmt-check-rust:
	@echo "==> Checking Rust formatting..."
	cd rust/1sec-engine && cargo fmt -- --check

# ─── Build ────────────────────────────────────────────────────────────────────

build: build-go build-rust

build-go:
	@echo "==> Building Go..."
	go build ./...

build-rust:
	@echo "==> Building Rust engine..."
	cd rust/1sec-engine && cargo build --no-default-features

# ─── Full CI Check ───────────────────────────────────────────────────────────

check: fmt-check lint test
	@echo ""
	@echo "==> All checks passed."

# ─── Vulnerability Scan ──────────────────────────────────────────────────────

vuln:
	@echo "==> Running Go vulnerability check..."
	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...
