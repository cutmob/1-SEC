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

.PHONY: test test-go test-rust lint lint-go lint-rust staticcheck fmt fmt-go fmt-rust fmt-check fmt-check-go fmt-check-rust build build-go build-rust check audit audit-go audit-rust vuln

GO_PACKAGE_PATTERNS := ./cmd/... ./internal/...
GO_PACKAGES := $(shell go list $(GO_PACKAGE_PATTERNS))
GO_PACKAGE_DIRS := $(shell go list -f '{{.Dir}}' $(GO_PACKAGES))

ifeq ($(OS),Windows_NT)
FMT_CHECK_GO = powershell -NoProfile -Command "$$files = gofmt -l $(GO_PACKAGE_DIRS); if ($$files) { Write-Host 'Files not formatted:'; $$files; exit 1 }"
else
FMT_CHECK_GO = test -z "$$(gofmt -l $(GO_PACKAGE_DIRS))" || (echo "Files not formatted:"; gofmt -l $(GO_PACKAGE_DIRS); exit 1)
endif

# ─── Test ─────────────────────────────────────────────────────────────────────

test: test-go test-rust

test-go:
	@echo "==> Running Go tests..."
	go test -timeout 120s $(GO_PACKAGES)

test-go-race:
	@echo "==> Running Go tests with race detector..."
	CGO_ENABLED=1 go test -race -timeout 120s $(GO_PACKAGES)

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
	go vet $(GO_PACKAGES)

staticcheck:
	@echo "==> Staticcheck..."
	staticcheck $(GO_PACKAGES)

lint-rust:
	@echo "==> Rust clippy..."
	cd rust/1sec-engine && cargo clippy --no-default-features -- -A dead-code -D warnings

# ─── Format ───────────────────────────────────────────────────────────────────

fmt: fmt-go fmt-rust

fmt-go:
	@echo "==> Formatting Go..."
	gofmt -w $(GO_PACKAGE_DIRS)

fmt-rust:
	@echo "==> Formatting Rust..."
	cd rust/1sec-engine && cargo fmt

fmt-check: fmt-check-go fmt-check-rust

fmt-check-go:
	@echo "==> Checking Go formatting..."
	$(FMT_CHECK_GO)

fmt-check-rust:
	@echo "==> Checking Rust formatting..."
	cd rust/1sec-engine && cargo fmt -- --check

# ─── Build ────────────────────────────────────────────────────────────────────

build: build-go build-rust

build-go:
	@echo "==> Building Go..."
	go build $(GO_PACKAGES)

build-rust:
	@echo "==> Building Rust engine..."
	cd rust/1sec-engine && cargo build --no-default-features

# ─── Full CI Check ───────────────────────────────────────────────────────────

check: fmt-check lint test audit
	@echo ""
	@echo "==> All checks passed."

# ─── Vulnerability Scan ──────────────────────────────────────────────────────

audit: audit-go audit-rust

audit-go:
	@echo "==> Running Go vulnerability check..."
	govulncheck $(GO_PACKAGES)

audit-rust:
	@echo "==> Running Rust dependency audit..."
	cd rust/1sec-engine && cargo audit

vuln: audit-go
