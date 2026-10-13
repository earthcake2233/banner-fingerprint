GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: help
help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-16s %s\n", $$1, $$2}'

.PHONY: build
build: ## build server and client into ./bin
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o bin/fingerprint-server ./cmd/server
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o bin/fingerprint-client ./cmd/client

.PHONY: test
test: ## run unit tests
	$(GO) test ./...

.PHONY: vet
vet: ## run go vet
	$(GO) vet ./...

.PHONY: fmt
fmt: ## format sources
	$(GO) fmt ./...

.PHONY: tidy
tidy: ## refresh go.mod/go.sum and vendor/
	$(GO) mod tidy && $(GO) mod vendor

.PHONY: sync-rules
sync-rules: ## copy rules/rules.yaml into the embedded fallback copy
	cp rules/rules.yaml internal/fingerprint/builtin/rules.yaml

.PHONY: run-server
run-server: ## run the server locally (uses ./rules/rules.yaml)
	$(GO) run ./cmd/server -addr :8080 -rules rules/rules.yaml

.PHONY: run-client
run-client: ## run the client locally against the local server
	$(GO) run ./cmd/client -url http://127.0.0.1:8080 -input samples/input.json

.PHONY: compose-up
compose-up: ## build and start the whole stack
	docker compose up --build

.PHONY: compose-down
compose-down: ## stop the stack and remove its containers
	docker compose down

.PHONY: verify
verify: vet test ## vet + test
	@echo "OK"
