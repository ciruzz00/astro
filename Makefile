# Every target runs inside the dev container: nothing is installed on the host.

export HOST_UID := $(shell id -u)
export HOST_GID := $(shell id -g)

COMPOSE := docker compose
RUN     := $(COMPOSE) run --rm dev
# Only the cli service loads the API keys from .env.
CLI     := $(COMPOSE) run --rm cli
VERSION ?= dev
DATE    ?= $(shell date -u +%Y-%m-%d)

.PHONY: help image shell tidy fmt verify vet lint vuln test check build run try serve token cross clean clean-all

help: ## List available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

image: ## Build the dev image
	$(COMPOSE) build dev

shell: ## Open a shell in the dev container
	$(RUN) bash

tidy: ## Run go mod tidy
	$(RUN) env GOFLAGS="-mod=mod -buildvcs=false" go mod tidy

fmt: ## Format the code
	$(RUN) gofmt -s -w .

verify: ## Verify module checksums
	$(RUN) go mod verify

vet: ## Run go vet
	$(RUN) go vet ./...

lint: ## Run staticcheck and gosec
	$(RUN) sh -c 'staticcheck ./... && gosec -quiet ./...'

vuln: ## Scan dependencies for known vulnerabilities
	$(RUN) govulncheck ./...

test: ## Run tests with the race detector
	$(RUN) go test -race ./...

check: verify vet lint vuln test ## Run every check (same as CI)

build: ## Build a linux binary for the container into dist/
	$(RUN) go build -trimpath -o dist/astro ./cmd/astro

run: ## Run astro in the container, e.g. make run ARGS="search T1059"
	$(CLI) go run ./cmd/astro $(ARGS)

try: ## Open a shell with astro built and on PATH, to try it out
	$(CLI) sh -c 'go build -trimpath -o /home/dev/bin/astro ./cmd/astro && \
		printf "\nastro is ready. Try:\n  astro sync --list\n  astro search CVE-2021-44228 T1059.001\n  astro --help\nType exit to leave.\n\n" && \
		PATH=/home/dev/bin:$$PATH exec bash'

serve: ## Start the REST API on http://127.0.0.1:8080 (Ctrl-C to stop)
	$(COMPOSE) up --build api

token: ## Create an API token, e.g. make token NAME=soar
	$(CLI) go run ./cmd/astro token create $(NAME)

cross: ## Build release packages for every OS/arch into dist/
	$(RUN) sh -c 'for t in linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64; do \
		scripts/package.sh "$(VERSION)" "$(DATE)" "$${t%/*}" "$${t#*/}" || exit 1; done'

clean: ## Remove astro containers, network, dangling images and build output
	-$(COMPOSE) down --remove-orphans
	-docker image prune -f --filter "dangling=true" --filter "label=com.docker.compose.project=astro" >/dev/null
	rm -rf dist coverage.out
	find . -name '*.test' -type f -delete

clean-all: clean ## Also remove the dev image and the cache/data volumes
	-$(COMPOSE) down --volumes --rmi all
