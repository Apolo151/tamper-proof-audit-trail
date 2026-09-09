# tamper-proof-audit-trail - developer + DevSecOps entrypoints.
# `make help` lists everything.

SHELL      := /bin/bash
BIN        := bin/auditd
IMAGE      := auditd:local
DEMO_DIR   := demo-data
KIND_NAME  := audit

GOFLAGS_BUILD := -trimpath -ldflags="-w -s"

.DEFAULT_GOAL := help

## --- build & test -------------------------------------------------------

.PHONY: build
build: ## Compile the static binary to bin/auditd
	CGO_ENABLED=0 go build $(GOFLAGS_BUILD) -o $(BIN) ./cmd/auditd

.PHONY: test
test: ## Run unit tests with the race detector + coverage
	go test -race -covermode=atomic -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1

.PHONY: run
run: ## Run the server locally (DATA_DIR=./data, PORT=8080)
	DATA_DIR=./data PORT=8080 LOG_LEVEL=debug go run ./cmd/auditd

.PHONY: tidy
tidy: ## go mod tidy + gofmt
	go mod tidy
	gofmt -w .

## --- container ---------------------------------------------------------

.PHONY: docker-build
docker-build: ## Build the hardened distroless image
	docker build -t $(IMAGE) .

.PHONY: compose-up
compose-up: ## Run via docker compose (read-only rootfs, caps dropped)
	docker compose up --build -d
	@echo "curl localhost:8080/healthz"

.PHONY: compose-down
compose-down: ## Stop docker compose and remove the volume
	docker compose down -v

## --- security scans (see INTERVIEW_NOTES.md for what each one is) -----

.PHONY: scan-secrets
scan-secrets: ## Secret scanning (gitleaks)
	gitleaks dir . --redact -v

.PHONY: scan-sast
scan-sast: ## SAST (go vet + staticcheck + gosec)
	go vet ./...
	staticcheck ./...
	gosec -severity medium -confidence medium ./...

.PHONY: scan-deps
scan-deps: ## SCA / dependency scanning (govulncheck + trivy fs)
	govulncheck ./...
	trivy fs --scanners vuln,secret,misconfig --ignore-unfixed --severity CRITICAL,HIGH .

.PHONY: scan-iac
scan-iac: ## IaC scanning (checkov on terraform + k8s, hadolint on Dockerfile)
	checkov -d terraform/ --config-file terraform/.checkov.yaml
	checkov -d deploy/k8s/ --framework kubernetes
	hadolint Dockerfile

.PHONY: scan-image
scan-image: docker-build ## Container image CVE scan (trivy image)
	trivy image --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 $(IMAGE)

.PHONY: sbom
sbom: docker-build ## Generate an SPDX SBOM for the image (syft)
	syft $(IMAGE) -o spdx-json=sbom.spdx.json
	@echo "wrote sbom.spdx.json"

.PHONY: scan-all
scan-all: scan-secrets scan-sast scan-deps scan-iac scan-image ## Run every scanner

## --- infra ------------------------------------------------------------

.PHONY: tf-validate
tf-validate: ## terraform fmt + validate (no cloud calls)
	terraform -chdir=terraform fmt -check
	terraform -chdir=terraform init -backend=false -input=false
	terraform -chdir=terraform validate

.PHONY: k8s-render
k8s-render: ## Render the kustomize output
	kubectl kustomize deploy/k8s/

.PHONY: k8s-deploy
k8s-deploy: docker-build ## Create a kind cluster and deploy auditd into it
	kind create cluster --name $(KIND_NAME) --config deploy/k8s/kind-cluster.yaml
	kind load docker-image $(IMAGE) --name $(KIND_NAME)
	kubectl apply -k deploy/k8s/
	kubectl -n audit rollout status deploy/auditd --timeout=90s

.PHONY: k8s-clean
k8s-clean: ## Delete the kind cluster
	kind delete cluster --name $(KIND_NAME)

## --- demos ----------------------------------------------------------

.PHONY: verify
verify: ## Hit a running server's verify endpoint (expects it on :8080)
	@curl -s localhost:8080/api/v1/audit/verify | tee /dev/stderr | grep -q '"intact":true'

.PHONY: tamper-demo
tamper-demo: build ## Show the chain catching an on-disk edit (offline, uses ./demo-data)
	@set -e; \
	rm -rf $(DEMO_DIR); mkdir -p $(DEMO_DIR); \
	DATA_DIR=$(DEMO_DIR) PORT=18080 $(BIN) & pid=$$!; sleep 1; \
	for a in alice bob carol; do \
	  curl -s -XPOST localhost:18080/api/v1/audit -H 'content-type: application/json' \
	    -d "{\"actor\":\"$$a\",\"action\":\"write\",\"resource\":\"db/records\"}" >/dev/null; \
	done; \
	kill $$pid; sleep 0.3; \
	echo "--- chain as written ---"; \
	DATA_DIR=$(DEMO_DIR) $(BIN) -verify; \
	echo "--- tampering: rewrite actor on record 2 ---"; \
	sed -i '2s/"actor":"bob"/"actor":"mallory"/' $(DEMO_DIR)/audit.log.jsonl; \
	echo "--- chain after tampering ---"; \
	if DATA_DIR=$(DEMO_DIR) $(BIN) -verify; then \
	  echo "FAIL: tampering not detected"; exit 1; \
	else \
	  echo "OK: tampering detected (exit 1)"; \
	fi; \
	rm -rf $(DEMO_DIR)

.PHONY: help
help: ## Show this help
	@awk 'BEGIN{FS":.*##"} /^[a-zA-Z0-9_-]+:.*##/ {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
