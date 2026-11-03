# tamper-proof-audit-trail - developer + DevSecOps entrypoints.
# `make help` lists everything.

SHELL      := /bin/bash
BIN        := bin/auditd
IMAGE      := auditd:local
DEMO_DIR   := demo-data
KIND_NAME  := audit
CHART      := deploy/helm/auditd
NAMESPACE  := audit
RENDERED   := bin/rendered-chart.yaml
PROM_RULES := deploy/prometheus

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

# Signed image published by CI. Verification is pinned to the exact workflow
# identity that signs it - without that, any GitHub workflow's signature passes.
GHCR_IMAGE    := ghcr.io/apolo151/auditd
CERT_IDENTITY := https://github.com/Apolo151/tamper-proof-audit-trail/.github/workflows/devsecops.yml@refs/heads/main
CERT_ISSUER   := https://token.actions.githubusercontent.com

.PHONY: verify-image
verify-image: ## Verify signature + SBOM + provenance of a published image (IMAGE_REF=ghcr.io/...@sha256:...)
	@test -n "$(IMAGE_REF)" || { echo "usage: make verify-image IMAGE_REF=$(GHCR_IMAGE)@sha256:<digest>"; exit 2; }
	cosign verify --certificate-identity "$(CERT_IDENTITY)" --certificate-oidc-issuer "$(CERT_ISSUER)" "$(IMAGE_REF)" >/dev/null
	cosign verify-attestation --type spdxjson --certificate-identity "$(CERT_IDENTITY)" --certificate-oidc-issuer "$(CERT_ISSUER)" "$(IMAGE_REF)" >/dev/null
	gh attestation verify "oci://$(IMAGE_REF)" --repo Apolo151/tamper-proof-audit-trail
	@echo "OK: $(IMAGE_REF) is signed by CI on main, with SBOM + SLSA provenance"

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
scan-iac: helm-template ## IaC scanning (checkov on terraform + rendered chart, hadolint on Dockerfile)
	checkov -d terraform/ --config-file terraform/.checkov.yaml
	checkov -f $(RENDERED) --framework kubernetes
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

.PHONY: helm-lint
helm-lint: ## helm lint --strict (default + kind values)
	helm lint --strict $(CHART)
	helm lint --strict $(CHART) -f $(CHART)/ci/kind-values.yaml

.PHONY: helm-template
helm-template: ## Render the chart to bin/rendered-chart.yaml
	@mkdir -p $(dir $(RENDERED))
	helm template auditd $(CHART) --namespace $(NAMESPACE) > $(RENDERED)
	@echo "wrote $(RENDERED)"

.PHONY: k8s-deploy
k8s-deploy: docker-build ## Create a kind cluster, install the chart, run helm test
	kind create cluster --name $(KIND_NAME) --config deploy/kind-cluster.yaml
	kind load docker-image $(IMAGE) --name $(KIND_NAME)
	kubectl --context kind-$(KIND_NAME) apply -f deploy/namespace.yaml
	helm --kube-context kind-$(KIND_NAME) upgrade --install auditd $(CHART) \
	  --namespace $(NAMESPACE) -f $(CHART)/ci/kind-values.yaml --wait --timeout 180s
	helm --kube-context kind-$(KIND_NAME) test auditd --namespace $(NAMESPACE)

.PHONY: k8s-clean
k8s-clean: ## Delete the kind cluster
	kind delete cluster --name $(KIND_NAME)

## --- observability ----------------------------------------------------

.PHONY: check-rules
check-rules: ## promtool check rules (syntax + PromQL)
	promtool check rules $(PROM_RULES)/recording-rules.yaml $(PROM_RULES)/alerts.yaml

.PHONY: test-rules
test-rules: check-rules ## promtool unit tests for every alert (fires / must-not-fire)
	promtool test rules $(PROM_RULES)/tests/alerts_test.yaml

.PHONY: check-metrics
check-metrics: build ## Run the binary and lint its /metrics output with promtool
	@set -e; d=$$(mktemp -d); \
	DATA_DIR=$$d PORT=18082 METRICS_PORT=19092 $(BIN) >/dev/null 2>&1 & pid=$$!; \
	trap 'kill $$pid 2>/dev/null; rm -rf $$d' EXIT; sleep 1; \
	curl -sf -XPOST localhost:18082/api/v1/audit -H 'content-type: application/json' \
	  -d '{"actor":"ci","action":"check","resource":"metrics"}' >/dev/null; \
	curl -sf localhost:19092/metrics | promtool check metrics; \
	echo "OK: /metrics passes promtool check metrics"

.PHONY: tamper-alert-demo
tamper-alert-demo: build ## Live server: edit the log on disk, watch auditd_chain_intact flip to 0
	@set -e; d=$$(mktemp -d); \
	DATA_DIR=$$d PORT=18083 METRICS_PORT=19093 VERIFY_INTERVAL=1s $(BIN) >/dev/null 2>&1 & pid=$$!; \
	trap 'kill $$pid 2>/dev/null; rm -rf $$d' EXIT; sleep 1; \
	for a in alice bob carol; do \
	  curl -sf -XPOST localhost:18083/api/v1/audit -H 'content-type: application/json' \
	    -d "{\"actor\":\"$$a\",\"action\":\"write\",\"resource\":\"db/records\"}" >/dev/null; \
	done; sleep 1.5; \
	echo "--- before:"; curl -s localhost:19093/metrics | grep -E '^auditd_chain_(intact|broken_seq|records) '; \
	echo "--- tampering with the file under the running server: bob -> mallory"; \
	sed -i 's/"actor":"bob"/"actor":"mallory"/' $$d/audit.log.jsonl; sleep 1.5; \
	echo "--- after:"; curl -s localhost:19093/metrics | grep -E '^auditd_chain_(intact|broken_seq|records) '; \
	curl -s 'localhost:18083/api/v1/audit/verify'; \
	if curl -s localhost:19093/metrics | grep -q '^auditd_chain_intact 0$$'; then \
	  echo "OK: AuditdChainTampered would fire (auditd_chain_intact == 0)"; \
	else \
	  echo "FAIL: tampering not reflected in metrics"; exit 1; \
	fi

## --- demos ----------------------------------------------------------

.PHONY: verify
verify: ## Hit a running server's verify endpoint (expects it on :8080)
	@curl -s localhost:8080/api/v1/audit/verify | tee /dev/stderr | grep -q '"intact":true'

.PHONY: tamper-demo
tamper-demo: build ## Show the chain catching an on-disk edit (offline, uses ./demo-data)
	@set -e; \
	rm -rf $(DEMO_DIR); mkdir -p $(DEMO_DIR); \
	DATA_DIR=$(DEMO_DIR) PORT=18080 METRICS_PORT=19080 $(BIN) & pid=$$!; sleep 1; \
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
