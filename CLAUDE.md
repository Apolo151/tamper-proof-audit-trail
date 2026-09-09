# CLAUDE.md

Guidance for working in this repository.

## What this is

A tamper-evident audit-logging microservice (Go, stdlib only) plus a full
DevSecOps setup: hardened container, Terraform for WORM S3 storage, hardened
Kubernetes manifests, and a shift-left GitHub Actions security pipeline.

## Layout

| Path | What |
|------|------|
| `cmd/auditd/` | entrypoint: `auditd` (server), `-verify`, `-healthcheck` |
| `internal/config/` | env-var configuration + validation |
| `internal/audit/` | the hash chain: `event.go` `chain.go` `store.go` `verify.go` |
| `internal/httpapi/` | HTTP handlers, middleware, server setup |
| `terraform/` | S3 (Object Lock/WORM) + KMS, Checkov-clean, **validate-only** |
| `deploy/k8s/` | hardened manifests + `kind-cluster.yaml` |
| `.github/workflows/devsecops.yml` | the pipeline |

## Build / test / run

```bash
make build          # -> bin/auditd
make test           # go test -race + coverage
make run            # DATA_DIR=./data PORT=8080
make tamper-demo    # writes 3 records, edits one on disk, shows verify catching it
```

## Local scanners

Each `make scan-*` target needs its tool on `PATH`
(`$HOME/.local/bin` + `$(go env GOPATH)/bin`):

| Target | Tools | Install |
|--------|-------|---------|
| `scan-secrets` | gitleaks | `go install github.com/gitleaks/gitleaks/v8@latest` |
| `scan-sast` | go vet, staticcheck, gosec | `go install honnef.co/go/tools/cmd/staticcheck@latest`; `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| `scan-deps` | govulncheck, trivy | `go install golang.org/x/vuln/cmd/govulncheck@latest`; trivy install script |
| `scan-iac` | checkov, hadolint | `pipx install checkov`; hadolint release binary |
| `scan-image` / `sbom` | trivy, syft | install scripts |

## Conventions

- **Standard library only.** No web framework, no ORM. `net/http` + `log/slog`.
- Packages live under `internal/`. Table-driven tests, `t.TempDir()` for fixtures.
- Structured logs: `slog` JSON handler, level from `LOG_LEVEL`.

## Gotchas

- Distroless runtime UID is **65532**; `/data` is pre-created in the image with
  that owner because there is no shell to `chown` at runtime.
- `-trimpath` is a `go build` flag, **not** an ldflag.
- Terraform is **validate + Checkov only** - never `apply` (no real AWS account).
- Keep the Deployment at **`replicas: 1`**: the chain is a single-writer log on
  an `emptyDir`. Multi-replica needs a StatefulSet + RWO PVC or a shared store.
- The hash pre-image hashes the client's **compacted raw metadata bytes**, not a
  re-marshalled map - don't "normalise" metadata through `map[string]any`.
