# tamper-proof-audit-trail

An immutable, tamper-**evident** audit-logging microservice, built as an
end-to-end DevSecOps exercise: security is enforced at the **application**,
**infrastructure**, and **pipeline** layers at the same time.

Other services POST events ("Admin deleted user X", "Service A updated table Y").
Each event is committed to an append-only, hash-chained log. Any later edit,
reordering, or deletion of a record breaks the chain and is caught by the
`/verify` endpoint.

---

## How the tamper-evidence works

Every record embeds the SHA-256 hash of its own canonical payload **and** the
hash of the record before it - a blockchain-style linked hash chain:

```
                 ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
 genesis  ──────▶│  record 1   │─────▶│  record 2   │─────▶│  record 3   │
 (64 zeros)      │ prev_hash   │      │ prev_hash = │      │ prev_hash = │
                 │  = genesis  │      │  hash(rec1) │      │  hash(rec2) │
                 │ hash = H(   │      │ hash = H(   │      │ hash = H(   │
                 │  prev ‖ body)│     │  prev ‖ body)│     │  prev ‖ body)│
                 └─────────────┘      └─────────────┘      └─────────────┘

hash(rec_n) = SHA-256( prev_hash  ‖  canonical_json(seq, ts, actor, action, resource, metadata) )
```

`GET /api/v1/audit/verify` walks the whole chain, recomputes every hash, and
reports the first broken link (`{"intact": false, "broken_seq": 2, "reason": "hash mismatch"}`).

**Canonicalisation caveat.** The hash pre-image contains the *compacted raw
metadata bytes the client sent*, not a value re-serialised through a Go map.
Re-marshalling could reorder keys or change number formatting and make a replay
from disk produce a different hash. This is the single most important
correctness decision in the codebase (`internal/audit/event.go`).

> This is tamper-**evident**, not tamper-**proof**: an attacker with write access
> can rewrite the entire chain from any point forward. Production hardening:
> ship each `hash` to an external WORM store (the S3 Object Lock bucket in
> `terraform/`), anchor periodically to a notary/transparency log, and sign
> records with a KMS key the service cannot export.

---

## API

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/audit` | append an event; returns the committed record (201) |
| `GET`  | `/api/v1/audit` | list the chain (`?limit=&offset=`) |
| `GET`  | `/api/v1/audit/verify` | walk + recompute the chain; `?strict=1` → 409 if broken |
| `GET`  | `/healthz` | liveness |
| `GET`  | `/readyz` | readiness (data dir writable) |

```bash
# append
curl -s -XPOST localhost:8080/api/v1/audit \
  -H 'content-type: application/json' \
  -d '{"actor":"admin@corp","action":"user.delete","resource":"user/1042","metadata":{"ticket":"SEC-88"}}'

# -> 201
# {"seq":1,"timestamp":"2026-09-09T20:26:00.43Z","actor":"admin@corp","action":"user.delete",
#  "resource":"user/1042","metadata":{"ticket":"SEC-88"},
#  "prev_hash":"0000...0000","hash":"3b7a90b4...5754"}

# verify - intact
curl -s localhost:8080/api/v1/audit/verify
# {"intact":true,"checked":1}

# verify - after someone edited audit.log.jsonl by hand
# {"intact":false,"checked":1,"broken_seq":2,"reason":"hash mismatch"}
```

### Configuration (environment variables)

| Var | Default | Meaning |
|-----|---------|---------|
| `PORT` | `8080` | listen port |
| `DATA_DIR` | `/data` | directory holding `audit.log.jsonl` |
| `LOG_LEVEL` | `info` | `debug\|info\|warn\|error` |
| `SHUTDOWN_TIMEOUT` | `10s` | grace period on SIGTERM |
| `READ_HEADER_TIMEOUT` | `5s` | slow-loris guard |
| `MAX_BODY_BYTES` | `65536` | request body cap |

---

## Run it

```bash
# local
make run                       # DATA_DIR=./data PORT=8080

# container (read-only rootfs, all caps dropped, non-root)
make compose-up
curl localhost:8080/healthz

# local Kubernetes (kind)
make k8s-deploy
kubectl -n audit port-forward svc/auditd 8080:80

# the tamper demo (offline): 3 records, edit one on disk, watch verify catch it
make tamper-demo
```

---

## Security posture

### Application layer
- Standard-library only - minimal dependency surface (zero third-party modules).
- Strict input validation, `DisallowUnknownFields`, `MaxBytesReader`, explicit
  `http.Server` timeouts, panic-recovery middleware, `nosniff`/`no-store` headers.
- Durable writes (`fsync` per append); chain re-verified on startup.

### Container layer
- Multi-stage build → `gcr.io/distroless/static:nonroot`: no shell, no package
  manager, ~9 MB. Static binary, symbols stripped, `-trimpath`.
- Runs as UID 65532. `docker-compose.yml` adds `read_only`, `cap_drop: [ALL]`,
  `no-new-privileges`.

### Infrastructure layer (`terraform/`, Checkov-clean)
- S3 bucket with **Object Lock in COMPLIANCE mode** (true WORM) + versioning.
- SSE-KMS with a **customer-managed key**, rotation enabled, account-scoped key
  policy (no wildcard principal).
- All four Block-Public-Access switches; TLS-only + encryption-required bucket
  policies; access logging to a separate hardened bucket; lifecycle tiering.

### Kubernetes layer (`deploy/k8s/`)
- Namespace with Pod Security Standard `restricted` enforced.
- `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`,
  `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`.
- ServiceAccount with `automountServiceAccountToken: false`.
- Default-deny `NetworkPolicy` + a single explicit allow (ingress 8080, egress DNS).
- Resource requests/limits; liveness/readiness/startup probes.

### Pipeline layer (`.github/workflows/devsecops.yml`)

Stages run in strict order (`needs:`) so a cheap early failure stops the run
before anything is built - "shift-left":

| # | Stage | Tools | Scanning class |
|---|-------|-------|----------------|
| 1 | secrets | **gitleaks** | secret scanning (full history) |
| 2 | sast | **go vet**, **staticcheck**, **gosec** | SAST |
| 3 | test | `go test -race -cover` | dynamic / correctness |
| 4 | sca | **govulncheck**, **trivy fs** | dependency / SCA scanning |
| 5 | iac | **checkov** (tf + k8s), **hadolint** | IaC scanning |
| 6 | image | **trivy image**, **syft** | container CVE scan + SBOM |

Workflow-level `permissions: contents: read`; `concurrency` cancels superseded runs.

---

## Project layout

```
cmd/auditd/            server | -verify | -healthcheck
internal/config/       env config + validation
internal/audit/        event.go chain.go store.go verify.go   (the hash chain)
internal/httpapi/      handlers, middleware, server
terraform/             S3 Object Lock (WORM) + KMS  -- validate-only
deploy/k8s/            hardened manifests + kind-cluster.yaml
.github/workflows/     devsecops.yml
```

See `CLAUDE.md` for build/scan commands and gotchas.
