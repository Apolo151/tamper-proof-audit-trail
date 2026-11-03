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

`GET /api/v1/audit/verify` re-reads the log **from disk**, recomputes every hash,
checks the file is exactly the chain the process committed (so a truncated or
consistently re-hashed file is caught too), and reports the first broken link (`{"intact": false, "broken_seq": 2, "reason": "hash mismatch"}`).

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
| `GET`  | `/readyz` | readiness (data dir present, log file open) |
| `GET`  | `:9090/metrics` | Prometheus metrics, on a **separate listener** (`METRICS_PORT`) |

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
| `METRICS_PORT` | `9090` | separate listener for `GET /metrics` (must differ from `PORT`) |
| `VERIFY_INTERVAL` | `60s` | how often the on-disk chain is re-verified (min `1s`) |

---

## Run it

```bash
# local
make run                       # DATA_DIR=./data PORT=8080

# container (read-only rootfs, all caps dropped, non-root)
make compose-up
curl localhost:8080/healthz

# local Kubernetes (kind): builds the image, installs the Helm chart into a
# PSS-restricted namespace, then runs `helm test`
make k8s-deploy
kubectl -n audit port-forward svc/auditd 8080:80

# or install the published, signed chart (pinned to the signed image digest)
kubectl apply -f deploy/namespace.yaml
helm install auditd oci://ghcr.io/apolo151/charts/auditd --version 0.2.0 -n audit

# the tamper demo (offline): 3 records, edit one on disk, watch verify catch it
make tamper-demo

# the same against a *running* server: auditd_chain_intact flips 1 -> 0
make tamper-alert-demo
```

---

## Observability: metrics, SLO alerts, runbooks

`GET /metrics` (port 9090) is written in the Prometheus text format with no
client library (`internal/metrics`, ~300 lines, stdlib only). It runs on its own
listener so it stays off the API and any ingress. The NetworkPolicy admits only
`metrics.scrapeFrom`, and scrapes don't flood the request log.

| Metric | Type | Use |
|--------|------|-----|
| `auditd_http_requests_total{route,method,code}` | counter | rate + errors (SLI). `route` is the mux pattern, unknown paths → `unmatched` (bounded cardinality) |
| `auditd_http_request_duration_seconds{route,method}` | histogram | latency, `histogram_quantile()` |
| `auditd_append_duration_seconds` / `auditd_append_errors_total` | histogram / counter | commit latency incl. fsync; storage failures |
| `auditd_chain_intact`, `_broken_seq`, `_records` | gauge | result of the background **on-disk** verification |
| `auditd_chain_last_verify_timestamp_seconds`, `_verify_duration_seconds` | gauge | is the verifier itself alive and fast? |

**SLO:** 99.5% of `/api/v1/audit*` requests succeed (non-5xx) over 30 days.
That gives an error budget of 0.5%, about 3.6 h of full outage. Alerts use multi-window,
multi-burn-rate rules (Google SRE Workbook): each needs a long window (is it significant?)
*and* a short one (is it still happening?), so a 3-minute blip doesn't page,
while a real outage pages within minutes.

| Alert | Condition | Severity | Runbook |
|-------|-----------|----------|---------|
| `AuditdErrorBudgetBurnFast` | burn > 14.4x over 1h **and** 5m | page | [error-budget-burn](docs/runbooks/auditd-error-budget-burn.md) |
| `AuditdErrorBudgetBurnSlow` | burn > 6x over 6h **and** 30m | page | [error-budget-burn](docs/runbooks/auditd-error-budget-burn.md) |
| `AuditdErrorBudgetBurnTicket` | burn > 1x over 3d **and** 6h | ticket | [error-budget-burn](docs/runbooks/auditd-error-budget-burn.md) |
| `AuditdChainTampered` | `auditd_chain_intact == 0`, fires immediately | critical / security | [chain-tampered](docs/runbooks/auditd-chain-tampered.md) |
| `AuditdChainVerifyStale` | no verification for > 5m | warning / security | [chain-verify-stale](docs/runbooks/auditd-chain-verify-stale.md) |
| `AuditdTargetDown` / `AuditdTargetMissing` | `up == 0` / `absent(up)` | page | [target-down](docs/runbooks/auditd-target-down.md) |

Rules live in `deploy/prometheus/`. Every alert has `promtool test rules` cases
for both firing and **must-not-fire** (`make test-rules`). The tests were
mutation-checked: breaking an expectation makes them fail. In-cluster, enable
`metrics.serviceMonitor.enabled` for prometheus-operator.

> Scope: this shows alerting *designed and tested as code*, plus runbooks. It
> is not production on-call experience.

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
- Both base images pinned by digest; the published image is signed and attested
  (see *Supply chain* below).
- Runs as UID 65532. `docker-compose.yml` adds `read_only`, `cap_drop: [ALL]`,
  `no-new-privileges`.

### Infrastructure layer (`terraform/`, Checkov-clean)
- S3 bucket with **Object Lock in COMPLIANCE mode** (true WORM) + versioning.
- SSE-KMS with a **customer-managed key**, rotation enabled, account-scoped key
  policy (no wildcard principal).
- All four Block-Public-Access switches; TLS-only + encryption-required bucket
  policies; access logging to a separate hardened bucket; lifecycle tiering.

### Kubernetes layer (`deploy/helm/auditd/`)
Shipped as a Helm chart. The hardening lives in the templates and is **not**
configurable: `values.schema.json` rejects unknown keys (so there is no
`securityContext` to override), pins `replicaCount` to 1 (single-writer chain),
and validates the image digest format.
- Namespace (`deploy/namespace.yaml`) with Pod Security Standard `restricted`
  enforced. It's kept out of the chart on purpose: the cluster owner sets the
  policy, and the chart has to fit it.
- `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`,
  `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`.
- ServiceAccount with `automountServiceAccountToken: false`.
- Default-deny `NetworkPolicy` + a single explicit allow (ingress 8080, egress DNS).
- Resource requests/limits; liveness/readiness/startup probes.
- Image addressed by `repository@sha256:…` when `image.digest` is set (pull
  policy then defaults to `Always`). The chart CI publishes is pinned to the
  digest it signed in the same run. A `helm test` pod (itself PSS-restricted)
  probes `/readyz` through the Service using the auditd binary, so the test
  adds no extra image.

### Pipeline layer (`.github/workflows/devsecops.yml`)

Stages run in strict order (`needs:`) so a cheap early failure stops the run
before anything is built - "shift-left":

| # | Stage | Tools | Scanning class |
|---|-------|-------|----------------|
| 1 | secrets | **gitleaks** | secret scanning (full history) |
| 2 | sast | **go vet**, **staticcheck**, **gosec** | SAST |
| 3 | test | `go test -race -cover` | dynamic / correctness |
| 4 | sca | **govulncheck**, **trivy fs** | dependency / SCA scanning |
| 5 | iac | **checkov** (terraform), **hadolint** | IaC scanning |
| 5b | helm | **helm lint**, **checkov** (rendered chart), **ct lint**, **ct install** on kind | chart lint + manifest scan + real install/`helm test` under restricted PSS |
| 5c | observability | **promtool** check/test rules, check metrics, tamper→alert demo | alert rules unit-tested; real `/metrics` output linted |
| 6 | image | **trivy image**, **syft** | container CVE scan + SBOM |
| 7 | publish *(main only)* | **GHCR**, **cosign**, **syft**, `attest-build-provenance`, **helm push** | push the scanned image, keyless-sign it, attach SBOM + SLSA provenance attestations; package the chart pinned to that digest, push it as an OCI artifact, sign it |
| 8 | verify-signature *(main only)* | **cosign verify**, `gh attestation verify` | fail the run unless the image signature, SBOM, provenance and chart signature verify against this workflow's exact identity |

Workflow-level `permissions: contents: read`; `concurrency` cancels superseded runs.
Only `publish` gets write scopes (`packages`, `id-token`, `attestations`), and
only on `main`: pull requests never receive a signing identity.

### Supply chain: signed images, SBOM and provenance

Scanning says the image *had no known CVEs when built*. Signing and provenance
say *this is the image our pipeline built, from this commit*.

- **Pinned inputs.** Every action is pinned to a full commit SHA and both base
  images to a `sha256` digest; Dependabot bumps them. Tags are mutable.
- **Build once.** `publish` pushes the exact tarball `image` scanned, and checks
  its image ID matches before pushing - it never rebuilds.
- **Keyless signing.** `cosign sign` exchanges the job's GitHub OIDC token for a
  short-lived Fulcio certificate bound to the workflow identity; the signature
  is recorded in the public Rekor transparency log. No long-lived keys exist.
- **Attestations, bound to the digest.** An SPDX SBOM (`cosign attest`) and SLSA
  build provenance (`actions/attest-build-provenance`) are signed in-toto
  statements whose subject is the image digest, stored next to it in GHCR.
- **Verify gate.** `verify-signature` checks all three against the exact signer
  identity, then runs a negative control: a foreign identity must be rejected.

Verify it yourself (needs `cosign` and `gh`):

```bash
make verify-image IMAGE_REF=ghcr.io/apolo151/auditd@sha256:<digest>

# or by hand - the identity flags are what make the check meaningful
cosign verify ghcr.io/apolo151/auditd@sha256:<digest> \
  --certificate-identity https://github.com/Apolo151/tamper-proof-audit-trail/.github/workflows/devsecops.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/apolo151/auditd@sha256:<digest> --repo Apolo151/tamper-proof-audit-trail
```

---

## Project layout

```
cmd/auditd/            server | -verify | -healthcheck
internal/config/       env config + validation
internal/audit/        event.go chain.go store.go verify.go   (the hash chain)
internal/httpapi/      handlers, middleware, server
internal/metrics/      stdlib Prometheus text-format registry
internal/telemetry/    auditd's metrics + background chain verifier
terraform/             S3 Object Lock (WORM) + KMS  -- validate-only
deploy/helm/auditd/    hardened Helm chart (values.schema.json, helm test)
deploy/namespace.yaml  PSS-restricted namespace (cluster policy, outside the chart)
deploy/kind-cluster.yaml
deploy/prometheus/     recording + alert rules, promtool unit tests
docs/runbooks/         one runbook per alert
ct.yaml                chart-testing config
.github/workflows/     devsecops.yml
```

See `CLAUDE.md` for build/scan commands and gotchas.
