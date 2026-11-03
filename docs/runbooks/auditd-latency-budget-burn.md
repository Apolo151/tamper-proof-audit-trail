# AuditdLatencyBudgetBurnFast / Slow

**SLO:** 99% of writes (`POST /api/v1/audit`) complete within 250ms over 30 days.
Error budget = 1% of writes may be slower. Reads are not part of this SLI:
callers block on writes, not on listing.

| Alert | Burn rate | Windows | Severity |
|-------|-----------|---------|----------|
| `AuditdLatencyBudgetBurnFast` | 14.4x (>14.4% slow) | 1h and 5m | page |
| `AuditdLatencyBudgetBurnSlow` | 6x (>6% slow) | 6h and 30m | page |

## Meaning
A significant share of audit writes take longer than 250ms. Callers that log
synchronously (most do: an audit event is written *before* the action is
confirmed) are slowed down with it.

## Impact
Upstream request latency, timeouts and retries. Under sustained slowness,
callers may drop events or skip auditing, which is a compliance risk.

## Diagnose
```promql
# p50 / p99 write latency
histogram_quantile(0.5,  sum by (le) (rate(auditd_http_request_duration_seconds_bucket{route="POST /api/v1/audit"}[5m])))
histogram_quantile(0.99, sum by (le) (rate(auditd_http_request_duration_seconds_bucket{route="POST /api/v1/audit"}[5m])))

# is it the commit itself (write + fsync)? If append p99 ~= request p99, it's storage.
histogram_quantile(0.99, sum by (le) (rate(auditd_append_duration_seconds_bucket[5m])))

# is the verifier holding the lock for long? (verification is O(chain size))
auditd_chain_verify_duration_seconds
auditd_chain_records
```
```bash
kubectl -n audit top pod -l app.kubernetes.io/name=auditd   # CPU near the 250m limit -> throttling
kubectl describe node <node>                               # disk pressure / IO contention
```
| Signal | Likely cause | Action |
|--------|--------------|--------|
| append p99 high | slow disk / fsync (noisy neighbour, network storage) | move to faster storage class (`persistence.storageClass`), or another node |
| append fine, request slow | CPU throttling | raise `resources.limits.cpu` |
| verify duration in the seconds and rising | large chain: verification blocks appends while it reads | raise `chainVerifyInterval` (and keep it under the 5m stale-alert threshold); plan WORM offload |

## Escalate
If storage is the cause, escalate to the platform/storage team. If the fast alert lasts
more than 30 minutes, tell the teams that call auditd.

## Afterwards
Record how much latency budget was used. If verification time is the cause, that's
the scaling signal for moving the chain to an external WORM store.
