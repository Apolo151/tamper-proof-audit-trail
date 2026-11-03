# AuditdErrorBudgetBurnFast / Slow / Ticket

**SLO:** 99.5% of audit API requests (`/api/v1/audit*`) succeed over 30 days.
Error budget = 0.5% ≈ 3.6 h of full outage per 30 days. Only 5xx counts; 4xx
is a client error.

| Alert | Burn rate | Windows | Budget used | Severity |
|-------|-----------|---------|-------------|----------|
| `AuditdErrorBudgetBurnFast` | 14.4x | 1h and 5m | 2% in 1h | page |
| `AuditdErrorBudgetBurnSlow` | 6x | 6h and 30m | 5% in 6h | page |
| `AuditdErrorBudgetBurnTicket` | 1x | 3d and 6h | 10% in 3d | ticket |

## Meaning
Services that send audit events are getting server errors. Audit events that
fail to commit may be **lost** unless callers retry, and for an audit trail
that's a compliance gap, not just an outage.

## Impact
- **Fast:** a real outage now. At this rate the monthly budget is gone in ~2 days.
- **Slow:** sustained partial failure; budget gone in ~5 days.
- **Ticket:** a low-grade leak; nobody needs to wake up, but the SLO will be missed.

## Diagnose
```promql
# which route / code is failing?
sum by (route, code) (rate(auditd_http_requests_total{job="auditd", code=~"5.."}[5m]))

# are appends failing (write/fsync)? -> storage problem
rate(auditd_append_errors_total[5m])

# is it slow rather than failing? p99 latency per route
histogram_quantile(0.99, sum by (le, route) (rate(auditd_http_request_duration_seconds_bucket[5m])))
histogram_quantile(0.99, sum by (le) (rate(auditd_append_duration_seconds_bucket[5m])))
```
```bash
NS=audit
kubectl -n $NS get pods -l app.kubernetes.io/name=auditd      # restarts? OOMKilled?
kubectl -n $NS describe pod -l app.kubernetes.io/name=auditd | tail -20
kubectl -n $NS logs deploy/auditd | grep -E '"level":"(ERROR|WARN)"' | tail -20
# "append failed" + "fsync" -> disk; "panic recovered" -> a code bug
```

## Mitigate
| Cause | Action |
|-------|--------|
| `append failed` / fsync errors, disk full | emptyDir (default): it sits on node disk, so check node disk pressure (`kubectl describe node`). PVC: check the volume's capacity, and expand it or raise `persistence.size`. **Without a PVC, restarting wipes the chain.** Only do it if you accept losing local history, and record that decision. |
| `panic recovered` after a deploy | `helm rollback auditd <prev-rev> -n audit` (same caveat without `persistence.enabled`: Recreate + emptyDir) |
| CPU throttling / latency (limit 250m) | Raise `resources.limits.cpu` via values and upgrade |
| `AuditdChainTampered` also firing | Stop. Follow [the tampered runbook](auditd-chain-tampered.md) instead, and do not restart. |

## Escalate
If 5xx persists after 30 minutes, or the cause is storage, escalate to the platform team.
Tell upstream teams whose events may have been dropped, and give them the time window.

## Afterwards
Record how much budget was consumed. If the budget is exhausted, freeze risky
changes until it recovers (error-budget policy).
