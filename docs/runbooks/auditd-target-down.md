# AuditdTargetDown / AuditdTargetMissing

**Severity:** page

## Meaning
- **TargetDown** (`up == 0` for 5m): Prometheus has an auditd target but every
  scrape of `:9090/metrics` fails.
- **TargetMissing** (`absent(up)` for 10m): there is no auditd target at all.
  Service discovery lost it.

## Impact
Monitoring is blind: neither the SLO alerts nor `AuditdChainTampered` can fire.
The service itself may be up or down. Find out which first.

## Diagnose
```bash
NS=audit
kubectl -n $NS get pods,svc,endpoints -l app.kubernetes.io/name=auditd
kubectl -n $NS port-forward deploy/auditd 9090:9090 & curl -s localhost:9090/metrics | head
kubectl -n $NS port-forward deploy/auditd 8080:8080 & curl -s localhost:8080/readyz
```
| Observation | Likely cause |
|-------------|--------------|
| Pod not Running / CrashLoopBackOff | Service down → `kubectl describe pod`, logs |
| Pod fine, port-forward to 9090 works, scrape fails | **NetworkPolicy**: the scraper's namespace isn't in `metrics.scrapeFrom` (chart values) |
| No target in Prometheus UI | Missing scrape config / ServiceMonitor, a label mismatch, or `metrics.serviceMonitor.enabled=false` |
| Endpoints empty | Readiness failing (`/readyz` → store not ready) |

## Mitigate
- NetworkPolicy: add the Prometheus namespace to `metrics.scrapeFrom` and `helm upgrade`.
- ServiceMonitor: enable it (`metrics.serviceMonitor.enabled=true`) and match your
  Prometheus' `serviceMonitorSelector` labels via `metrics.serviceMonitor.labels`.
- Pod down: follow the pod's events and logs. Remember a restart starts a fresh chain
  (unless `persistence.enabled`). Check that `AuditdChainTampered` was not firing before the outage.

## Escalate
Escalate to the platform/monitoring team if Prometheus itself is unhealthy
(other targets down too).
