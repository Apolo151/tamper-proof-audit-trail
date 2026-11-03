# AuditdChainVerifyStale

**Severity:** warning · **Team:** security · **Fires:** no verification for > 5m, sustained 5m

## Meaning
`auditd_chain_last_verify_timestamp_seconds` has stopped advancing. The
background verifier runs every `VERIFY_INTERVAL` (default 60s); it has not
completed a run for over 5 minutes.

## Impact
**Tampering would currently go undetected.** `AuditdChainTampered` can only fire
if the verifier runs. This alert guards the guard. The API itself may be fine.

## Diagnose
```promql
time() - auditd_chain_last_verify_timestamp_seconds{job="auditd"}   # seconds since last run
auditd_chain_verify_duration_seconds                                 # did runs get very slow?
auditd_chain_records                                                 # chain size (verify is O(n))
```
```bash
NS=audit
kubectl -n $NS get deploy auditd -o jsonpath='{.spec.template.spec.containers[0].env}'   # VERIFY_INTERVAL?
kubectl -n $NS logs deploy/auditd | tail -50
```
Likely causes:
- **Verification got slow.** Duration approaches the interval as the chain grows,
  and appends hold the write lock. Check `auditd_chain_verify_duration_seconds`.
- **The verifier is blocked.** It needs the store's read lock; a stuck append
  (an fsync hanging on a sick disk) blocks it. Correlate with append latency and errors.
- **`VERIFY_INTERVAL` was set much longer than 5m.** That's a configuration error,
  so align the interval with this alert's threshold.

## Mitigate
- Slow verification: raise `VERIFY_INTERVAL` *and* this alert's threshold together,
  or move to incremental verification (only verify records since the last verified seq).
- Disk hang: see the storage section of the [error-budget runbook](auditd-error-budget-burn.md).
- Before any restart, check that `AuditdChainTampered` is **not** firing, and
  preserve `/data` if there is any doubt.

## Escalate
If it isn't resolved within 30 minutes, escalate to security: the detection control is down.
