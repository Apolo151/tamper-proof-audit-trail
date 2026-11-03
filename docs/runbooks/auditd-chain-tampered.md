# AuditdChainTampered

**Severity:** critical · **Team:** security + on-call · **Fires:** immediately (no `for:`)

> **Do not restart, redeploy, scale or `helm upgrade` auditd.** With the default
> `persistence.enabled=false` the chain lives on an `emptyDir`: a new pod starts
> with an empty log and the evidence is gone. Even with a PVC, preserve a copy
> first; nothing should touch the volume until it's captured.

## Meaning
`auditd_chain_intact == 0`: the background verifier re-read `audit.log.jsonl`
from disk and either

- a record's hash, `prev_hash` link or sequence no longer checks out
  (an edit, insertion, reorder or deletion), **or**
- the file is a valid chain but **not the one this process committed**
  (`reason: on-disk chain diverges from committed chain`): the tail was truncated, or
  someone rewrote and re-hashed the chain from some record onward, **or**
- the file is unreadable or malformed (`reason: audit log unreadable`).

`auditd_chain_broken_seq` is the first record that fails.

## Impact
Records from `broken_seq` onward can no longer be trusted as evidence. Writes
still succeed (the in-memory chain is intact and appends continue), so new
events are still being recorded. The integrity of the *stored* history is in
question.

Treat it as a **security incident** until proven otherwise. Hardware or disk
corruption is possible, but less likely: every append is fsync'd.

## Diagnose
```bash
NS=audit; POD=$(kubectl -n $NS get pod -l app.kubernetes.io/name=auditd -o name | head -1)

# 1. What the service says (verifies the file on disk right now)
kubectl -n $NS port-forward "$POD" 8080:8080 &
curl -s localhost:8080/api/v1/audit/verify        # {"intact":false,"broken_seq":N,"reason":"..."}

# 2. What the verifier logged (first detection time)
kubectl -n $NS logs "$POD" | grep 'audit chain verification failed' | head -3

# 3. Who could write to the volume? Look for exec / cp / debug sessions:
#    Kubernetes audit log, filtered to pods/exec, pods/attach, ephemeralcontainers
#    in namespace audit around the first detection time.
```
PromQL: `auditd_chain_broken_seq`, `changes(auditd_chain_intact[1d])`.

## Mitigate (contain and preserve, don't "fix")
1. **Preserve evidence first.** Copy the log out, read-only, with a checksum:
   ```bash
   TS=$(date -u +%Y%m%dT%H%M%SZ)
   kubectl -n $NS exec "$POD" -- cat /data/audit.log.jsonl > "evidence-$TS.jsonl"
   sha256sum "evidence-$TS.jsonl" | tee "evidence-$TS.sha256"
   ```
   (`kubectl cp` needs `tar` in the container; distroless has none, so use `exec cat`.)
2. **Confirm offline** on the copy: `DATA_DIR=<dir with the copy renamed to audit.log.jsonl> auditd -verify`.
3. **Compare against the external copy.** If hashes are shipped to the WORM S3
   bucket (`terraform/`, Object Lock COMPLIANCE), diff `seq`/`hash` from `broken_seq`
   onward. That shows exactly which records changed.
4. **Contain:** restrict exec into the namespace (RBAC). Rotate any credential
   that could reach the node or volume. Keep the pod running.

## Escalate
Page the security on-call immediately (the alert routes to `team: security`).
Do not try to restore the chain yourself: a "repaired" chain is indistinguishable
from a forged one.

## Afterwards
- Postmortem: how did write access to the volume exist? Who had `pods/exec`?
- Hardening backlog: ship every record hash to WORM storage as it's written,
  anchor periodically to a transparency log, sign records with a KMS key,
  move to a PVC/StatefulSet so evidence survives restarts.
