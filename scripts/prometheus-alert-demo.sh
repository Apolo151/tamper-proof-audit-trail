#!/usr/bin/env bash
# End-to-end alerting demo: a real Prometheus server scrapes a live auditd,
# evaluates the chart's rule files, and we watch AuditdChainTampered go from
# inactive to firing after the log is edited on disk.
#
#   usage: scripts/prometheus-alert-demo.sh [path/to/auditd]
#   needs: prometheus, curl, jq on PATH
set -euo pipefail

BIN=${1:-bin/auditd}
RULES=deploy/helm/auditd/files/prometheus
API_PORT=18084 METRICS_PORT=19094 PROM_PORT=19095

for tool in prometheus curl jq; do
  command -v "$tool" >/dev/null || { echo "missing $tool on PATH" >&2; exit 2; }
done

work=$(mktemp -d)
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT

# 1. auditd, re-verifying the on-disk chain every second
mkdir -p "$work/data"
DATA_DIR="$work/data" PORT=$API_PORT METRICS_PORT=$METRICS_PORT VERIFY_INTERVAL=1s \
  "$BIN" >"$work/auditd.log" 2>&1 &
pids+=($!)

# 2. Prometheus scraping it as job="auditd" (what the rules select on), with
#    1s scrape/evaluation so the demo takes seconds, not minutes
cat >"$work/prometheus.yml" <<EOF
global:
  scrape_interval: 1s
  evaluation_interval: 1s
rule_files:
  - $PWD/$RULES/recording-rules.yaml
  - $PWD/$RULES/alerts.yaml
scrape_configs:
  - job_name: auditd
    static_configs:
      - targets: ["127.0.0.1:$METRICS_PORT"]
EOF
prometheus --config.file="$work/prometheus.yml" --storage.tsdb.path="$work/tsdb" \
  --web.listen-address="127.0.0.1:$PROM_PORT" --log.level=warn >"$work/prometheus.log" 2>&1 &
pids+=($!)

wait_for() { # wait_for <seconds> <description> <command...>
  local secs=$1 what=$2; shift 2
  for ((i = 0; i < secs * 2; i++)); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  echo "FAIL: timed out waiting for $what" >&2
  tail -5 "$work/prometheus.log" "$work/auditd.log" >&2 || true
  return 1
}
alert_state() { # prints the state of AuditdChainTampered, or "inactive"
  curl -s "127.0.0.1:$PROM_PORT/api/v1/alerts" |
    jq -r '[.data.alerts[] | select(.labels.alertname == "AuditdChainTampered") | .state] | first // "inactive"'
}
target_up() {
  curl -s "127.0.0.1:$PROM_PORT/api/v1/query?query=up%7Bjob%3D%22auditd%22%7D" |
    jq -e '.data.result[0].value[1] == "1"'
}

wait_for 20 "auditd + prometheus" target_up
echo "prometheus is scraping auditd (up == 1)"

for actor in alice bob carol; do
  curl -sf -XPOST "127.0.0.1:$API_PORT/api/v1/audit" -H 'content-type: application/json' \
    -d "{\"actor\":\"$actor\",\"action\":\"write\",\"resource\":\"db/records\"}" >/dev/null
done
sleep 3
before=$(alert_state)
echo "before tampering: AuditdChainTampered is $before"
[[ $before == inactive ]] || { echo "FAIL: alert active on an intact chain" >&2; exit 1; }

echo "tampering with audit.log.jsonl under the running server (bob -> mallory)"
sed -i 's/"actor":"bob"/"actor":"mallory"/' "$work/data/audit.log.jsonl"

is_firing() { [[ $(alert_state) == firing ]]; }
wait_for 30 "AuditdChainTampered to fire" is_firing
curl -s "127.0.0.1:$PROM_PORT/api/v1/alerts" |
  jq -r '.data.alerts[] | select(.labels.alertname == "AuditdChainTampered")
         | "after tampering: \(.labels.alertname) is \(.state) [severity=\(.labels.severity) team=\(.labels.team)]\n  \(.annotations.summary)\n  runbook: \(.annotations.runbook_url)"'
echo "OK: a real Prometheus fired AuditdChainTampered"
