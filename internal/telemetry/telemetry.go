// Package telemetry defines auditd's Prometheus metrics and the background
// chain verifier that feeds the "chain tampered" alert.
//
// Metric design:
//   - RED for the API: request rate and errors (auditd_http_requests_total by
//     route pattern, method and status code) and duration (a histogram).
//     Labels are bounded: the route is the ServeMux pattern, never the raw
//     path, so a scanner hitting random URLs cannot blow up cardinality.
//   - Append latency, which includes the fsync, is where write latency lives.
//   - Chain integrity as gauges, refreshed on a timer rather than per scrape:
//     verification is O(n) over the whole chain.
package telemetry

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/Apolo151/tamper-proof-audit-trail/internal/audit"
	"github.com/Apolo151/tamper-proof-audit-trail/internal/metrics"
)

// UnmatchedRoute labels requests that matched no ServeMux pattern (404/405).
const UnmatchedRoute = "unmatched"

var latencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5}

// Telemetry is the service's metric set.
type Telemetry struct {
	Registry *metrics.Registry

	requests       *metrics.Counter
	duration       *metrics.Histogram
	appendDuration *metrics.Histogram
	appendErrors   *metrics.Counter

	chainIntact         *metrics.Gauge
	chainRecords        *metrics.Gauge
	chainBrokenSeq      *metrics.Gauge
	chainLastVerify     *metrics.Gauge
	chainVerifyDuration *metrics.Gauge
}

// New registers every auditd metric on a fresh registry.
func New() *Telemetry {
	r := metrics.NewRegistry()
	return &Telemetry{
		Registry: r,
		requests: r.NewCounter("auditd_http_requests_total",
			"HTTP requests served, by route pattern, method and status code.",
			"route", "method", "code"),
		duration: r.NewHistogram("auditd_http_request_duration_seconds",
			"HTTP request latency, by route pattern and method.",
			latencyBuckets, "route", "method"),
		appendDuration: r.NewHistogram("auditd_append_duration_seconds",
			"Time to commit one record to the chain, including fsync.",
			latencyBuckets),
		appendErrors: r.NewCounter("auditd_append_errors_total",
			"Records that could not be committed (write or fsync failed)."),
		chainIntact: r.NewGauge("auditd_chain_intact",
			"1 if the last on-disk chain verification passed, 0 if the chain is broken or tampered."),
		chainRecords: r.NewGauge("auditd_chain_records",
			"Records checked by the last chain verification."),
		chainBrokenSeq: r.NewGauge("auditd_chain_broken_seq",
			"Sequence number of the first broken record, 0 when intact."),
		chainLastVerify: r.NewGauge("auditd_chain_last_verify_timestamp_seconds",
			"Unix time of the last chain verification."),
		chainVerifyDuration: r.NewGauge("auditd_chain_verify_duration_seconds",
			"How long the last chain verification took."),
	}
}

// ObserveRequest records one served HTTP request. An empty route means the
// request matched no pattern.
func (t *Telemetry) ObserveRequest(route, method string, code int, took time.Duration) {
	if route == "" {
		route = UnmatchedRoute
	}
	t.requests.Inc(route, method, strconv.Itoa(code))
	t.duration.Observe(took.Seconds(), route, method)
}

// ObserveAppend records one attempt to commit a record.
func (t *Telemetry) ObserveAppend(took time.Duration, err error) {
	t.appendDuration.Observe(took.Seconds())
	if err != nil {
		t.appendErrors.Inc()
	}
}

// DiskVerifier is the subset of *audit.Store the verifier needs.
type DiskVerifier interface {
	VerifyDisk() audit.VerifyResult
}

// VerifyChain verifies the on-disk chain once and updates the chain gauges.
// A broken chain is logged at error level every time it is seen.
func (t *Telemetry) VerifyChain(v DiskVerifier, now time.Time, logger *slog.Logger) {
	start := time.Now()
	res := v.VerifyDisk()
	took := time.Since(start)

	intact, broken := 1.0, 0.0
	if !res.Intact {
		intact = 0
		if res.BrokenSeq != nil {
			broken = float64(*res.BrokenSeq)
		}
		logger.Error("audit chain verification failed",
			slog.Float64("broken_seq", broken),
			slog.String("reason", res.Reason),
			slog.Int("checked", res.Checked))
	}
	t.chainIntact.Set(intact)
	t.chainBrokenSeq.Set(broken)
	t.chainRecords.Set(float64(res.Checked))
	t.chainVerifyDuration.Set(took.Seconds())
	t.chainLastVerify.Set(float64(now.UnixNano()) / 1e9)
}

// RunChainVerifier calls VerifyChain every interval until ctx is cancelled.
// Callers should run VerifyChain once before serving, so the first scrape
// never sees the zero value of auditd_chain_intact.
func (t *Telemetry) RunChainVerifier(ctx context.Context, v DiskVerifier, interval time.Duration, logger *slog.Logger) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			t.VerifyChain(v, now, logger)
		}
	}
}
