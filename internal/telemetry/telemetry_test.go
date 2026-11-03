package telemetry

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Apolo151/tamper-proof-audit-trail/internal/audit"
)

func scrape(t *testing.T, tel *Telemetry) string {
	t.Helper()
	var b strings.Builder
	if err := tel.Registry.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func mustContain(t *testing.T, body string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if !strings.Contains(body, l+"\n") {
			t.Errorf("missing %q in exposition:\n%s", l, body)
		}
	}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

func TestObserveRequestAndAppend(t *testing.T) {
	tel := New()
	tel.ObserveRequest("POST /api/v1/audit", "POST", 201, 20*time.Millisecond)
	tel.ObserveRequest("", "GET", 404, time.Millisecond)
	tel.ObserveAppend(3*time.Millisecond, nil)
	tel.ObserveAppend(time.Millisecond, errors.New("disk full"))

	mustContain(t, scrape(t, tel),
		`auditd_http_requests_total{route="POST /api/v1/audit",method="POST",code="201"} 1`,
		`auditd_http_requests_total{route="unmatched",method="GET",code="404"} 1`,
		`auditd_http_request_duration_seconds_bucket{route="POST /api/v1/audit",method="POST",le="0.025"} 1`,
		`auditd_append_duration_seconds_count 2`,
		`auditd_append_errors_total 1`,
	)
}

type fakeVerifier struct {
	res   atomic.Value // audit.VerifyResult
	calls atomic.Int64
}

func (f *fakeVerifier) VerifyDisk() audit.VerifyResult {
	f.calls.Add(1)
	return f.res.Load().(audit.VerifyResult)
}

func TestVerifyChainSetsGauges(t *testing.T) {
	tel := New()
	fv := &fakeVerifier{}
	now := time.Unix(1_700_000_000, 0)

	fv.res.Store(audit.VerifyResult{Intact: true, Checked: 3})
	tel.VerifyChain(fv, now, quietLogger())
	mustContain(t, scrape(t, tel),
		"auditd_chain_intact 1",
		"auditd_chain_records 3",
		"auditd_chain_broken_seq 0",
		"auditd_chain_last_verify_timestamp_seconds 1.7e+09",
	)

	seq := uint64(2)
	fv.res.Store(audit.VerifyResult{Intact: false, Checked: 1, BrokenSeq: &seq, Reason: audit.ReasonHashBroken})
	tel.VerifyChain(fv, now.Add(time.Minute), quietLogger())
	mustContain(t, scrape(t, tel),
		"auditd_chain_intact 0",
		"auditd_chain_broken_seq 2",
		"auditd_chain_last_verify_timestamp_seconds 1.70000006e+09",
	)
}

func TestRunChainVerifierTicksUntilCancelled(t *testing.T) {
	tel := New()
	fv := &fakeVerifier{}
	fv.res.Store(audit.VerifyResult{Intact: true})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		tel.RunChainVerifier(ctx, fv, 5*time.Millisecond, quietLogger())
		close(done)
	}()

	deadline := time.After(2 * time.Second)
	for fv.calls.Load() < 3 {
		select {
		case <-deadline:
			t.Fatalf("verifier ran %d times, want >= 3", fv.calls.Load())
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunChainVerifier did not return after cancel")
	}
}
