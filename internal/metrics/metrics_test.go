package metrics

import (
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestWriteTextGolden(t *testing.T) {
	r := NewRegistry()
	req := r.NewCounter("app_requests_total", "Requests served.", "route", "code")
	up := r.NewGauge("app_up", "1 if the app is up.")
	lat := r.NewHistogram("app_latency_seconds", "Request latency.", []float64{0.1, 0.5}, "route")
	_ = r.NewCounter("app_unused_total", "Labelled, never incremented.", "x")

	req.Inc("GET /a", "200")
	req.Inc("GET /a", "200")
	req.Add(3, "GET /b", "500")
	up.Set(1)
	lat.Observe(0.05, "GET /a")
	lat.Observe(0.2, "GET /a")
	lat.Observe(7, "GET /a")

	var b strings.Builder
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	want := `# HELP app_requests_total Requests served.
# TYPE app_requests_total counter
app_requests_total{route="GET /a",code="200"} 2
app_requests_total{route="GET /b",code="500"} 3
# HELP app_up 1 if the app is up.
# TYPE app_up gauge
app_up 1
# HELP app_latency_seconds Request latency.
# TYPE app_latency_seconds histogram
app_latency_seconds_bucket{route="GET /a",le="0.1"} 1
app_latency_seconds_bucket{route="GET /a",le="0.5"} 2
app_latency_seconds_bucket{route="GET /a",le="+Inf"} 3
app_latency_seconds_sum{route="GET /a"} 7.25
app_latency_seconds_count{route="GET /a"} 3
# HELP app_unused_total Labelled, never incremented.
# TYPE app_unused_total counter
`
	if got := b.String(); got != want {
		t.Fatalf("exposition mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestUnlabelledMetricsStartAtZero(t *testing.T) {
	r := NewRegistry()
	r.NewCounter("c_total", "c")
	r.NewGauge("g", "g")
	r.NewHistogram("h_seconds", "h", []float64{1})
	var b strings.Builder
	_ = r.WriteText(&b)
	for _, line := range []string{"c_total 0", "g 0", `h_seconds_bucket{le="+Inf"} 0`, "h_seconds_count 0"} {
		if !strings.Contains(b.String(), line+"\n") {
			t.Errorf("missing %q in:\n%s", line, b.String())
		}
	}
}

func TestEscaping(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("e_total", "Help with \\ and\nnewline.", "v")
	c.Inc("a\"b\\c\nd")
	var b strings.Builder
	_ = r.WriteText(&b)
	for _, want := range []string{
		`# HELP e_total Help with \\ and\nnewline.`,
		`e_total{v="a\"b\\c\nd"} 1`,
	} {
		if !strings.Contains(b.String(), want+"\n") {
			t.Errorf("missing %q in:\n%s", want, b.String())
		}
	}
}

func TestFormatFloat(t *testing.T) {
	tests := []struct {
		in   float64
		want string
	}{
		{0, "0"}, {1, "1"}, {0.25, "0.25"}, {1e-9, "1e-09"},
		{1777777777, "1.777777777e+09"},
		{math.Inf(1), "+Inf"}, {math.Inf(-1), "-Inf"}, {math.NaN(), "NaN"},
	}
	for _, tt := range tests {
		if got := formatFloat(tt.in); got != tt.want {
			t.Errorf("formatFloat(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLabelCountMismatchPanics(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("p_total", "p", "a", "b")
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on wrong label count")
		}
	}()
	c.Inc("only-one")
}

func TestDuplicateNamePanics(t *testing.T) {
	r := NewRegistry()
	r.NewGauge("dup", "d")
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	r.NewCounter("dup", "d")
}

func TestCounterRejectsNegativeAdd(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("n_total", "n")
	c.Add(-1)
	var b strings.Builder
	_ = r.WriteText(&b)
	if !strings.Contains(b.String(), "n_total 0\n") {
		t.Fatalf("counter went negative:\n%s", b.String())
	}
}

func TestConcurrentUse(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("cc_total", "c", "k")
	h := r.NewHistogram("hh_seconds", "h", []float64{1}, "k")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.Inc("x")
				h.Observe(0.5, "x")
				_ = r.WriteText(&strings.Builder{})
			}
		}()
	}
	wg.Wait()
	var b strings.Builder
	_ = r.WriteText(&b)
	if !strings.Contains(b.String(), `cc_total{k="x"} 5000`+"\n") {
		t.Fatalf("lost increments:\n%s", b.String())
	}
}

func TestHandler(t *testing.T) {
	r := NewRegistry()
	r.NewGauge("hg", "h").Set(2)
	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != ContentType {
		t.Errorf("Content-Type = %q, want %q", ct, ContentType)
	}
	if !strings.Contains(rr.Body.String(), "hg 2\n") {
		t.Errorf("body = %q", rr.Body.String())
	}
}
