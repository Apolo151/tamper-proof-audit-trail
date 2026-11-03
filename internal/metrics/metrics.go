// Package metrics is a minimal, standard-library-only implementation of the
// Prometheus text exposition format (version 0.0.4): counters, gauges and
// histograms with labels, rendered by a Registry.
//
// It deliberately covers only what this service needs, so the project keeps
// zero third-party modules. Label values are positional: they are passed in
// the same order as the label names given at registration, and a wrong count
// panics (a programming error, caught by tests).
package metrics

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ContentType is the media type of the text exposition format.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Registry holds metric families and renders them in registration order.
type Registry struct {
	mu       sync.Mutex
	families []family
	names    map[string]bool
}

// family is implemented by Counter, Gauge and Histogram.
type family interface {
	write(w *bufio.Writer)
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{names: map[string]bool{}}
}

func (r *Registry) register(name string, f family) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.names[name] {
		panic("metrics: duplicate metric name " + name)
	}
	r.names[name] = true
	r.families = append(r.families, f)
}

// WriteText renders every registered metric in the text exposition format.
func (r *Registry) WriteText(w io.Writer) error {
	r.mu.Lock()
	fams := append([]family(nil), r.families...)
	r.mu.Unlock()

	bw := bufio.NewWriter(w)
	for _, f := range fams {
		f.write(bw)
	}
	return bw.Flush()
}

// Handler serves the registry, for mounting at GET /metrics.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ContentType)
		_ = r.WriteText(w)
	})
}

// --- shared plumbing ---------------------------------------------------------

// vec is a set of series keyed by their label values.
type vec[S any] struct {
	name, help, typ string
	labels          []string

	mu     sync.Mutex
	series map[string]*entry[S]
	newS   func() *S
}

type entry[S any] struct {
	values []string
	s      *S
}

func newVec[S any](name, help, typ string, labels []string, newS func() *S) *vec[S] {
	v := &vec[S]{name: name, help: help, typ: typ, labels: labels, series: map[string]*entry[S]{}, newS: newS}
	if len(labels) == 0 {
		// An unlabelled metric exists from the start, so it reads 0 rather
		// than being absent before its first update.
		v.series[""] = &entry[S]{s: newS()}
	}
	return v
}

// with returns the series for values, creating it. Callers hold v.mu.
func (v *vec[S]) with(values []string) *S {
	if len(values) != len(v.labels) {
		panic(fmt.Sprintf("metrics: %s takes %d label values, got %d", v.name, len(v.labels), len(values)))
	}
	key := strings.Join(values, "\xff")
	e, ok := v.series[key]
	if !ok {
		e = &entry[S]{values: append([]string(nil), values...), s: v.newS()}
		v.series[key] = e
	}
	return e.s
}

// each calls fn for every series in a stable (sorted) order. Callers hold v.mu.
func (v *vec[S]) each(fn func(values []string, s *S)) {
	keys := make([]string, 0, len(v.series))
	for k := range v.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fn(v.series[k].values, v.series[k].s)
	}
}

func (v *vec[S]) header(w *bufio.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", v.name, escapeHelp(v.help), v.name, v.typ)
}

// --- counter ----------------------------------------------------------------

// Counter is a monotonically increasing value.
type Counter struct{ v *vec[float64] }

// NewCounter registers a counter. By convention its name ends in _total.
func (r *Registry) NewCounter(name, help string, labels ...string) *Counter {
	c := &Counter{v: newVec(name, help, "counter", labels, func() *float64 { return new(float64) })}
	r.register(name, c)
	return c
}

// Inc adds 1 to the series for the given label values.
func (c *Counter) Inc(labelValues ...string) { c.Add(1, labelValues...) }

// Add adds delta (ignored if negative: counters only go up).
func (c *Counter) Add(delta float64, labelValues ...string) {
	c.v.mu.Lock()
	defer c.v.mu.Unlock()
	s := c.v.with(labelValues)
	if delta > 0 {
		*s += delta
	}
}

func (c *Counter) write(w *bufio.Writer) {
	c.v.mu.Lock()
	defer c.v.mu.Unlock()
	c.v.header(w)
	c.v.each(func(values []string, s *float64) {
		writeSample(w, c.v.name, c.v.labels, values, "", "", *s)
	})
}

// --- gauge ------------------------------------------------------------------

// Gauge is a value that can go up and down.
type Gauge struct{ v *vec[float64] }

// NewGauge registers a gauge.
func (r *Registry) NewGauge(name, help string, labels ...string) *Gauge {
	g := &Gauge{v: newVec(name, help, "gauge", labels, func() *float64 { return new(float64) })}
	r.register(name, g)
	return g
}

// Set sets the series for the given label values to val.
func (g *Gauge) Set(val float64, labelValues ...string) {
	g.v.mu.Lock()
	defer g.v.mu.Unlock()
	*g.v.with(labelValues) = val
}

func (g *Gauge) write(w *bufio.Writer) {
	g.v.mu.Lock()
	defer g.v.mu.Unlock()
	g.v.header(w)
	g.v.each(func(values []string, s *float64) {
		writeSample(w, g.v.name, g.v.labels, values, "", "", *s)
	})
}

// --- histogram --------------------------------------------------------------

// Histogram counts observations into cumulative buckets. Unlike a summary it
// can be aggregated across instances and queried with histogram_quantile().
type Histogram struct {
	v       *vec[histSeries]
	buckets []float64 // sorted upper bounds, without +Inf
}

type histSeries struct {
	counts []uint64 // per bucket (non-cumulative); last slot is +Inf
	sum    float64
	count  uint64
}

// NewHistogram registers a histogram with the given bucket upper bounds.
func (r *Registry) NewHistogram(name, help string, buckets []float64, labels ...string) *Histogram {
	b := append([]float64(nil), buckets...)
	sort.Float64s(b)
	h := &Histogram{buckets: b}
	h.v = newVec(name, help, "histogram", labels, func() *histSeries {
		return &histSeries{counts: make([]uint64, len(b)+1)}
	})
	r.register(name, h)
	return h
}

// Observe records one value for the given label values.
func (h *Histogram) Observe(val float64, labelValues ...string) {
	h.v.mu.Lock()
	defer h.v.mu.Unlock()
	s := h.v.with(labelValues)
	i := sort.SearchFloat64s(h.buckets, val) // first bucket with bound >= val
	s.counts[i]++
	s.sum += val
	s.count++
}

func (h *Histogram) write(w *bufio.Writer) {
	h.v.mu.Lock()
	defer h.v.mu.Unlock()
	h.v.header(w)
	h.v.each(func(values []string, s *histSeries) {
		var cum uint64
		for i, c := range s.counts {
			cum += c
			le := "+Inf"
			if i < len(h.buckets) {
				le = formatFloat(h.buckets[i])
			}
			writeSample(w, h.v.name+"_bucket", h.v.labels, values, "le", le, float64(cum))
		}
		writeSample(w, h.v.name+"_sum", h.v.labels, values, "", "", s.sum)
		writeSample(w, h.v.name+"_count", h.v.labels, values, "", "", float64(s.count))
	})
}

// --- formatting -------------------------------------------------------------

// writeSample writes `name{l1="v1",...,extra="x"} value`.
func writeSample(w *bufio.Writer, name string, labels, values []string, extraName, extraValue string, val float64) {
	w.WriteString(name)
	if len(labels) > 0 || extraName != "" {
		w.WriteByte('{')
		for i, l := range labels {
			if i > 0 {
				w.WriteByte(',')
			}
			fmt.Fprintf(w, "%s=\"%s\"", l, escapeLabel(values[i]))
		}
		if extraName != "" {
			if len(labels) > 0 {
				w.WriteByte(',')
			}
			fmt.Fprintf(w, "%s=\"%s\"", extraName, escapeLabel(extraValue))
		}
		w.WriteByte('}')
	}
	w.WriteByte(' ')
	w.WriteString(formatFloat(val))
	w.WriteByte('\n')
}

func formatFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	case math.IsNaN(f):
		return "NaN"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

var (
	helpEscaper  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
	labelEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
)

func escapeHelp(s string) string  { return helpEscaper.Replace(s) }
func escapeLabel(s string) string { return labelEscaper.Replace(s) }
