package httpapi

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/Apolo151/tamper-proof-audit-trail/internal/telemetry"
)

// statusRecorder captures the status code and byte count written to the client
// so the logging middleware can report them.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// code is the status the client received: net/http sends 200 when a handler
// writes nothing at all, so an unset status means 200, not 0.
func (r *statusRecorder) code() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// withMiddleware wraps h with, from outside in: metrics, panic recovery,
// structured request logging, and a couple of always-on security headers.
// Metrics sit outside recovery so a recovered panic is counted as the 500 the
// client actually received.
func withMiddleware(h http.Handler, logger *slog.Logger, tel *telemetry.Telemetry) http.Handler {
	return instrument(recoverPanic(requestLogger(securityHeaders(h), logger), logger), tel)
}

// instrument records request count and latency. The route label is the
// ServeMux pattern (e.g. "POST /api/v1/audit"), which the mux sets on the
// shared *http.Request while routing; requests that match no pattern get a
// single "unmatched" label, so arbitrary paths cannot create new series.
func instrument(next http.Handler, tel *telemetry.Telemetry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		tel.ObserveRequest(r.Pattern, r.Method, rec.code(), time.Since(start))
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func requestLogger(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		logger.Info("http request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.code()),
			slog.Int("bytes", rec.bytes),
			slog.Duration("duration", time.Since(start)),
			slog.String("remote", r.RemoteAddr),
		)
	})
}

func recoverPanic(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				logger.Error("panic recovered",
					slog.Any("value", v),
					slog.String("path", r.URL.Path),
					slog.String("stack", string(debug.Stack())),
				)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
