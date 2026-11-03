package httpapi

import (
	"net"
	"net/http"
	"time"

	"github.com/Apolo151/tamper-proof-audit-trail/internal/telemetry"
)

// NewServer returns an *http.Server with conservative, explicit timeouts. The
// explicit ReadHeaderTimeout in particular defends against slow-loris clients
// (and satisfies gosec G112).
func NewServer(addr string, handler http.Handler, readHeaderTimeout time.Duration) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
}

// NewMetricsHandler serves GET /metrics (and nothing else) for the metrics
// listener. It is deliberately not wrapped in request logging or metrics.
func NewMetricsHandler(tel *telemetry.Telemetry) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", tel.Registry.Handler())
	return securityHeaders(mux)
}

// JoinHostPort builds a listen address from a bare port, binding all interfaces.
func JoinHostPort(port string) string {
	return net.JoinHostPort("", port)
}
