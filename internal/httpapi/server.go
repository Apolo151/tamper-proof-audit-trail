package httpapi

import (
	"net"
	"net/http"
	"time"
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

// JoinHostPort builds a listen address from a bare port, binding all interfaces.
func JoinHostPort(port string) string {
	return net.JoinHostPort("", port)
}
