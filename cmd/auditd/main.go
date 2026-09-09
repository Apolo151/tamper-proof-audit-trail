// Command auditd is the tamper-proof audit-trail microservice.
//
// Modes:
//
//	auditd                 run the HTTP server (default)
//	auditd -verify         replay DATA_DIR, print the verification result, exit 0/1
//	auditd -healthcheck    probe a running server's /healthz, exit 0/1 (container HEALTHCHECK)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Apolo151/tamper-proof-audit-trail/internal/audit"
	"github.com/Apolo151/tamper-proof-audit-trail/internal/config"
	"github.com/Apolo151/tamper-proof-audit-trail/internal/httpapi"
)

func main() {
	var (
		doVerify      = flag.Bool("verify", false, "replay DATA_DIR, print verification result, exit non-zero if broken")
		doHealthcheck = flag.Bool("healthcheck", false, "probe http://127.0.0.1:$PORT/healthz and exit 0/1")
	)
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	switch {
	case *doHealthcheck:
		os.Exit(healthcheck(cfg.Port))
	case *doVerify:
		os.Exit(verifyDir(cfg.DataDir))
	default:
		os.Exit(runServer(cfg))
	}
}

func newLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

func runServer(cfg config.Config) int {
	logger := newLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	store, err := audit.Open(cfg.DataDir, logger)
	if err != nil {
		logger.Error("cannot open audit store", slog.String("error", err.Error()))
		return 1
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			logger.Error("closing audit store", slog.String("error", cerr.Error()))
		}
	}()

	handler := httpapi.NewHandler(store, logger, cfg.MaxBodyBytes)
	srv := httpapi.NewServer(httpapi.JoinHostPort(cfg.Port), handler, cfg.ReadHeaderTimeout)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("audit service listening",
			slog.String("addr", srv.Addr),
			slog.String("data_dir", cfg.DataDir))
		if serveErr := srv.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
	}()

	select {
	case serveErr := <-errCh:
		logger.Error("server error", slog.String("error", serveErr.Error()))
		return 1
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining", slog.Duration("timeout", cfg.ShutdownTimeout))
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", slog.String("error", err.Error()))
		return 1
	}
	logger.Info("shutdown complete")
	return 0
}

func verifyDir(dir string) int {
	// Quiet logger: -verify writes a machine-readable result to stdout only.
	store, err := audit.Open(dir, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer store.Close()

	res := audit.Verify(store.List())
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
	if res.Intact {
		return 0
	}
	return 1
}

func healthcheck(port string) int {
	client := &http.Client{Timeout: 2 * time.Second}
	url := "http://127.0.0.1:" + port + "/healthz"
	resp, err := client.Get(url) // #nosec G107 -- fixed localhost URL, container self-probe
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthz returned %d\n", resp.StatusCode)
		return 1
	}
	return 0
}
