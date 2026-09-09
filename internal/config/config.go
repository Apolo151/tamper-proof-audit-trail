// Package config loads and validates the service configuration from environment
// variables. Keeping configuration in the environment (rather than flags or a
// file) keeps the container image immutable and works cleanly with Kubernetes
// ConfigMaps/Secrets.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config is the fully-resolved runtime configuration.
type Config struct {
	Port              string        // TCP port to listen on
	DataDir           string        // directory holding the append-only audit log
	LogLevel          slog.Level    // slog level for structured logs
	ShutdownTimeout   time.Duration // grace period for in-flight requests on SIGTERM
	ReadHeaderTimeout time.Duration // guard against slow-loris (gosec G112)
	MaxBodyBytes      int64         // request body cap for POST /api/v1/audit
}

// Default values, used when the corresponding environment variable is unset.
const (
	defaultPort              = "8080"
	defaultDataDir           = "/data"
	defaultLogLevel          = "info"
	defaultShutdownTimeout   = 10 * time.Second
	defaultReadHeaderTimeout = 5 * time.Second
	defaultMaxBodyBytes      = 64 * 1024
)

// Load reads configuration from the environment, applies defaults and validates
// the result. It never reads from anything other than the process environment.
func Load() (Config, error) {
	cfg := Config{
		Port:              getenv("PORT", defaultPort),
		DataDir:           filepath.Clean(getenv("DATA_DIR", defaultDataDir)),
		ShutdownTimeout:   defaultShutdownTimeout,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		MaxBodyBytes:      defaultMaxBodyBytes,
	}

	lvl, err := parseLevel(getenv("LOG_LEVEL", defaultLogLevel))
	if err != nil {
		return Config{}, err
	}
	cfg.LogLevel = lvl

	if cfg.ShutdownTimeout, err = getenvDuration("SHUTDOWN_TIMEOUT", defaultShutdownTimeout); err != nil {
		return Config{}, err
	}
	if cfg.ReadHeaderTimeout, err = getenvDuration("READ_HEADER_TIMEOUT", defaultReadHeaderTimeout); err != nil {
		return Config{}, err
	}
	if cfg.MaxBodyBytes, err = getenvInt("MAX_BODY_BYTES", defaultMaxBodyBytes); err != nil {
		return Config{}, err
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.DataDir) == "" || c.DataDir == "." {
		return fmt.Errorf("config: DATA_DIR must be a non-empty path")
	}
	if p, err := strconv.Atoi(c.Port); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("config: PORT %q is not a valid port number", c.Port)
	}
	if c.MaxBodyBytes < 1 {
		return fmt.Errorf("config: MAX_BODY_BYTES must be positive, got %d", c.MaxBodyBytes)
	}
	if c.ShutdownTimeout <= 0 {
		return fmt.Errorf("config: SHUTDOWN_TIMEOUT must be positive")
	}
	return nil
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func getenvDuration(key string, fallback time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not a valid duration: %w", key, v, err)
	}
	return d, nil
}

func getenvInt(key string, fallback int64) (int64, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not a valid integer: %w", key, v, err)
	}
	return n, nil
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("config: LOG_LEVEL %q is not one of debug|info|warn|error", s)
	}
}
