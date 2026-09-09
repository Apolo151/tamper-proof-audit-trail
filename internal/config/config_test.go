package config

import (
	"log/slog"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	// t.Setenv guarantees the env is restored after the test and forbids
	// t.Parallel, so these tests stay isolated.
	for _, k := range []string{"PORT", "DATA_DIR", "LOG_LEVEL", "SHUTDOWN_TIMEOUT", "READ_HEADER_TIMEOUT", "MAX_BODY_BYTES"} {
		t.Setenv(k, "")
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Port != "8080" {
		t.Errorf("Port = %q, want 8080", cfg.Port)
	}
	if cfg.DataDir != "/data" {
		t.Errorf("DataDir = %q, want /data", cfg.DataDir)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want info", cfg.LogLevel)
	}
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 10s", cfg.ShutdownTimeout)
	}
	if cfg.MaxBodyBytes != 64*1024 {
		t.Errorf("MaxBodyBytes = %d, want 65536", cfg.MaxBodyBytes)
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Setenv("PORT", "9090")
	t.Setenv("DATA_DIR", "/var/lib/audit/")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("SHUTDOWN_TIMEOUT", "30s")
	t.Setenv("READ_HEADER_TIMEOUT", "2s")
	t.Setenv("MAX_BODY_BYTES", "1024")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Port != "9090" {
		t.Errorf("Port = %q, want 9090", cfg.Port)
	}
	if cfg.DataDir != "/var/lib/audit" { // filepath.Clean strips the trailing slash
		t.Errorf("DataDir = %q, want /var/lib/audit", cfg.DataDir)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %v, want debug", cfg.LogLevel)
	}
	if cfg.ShutdownTimeout != 30*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 30s", cfg.ShutdownTimeout)
	}
	if cfg.ReadHeaderTimeout != 2*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 2s", cfg.ReadHeaderTimeout)
	}
	if cfg.MaxBodyBytes != 1024 {
		t.Errorf("MaxBodyBytes = %d, want 1024", cfg.MaxBodyBytes)
	}
}

func TestLoadInvalid(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{"bad port", map[string]string{"PORT": "not-a-port"}},
		{"port out of range", map[string]string{"PORT": "70000"}},
		{"bad log level", map[string]string{"LOG_LEVEL": "verbose"}},
		{"bad duration", map[string]string{"SHUTDOWN_TIMEOUT": "soon"}},
		{"bad int", map[string]string{"MAX_BODY_BYTES": "big"}},
		{"empty data dir", map[string]string{"DATA_DIR": "."}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Fatalf("Load() = nil error, want error for %s", tt.name)
			}
		})
	}
}
