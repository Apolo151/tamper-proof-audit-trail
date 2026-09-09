package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Apolo151/tamper-proof-audit-trail/internal/audit"
)

func seedChain(t *testing.T, dir string) {
	t.Helper()
	s, err := audit.Open(dir, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, e := range []audit.Event{
		{Actor: "alice", Action: "login", Resource: "/session"},
		{Actor: "bob", Action: "delete", Resource: "record/42"},
	} {
		if _, err := s.Append(e); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVerifyDir(t *testing.T) {
	dir := t.TempDir()

	// Empty dir -> intact -> exit 0.
	if code := verifyDir(dir); code != 0 {
		t.Fatalf("verifyDir(empty) = %d, want 0", code)
	}

	seedChain(t, dir)
	if code := verifyDir(dir); code != 0 {
		t.Fatalf("verifyDir(good) = %d, want 0", code)
	}

	path := filepath.Join(dir, "audit.log.jsonl")
	raw, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	corrupt := strings.Replace(string(raw), `"action":"login"`, `"action":"logout"`, 1)
	if err := os.WriteFile(path, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := verifyDir(dir); code != 1 {
		t.Fatalf("verifyDir(tampered) = %d, want 1", code)
	}
}

func TestHealthcheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	port := strings.TrimPrefix(srv.URL, "http://127.0.0.1:")
	if code := healthcheck(port); code != 0 {
		t.Fatalf("healthcheck(up) = %d, want 0", code)
	}
	if code := healthcheck("1"); code != 1 { // nothing listening on port 1
		t.Fatalf("healthcheck(down) = %d, want 1", code)
	}
}
