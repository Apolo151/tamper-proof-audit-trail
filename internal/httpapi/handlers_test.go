package httpapi

import (
	"encoding/json"
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

// corruptFirstActor rewrites the actor on the first JSONL line of the audit log
// in dir, simulating an attacker editing the file directly.
func corruptFirstActor(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "audit.log.jsonl")
	raw, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	lines[0] = strings.Replace(lines[0], `"actor":"a"`, `"actor":"z"`, 1)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newTestAPI(t *testing.T) (http.Handler, *audit.Store) {
	t.Helper()
	store, err := audit.Open(t.TempDir(), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	h := NewHandler(store, slog.New(slog.NewJSONHandler(io.Discard, nil)), 4096)
	return h, store
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestAppendHappyPath(t *testing.T) {
	h, _ := newTestAPI(t)
	rr := do(t, h, "POST", "/api/v1/audit", `{"actor":"alice","action":"login","resource":"/session"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body)
	}
	var rec audit.Record
	if err := json.Unmarshal(rr.Body.Bytes(), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Seq != 1 {
		t.Errorf("Seq = %d, want 1", rec.Seq)
	}
	if rec.PrevHash != audit.GenesisPrevHash {
		t.Errorf("PrevHash = %q, want genesis", rec.PrevHash)
	}
	if len(rec.Hash) != 64 {
		t.Errorf("Hash length = %d, want 64", len(rec.Hash))
	}
}

func TestAppendValidationErrors(t *testing.T) {
	h, _ := newTestAPI(t)
	tests := []struct {
		name, body string
		want       int
	}{
		{"missing action", `{"actor":"alice","resource":"/x"}`, http.StatusBadRequest},
		{"malformed json", `{"actor":`, http.StatusBadRequest},
		{"unknown field", `{"actor":"a","action":"b","resource":"c","extra":1}`, http.StatusBadRequest},
		{"blank actor", `{"actor":"  ","action":"b","resource":"c"}`, http.StatusBadRequest},
		{"metadata not object", `{"actor":"a","action":"b","resource":"c","metadata":[1,2]}`, http.StatusBadRequest},
		{"trailing object", `{"actor":"a","action":"b","resource":"c"}{"x":1}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := do(t, h, "POST", "/api/v1/audit", tt.body)
			if rr.Code != tt.want {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tt.want, rr.Body)
			}
		})
	}
}

func TestAppendBodyTooLarge(t *testing.T) {
	h, _ := newTestAPI(t)
	big := `{"actor":"a","action":"b","resource":"c","metadata":{"blob":"` + strings.Repeat("x", 5000) + `"}}`
	rr := do(t, h, "POST", "/api/v1/audit", big)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", rr.Code, rr.Body)
	}
}

func TestAppendWrongContentType(t *testing.T) {
	h, _ := newTestAPI(t)
	req := httptest.NewRequest("POST", "/api/v1/audit", strings.NewReader(`{"actor":"a","action":"b","resource":"c"}`))
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", rr.Code)
	}
}

func TestListAndVerifyFlow(t *testing.T) {
	h, _ := newTestAPI(t)
	for _, b := range []string{
		`{"actor":"alice","action":"login","resource":"/session"}`,
		`{"actor":"bob","action":"delete","resource":"record/42"}`,
	} {
		if rr := do(t, h, "POST", "/api/v1/audit", b); rr.Code != http.StatusCreated {
			t.Fatalf("seed append: %d", rr.Code)
		}
	}

	rr := do(t, h, "GET", "/api/v1/audit", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list status = %d", rr.Code)
	}
	var lr listResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &lr); err != nil {
		t.Fatal(err)
	}
	if lr.Count != 2 || len(lr.Records) != 2 {
		t.Fatalf("list = %+v, want count 2", lr)
	}

	rr = do(t, h, "GET", "/api/v1/audit/verify", "")
	var vr audit.VerifyResult
	if err := json.Unmarshal(rr.Body.Bytes(), &vr); err != nil {
		t.Fatal(err)
	}
	if !vr.Intact {
		t.Fatalf("verify = %+v, want intact", vr)
	}
}

func TestVerifyStrictReturns409(t *testing.T) {
	// Build a broken chain on disk, then serve it.
	dir := t.TempDir()
	s, err := audit.Open(dir, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(audit.Event{Actor: "a", Action: "b", Resource: "c"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(audit.Event{Actor: "d", Action: "e", Resource: "f"}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	// Tamper with line 1 on disk.
	corruptFirstActor(t, dir)

	s2, err := audit.Open(dir, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	h := NewHandler(s2, slog.New(slog.NewJSONHandler(io.Discard, nil)), 4096)

	rr := do(t, h, "GET", "/api/v1/audit/verify", "")
	if rr.Code != http.StatusOK {
		t.Errorf("non-strict verify status = %d, want 200", rr.Code)
	}
	rr = do(t, h, "GET", "/api/v1/audit/verify?strict=1", "")
	if rr.Code != http.StatusConflict {
		t.Errorf("strict verify status = %d, want 409", rr.Code)
	}
}

func TestHealthAndReady(t *testing.T) {
	h, _ := newTestAPI(t)
	if rr := do(t, h, "GET", "/healthz", ""); rr.Code != http.StatusOK {
		t.Errorf("healthz = %d", rr.Code)
	}
	if rr := do(t, h, "GET", "/readyz", ""); rr.Code != http.StatusOK {
		t.Errorf("readyz = %d", rr.Code)
	}
}
