package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/Apolo151/tamper-proof-audit-trail/internal/audit"
)

// Store is the subset of *audit.Store the HTTP layer depends on. Defining it
// here keeps handlers testable with a fake and documents the contract.
type Store interface {
	Append(audit.Event) (audit.Record, error)
	List() []audit.Record
	Ready() error
}

type api struct {
	store   Store
	log     *slog.Logger
	maxBody int64
}

// NewHandler builds the fully-wrapped HTTP handler for the audit service.
func NewHandler(store Store, logger *slog.Logger, maxBodyBytes int64) http.Handler {
	a := &api{store: store, log: logger, maxBody: maxBodyBytes}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/audit", a.handleAppend)
	mux.HandleFunc("GET /api/v1/audit", a.handleList)
	mux.HandleFunc("GET /api/v1/audit/verify", a.handleVerify)
	mux.HandleFunc("GET /healthz", a.handleHealthz)
	mux.HandleFunc("GET /readyz", a.handleReadyz)

	return withMiddleware(mux, logger)
}

func (a *api) handleAppend(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); ct != "" && !isJSON(ct) {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, a.maxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var ev audit.Event
	if err := dec.Decode(&ev); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "body must contain a single JSON object")
		return
	}
	if err := ev.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	rec, err := a.store.Append(ev)
	if err != nil {
		a.log.Error("append failed", slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "could not persist audit event")
		return
	}
	writeJSON(w, http.StatusCreated, rec)
}

type listResponse struct {
	Count   int            `json:"count"`
	Records []audit.Record `json:"records"`
}

func (a *api) handleList(w http.ResponseWriter, r *http.Request) {
	all := a.store.List()

	limit := clampAtoi(r.URL.Query().Get("limit"), len(all), 0, len(all))
	offset := clampAtoi(r.URL.Query().Get("offset"), 0, 0, len(all))

	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	page := all[offset:end]

	writeJSON(w, http.StatusOK, listResponse{Count: len(all), Records: page})
}

func (a *api) handleVerify(w http.ResponseWriter, r *http.Request) {
	res := audit.Verify(a.store.List())
	// Always 200: the verify endpoint always succeeds; the body says whether the
	// chain is intact. Callers that want a non-2xx on tampering pass ?strict=1.
	status := http.StatusOK
	if !res.Intact && r.URL.Query().Get("strict") == "1" {
		status = http.StatusConflict
	}
	writeJSON(w, status, res)
}

func (a *api) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *api) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if err := a.store.Ready(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unready", "reason": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func isJSON(contentType string) bool {
	// Accept "application/json" and "application/json; charset=utf-8".
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.EqualFold(mt, "application/json")
}

func clampAtoi(s string, def, lo, hi int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}
