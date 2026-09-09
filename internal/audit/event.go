// Package audit implements a tamper-evident audit log: an append-only chain of
// records where every record embeds the SHA-256 hash of its canonical payload
// together with the hash of the record before it. Any modification, reordering
// or deletion of a record breaks the chain and is detected by Verify.
package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// maxFieldRunes bounds the free-text fields; maxMetadataBytes bounds the opaque
// metadata blob. Both keep a single record small and the hash cheap to compute.
const (
	maxFieldRunes    = 256
	maxMetadataBytes = 8 * 1024
)

// Event is the caller-supplied payload for POST /api/v1/audit. The server is the
// sole authority for Seq, Timestamp, PrevHash and Hash, so those are not part of
// the input type.
type Event struct {
	Actor    string          `json:"actor"`
	Action   string          `json:"action"`
	Resource string          `json:"resource"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// Record is a committed, hash-chained audit entry as stored on disk (one JSON
// object per line) and returned by the API. The JSON field order is fixed and
// load-bearing: see canonicalBytes.
type Record struct {
	Seq       uint64          `json:"seq"`
	Timestamp time.Time       `json:"timestamp"`
	Actor     string          `json:"actor"`
	Action    string          `json:"action"`
	Resource  string          `json:"resource"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	PrevHash  string          `json:"prev_hash"`
	Hash      string          `json:"hash"`
}

// Validate checks a caller-supplied Event before it is committed to the chain.
func (e Event) Validate() error {
	for _, f := range []struct {
		name, val string
	}{
		{"actor", e.Actor},
		{"action", e.Action},
		{"resource", e.Resource},
	} {
		v := strings.TrimSpace(f.val)
		if v == "" {
			return fmt.Errorf("%s must not be empty", f.name)
		}
		if utf8.RuneCountInString(v) > maxFieldRunes {
			return fmt.Errorf("%s must be at most %d characters", f.name, maxFieldRunes)
		}
	}

	if len(bytes.TrimSpace(e.Metadata)) > 0 {
		if len(e.Metadata) > maxMetadataBytes {
			return fmt.Errorf("metadata must be at most %d bytes", maxMetadataBytes)
		}
		if !json.Valid(e.Metadata) {
			return fmt.Errorf("metadata must be valid JSON")
		}
		if bytes.TrimSpace(e.Metadata)[0] != '{' {
			return fmt.Errorf("metadata must be a JSON object")
		}
	}
	return nil
}

// compactMetadata normalises an optional metadata blob to a stable byte form:
// the caller's bytes with insignificant whitespace removed, or "{}" when absent.
// Hashing these verbatim (rather than re-marshalling through a Go map) means a
// replay from disk reproduces byte-identical hash pre-images.
func compactMetadata(raw json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return json.RawMessage("{}"), nil
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, fmt.Errorf("compact metadata: %w", err)
	}
	return compact.Bytes(), nil
}

// canonicalInput is the exact, ordered set of fields that gets hashed for a
// record. Field order here defines the hash pre-image and must never change
// without a chain-version bump.
type canonicalInput struct {
	Seq       uint64          `json:"seq"`
	Timestamp string          `json:"timestamp"`
	Actor     string          `json:"actor"`
	Action    string          `json:"action"`
	Resource  string          `json:"resource"`
	Metadata  json.RawMessage `json:"metadata"`
}

// canonicalBytes produces the deterministic hash pre-image shared by both the
// append path (from an Event) and the verify path (from a stored Record).
func canonicalBytes(seq uint64, ts time.Time, actor, action, resource string, metaCompact json.RawMessage) ([]byte, error) {
	ci := canonicalInput{
		Seq:       seq,
		Timestamp: ts.UTC().Format(time.RFC3339Nano),
		Actor:     actor,
		Action:    action,
		Resource:  resource,
		Metadata:  metaCompact,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(ci); err != nil {
		return nil, fmt.Errorf("encode canonical payload: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// canonicalForRecord recomputes the hash pre-image for a record already on the
// chain, used by Verify.
func canonicalForRecord(r Record) ([]byte, error) {
	meta, err := compactMetadata(r.Metadata)
	if err != nil {
		return nil, err
	}
	return canonicalBytes(r.Seq, r.Timestamp, r.Actor, r.Action, r.Resource, meta)
}
