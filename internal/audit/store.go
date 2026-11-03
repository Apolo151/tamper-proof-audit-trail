package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// logFileName is the append-only chain file inside the data directory.
const logFileName = "audit.log.jsonl"

// maxLineBytes caps a single JSONL record on replay (metadata is capped at 8 KiB
// so 1 MiB is comfortably generous).
const maxLineBytes = 1 << 20

// Store is a concurrency-safe, append-only audit-log backed by a JSON-Lines file.
// Writes are serialised and fsync'd; the full chain is also held in memory for
// fast listing and verification.
type Store struct {
	mu      sync.RWMutex
	dir     string
	path    string
	f       *os.File
	records []Record
	head    *Record
}

// Open prepares the data directory, opens (creating if needed) the append-only
// log and replays it into memory. A chain that is already broken on disk is
// logged as a warning but does not stop startup: the service must remain able to
// *report* tampering via GET /api/v1/audit/verify.
func Open(dir string, logger *slog.Logger) (*Store, error) {
	if logger == nil {
		logger = slog.Default()
	}
	clean := filepath.Clean(dir)
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	path := filepath.Join(clean, logFileName)
	// #nosec G304 -- path is derived from operator-controlled configuration
	// (DATA_DIR), cleaned above, and the file name is a constant.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}

	s := &Store{dir: clean, path: path, f: f}
	if err := s.replay(); err != nil {
		_ = f.Close()
		return nil, err
	}

	if res := Verify(s.records); !res.Intact {
		logger.Warn("audit chain is broken on disk",
			slog.Uint64("broken_seq", derefSeq(res.BrokenSeq)),
			slog.String("reason", res.Reason),
			slog.Int("records", len(s.records)))
	}
	return s, nil
}

func (s *Store) replay() error {
	if _, err := s.f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek audit log: %w", err)
	}
	recs, err := readRecords(s.f)
	if err != nil {
		return err
	}
	s.records = recs
	if n := len(s.records); n > 0 {
		s.head = &s.records[n-1]
	}
	// Re-seek to end so O_APPEND writes continue cleanly.
	if _, err := s.f.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek audit log end: %w", err)
	}
	return nil
}

// readRecords parses a JSON-Lines chain, one Record per non-empty line.
func readRecords(r io.Reader) ([]Record, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	var (
		recs []Record
		line int
	)
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var rec Record
		if err := dec.Decode(&rec); err != nil {
			return nil, fmt.Errorf("parse audit log line %d: %w", line, err)
		}
		recs = append(recs, rec)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan audit log: %w", err)
	}
	return recs, nil
}

// VerifyDisk re-reads the log file and checks two things:
//
//  1. the on-disk chain verifies on its own (catches edits, reordering,
//     deletions in the middle), and
//  2. it is exactly the chain this process committed - same length, same
//     hashes. That catches what (1) cannot: a truncated tail, or a chain an
//     attacker rewrote and re-hashed consistently from some point onward.
//
// Verifying only the in-memory copy would miss all on-disk tampering until
// the next restart, because memory is only ever changed by Append. The read
// holds the read lock so it never observes a half-written append.
func (s *Store) VerifyDisk() VerifyResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// #nosec G304 -- s.path is built from the cleaned, operator-configured
	// DATA_DIR and a constant file name (see Open).
	f, err := os.Open(s.path)
	if err != nil {
		return VerifyResult{Intact: false, Reason: ReasonUnreadable}
	}
	defer f.Close()
	disk, err := readRecords(f)
	if err != nil {
		return VerifyResult{Intact: false, Reason: ReasonUnreadable}
	}

	if res := Verify(disk); !res.Intact {
		return res
	}
	n := min(len(disk), len(s.records))
	for i := 0; i < n; i++ {
		if disk[i].Hash != s.records[i].Hash {
			seq := disk[i].Seq
			return VerifyResult{Intact: false, Checked: i, BrokenSeq: &seq, Reason: ReasonDiskDiverged}
		}
	}
	if len(disk) != len(s.records) {
		seq := uint64(n + 1) // first record present on one side only
		return VerifyResult{Intact: false, Checked: n, BrokenSeq: &seq, Reason: ReasonDiskDiverged}
	}
	return VerifyResult{Intact: true, Checked: len(disk)}
}

// Append validates nothing (callers pass an already-validated Event), commits
// the next record to disk durably, then updates the in-memory chain.
func (s *Store) Append(e Event) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := nextRecord(s.head, e, time.Now())
	if err != nil {
		return Record{}, err
	}

	buf, err := json.Marshal(rec)
	if err != nil {
		return Record{}, fmt.Errorf("marshal record: %w", err)
	}
	buf = append(buf, '\n')
	if _, err := s.f.Write(buf); err != nil {
		return Record{}, fmt.Errorf("write record: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return Record{}, fmt.Errorf("fsync audit log: %w", err)
	}

	s.records = append(s.records, rec)
	s.head = &s.records[len(s.records)-1]
	return rec, nil
}

// List returns a copy of the full chain, newest last.
func (s *Store) List() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, len(s.records))
	copy(out, s.records)
	return out
}

// Len reports the number of records currently in the chain.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records)
}

// Ready reports whether the store can still serve writes: the data directory
// exists and the log file handle is open.
func (s *Store) Ready() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.f == nil {
		return fmt.Errorf("audit log file is not open")
	}
	info, err := os.Stat(s.dir)
	if err != nil {
		return fmt.Errorf("stat data dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("data dir %q is not a directory", s.dir)
	}
	return nil
}

// Close flushes and closes the underlying file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

func derefSeq(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}
