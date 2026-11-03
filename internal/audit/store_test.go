package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreAppendReloadVerify(t *testing.T) {
	dir := t.TempDir()

	s, err := Open(dir, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, e := range []Event{
		{Actor: "alice", Action: "login", Resource: "/session"},
		{Actor: "bob", Action: "delete", Resource: "record/42"},
		{Actor: "carol", Action: "update", Resource: "db/users"},
	} {
		if _, err := s.Append(e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if s.Len() != 3 {
		t.Fatalf("Len = %d, want 3", s.Len())
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen from disk: chain head and integrity must survive a restart.
	s2, err := Open(dir, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	if s2.Len() != 3 {
		t.Fatalf("reloaded Len = %d, want 3", s2.Len())
	}
	if res := Verify(s2.List()); !res.Intact {
		t.Fatalf("reloaded chain not intact: %+v", res)
	}
	if head := s2.List()[2]; head.Seq != 3 {
		t.Errorf("reloaded head Seq = %d, want 3", head.Seq)
	}
}

func TestStoreReloadDetectsOnDiskCorruption(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, e := range []Event{
		{Actor: "alice", Action: "login", Resource: "/session"},
		{Actor: "bob", Action: "delete", Resource: "record/42"},
	} {
		if _, err := s.Append(e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	_ = s.Close()

	// Hand-corrupt line 1 on disk: flip the actor without touching the hash.
	path := filepath.Join(dir, logFileName)
	raw, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	lines[0] = strings.Replace(lines[0], `"actor":"alice"`, `"actor":"mallory"`, 1)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir, nil)
	if err != nil {
		t.Fatalf("reopen after corruption: %v", err)
	}
	defer s2.Close()

	res := Verify(s2.List())
	if res.Intact {
		t.Fatal("Verify reported intact after on-disk corruption")
	}
	if res.BrokenSeq == nil || *res.BrokenSeq != 1 {
		t.Fatalf("BrokenSeq = %v, want 1", res.BrokenSeq)
	}
}

func TestStoreReadyAndClose(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Ready(); err != nil {
		t.Errorf("Ready on a fresh store: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Ready(); err == nil {
		t.Error("Ready returned nil after Close, want error")
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// openWith3 opens a store in dir and appends three events.
func openWith3(t *testing.T, dir string, actorPrefix string) *Store {
	t.Helper()
	s, err := Open(dir, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for _, a := range []string{"1", "2", "3"} {
		if _, err := s.Append(Event{Actor: actorPrefix + a, Action: "write", Resource: "db/records"}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	return s
}

// TestVerifyDiskWhileRunning edits the log file underneath a live store: the
// in-memory chain is untouched, so only a re-read from disk can notice.
func TestVerifyDiskWhileRunning(t *testing.T) {
	logPath := func(dir string) string { return filepath.Join(dir, logFileName) }

	tests := []struct {
		name       string
		tamper     func(t *testing.T, dir string)
		wantReason string
		wantSeq    uint64
	}{
		{
			name:   "untouched",
			tamper: func(*testing.T, string) {},
		},
		{
			name: "field edited",
			tamper: func(t *testing.T, dir string) {
				rewrite(t, logPath(dir), func(s string) string {
					return strings.Replace(s, `"actor":"u2"`, `"actor":"mallory"`, 1)
				})
			},
			wantReason: ReasonHashBroken,
			wantSeq:    2,
		},
		{
			name: "last record deleted",
			tamper: func(t *testing.T, dir string) {
				rewrite(t, logPath(dir), func(s string) string {
					lines := strings.SplitAfter(s, "\n")
					return strings.Join(lines[:2], "")
				})
			},
			wantReason: ReasonDiskDiverged,
			wantSeq:    3,
		},
		{
			// The attacker recomputes every hash: the file is a valid chain on
			// its own, but it is not the chain this process wrote.
			name: "whole chain rewritten consistently",
			tamper: func(t *testing.T, dir string) {
				forged := t.TempDir()
				_ = openWith3(t, forged, "x")
				raw, err := os.ReadFile(logPath(forged)) // #nosec G304 -- test temp path
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(logPath(dir), raw, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantReason: ReasonDiskDiverged,
			wantSeq:    1,
		},
		{
			name: "garbage line",
			tamper: func(t *testing.T, dir string) {
				rewrite(t, logPath(dir), func(s string) string { return s + "not json\n" })
			},
			wantReason: ReasonUnreadable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			s := openWith3(t, dir, "u")
			tt.tamper(t, dir)

			res := s.VerifyDisk()
			if tt.wantReason == "" {
				if !res.Intact || res.Checked != 3 {
					t.Fatalf("VerifyDisk = %+v, want intact with 3 checked", res)
				}
				return
			}
			if res.Intact {
				t.Fatalf("VerifyDisk = %+v, want broken (%s)", res, tt.wantReason)
			}
			if res.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", res.Reason, tt.wantReason)
			}
			if tt.wantSeq != 0 && derefSeq(res.BrokenSeq) != tt.wantSeq {
				t.Errorf("BrokenSeq = %d, want %d", derefSeq(res.BrokenSeq), tt.wantSeq)
			}
			// The live chain is unaffected: appends keep working.
			if _, err := s.Append(Event{Actor: "after", Action: "write", Resource: "r"}); err != nil {
				t.Errorf("Append after tamper: %v", err)
			}
		})
	}
}

func rewrite(t *testing.T, path string, edit func(string) string) {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(edit(string(raw))), 0o600); err != nil {
		t.Fatal(err)
	}
}
