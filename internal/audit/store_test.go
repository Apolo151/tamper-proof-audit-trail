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
