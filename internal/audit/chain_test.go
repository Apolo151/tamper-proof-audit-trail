package audit

import (
	"encoding/json"
	"testing"
	"time"
)

func mustAppend(t *testing.T, prev *Record, e Event) Record {
	t.Helper()
	rec, err := nextRecord(prev, e, time.Now())
	if err != nil {
		t.Fatalf("nextRecord: %v", err)
	}
	return rec
}

func TestChainLinksAndSequence(t *testing.T) {
	r1 := mustAppend(t, nil, Event{Actor: "alice", Action: "login", Resource: "/session"})
	r2 := mustAppend(t, &r1, Event{Actor: "bob", Action: "delete", Resource: "record/42"})
	r3 := mustAppend(t, &r2, Event{Actor: "carol", Action: "update", Resource: "db/users",
		Metadata: json.RawMessage(`{"rows": 3}`)})

	if r1.Seq != 1 || r2.Seq != 2 || r3.Seq != 3 {
		t.Fatalf("sequence numbers = %d,%d,%d, want 1,2,3", r1.Seq, r2.Seq, r3.Seq)
	}
	if r1.PrevHash != GenesisPrevHash {
		t.Errorf("r1.PrevHash = %q, want genesis", r1.PrevHash)
	}
	if r2.PrevHash != r1.Hash {
		t.Errorf("r2.PrevHash = %q, want r1.Hash %q", r2.PrevHash, r1.Hash)
	}
	if r3.PrevHash != r2.Hash {
		t.Errorf("r3.PrevHash = %q, want r2.Hash %q", r3.PrevHash, r2.Hash)
	}
	if len(r1.Hash) != 64 {
		t.Errorf("hash length = %d, want 64 hex chars", len(r1.Hash))
	}

	res := Verify([]Record{r1, r2, r3})
	if !res.Intact {
		t.Fatalf("Verify on a good chain: %+v", res)
	}
	if res.Checked != 3 {
		t.Errorf("Checked = %d, want 3", res.Checked)
	}
}

func TestHashIsDeterministic(t *testing.T) {
	ts := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	e := Event{Actor: "alice", Action: "x", Resource: "y", Metadata: json.RawMessage(`{"b":2,"a":1}`)}

	a, err := nextRecord(nil, e, ts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := nextRecord(nil, e, ts)
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash != b.Hash {
		t.Fatalf("same input produced different hashes: %q vs %q", a.Hash, b.Hash)
	}
}

func TestEmptyChainIsIntact(t *testing.T) {
	if res := Verify(nil); !res.Intact || res.Checked != 0 {
		t.Fatalf("Verify(nil) = %+v, want intact/0", res)
	}
}
