package audit

import (
	"testing"
	"time"
)

func goodChain(t *testing.T) []Record {
	t.Helper()
	var recs []Record
	var prev *Record
	for _, e := range []Event{
		{Actor: "alice", Action: "login", Resource: "/session"},
		{Actor: "bob", Action: "delete", Resource: "record/42"},
		{Actor: "carol", Action: "update", Resource: "db/users"},
	} {
		rec, err := nextRecord(prev, e, time.Now())
		if err != nil {
			t.Fatalf("nextRecord: %v", err)
		}
		recs = append(recs, rec)
		prev = &recs[len(recs)-1]
	}
	return recs
}

func TestVerifyDetectsFieldTampering(t *testing.T) {
	recs := goodChain(t)
	recs[1].Actor = "mallory" // rewrite a committed field, leave the hash alone

	res := Verify(recs)
	if res.Intact {
		t.Fatal("Verify reported intact after field tampering")
	}
	if res.BrokenSeq == nil || *res.BrokenSeq != 2 {
		t.Fatalf("BrokenSeq = %v, want 2", res.BrokenSeq)
	}
	if res.Reason != ReasonHashBroken {
		t.Errorf("Reason = %q, want %q", res.Reason, ReasonHashBroken)
	}
}

func TestVerifyDetectsPrevHashTampering(t *testing.T) {
	recs := goodChain(t)
	recs[2].PrevHash = GenesisPrevHash // unlink record 3 from record 2

	res := Verify(recs)
	if res.Intact {
		t.Fatal("Verify reported intact after prev_hash tampering")
	}
	if res.BrokenSeq == nil || *res.BrokenSeq != 3 {
		t.Fatalf("BrokenSeq = %v, want 3", res.BrokenSeq)
	}
	if res.Reason != ReasonPrevHashBroken {
		t.Errorf("Reason = %q, want %q", res.Reason, ReasonPrevHashBroken)
	}
}

func TestVerifyDetectsDeletion(t *testing.T) {
	recs := goodChain(t)
	recs = append(recs[:1], recs[2:]...) // drop record 2

	res := Verify(recs)
	if res.Intact {
		t.Fatal("Verify reported intact after a record was deleted")
	}
	// record 3 now sits at index 1, so its Seq (3) != wanted (2).
	if res.Reason != ReasonSequenceGap {
		t.Errorf("Reason = %q, want %q", res.Reason, ReasonSequenceGap)
	}
}
