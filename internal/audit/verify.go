package audit

// Verify reasons, returned in VerifyResult.Reason.
const (
	ReasonSequenceGap    = "sequence gap"
	ReasonPrevHashBroken = "prev_hash mismatch"
	ReasonHashBroken     = "hash mismatch"
	ReasonEncodingError  = "canonical encoding error"
)

// VerifyResult is the outcome of walking the chain. It is safe to serialise
// directly as the body of GET /api/v1/audit/verify.
type VerifyResult struct {
	Intact    bool    `json:"intact"`
	Checked   int     `json:"checked"`
	BrokenSeq *uint64 `json:"broken_seq,omitempty"`
	Reason    string  `json:"reason,omitempty"`
}

// Verify walks records in order and recomputes each hash link. It stops at and
// reports the first broken link. An empty chain is considered intact.
func Verify(records []Record) VerifyResult {
	prevHash := GenesisPrevHash
	for i, rec := range records {
		wantSeq := uint64(i + 1)
		if rec.Seq != wantSeq {
			s := rec.Seq
			return VerifyResult{Intact: false, Checked: i, BrokenSeq: &s, Reason: ReasonSequenceGap}
		}
		if rec.PrevHash != prevHash {
			s := rec.Seq
			return VerifyResult{Intact: false, Checked: i, BrokenSeq: &s, Reason: ReasonPrevHashBroken}
		}

		canonical, err := canonicalForRecord(rec)
		if err != nil {
			s := rec.Seq
			return VerifyResult{Intact: false, Checked: i, BrokenSeq: &s, Reason: ReasonEncodingError}
		}
		if computeHash(rec.PrevHash, canonical) != rec.Hash {
			s := rec.Seq
			return VerifyResult{Intact: false, Checked: i, BrokenSeq: &s, Reason: ReasonHashBroken}
		}
		prevHash = rec.Hash
	}
	return VerifyResult{Intact: true, Checked: len(records)}
}
