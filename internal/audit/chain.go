package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// GenesisPrevHash is the synthetic predecessor hash for the first record in the
// chain: 64 hex zeros (the width of a SHA-256 digest).
var GenesisPrevHash = strings.Repeat("0", sha256.Size*2)

// computeHash returns hex(SHA-256(prevHash || canonical)). prevHash is mixed in
// as its ASCII bytes so that each record's hash commits to the entire history
// before it.
func computeHash(prevHash string, canonical []byte) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil))
}

// nextRecord builds the successor to prev (nil for the genesis record) from a
// validated Event and a commit timestamp.
func nextRecord(prev *Record, e Event, now time.Time) (Record, error) {
	var (
		seq      uint64 = 1
		prevHash        = GenesisPrevHash
	)
	if prev != nil {
		seq = prev.Seq + 1
		prevHash = prev.Hash
	}

	meta, err := compactMetadata(e.Metadata)
	if err != nil {
		return Record{}, err
	}

	ts := now.UTC().Truncate(0)
	canonical, err := canonicalBytes(seq, ts, e.Actor, e.Action, e.Resource, meta)
	if err != nil {
		return Record{}, err
	}

	return Record{
		Seq:       seq,
		Timestamp: ts,
		Actor:     e.Actor,
		Action:    e.Action,
		Resource:  e.Resource,
		Metadata:  meta,
		PrevHash:  prevHash,
		Hash:      computeHash(prevHash, canonical),
	}, nil
}
