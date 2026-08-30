// Reference generator + validator for audit-checkpoint conformance vectors.
//
//	go run . gen  <out.json>   -> deterministically produce the vectors
//	go run . validate <in.json> -> re-derive and check every vector + the chain
//
// Canonicalization is RFC 8785 (JCS) via github.com/gowebpki/jcs.
// The chain hash is SHA-256 over the canonical bytes; the signature is
// Ed25519 over the same canonical bytes. Ed25519 is deterministic, so a
// correct independent implementation MUST reproduce identical signatures.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"

	"github.com/gowebpki/jcs"
)

// sha256Empty is the canonical genesis prev_hash (SHA-256 of the empty string).
const sha256Empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// supportedFormatVersion is the highest suite format this build understands.
// Vectors carrying a higher min_format_version are skipped, not failed.
const supportedFormatVersion = 2

// skipVector reports whether a vector requiring minVer must be skipped by a
// validator supporting supportedVer. A minVer of 0 means "no minimum".
func skipVector(minVer, supportedVer int) bool {
	return minVer > supportedVer
}

// Fixed TEST-ONLY signing seed: bytes 0x00..0x1f. Never use for anything real.
func testSeed() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

type Tip struct {
	EntryCount     int    `json:"entry_count"`
	Epoch          *int   `json:"epoch,omitempty"`
	SequenceNumber int    `json:"sequence_number"`
	StreamID       string `json:"stream_id"`
	TipHash        string `json:"tip_hash"`
}

// ptr returns a pointer to i, for building tips with an explicit epoch.
func ptr(i int) *int { return &i }

// tipEpoch reads a tip's epoch, treating an absent value as 0. Absence is
// legal only in format_version 1 vectors; checkEpochPresence enforces that.
func tipEpoch(t Tip) int {
	if t.Epoch == nil {
		return 0
	}
	return *t.Epoch
}

type Checkpoint struct {
	PrevHash  string `json:"prev_hash"`
	Seq       int    `json:"seq"`
	Timestamp string `json:"timestamp"`
	Tips      []Tip  `json:"tips"`
}

// tipIdentity is the uniqueness and sort key. Epoch is part of it (spec R4):
// two tips for one stream at different epochs are legal in a single checkpoint,
// so sorting on stream_id alone would let input order leak into signed bytes.
// The \x00 separator cannot occur in a stream id and sorts below every
// printable byte, so the encoding is prefix-free; the zero-padded epoch makes
// string comparison agree with numeric order.
func tipIdentity(t Tip) string {
	return fmt.Sprintf("%s\x00%020d", t.StreamID, tipEpoch(t))
}

// canonical returns the JCS canonical bytes of a checkpoint. Tips are sorted
// by identity first: JCS fixes object-key order but preserves array order, so
// the producer MUST impose a deterministic tip order for reproducibility. Two
// tips sharing an identity would make that order (and thus the canonical
// bytes) depend on input order, so duplicates are rejected outright.
func canonical(c Checkpoint) ([]byte, error) {
	seen := make(map[string]struct{}, len(c.Tips))
	for _, t := range c.Tips {
		id := tipIdentity(t)
		if _, dup := seen[id]; dup {
			return nil, fmt.Errorf("duplicate tip identity %q: canonical bytes would depend on input order", id)
		}
		seen[id] = struct{}{}
	}
	tips := make([]Tip, len(c.Tips))
	copy(tips, c.Tips)
	sort.Slice(tips, func(i, j int) bool { return tipIdentity(tips[i]) < tipIdentity(tips[j]) })
	c.Tips = tips // sort a copy; leave the caller's input order intact
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}

// SignedCheckpoint is one checkpoint of a vector's preceding context.
// A validator MUST verify each prefix signature, not merely hash it for
// linkage -- the vector should exercise what a production verifier does.
// verifyPrefixes is the single place that MUST is enforced, and it is used by
// the positive and the negative path alike; the tampered_prefix_signature
// vector is what makes skipping it detectable from outside.
type SignedCheckpoint struct {
	Input     Checkpoint `json:"input"`
	Signature string     `json:"signature"`
}

type Vector struct {
	Name      string     `json:"name"`
	Input     Checkpoint `json:"input"`
	Canonical string     `json:"canonical"`
	SHA256    string     `json:"sha256"`
	Signature string     `json:"signature"`
	// Chain is the preceding, already-signed context this vector's Tier B
	// rules are evaluated against. ExpectWarnings is what makes an advisory
	// rule testable: without it a validator that silently accepts still
	// passes a must-accept vector, so B4/B5 would be asserted but never
	// exercised.
	Chain            []SignedCheckpoint `json:"chain,omitempty"`
	ExpectWarnings   []string           `json:"expect_warnings,omitempty"`
	MinFormatVersion int                `json:"min_format_version,omitempty"`
}

// NegativeVector is a case a conformant validator MUST reject. Expect names the
// check that should catch it: "schema", "canonical", "signature", "tier_b" or
// "chain". PrevSHA256, when set, is the hash the input's prev_hash is expected
// to chain to. Chain, when set, is the preceding signed context the
// cross-checkpoint (Tier B) rules are evaluated against.
type NegativeVector struct {
	Name             string             `json:"name"`
	Expect           string             `json:"expect"`
	Reason           string             `json:"reason"`
	Input            Checkpoint         `json:"input"`
	Signature        string             `json:"signature"`
	PrevSHA256       string             `json:"prev_sha256,omitempty"`
	Chain            []SignedCheckpoint `json:"chain,omitempty"`
	MinFormatVersion int                `json:"min_format_version,omitempty"`
}

type Suite struct {
	FormatVersion int              `json:"format_version"`
	Description   string           `json:"description"`
	Algorithm     string           `json:"algorithm"`
	SeedHex       string           `json:"signing_seed_hex"`
	PublicKeyHex  string           `json:"public_key_hex"`
	Vectors       []Vector         `json:"vectors"`
	Negatives     []NegativeVector `json:"negatives"`
}

// signCP canonicalizes and signs a checkpoint, panicking on malformed input so
// a bad vector can never be published.
func signCP(priv ed25519.PrivateKey, cp Checkpoint) SignedCheckpoint {
	cb, err := canonical(cp)
	if err != nil {
		panic(fmt.Sprintf("gen: malformed checkpoint: %v", err))
	}
	return SignedCheckpoint{Input: cp, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, cb))}
}

// cpHash returns the hex SHA-256 of a checkpoint's canonical bytes -- the value
// the next checkpoint's prev_hash must carry.
func cpHash(cp Checkpoint) string {
	cb, err := canonical(cp)
	if err != nil {
		panic(fmt.Sprintf("gen: malformed checkpoint: %v", err))
	}
	sum := sha256.Sum256(cb)
	return hex.EncodeToString(sum[:])
}

// linkCheckpoints sets each checkpoint's prev_hash from its predecessor's
// canonical bytes and returns the slice. A vector that means to break one link
// overwrites that prev_hash afterwards and relinks whatever follows, so the
// defect it publishes is exactly one and sits at exactly one index.
func linkCheckpoints(cps []Checkpoint) []Checkpoint {
	prev := sha256Empty
	for i := range cps {
		cps[i].PrevHash = prev
		prev = cpHash(cps[i])
	}
	return cps
}

// relinkFrom recomputes prev_hash from index `from` onwards, after an earlier
// checkpoint has been mutated.
func relinkFrom(cps []Checkpoint, from int) {
	for i := from; i < len(cps); i++ {
		cps[i].PrevHash = cpHash(cps[i-1])
	}
}

// signAll signs each checkpoint, producing a vector's chain prefix list.
func signAll(priv ed25519.PrivateKey, cps []Checkpoint) []SignedCheckpoint {
	out := make([]SignedCheckpoint, 0, len(cps))
	for _, cp := range cps {
		out = append(out, signCP(priv, cp))
	}
	return out
}

// posChain builds a clean, correctly linked chain of n checkpoints, each
// committing one distinct stream at epoch 0 with a strictly increasing
// timestamp. The positional vectors below start from one of these and inject a
// single defect at a chosen index.
//
// n is 4 for every caller, which is the point: with four checkpoints the chain
// has three transitions, so "first", "middle" and "last" are three DISTINCT
// positions. Every chain in the suite before this one was short enough that at
// least two of those coincided -- which is what let a rule applied at only one
// position pass the whole suite.
func posChain(idPrefix string, n int) []Checkpoint {
	cps := make([]Checkpoint, n)
	for i := range cps {
		cps[i] = Checkpoint{
			Seq:       i + 1,
			Timestamp: fmt.Sprintf("2026-10-01T00:%02d:00Z", i),
			Tips: []Tip{{
				EntryCount: i + 1, Epoch: ptr(0), SequenceNumber: i + 1,
				StreamID: fmt.Sprintf("%s-0000-4000-8000-%012d", idPrefix, i+1),
				TipHash:  fmt.Sprintf("%02x", i+1) + repeat("00", 31),
			}},
		}
	}
	return linkCheckpoints(cps)
}

func gen() Suite {
	priv := ed25519.NewKeyFromSeed(testSeed())
	pub := priv.Public().(ed25519.PublicKey)

	// Three chained checkpoints: genesis (empty tips), single tip, multi tip
	// (given out of stream_id order to exercise the sort rule).
	inputs := []struct {
		name string
		cp   Checkpoint
	}{
		{"genesis_empty_tips", Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{}}},
		{"single_tip", Checkpoint{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{
			{EntryCount: 3, SequenceNumber: 3, StreamID: "11111111-1111-4111-8111-111111111111", TipHash: "aa" + repeat("00", 31)},
		}}},
		{"multi_tip_unsorted_input", Checkpoint{Seq: 3, Timestamp: "2026-01-01T00:00:10Z", Tips: []Tip{
			{EntryCount: 2, SequenceNumber: 2, StreamID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", TipHash: "cc" + repeat("00", 31)},
			{EntryCount: 7, SequenceNumber: 7, StreamID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", TipHash: "bb" + repeat("00", 31)},
		}}},
	}

	var suite Suite
	suite.FormatVersion = supportedFormatVersion
	suite.Description = "Conformance vectors for the audit-checkpoint canonical form (RFC 8785 JCS + SHA-256 chain + Ed25519). TEST KEY ONLY."
	suite.Algorithm = "ed25519"
	suite.SeedHex = hex.EncodeToString(testSeed())
	suite.PublicKeyHex = hex.EncodeToString(pub)

	prev := ""
	for i, in := range inputs {
		cp := in.cp
		if i == 0 {
			prev = cp.PrevHash // genesis carries its own prev_hash
		} else {
			cp.PrevHash = prev // chain to the previous checkpoint
		}
		cb, err := canonical(cp)
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(cb)
		hexSum := hex.EncodeToString(sum[:])
		sig := ed25519.Sign(priv, cb)
		suite.Vectors = append(suite.Vectors, Vector{
			Name:      in.name,
			Input:     cp,
			Canonical: string(cb),
			SHA256:    hexSum,
			Signature: base64.StdEncoding.EncodeToString(sig),
		})
		prev = hexSum
	}

	// R4: two tips for ONE stream at different epochs are legal in a single
	// checkpoint, so the sort key is composite. Epochs 2 and 10 are chosen
	// deliberately: with a naive "%s\x00%d" key Go orders them [10, 2] while
	// Python's tuple compare orders them [2, 10], so the two implementations
	// would disagree on published bytes and nothing else in the suite would
	// notice. Given in reverse order so the sort has to fix it. This vector is
	// the only thing that pins the zero-padding width.
	//
	// It carries a chain prefix committing the same stream at epoch 0, so the
	// checkpoint makes TWO epoch transitions (0->2 and 2->10) and B4 is emitted
	// once per transition -- two identical tokens. The chain also keeps the
	// vector's advisory assertion binding: a positive vector's Tier B block
	// must run for it, chain or no chain.
	mePrefix := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:10Z", Tips: []Tip{
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", TipHash: "0a" + repeat("00", 31)},
	}}
	mePrefixCanon, err := canonical(mePrefix)
	if err != nil {
		panic(fmt.Sprintf("gen: multi-epoch prefix is malformed: %v", err))
	}
	mePrefixSum := sha256.Sum256(mePrefixCanon)
	multiEpoch := Checkpoint{PrevHash: hex.EncodeToString(mePrefixSum[:]), Seq: 2, Timestamp: "2026-01-01T00:00:15Z", Tips: []Tip{
		{EntryCount: 11, Epoch: ptr(10), SequenceNumber: 11, StreamID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", TipHash: "bb" + repeat("00", 31)},
		{EntryCount: 3, Epoch: ptr(2), SequenceNumber: 3, StreamID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", TipHash: "aa" + repeat("00", 31)},
	}}
	meCanon, err := canonical(multiEpoch)
	if err != nil {
		panic(fmt.Sprintf("gen: multi-epoch vector is malformed: %v", err))
	}
	meSum := sha256.Sum256(meCanon)
	suite.Vectors = append(suite.Vectors, Vector{
		Name:      "multi_epoch_same_stream",
		Input:     multiEpoch,
		Canonical: string(meCanon),
		SHA256:    hex.EncodeToString(meSum[:]),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, meCanon)),
		Chain:     []SignedCheckpoint{signCP(priv, mePrefix)},
		// Once per transition: 0->2 and 2->10.
		ExpectWarnings: []string{
			"B4:eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
			"B4:eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
		},
		MinFormatVersion: 2,
	})

	// Negative vectors: a conformant validator MUST reject each of these.
	base := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-02-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 7, SequenceNumber: 7, StreamID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", TipHash: "aa" + repeat("00", 31)},
	}}
	baseCanon, err := canonical(base)
	if err != nil {
		panic(fmt.Sprintf("gen: negative-vector base is malformed: %v", err))
	}
	baseSig := ed25519.Sign(priv, baseCanon)

	// 1. One byte of a valid signature flipped.
	tsig := append([]byte(nil), baseSig...)
	tsig[0] ^= 0x01
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "tampered_signature", Expect: "signature",
		Reason: "one byte of a valid signature is flipped; verification must fail",
		Input:  base, Signature: base64.StdEncoding.EncodeToString(tsig),
	})

	// 2. A truncation hidden by rewriting the committed tip, original signature kept.
	mutTips := make([]Tip, len(base.Tips))
	copy(mutTips, base.Tips)
	mutTips[0].EntryCount = 5
	mutTips[0].TipHash = "ee" + repeat("00", 31)
	mut := base
	mut.Tips = mutTips
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "truncation_rewrites_committed_tip", Expect: "signature",
		Reason: "the stream was truncated (entry_count 7 to 5) and the checkpoint tip rewritten to match, but the original signature no longer covers the mutated tip",
		Input:  mut, Signature: base64.StdEncoding.EncodeToString(baseSig),
	})

	// 3. Valid signature, but prev_hash does not chain to the expected previous hash.
	bc := base
	bc.PrevHash = "11" + repeat("11", 31)
	bcCanon, err := canonical(bc)
	if err != nil {
		panic(fmt.Sprintf("gen: broken_chain vector is malformed: %v", err))
	}
	bcSig := ed25519.Sign(priv, bcCanon)
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "broken_chain", Expect: "chain",
		Reason: "signature is valid, but prev_hash does not equal the previous checkpoint's hash",
		Input:  bc, Signature: base64.StdEncoding.EncodeToString(bcSig),
		PrevSHA256: sha256Empty,
	})

	// 4. Two tips with the same identity: canonical bytes would depend on
	// input order, so the checkpoint is rejected before any signature check.
	// The duplicate pair is separated by a third, non-duplicate tip so the
	// pair is non-adjacent in input order -- a naive adjacent-scan duplicate
	// check (comparing element i to i-1 in original order) would miss this;
	// only a check over the full set of identities catches it.
	dup := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-02-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 7, SequenceNumber: 7, StreamID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", TipHash: "aa" + repeat("00", 31)},
		{EntryCount: 9, SequenceNumber: 9, StreamID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", TipHash: "cc" + repeat("00", 31)},
		{EntryCount: 5, SequenceNumber: 5, StreamID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", TipHash: "bb" + repeat("00", 31)},
	}}
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "duplicate_tip_identity", Expect: "canonical",
		Reason: "two tips share an identity, so the canonical bytes would depend on input order",
		Input:  dup, Signature: "",
	})

	// Tier B, all at format_version 2. Each carries one preceding checkpoint.
	tbBase := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-03-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 7, Epoch: ptr(0), SequenceNumber: 7, StreamID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", TipHash: "aa" + repeat("00", 31)},
	}}
	tbSigned := signCP(priv, tbBase)
	tbBaseCanon, err := canonical(tbBase)
	if err != nil {
		panic(fmt.Sprintf("gen: tier-B base is malformed: %v", err))
	}
	tbSum := sha256.Sum256(tbBaseCanon)
	tbPrev := hex.EncodeToString(tbSum[:])

	// B3: same stream and epoch committed a second time.
	reco := Checkpoint{PrevHash: tbPrev, Seq: 2, Timestamp: "2026-03-01T00:00:05Z", Tips: []Tip{
		{EntryCount: 9, Epoch: ptr(0), SequenceNumber: 9, StreamID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", TipHash: "cc" + repeat("00", 31)},
	}}
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "stream_recommitted_same_epoch", Expect: "tier_b",
		Reason:           "stream committed twice under the same epoch; within one producer generation the dedup map is intact, so no second commit is legitimate",
		Input:            reco,
		Signature:        signCP(priv, reco).Signature,
		Chain:            []SignedCheckpoint{tbSigned},
		MinFormatVersion: 2,
	})

	// B3: same identity, lower entry_count -- a rollback inside one generation.
	roll := Checkpoint{PrevHash: tbPrev, Seq: 2, Timestamp: "2026-03-01T00:00:05Z", Tips: []Tip{
		{EntryCount: 5, Epoch: ptr(0), SequenceNumber: 5, StreamID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", TipHash: "dd" + repeat("00", 31)},
	}}
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "tip_rollback_same_epoch", Expect: "tier_b",
		Reason:           "committed tip regresses (entry_count 7 to 5) under the same epoch",
		Input:            roll,
		Signature:        signCP(priv, roll).Signature,
		Chain:            []SignedCheckpoint{tbSigned},
		MinFormatVersion: 2,
	})

	// B1: a checkpoint that skips a sequence number.
	skip := Checkpoint{PrevHash: tbPrev, Seq: 3, Timestamp: "2026-03-01T00:00:05Z", Tips: []Tip{
		{EntryCount: 2, Epoch: ptr(0), SequenceNumber: 2, StreamID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", TipHash: "bb" + repeat("00", 31)},
	}}
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "seq_skip", Expect: "tier_b",
		Reason:           "checkpoint seq jumps from 1 to 3",
		Input:            skip,
		Signature:        signCP(priv, skip).Signature,
		Chain:            []SignedCheckpoint{tbSigned},
		MinFormatVersion: 2,
	})

	// A version-2 tip with no epoch: the boundary rule must be enforced, not
	// merely stated, or a v2 tip missing epoch silently validates as epoch 0.
	// The offending tip is deliberately NOT first: a check that inspects only
	// Tips[0] would pass this vector.
	noEpoch := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-03-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 4, Epoch: ptr(0), SequenceNumber: 4, StreamID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", TipHash: "ca" + repeat("00", 31)},
		{EntryCount: 1, Epoch: nil, SequenceNumber: 1, StreamID: "dddddddd-dddd-4ddd-8ddd-ddddddddddd1", TipHash: "cc" + repeat("00", 31)},
	}}
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "missing_epoch_in_v2", Expect: "schema",
		Reason:           "epoch is required on every tip at format_version 2 and above; here the second tip omits it",
		Input:            noEpoch,
		Signature:        signCP(priv, noEpoch).Signature,
		MinFormatVersion: 2,
	})

	// Must-accept: the declared at-least-once path. Accepted, with a B4 warning.
	adv := Checkpoint{PrevHash: tbPrev, Seq: 2, Timestamp: "2026-03-01T00:00:05Z", Tips: []Tip{
		{EntryCount: 5, Epoch: ptr(1), SequenceNumber: 5, StreamID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", TipHash: "ee" + repeat("00", 31)},
	}}
	advCanon, err := canonical(adv)
	if err != nil {
		panic(fmt.Sprintf("gen: advisory vector is malformed: %v", err))
	}
	advSum := sha256.Sum256(advCanon)
	suite.Vectors = append(suite.Vectors, Vector{
		Name:             "advisory_stream_recommitted_new_epoch",
		Input:            adv,
		Canonical:        string(advCanon),
		SHA256:           hex.EncodeToString(advSum[:]),
		Signature:        base64.StdEncoding.EncodeToString(ed25519.Sign(priv, advCanon)),
		Chain:            []SignedCheckpoint{tbSigned},
		ExpectWarnings:   []string{"B4:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
		MinFormatVersion: 2,
	})

	// Must-accept: a timestamp regression warns and is not rejected.
	back := Checkpoint{PrevHash: tbPrev, Seq: 2, Timestamp: "2026-02-28T23:59:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", TipHash: "ff" + repeat("00", 31)},
	}}
	backCanon, err := canonical(back)
	if err != nil {
		panic(fmt.Sprintf("gen: advisory timestamp vector is malformed: %v", err))
	}
	backSum := sha256.Sum256(backCanon)
	suite.Vectors = append(suite.Vectors, Vector{
		Name:             "advisory_timestamp_regression",
		Input:            back,
		Canonical:        string(backCanon),
		SHA256:           hex.EncodeToString(backSum[:]),
		Signature:        base64.StdEncoding.EncodeToString(ed25519.Sign(priv, backCanon)),
		Chain:            []SignedCheckpoint{tbSigned},
		ExpectWarnings:   []string{"B5:2"},
		MinFormatVersion: 2,
	})

	// Must-accept: B4 and B5 raised by the SAME checkpoint. Without this the
	// two warnings never co-occur, so their relative order is mirrored between
	// the implementations but verified by nothing.
	both := Checkpoint{PrevHash: tbPrev, Seq: 2, Timestamp: "2026-02-28T23:59:00Z", Tips: []Tip{
		{EntryCount: 6, Epoch: ptr(1), SequenceNumber: 6, StreamID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", TipHash: "1a" + repeat("00", 31)},
	}}
	bothCanon, err := canonical(both)
	if err != nil {
		panic(fmt.Sprintf("gen: dual-warning vector is malformed: %v", err))
	}
	bothSum := sha256.Sum256(bothCanon)
	suite.Vectors = append(suite.Vectors, Vector{
		Name:             "advisory_new_epoch_and_timestamp_regression",
		Input:            both,
		Canonical:        string(bothCanon),
		SHA256:           hex.EncodeToString(bothSum[:]),
		Signature:        base64.StdEncoding.EncodeToString(ed25519.Sign(priv, bothCanon)),
		Chain:            []SignedCheckpoint{tbSigned},
		ExpectWarnings:   []string{"B4:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "B5:2"},
		MinFormatVersion: 2,
	})

	// Two DIFFERENT streams each changing epoch in one checkpoint, with the
	// tips supplied in non-identity input order. This is what makes the
	// identity-order tip walk load-bearing: an input-order walk emits
	// ["B4:2000...", "B4:1000..."] here and ["B4:1000...", "B4:2000..."] if the
	// same two tips are supplied the other way round. Warnings are compared as
	// ordered lists and a checkpoint's input.tips are explicitly allowed to be
	// unsorted, so without a fixed walk order the two implementations can
	// disagree on the warning sequence for identical signed bytes.
	twoStreamsPrefix := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-04-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "10000000-0000-4000-8000-000000000001", TipHash: "1a" + repeat("00", 31)},
		{EntryCount: 2, Epoch: ptr(0), SequenceNumber: 2, StreamID: "20000000-0000-4000-8000-000000000002", TipHash: "2a" + repeat("00", 31)},
	}}
	tsPrefixCanon, err := canonical(twoStreamsPrefix)
	if err != nil {
		panic(fmt.Sprintf("gen: two-stream prefix is malformed: %v", err))
	}
	tsPrefixSum := sha256.Sum256(tsPrefixCanon)
	twoStreams := Checkpoint{PrevHash: hex.EncodeToString(tsPrefixSum[:]), Seq: 2, Timestamp: "2026-04-01T00:00:05Z", Tips: []Tip{
		// Deliberately NOT in identity order.
		{EntryCount: 4, Epoch: ptr(1), SequenceNumber: 4, StreamID: "20000000-0000-4000-8000-000000000002", TipHash: "2b" + repeat("00", 31)},
		{EntryCount: 3, Epoch: ptr(1), SequenceNumber: 3, StreamID: "10000000-0000-4000-8000-000000000001", TipHash: "1b" + repeat("00", 31)},
	}}
	tsCanon, err := canonical(twoStreams)
	if err != nil {
		panic(fmt.Sprintf("gen: two-stream vector is malformed: %v", err))
	}
	tsSum := sha256.Sum256(tsCanon)
	suite.Vectors = append(suite.Vectors, Vector{
		Name:             "advisory_two_streams_new_epoch",
		Input:            twoStreams,
		Canonical:        string(tsCanon),
		SHA256:           hex.EncodeToString(tsSum[:]),
		Signature:        base64.StdEncoding.EncodeToString(ed25519.Sign(priv, tsCanon)),
		Chain:            []SignedCheckpoint{signCP(priv, twoStreamsPrefix)},
		ExpectWarnings:   []string{"B4:10000000-0000-4000-8000-000000000001", "B4:20000000-0000-4000-8000-000000000002"},
		MinFormatVersion: 2,
	})

	// A TWO-prefix chain whose SECOND prefix is tampered. Every other chain in
	// the suite has exactly one prefix, so per-prefix logic that is right at
	// index 0 and wrong afterwards would be invisible. The input and both
	// prefixes are otherwise clean and the whole chain passes Tier B, so only
	// a validator that verifies every prefix rejects this.
	p1 := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-05-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "aaaa1111-1111-4111-8111-111111111111", TipHash: "a1" + repeat("00", 31)},
	}}
	p1Canon, err := canonical(p1)
	if err != nil {
		panic(fmt.Sprintf("gen: first prefix is malformed: %v", err))
	}
	p1Sum := sha256.Sum256(p1Canon)
	p2 := Checkpoint{PrevHash: hex.EncodeToString(p1Sum[:]), Seq: 2, Timestamp: "2026-05-01T00:00:05Z", Tips: []Tip{
		{EntryCount: 2, Epoch: ptr(0), SequenceNumber: 2, StreamID: "bbbb2222-2222-4222-8222-222222222222", TipHash: "b2" + repeat("00", 31)},
	}}
	p2Signed := signCP(priv, p2)
	p2Raw, err := base64.StdEncoding.DecodeString(p2Signed.Signature)
	if err != nil {
		panic(fmt.Sprintf("gen: second prefix signature is not base64: %v", err))
	}
	p2Bad := append([]byte(nil), p2Raw...)
	p2Bad[0] ^= 0x01
	p2Canon, err := canonical(p2)
	if err != nil {
		panic(fmt.Sprintf("gen: second prefix is malformed: %v", err))
	}
	p2Sum := sha256.Sum256(p2Canon)
	afterP2 := Checkpoint{PrevHash: hex.EncodeToString(p2Sum[:]), Seq: 3, Timestamp: "2026-05-01T00:00:10Z", Tips: []Tip{
		{EntryCount: 3, Epoch: ptr(0), SequenceNumber: 3, StreamID: "cccc3333-3333-4333-8333-333333333333", TipHash: "c3" + repeat("00", 31)},
	}}
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "tampered_second_prefix_signature", Expect: "signature",
		Reason:    "one byte of the SECOND chain prefix's signature is flipped; a validator that verifies only the first prefix accepts this",
		Input:     afterP2,
		Signature: signCP(priv, afterP2).Signature,
		Chain: []SignedCheckpoint{
			signCP(priv, p1),
			{Input: p2, Signature: base64.StdEncoding.EncodeToString(p2Bad)},
		},
		MinFormatVersion: 2,
	})

	// A chain prefix whose signature is tampered. The input is otherwise clean
	// and passes Tier B on its own, so the ONLY thing that rejects this vector
	// is actually verifying the prefix signature -- which is what makes the
	// MUST on SignedCheckpoint enforceable rather than decorative.
	tbSigRaw, err := base64.StdEncoding.DecodeString(tbSigned.Signature)
	if err != nil {
		panic(fmt.Sprintf("gen: tier-B base signature is not base64: %v", err))
	}
	badSig := append([]byte(nil), tbSigRaw...)
	badSig[0] ^= 0x01
	tamperedPrefix := SignedCheckpoint{Input: tbBase, Signature: base64.StdEncoding.EncodeToString(badSig)}
	cleanNext := Checkpoint{PrevHash: tbPrev, Seq: 2, Timestamp: "2026-03-01T00:00:05Z", Tips: []Tip{
		{EntryCount: 4, Epoch: ptr(0), SequenceNumber: 4, StreamID: "99999999-9999-4999-8999-999999999999", TipHash: "9a" + repeat("00", 31)},
	}}
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "tampered_prefix_signature", Expect: "signature",
		Reason:           "one byte of the CHAIN PREFIX's signature is flipped; the vector's own input is valid and passes Tier B, so only a validator that verifies prefix signatures rejects this",
		Input:            cleanNext,
		Signature:        signCP(priv, cleanNext).Signature,
		Chain:            []SignedCheckpoint{tamperedPrefix},
		MinFormatVersion: 2,
	})

	// A correctly signed chain prefix whose tip omits epoch at version 2. Left
	// unchecked, tipEpoch reads it as 0 and it silently feeds B3 identity and
	// B4 comparisons -- the Step 7 failure, one level down.
	//
	// The offending prefix is the SECOND one: with a single-prefix chain, a
	// validator that epoch-checks only chain[0] still rejects this and the gap
	// is invisible.
	goodPrefix := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-03-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "44444444-4444-4444-8444-444444444444", TipHash: "4a" + repeat("00", 31)},
	}}
	badPrefixCP := Checkpoint{PrevHash: cpHash(goodPrefix), Seq: 2, Timestamp: "2026-03-01T00:00:05Z", Tips: []Tip{
		{EntryCount: 3, Epoch: nil, SequenceNumber: 3, StreamID: "66666666-6666-4666-8666-666666666666", TipHash: "6a" + repeat("00", 31)},
	}}
	afterBadPrefix := Checkpoint{PrevHash: cpHash(badPrefixCP), Seq: 3, Timestamp: "2026-03-01T00:00:10Z", Tips: []Tip{
		{EntryCount: 2, Epoch: ptr(0), SequenceNumber: 2, StreamID: "55555555-5555-4555-8555-555555555555", TipHash: "5a" + repeat("00", 31)},
	}}
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "chain_prefix_missing_epoch", Expect: "schema",
		Reason:           "the SECOND version-2 chain prefix omits epoch on its tip; the boundary applies to every prefix, not only to chain[0] or to the vector's own input",
		Input:            afterBadPrefix,
		Signature:        signCP(priv, afterBadPrefix).Signature,
		Chain:            []SignedCheckpoint{signCP(priv, goodPrefix), signCP(priv, badPrefixCP)},
		MinFormatVersion: 2,
	})

	// A two-prefix chain in which the SECOND prefix does not hash-link to the
	// first. Every checkpoint is correctly signed and the vector's own
	// prev_hash is right, so the vector-level prev_sha256 field cannot see
	// this: only a linkage check across the assembled chain rejects it.
	linkP1 := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-08-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "b1b1b1b1-0000-4000-8000-000000000001", TipHash: "b1" + repeat("00", 31)},
	}}
	linkP2 := Checkpoint{PrevHash: "22" + repeat("22", 31), Seq: 2, Timestamp: "2026-08-01T00:00:05Z", Tips: []Tip{
		{EntryCount: 2, Epoch: ptr(0), SequenceNumber: 2, StreamID: "b2b2b2b2-0000-4000-8000-000000000002", TipHash: "b2" + repeat("00", 31)},
	}}
	afterLink := Checkpoint{PrevHash: cpHash(linkP2), Seq: 3, Timestamp: "2026-08-01T00:00:10Z", Tips: []Tip{
		{EntryCount: 3, Epoch: ptr(0), SequenceNumber: 3, StreamID: "b3b3b3b3-0000-4000-8000-000000000003", TipHash: "b3" + repeat("00", 31)},
	}}
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "chain_prefix_broken_link", Expect: "tier_b",
		Reason:           "the second chain prefix's prev_hash does not equal the first prefix's hash; B2 must hold across the whole assembled chain, not only at the vector's own link",
		Input:            afterLink,
		Signature:        signCP(priv, afterLink).Signature,
		Chain:            []SignedCheckpoint{signCP(priv, linkP1), signCP(priv, linkP2)},
		MinFormatVersion: 2,
	})

	// A seq gap at the LAST transition of a three-checkpoint chain. seq_skip
	// puts its gap at the first transition, so a validator that checks B1 only
	// between chain[0] and chain[1] still passes the whole suite.
	lateP1 := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-09-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "c1c1c1c1-0000-4000-8000-000000000001", TipHash: "c1" + repeat("00", 31)},
	}}
	lateP2 := Checkpoint{PrevHash: cpHash(lateP1), Seq: 2, Timestamp: "2026-09-01T00:00:05Z", Tips: []Tip{
		{EntryCount: 2, Epoch: ptr(0), SequenceNumber: 2, StreamID: "c2c2c2c2-0000-4000-8000-000000000002", TipHash: "c2" + repeat("00", 31)},
	}}
	lateSkip := Checkpoint{PrevHash: cpHash(lateP2), Seq: 4, Timestamp: "2026-09-01T00:00:10Z", Tips: []Tip{
		{EntryCount: 3, Epoch: ptr(0), SequenceNumber: 3, StreamID: "c3c3c3c3-0000-4000-8000-000000000003", TipHash: "c3" + repeat("00", 31)},
	}}
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "seq_skip_after_first_transition", Expect: "tier_b",
		Reason:           "checkpoint seq jumps from 2 to 4 at the chain's SECOND transition; B1 must hold at every transition, not only the first",
		Input:            lateSkip,
		Signature:        signCP(priv, lateSkip).Signature,
		Chain:            []SignedCheckpoint{signCP(priv, lateP1), signCP(priv, lateP2)},
		MinFormatVersion: 2,
	})

	// Must-accept, TWO prefixes: cp2 regresses its timestamp (B5:2) and cp3
	// changes a stream's epoch (B4). The warning sequence is therefore
	// ["B5:2", "B4:..."] -- NOT in sorted order, which is the only shape that
	// can distinguish an ordered comparison from a multiset one. It is also the
	// suite's only vector whose Tier B rules run over a three-checkpoint chain,
	// so prefix ordering and B1/B2 past the first transition are load-bearing.
	longP1 := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-06-01T00:00:10Z", Tips: []Tip{
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "d1d1d1d1-0000-4000-8000-000000000001", TipHash: "d1" + repeat("00", 31)},
	}}
	longP2 := Checkpoint{PrevHash: cpHash(longP1), Seq: 2, Timestamp: "2026-06-01T00:00:05Z", Tips: []Tip{
		{EntryCount: 2, Epoch: ptr(0), SequenceNumber: 2, StreamID: "d2d2d2d2-0000-4000-8000-000000000002", TipHash: "d2" + repeat("00", 31)},
	}}
	longTail := Checkpoint{PrevHash: cpHash(longP2), Seq: 3, Timestamp: "2026-06-01T00:00:20Z", Tips: []Tip{
		{EntryCount: 3, Epoch: ptr(1), SequenceNumber: 3, StreamID: "d1d1d1d1-0000-4000-8000-000000000001", TipHash: "d3" + repeat("00", 31)},
	}}
	longCanon, err := canonical(longTail)
	if err != nil {
		panic(fmt.Sprintf("gen: three-checkpoint vector is malformed: %v", err))
	}
	longSum := sha256.Sum256(longCanon)
	suite.Vectors = append(suite.Vectors, Vector{
		Name:             "advisory_chain_b5_then_b4",
		Input:            longTail,
		Canonical:        string(longCanon),
		SHA256:           hex.EncodeToString(longSum[:]),
		Signature:        base64.StdEncoding.EncodeToString(ed25519.Sign(priv, longCanon)),
		Chain:            []SignedCheckpoint{signCP(priv, longP1), signCP(priv, longP2)},
		ExpectWarnings:   []string{"B5:2", "B4:d1d1d1d1-0000-4000-8000-000000000001"},
		MinFormatVersion: 2,
	})

	// Must-accept: a stream re-committed under an OLDER generation. This is the
	// most rollback-shaped case B4 exists to surface, and B3 does not cover it:
	// (s,5) and (s,3) are distinct identities. Every other epoch transition in
	// the suite increases, so without this a validator that warns only on an
	// epoch INCREASE passes everything.
	regPrefix := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-07-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 9, Epoch: ptr(5), SequenceNumber: 9, StreamID: "e5e5e5e5-0000-4000-8000-000000000005", TipHash: "e5" + repeat("00", 31)},
	}}
	regTail := Checkpoint{PrevHash: cpHash(regPrefix), Seq: 2, Timestamp: "2026-07-01T00:00:05Z", Tips: []Tip{
		{EntryCount: 4, Epoch: ptr(3), SequenceNumber: 4, StreamID: "e5e5e5e5-0000-4000-8000-000000000005", TipHash: "e3" + repeat("00", 31)},
	}}
	regCanon, err := canonical(regTail)
	if err != nil {
		panic(fmt.Sprintf("gen: epoch-regression vector is malformed: %v", err))
	}
	regSum := sha256.Sum256(regCanon)
	suite.Vectors = append(suite.Vectors, Vector{
		Name:             "advisory_epoch_regression",
		Input:            regTail,
		Canonical:        string(regCanon),
		SHA256:           hex.EncodeToString(regSum[:]),
		Signature:        base64.StdEncoding.EncodeToString(ed25519.Sign(priv, regCanon)),
		Chain:            []SignedCheckpoint{signCP(priv, regPrefix)},
		ExpectWarnings:   []string{"B4:e5e5e5e5-0000-4000-8000-000000000005"},
		MinFormatVersion: 2,
	})

	// A negative epoch. Go zero-pads the epoch into the sort key and Python
	// compares it as a tuple element: "-1" sorts above the digits in Go, while
	// -10 sorts below -1 in Python. The two implementations would order the
	// same tips differently, so the value is rejected outright. The offending
	// tip is again NOT first.
	negEpoch := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-03-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "77777777-7777-4777-8777-777777777777", TipHash: "7a" + repeat("00", 31)},
		{EntryCount: 2, Epoch: ptr(-1), SequenceNumber: 2, StreamID: "88888888-8888-4888-8888-888888888888", TipHash: "8a" + repeat("00", 31)},
	}}
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "negative_epoch", Expect: "schema",
		Reason:           "epoch must be non-negative; a negative value sorts differently in the two implementations, so it is rejected rather than ordered arbitrarily",
		Input:            negEpoch,
		Signature:        signCP(priv, negEpoch).Signature,
		MinFormatVersion: 2,
	})

	// ------------------------------------------------------------------
	// Positional coverage. Every vector above pins its rule at exactly ONE
	// chain position, so a validator that applies the rule only at that
	// position passes the whole suite. The vectors below put the defect in
	// the MIDDLE of a four-checkpoint chain, where "only the first" and
	// "only the last" both miss it, and one puts it on the FINAL link,
	// which no chain-carrying vector reached before.
	// ------------------------------------------------------------------

	// Must-accept over a THREE-prefix chain. It pins two things no other
	// vector can:
	//
	//   * The second prefix supplies its tips OUT of identity order. B2 hashes
	//     the previous checkpoint's CANONICAL bytes, so the link still holds;
	//     a validator that hashed the checkpoint as received (JCS with no tip
	//     sort) computes a different digest and rejects a legitimate chain.
	//     Every other chain prefix in the suite already has its tips in
	//     identity order, so nothing else could tell the two apart.
	//   * The timestamp regresses at the SECOND and the FINAL transition but
	//     not at the first, and each regressed value is still ABOVE chain[0]'s
	//     timestamp. A validator comparing against chain[0] instead of the
	//     immediate predecessor emits a spurious B5 for checkpoint 3, so the
	//     ordered warning list no longer matches.
	//
	// B4 likewise fires at the middle and the last transition and not at the
	// first, so a B4 pinned to i == 1 produces no tokens at all here.
	fs1 := "f1f1f1f1-0000-4000-8000-000000000001"
	fs2 := "f2f2f2f2-0000-4000-8000-000000000002"
	fs3 := "f3f3f3f3-0000-4000-8000-000000000003"
	posP1 := Checkpoint{Seq: 1, Timestamp: "2026-10-01T00:00:30Z", Tips: []Tip{
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: fs1, TipHash: "f1" + repeat("00", 31)},
	}}
	posP2 := Checkpoint{Seq: 2, Timestamp: "2026-10-01T00:00:10Z", Tips: []Tip{
		// Deliberately NOT in identity order: fs2 sorts before fs3.
		{EntryCount: 3, Epoch: ptr(0), SequenceNumber: 3, StreamID: fs3, TipHash: "f3" + repeat("00", 31)},
		{EntryCount: 2, Epoch: ptr(0), SequenceNumber: 2, StreamID: fs2, TipHash: "f2" + repeat("00", 31)},
	}}
	posP3 := Checkpoint{Seq: 3, Timestamp: "2026-10-01T00:00:25Z", Tips: []Tip{
		{EntryCount: 4, Epoch: ptr(1), SequenceNumber: 4, StreamID: fs1, TipHash: "f4" + repeat("00", 31)},
	}}
	posTail := Checkpoint{Seq: 4, Timestamp: "2026-10-01T00:00:20Z", Tips: []Tip{
		{EntryCount: 5, Epoch: ptr(1), SequenceNumber: 5, StreamID: fs2, TipHash: "f5" + repeat("00", 31)},
	}}
	posAll := linkCheckpoints([]Checkpoint{posP1, posP2, posP3, posTail})
	posCanon, err := canonical(posAll[3])
	if err != nil {
		panic(fmt.Sprintf("gen: positional advisory vector is malformed: %v", err))
	}
	posSum := sha256.Sum256(posCanon)
	suite.Vectors = append(suite.Vectors, Vector{
		Name:      "advisory_middle_chain_unsorted_prefix_tips",
		Input:     posAll[3],
		Canonical: string(posCanon),
		SHA256:    hex.EncodeToString(posSum[:]),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, posCanon)),
		Chain:     signAll(priv, posAll[:3]),
		// B5 at transition 1, B4 at transitions 2 and 3, B5 again at 3.
		ExpectWarnings:   []string{"B5:2", "B4:" + fs1, "B4:" + fs2, "B5:4"},
		MinFormatVersion: 2,
	})

	// The MIDDLE prefix's signature is tampered. tampered_prefix_signature
	// puts the defect on a chain's only prefix and
	// tampered_second_prefix_signature on its last, so a validator that
	// verifies only the last prefix passes both; this one it cannot.
	midSig := posChain("a1a1a1a1", 4)
	midSigChain := signAll(priv, midSig[:3])
	midSigRaw, err := base64.StdEncoding.DecodeString(midSigChain[1].Signature)
	if err != nil {
		panic(fmt.Sprintf("gen: middle prefix signature is not base64: %v", err))
	}
	midSigBad := append([]byte(nil), midSigRaw...)
	midSigBad[0] ^= 0x01
	midSigChain[1].Signature = base64.StdEncoding.EncodeToString(midSigBad)
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "tampered_middle_prefix_signature", Expect: "signature",
		Reason:           "one byte of the MIDDLE chain prefix's signature is flipped; a validator that verifies only the first or only the last prefix accepts this",
		Input:            midSig[3],
		Signature:        signCP(priv, midSig[3]).Signature,
		Chain:            midSigChain,
		MinFormatVersion: 2,
	})

	// The MIDDLE prefix omits epoch at version 2. chain_prefix_missing_epoch
	// puts the same defect on a two-prefix chain, where index 1 is also the
	// last index -- so a boundary check applied only to the last prefix passes
	// it. Here the last prefix is clean.
	midEpoch := posChain("a2a2a2a2", 4)
	midEpoch[1].Tips[0].Epoch = nil
	relinkFrom(midEpoch, 2)
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "middle_chain_prefix_missing_epoch", Expect: "schema",
		Reason:           "the MIDDLE version-2 chain prefix omits epoch on its tip; the boundary applies at every prefix index, not only the first or the last",
		Input:            midEpoch[3],
		Signature:        signCP(priv, midEpoch[3]).Signature,
		Chain:            signAll(priv, midEpoch[:3]),
		MinFormatVersion: 2,
	})

	// B2 broken at the MIDDLE transition. chain_prefix_broken_link breaks the
	// first transition, so B2 applied only at i == 1 still rejects it; the
	// first and last links here are both correct.
	midLink := posChain("a3a3a3a3", 4)
	midLink[2].PrevHash = "33" + repeat("33", 31)
	relinkFrom(midLink, 3)
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "middle_chain_link_broken", Expect: "tier_b",
		Reason:           "the third checkpoint's prev_hash does not equal the second's hash; B2 must hold at every transition, and here the first and last links are both correct",
		Input:            midLink[3],
		Signature:        signCP(priv, midLink[3]).Signature,
		Chain:            signAll(priv, midLink[:3]),
		MinFormatVersion: 2,
	})

	// B2 broken at the FINAL transition -- the vector's own link to its last
	// prefix. broken_chain covers a bad final link through the separate
	// prev_sha256 field and carries no chain, so nothing before this pinned B2
	// at the last transition of a chain that actually reaches checkTierB.
	lastLink := posChain("a4a4a4a4", 4)
	lastLink[3].PrevHash = "44" + repeat("44", 31)
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "final_chain_link_broken", Expect: "tier_b",
		Reason:           "the vector's own prev_hash does not equal its last prefix's hash; all three prefixes link correctly, so only a B2 applied at the FINAL transition rejects this",
		Input:            lastLink[3],
		Signature:        signCP(priv, lastLink[3]).Signature,
		Chain:            signAll(priv, lastLink[:3]),
		MinFormatVersion: 2,
	})

	// B1 broken at the MIDDLE transition only: 1, 2, 4, 5. seq_skip breaks the
	// first transition and seq_skip_after_first_transition the last, so this is
	// the position neither reaches.
	midSeq := posChain("a5a5a5a5", 4)
	midSeq[2].Seq = 4
	midSeq[3].Seq = 5
	relinkFrom(midSeq, 2)
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "seq_skip_at_middle_transition", Expect: "tier_b",
		Reason:           "checkpoint seq runs 1, 2, 4, 5: the gap is at the MIDDLE transition, while the first and last transitions are both contiguous",
		Input:            midSeq[3],
		Signature:        signCP(priv, midSeq[3]).Signature,
		Chain:            signAll(priv, midSeq[:3]),
		MinFormatVersion: 2,
	})

	// B3 violated BETWEEN two prefixes, with the vector's own input clean.
	// stream_recommitted_same_epoch duplicates chain[0] against the input, so a
	// validator that only compares the input against chain[0] rejects it; that
	// validator accepts this one.
	dupMid := posChain("a6a6a6a6", 4)
	dupMid[2].Tips[0].StreamID = dupMid[1].Tips[0].StreamID
	dupMid[2].Tips[0].TipHash = "d6" + repeat("00", 31)
	relinkFrom(dupMid, 2)
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "stream_recommitted_between_prefixes", Expect: "tier_b",
		Reason:           "the same (stream_id, epoch) is committed by the second and third chain prefixes; the vector's own input is clean, so only a B3 that spans the whole chain rejects this",
		Input:            dupMid[3],
		Signature:        signCP(priv, dupMid[3]).Signature,
		Chain:            signAll(priv, dupMid[:3]),
		MinFormatVersion: 2,
	})

	// ------------------------------------------------------------------
	// The cross-product. Chain index is only one factor of "position":
	//
	//   (chain index) x (tip index within a checkpoint)
	//                 x (prefix vs the vector's own checkpoint)
	//                 x (vector-list index in this file)
	//
	// The vectors below put the defect at a factor the chain-index vectors
	// above cannot reach. Several carry THREE tips supplied in reverse
	// identity order, so an "interior tip" exists at all -- before these, no
	// checkpoint that reached checkTierB had more than two tips, and no
	// published positive needed more than a single swap to sort.
	// ------------------------------------------------------------------

	c1, c2, c3 := "c1000000-0000-4000-8000-000000000001", "c2000000-0000-4000-8000-000000000002", "c3000000-0000-4000-8000-000000000003"
	b0, d9 := "b0000000-0000-4000-8000-000000000000", "d9000000-0000-4000-8000-000000000009"

	// Must-accept. chain[0] itself supplies its tips OUT of identity order:
	// advisory_middle_chain_unsorted_prefix_tips puts the unsorted prefix at
	// index 1, so a validator that hashes chain[0] as received and everything
	// else canonically passes it and fails this. Three tips in REVERSE order
	// also need a full sort rather than one adjacent swap. The tip whose epoch
	// changes is the identity-INTERIOR one of three, so a tip walk that
	// registers only the first and last tip emits no B4 at all.
	upP1 := Checkpoint{Seq: 1, Timestamp: "2026-11-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 3, Epoch: ptr(0), SequenceNumber: 3, StreamID: c3, TipHash: "c3" + repeat("00", 31)},
		{EntryCount: 2, Epoch: ptr(0), SequenceNumber: 2, StreamID: c2, TipHash: "c2" + repeat("00", 31)},
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: c1, TipHash: "c1" + repeat("00", 31)},
	}}
	upTail := Checkpoint{Seq: 2, Timestamp: "2026-11-01T00:00:05Z", Tips: []Tip{
		{EntryCount: 9, Epoch: ptr(0), SequenceNumber: 9, StreamID: d9, TipHash: "d9" + repeat("00", 31)},
		{EntryCount: 5, Epoch: ptr(1), SequenceNumber: 5, StreamID: c2, TipHash: "cc" + repeat("00", 31)},
		{EntryCount: 4, Epoch: ptr(0), SequenceNumber: 4, StreamID: b0, TipHash: "b0" + repeat("00", 31)},
	}}
	upAll := linkCheckpoints([]Checkpoint{upP1, upTail})
	upCanon, err := canonical(upAll[1])
	if err != nil {
		panic(fmt.Sprintf("gen: unsorted-first-prefix vector is malformed: %v", err))
	}
	upSum := sha256.Sum256(upCanon)
	suite.Vectors = append(suite.Vectors, Vector{
		Name:             "advisory_first_prefix_unsorted_tips",
		Input:            upAll[1],
		Canonical:        string(upCanon),
		SHA256:           hex.EncodeToString(upSum[:]),
		Signature:        base64.StdEncoding.EncodeToString(ed25519.Sign(priv, upCanon)),
		Chain:            signAll(priv, upAll[:1]),
		ExpectWarnings:   []string{"B4:" + c2},
		MinFormatVersion: 2,
	})

	// B3 violated by the identity-INTERIOR tip of a three-tip checkpoint,
	// against the identity-interior tip of a three-tip prefix. Every other B3
	// vector duplicates a checkpoint's only tip, so a tip walk that registers
	// just the first and last tip catches all of them and misses this.
	e1, e2, e3 := "e1000000-0000-4000-8000-000000000001", "e2000000-0000-4000-8000-000000000002", "e3000000-0000-4000-8000-000000000003"
	itP1 := Checkpoint{Seq: 1, Timestamp: "2026-11-02T00:00:00Z", Tips: []Tip{
		{EntryCount: 3, Epoch: ptr(0), SequenceNumber: 3, StreamID: e3, TipHash: "e3" + repeat("00", 31)},
		{EntryCount: 2, Epoch: ptr(0), SequenceNumber: 2, StreamID: e2, TipHash: "e2" + repeat("00", 31)},
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: e1, TipHash: "e1" + repeat("00", 31)},
	}}
	itTail := Checkpoint{Seq: 2, Timestamp: "2026-11-02T00:00:05Z", Tips: []Tip{
		{EntryCount: 9, Epoch: ptr(0), SequenceNumber: 9, StreamID: "f9000000-0000-4000-8000-000000000009", TipHash: "f9" + repeat("00", 31)},
		{EntryCount: 7, Epoch: ptr(0), SequenceNumber: 7, StreamID: e2, TipHash: "ee" + repeat("00", 31)},
		{EntryCount: 4, Epoch: ptr(0), SequenceNumber: 4, StreamID: "d0000000-0000-4000-8000-000000000000", TipHash: "d0" + repeat("00", 31)},
	}}
	itAll := linkCheckpoints([]Checkpoint{itP1, itTail})
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "interior_tip_recommitted_same_epoch", Expect: "tier_b",
		Reason:           "the identity-INTERIOR tip of a three-tip checkpoint re-commits a (stream_id, epoch) already committed by the interior tip of a three-tip prefix; a validator that inspects only a checkpoint's first and last tip accepts this",
		Input:            itAll[1],
		Signature:        signCP(priv, itAll[1]).Signature,
		Chain:            signAll(priv, itAll[:1]),
		MinFormatVersion: 2,
	})

	// The epoch boundary at an INTERIOR tip index. missing_epoch_in_v2 and
	// negative_epoch both put their defect on the LAST tip of two, so a check
	// that inspects only the last tip passes the whole suite.
	aa1, aa2, aa3 := "aa100000-0000-4000-8000-000000000001", "aa200000-0000-4000-8000-000000000002", "aa300000-0000-4000-8000-000000000003"
	noEpochMid := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-11-03T00:00:00Z", Tips: []Tip{
		{EntryCount: 3, Epoch: ptr(0), SequenceNumber: 3, StreamID: aa3, TipHash: "a3" + repeat("00", 31)},
		{EntryCount: 2, Epoch: nil, SequenceNumber: 2, StreamID: aa2, TipHash: "a2" + repeat("00", 31)},
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: aa1, TipHash: "a1" + repeat("00", 31)},
	}}
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "missing_epoch_interior_tip", Expect: "schema",
		Reason:           "the middle tip of three omits epoch at format_version 2; the boundary applies at every tip index, not only the first or the last",
		Input:            noEpochMid,
		Signature:        signCP(priv, noEpochMid).Signature,
		MinFormatVersion: 2,
	})

	// Same tip index, for the non-negativity guard -- and at magnitude -3
	// rather than -1, so a guard weakened to `< -1` is also caught.
	negEpochMid := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-11-03T00:00:05Z", Tips: []Tip{
		{EntryCount: 3, Epoch: ptr(0), SequenceNumber: 3, StreamID: aa3, TipHash: "b3" + repeat("00", 31)},
		{EntryCount: 2, Epoch: ptr(-3), SequenceNumber: 2, StreamID: aa2, TipHash: "b2" + repeat("00", 31)},
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: aa1, TipHash: "b1" + repeat("00", 31)},
	}}
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "negative_epoch_interior_tip", Expect: "schema",
		Reason:           "the middle tip of three carries epoch -3; the non-negativity guard applies at every tip index and at every magnitude, not only to the last tip at -1",
		Input:            negEpochMid,
		Signature:        signCP(priv, negEpochMid).Signature,
		MinFormatVersion: 2,
	})

	// The epoch boundary on a vector's OWN input while it carries a chain.
	// Every other epoch-boundary negative is chainless, and every chain-carrying
	// epoch negative puts the defect in a prefix, so a validator that checks the
	// own input only when there is no chain passes all of them. The defect is on
	// the FIRST tip, which is also the tip index the suite otherwise never uses.
	ccPrefix := Checkpoint{Seq: 1, Timestamp: "2026-11-04T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "ba000000-0000-4000-8000-000000000001", TipHash: "ba" + repeat("00", 31)},
	}}
	ccTail := Checkpoint{Seq: 2, Timestamp: "2026-11-04T00:00:05Z", Tips: []Tip{
		{EntryCount: 2, Epoch: nil, SequenceNumber: 2, StreamID: "bb000000-0000-4000-8000-000000000002", TipHash: "bb" + repeat("00", 31)},
		{EntryCount: 3, Epoch: ptr(0), SequenceNumber: 3, StreamID: "bc000000-0000-4000-8000-000000000003", TipHash: "bc" + repeat("00", 31)},
	}}
	ccAll := linkCheckpoints([]Checkpoint{ccPrefix, ccTail})
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "chain_carrier_missing_epoch", Expect: "schema",
		Reason:           "the vector's OWN first tip omits epoch while the vector carries a chain; the boundary applies to the vector's own input whether or not chain context is present",
		Input:            ccAll[1],
		Signature:        signCP(priv, ccAll[1]).Signature,
		Chain:            signAll(priv, ccAll[:1]),
		MinFormatVersion: 2,
	})

	// The chain prefixes are supplied in the WRONG ORDER. The chain array is
	// input, so its order is the producer's claim about history; a validator
	// that sorts the prefixes by seq before checking silently repairs a
	// reordered chain, and every other chain in the suite is already ordered.
	ooAll := posChain("a7a7a7a7", 3)
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "prefixes_out_of_order", Expect: "tier_b",
		Reason:           "the two chain prefixes are supplied newest-first; the chain array's order is the claim being verified, so it must be checked as given rather than sorted into shape",
		Input:            ooAll[2],
		Signature:        signCP(priv, ooAll[2]).Signature,
		Chain:            []SignedCheckpoint{signCP(priv, ooAll[1]), signCP(priv, ooAll[0])},
		MinFormatVersion: 2,
	})

	// A signature that is not valid base64 at all: one stray "!" spliced into
	// an otherwise valid 88-character encoding. Every other signature negative
	// carries well-formed base64 whose BYTES are wrong, so nothing in the
	// suite pinned the ENCODING. A decoder that skips characters outside the
	// base64 alphabet -- which is what Python's base64.b64decode does by
	// default -- recovers the original signature from this string and accepts
	// the vector, while Go's strict decoder rejects it. The stray character is
	// deliberately placed mid-string rather than at either end, where a
	// trailing-garbage check would find it.
	strayCP := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-11-05T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "5a000000-0000-4000-8000-000000000001", TipHash: "5a" + repeat("00", 31)},
	}}
	strayGood := signCP(priv, strayCP).Signature
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "signature_with_stray_character", Expect: "signature",
		Reason:           "the signature is not valid base64: a stray \"!\" is spliced into an otherwise valid encoding. A lenient decoder discards it, recovers the original signature and accepts the vector, so this separates a validator that rejects malformed base64 from one that silently repairs it",
		Input:            strayCP,
		Signature:        strayGood[:10] + "!" + strayGood[10:],
		MinFormatVersion: 2,
	})

	return suite
}

// checkTierB applies the cross-checkpoint rules to an ordered chain, returning
// a rejection error (B1, B3) and the advisory warnings raised (B4, B5).
// Warning tokens are stable, machine-comparable strings so the Go and Python
// validators can be checked for agreement rather than eyeballed.
//
// B2 (prev_hash linkage) is applied here rather than only via a vector's
// prev_sha256 field, because that field pins only the final link.
//
// Tier B applies only to chains whose checkpoints are all format_version 2 or
// above; mixed-version chains are out of scope and are never constructed here.
func checkTierB(chain []Checkpoint) (error, []string) {
	var warns []string
	seenIdentity := make(map[string]int)
	lastEpoch := make(map[string]int)
	for i, cp := range chain {
		if i > 0 {
			if cp.Seq != chain[i-1].Seq+1 {
				return fmt.Errorf("B1: checkpoint seq %d follows %d; must increment by exactly 1",
					cp.Seq, chain[i-1].Seq), warns
			}
			// B2 across the assembled chain. The vector-level prev_sha256 field
			// only pins the LAST link, so without this a chain whose prefixes do
			// not hash-link is accepted -- the linkage rule would be enforced
			// exactly where it does not matter.
			prevCanon, err := canonical(chain[i-1])
			if err != nil {
				return fmt.Errorf("B2: checkpoint %d: previous checkpoint is malformed: %v", cp.Seq, err), warns
			}
			sum := sha256.Sum256(prevCanon)
			if want := hex.EncodeToString(sum[:]); cp.PrevHash != want {
				return fmt.Errorf("B2: checkpoint %d prev_hash=%s does not link to checkpoint %d (%s)",
					cp.Seq, cp.PrevHash, chain[i-1].Seq, want), warns
			}
		}
		// Iterate tips in identity order, not input order. Warnings are
		// compared as ORDERED lists and a checkpoint's tips are explicitly
		// allowed to arrive unsorted, so when two streams each change epoch in
		// one checkpoint an input-order walk emits their B4 tokens in whatever
		// order the tips happened to be supplied -- two conformant validators
		// handed the same signed bytes could report different sequences.
		// (It does NOT change whether a later checkpoint warns: B3 rejects any
		// repeat of a (stream_id, epoch), so the next epoch differs from every
		// value lastEpoch could hold and B4 fires either way.)
		// advisory_two_streams_new_epoch is the vector that pins this.
		tips := make([]Tip, len(cp.Tips))
		copy(tips, cp.Tips)
		sort.Slice(tips, func(a, b int) bool { return tipIdentity(tips[a]) < tipIdentity(tips[b]) })
		for _, t := range tips {
			id := tipIdentity(t)
			if prevSeq, dup := seenIdentity[id]; dup {
				return fmt.Errorf("B3: stream %q epoch %d committed in checkpoint %d and again in %d",
					t.StreamID, tipEpoch(t), prevSeq, cp.Seq), warns
			}
			seenIdentity[id] = cp.Seq
			if prev, seen := lastEpoch[t.StreamID]; seen && tipEpoch(t) != prev {
				warns = append(warns, "B4:"+t.StreamID)
			}
			lastEpoch[t.StreamID] = tipEpoch(t)
		}
		// B5 is a plain string comparison: the pinned YYYY-MM-DDTHH:MM:SSZ
		// profile sorts chronologically, so no date parsing is needed.
		if i > 0 && cp.Timestamp < chain[i-1].Timestamp {
			warns = append(warns, fmt.Sprintf("B5:%d", cp.Seq))
		}
	}
	return nil, warns
}

// checkEpochPresence enforces the format_version boundary from spec 5a:
// epoch is required on every tip at version 2 and above, and must be absent in
// version 1 vectors. Without this the absent-vs-zero distinction is unenforced
// spec text, and a version-2 tip missing epoch would silently validate as 0.
func checkEpochPresence(cp Checkpoint, minVer int) error {
	for _, t := range cp.Tips {
		if minVer >= 2 && t.Epoch == nil {
			return fmt.Errorf("stream %q: epoch is required at format_version >= 2", t.StreamID)
		}
		if minVer < 2 && t.Epoch != nil {
			return fmt.Errorf("stream %q: epoch is not permitted in a format_version 1 vector", t.StreamID)
		}
		// Epoch must be non-negative. tipIdentity zero-pads it into a sort key,
		// and a leading "-" sorts above the digits in Go while Python's tuple
		// compare puts -10 below -1: the two implementations would order the
		// same tips differently, which is precisely what this repo exists to
		// rule out. A conformant producer never emits one, but a third party
		// feeding its own data must be told, not silently mis-sorted.
		if t.Epoch != nil && *t.Epoch < 0 {
			return fmt.Errorf("stream %q: epoch must be non-negative, got %d", t.StreamID, *t.Epoch)
		}
	}
	return nil
}

// verifyPrefixes checks a vector's preceding chain context and returns the
// prefix checkpoints in order, or the reason they are rejected ("" on success).
//
// Each prefix is held to the same bar as the vector's own input: the
// format_version epoch boundary AND a real signature verification. The
// signature check is the MUST documented on SignedCheckpoint -- a verifier that
// merely hashed prefixes for linkage would accept a forged history. Shared by
// the positive and negative paths so the rule cannot drift between them.
func verifyPrefixes(pub ed25519.PublicKey, chain []SignedCheckpoint, minVer int) ([]Checkpoint, string) {
	full := make([]Checkpoint, 0, len(chain)+1)
	for _, sc := range chain {
		if err := checkEpochPresence(sc.Input, minVer); err != nil {
			return nil, "schema"
		}
		cb, err := canonical(sc.Input)
		if err != nil {
			return nil, "canonical"
		}
		sig, err := base64.StdEncoding.DecodeString(sc.Signature)
		if err != nil || !ed25519.Verify(pub, cb, sig) {
			return nil, "signature"
		}
		full = append(full, sc.Input)
	}
	return full, ""
}

// rejectReason returns the check that rejects a negative vector, or "" if the
// vector is (wrongly) accepted.
func rejectReason(pub ed25519.PublicKey, nv NegativeVector) string {
	if err := checkEpochPresence(nv.Input, nv.MinFormatVersion); err != nil {
		return "schema"
	}
	cb, err := canonical(nv.Input)
	if err != nil {
		return "canonical"
	}
	sig, err := base64.StdEncoding.DecodeString(nv.Signature)
	if err != nil || !ed25519.Verify(pub, cb, sig) {
		return "signature"
	}
	if len(nv.Chain) > 0 {
		full, reason := verifyPrefixes(pub, nv.Chain, nv.MinFormatVersion)
		if reason != "" {
			return reason
		}
		full = append(full, nv.Input)
		if err, _ := checkTierB(full); err != nil {
			return "tier_b"
		}
	}
	if nv.PrevSHA256 != "" && nv.Input.PrevHash != nv.PrevSHA256 {
		return "chain"
	}
	return ""
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func validate(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var suite Suite
	if err := json.Unmarshal(data, &suite); err != nil {
		return err
	}
	if suite.FormatVersion > supportedFormatVersion {
		fmt.Printf("  note: suite format_version=%d exceeds supported=%d; unsupported vectors will be skipped\n",
			suite.FormatVersion, supportedFormatVersion)
	}
	pub, err := hex.DecodeString(suite.PublicKeyHex)
	if err != nil {
		return err
	}
	// How many entries MUST be checked, computed in a pre-pass that is
	// textually separate from the loops that do the checking. The rules cannot
	// fix a harness that silently skips vectors: a loop truncated to its first
	// entry, or a Tier B block that runs only for the first chain-carrying
	// vector, leaves every rule intact and every gate green. Counting what was
	// actually reached and comparing it here is the only instrument that sees
	// that class.
	wantPositives, wantTierB, wantNegatives := 0, 0, 0
	for _, v := range suite.Vectors {
		if skipVector(v.MinFormatVersion, supportedFormatVersion) {
			continue
		}
		wantPositives++
		if len(v.Chain) != 0 || len(v.ExpectWarnings) != 0 {
			wantTierB++
		}
	}
	for _, nv := range suite.Negatives {
		if !skipVector(nv.MinFormatVersion, supportedFormatVersion) {
			wantNegatives++
		}
	}
	gotPositives, gotTierB, gotNegatives := 0, 0, 0

	prevExpected := ""
	for i, v := range suite.Vectors {
		if skipVector(v.MinFormatVersion, supportedFormatVersion) {
			fmt.Printf("  skip %-34s requires format_version %d\n", v.Name, v.MinFormatVersion)
			prevExpected = ""
			continue
		}
		if err := checkEpochPresence(v.Input, v.MinFormatVersion); err != nil {
			return fmt.Errorf("[%s] %v", v.Name, err)
		}
		cb, err := canonical(v.Input)
		if err != nil {
			return err
		}
		if string(cb) != v.Canonical {
			return fmt.Errorf("[%s] canonical mismatch:\n got:  %s\n want: %s", v.Name, cb, v.Canonical)
		}
		sum := sha256.Sum256(cb)
		if hex.EncodeToString(sum[:]) != v.SHA256 {
			return fmt.Errorf("[%s] sha256 mismatch", v.Name)
		}
		sig, err := base64.StdEncoding.DecodeString(v.Signature)
		if err != nil {
			return err
		}
		if !ed25519.Verify(pub, cb, sig) {
			return fmt.Errorf("[%s] signature does not verify", v.Name)
		}
		if len(v.Chain) > 0 || len(v.ExpectWarnings) > 0 {
			// A must-accept vector's prefixes are verified exactly as a
			// negative's are: same helper, same MUST.
			full, reason := verifyPrefixes(pub, v.Chain, v.MinFormatVersion)
			if reason != "" {
				return fmt.Errorf("[%s] must be accepted, but its chain context was rejected (%s)", v.Name, reason)
			}
			full = append(full, v.Input)
			err, warns := checkTierB(full)
			if err != nil {
				return fmt.Errorf("[%s] must be accepted, but Tier B rejected it: %v", v.Name, err)
			}
			// slices.Equal, not a joined string: joining conflates the single
			// warning ["A,B"] with the pair ["A","B"].
			if !slices.Equal(warns, v.ExpectWarnings) {
				return fmt.Errorf("[%s] warnings %v, want %v", v.Name, warns, v.ExpectWarnings)
			}
			gotTierB++
		}
		// A vector carrying its own chain context is not part of the
		// positives' own hash chain, so prevExpected does not apply to it.
		if i > 0 && prevExpected != "" && len(v.Chain) == 0 && v.Input.PrevHash != prevExpected {
			return fmt.Errorf("[%s] chain break: prev_hash=%s expected=%s", v.Name, v.Input.PrevHash, prevExpected)
		}
		if len(v.Chain) == 0 {
			// Only vectors in the positives' own hash chain advance it; a
			// chain-carrying vector must not become the next one's expected
			// predecessor.
			prevExpected = v.SHA256
		}
		gotPositives++
		fmt.Printf("  ok  %-34s sha256=%s…\n", v.Name, v.SHA256[:16])
	}

	// Negative vectors: each MUST be rejected, for the stated reason.
	for _, nv := range suite.Negatives {
		if skipVector(nv.MinFormatVersion, supportedFormatVersion) {
			fmt.Printf("  skip %-34s requires format_version %d\n", nv.Name, nv.MinFormatVersion)
			continue
		}
		got := rejectReason(pub, nv)
		if got == "" {
			return fmt.Errorf("[%s] accepted, but must be rejected (%s)", nv.Name, nv.Expect)
		}
		if got != nv.Expect {
			return fmt.Errorf("[%s] rejected for %q, expected %q", nv.Name, got, nv.Expect)
		}
		gotNegatives++
		fmt.Printf("  ok  %-34s rejected (%s)\n", nv.Name, got)
	}

	if gotPositives != wantPositives {
		return fmt.Errorf("harness: validated %d of %d positive vectors", gotPositives, wantPositives)
	}
	if gotTierB != wantTierB {
		return fmt.Errorf("harness: ran the cross-checkpoint block for %d of %d chain-carrying positive vectors", gotTierB, wantTierB)
	}
	if gotNegatives != wantNegatives {
		return fmt.Errorf("harness: checked %d of %d negative vectors", gotNegatives, wantNegatives)
	}
	fmt.Printf("  checked: %d positive (%d through Tier B) + %d negative\n", gotPositives, gotTierB, gotNegatives)
	fmt.Printf("PASS: %d positive + %d negative vectors, all as expected\n", gotPositives, gotNegatives)
	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: go run . [gen|validate] <path>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "gen":
		suite := gen()
		out, _ := json.MarshalIndent(suite, "", "  ")
		if err := os.WriteFile(os.Args[2], append(out, '\n'), 0o644); err != nil {
			panic(err)
		}
		fmt.Printf("wrote %d vectors to %s\n", len(suite.Vectors), os.Args[2])
	case "validate":
		if err := validate(os.Args[2]); err != nil {
			fmt.Println("FAIL:", err)
			os.Exit(1)
		}
	default:
		fmt.Println("unknown command:", os.Args[1])
		os.Exit(2)
	}
}
