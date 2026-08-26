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
	"sort"
	"strings"

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
	suite.FormatVersion = 2
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
	noEpoch := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-03-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: nil, SequenceNumber: 1, StreamID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", TipHash: "cc" + repeat("00", 31)},
	}}
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "missing_epoch_in_v2", Expect: "schema",
		Reason:           "epoch is required on every tip at format_version 2 and above",
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

	return suite
}

// checkTierB applies the cross-checkpoint rules to an ordered chain, returning
// a rejection error (B1, B3) and the advisory warnings raised (B4, B5).
// Warning tokens are stable, machine-comparable strings so the Go and Python
// validators can be checked for agreement rather than eyeballed.
//
// Tier B applies only to chains whose checkpoints are all format_version 2 or
// above; mixed-version chains are out of scope and are never constructed here.
func checkTierB(chain []Checkpoint) (error, []string) {
	var warns []string
	seenIdentity := make(map[string]int)
	lastEpoch := make(map[string]int)
	for i, cp := range chain {
		if i > 0 && cp.Seq != chain[i-1].Seq+1 {
			return fmt.Errorf("B1: checkpoint seq %d follows %d; must increment by exactly 1",
				cp.Seq, chain[i-1].Seq), warns
		}
		for _, t := range cp.Tips {
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
	}
	return nil
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
		full := make([]Checkpoint, 0, len(nv.Chain)+1)
		for _, sc := range nv.Chain {
			cb, err := canonical(sc.Input)
			if err != nil {
				return "canonical"
			}
			s, err := base64.StdEncoding.DecodeString(sc.Signature)
			if err != nil || !ed25519.Verify(pub, cb, s) {
				return "signature"
			}
			full = append(full, sc.Input)
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
			full := make([]Checkpoint, 0, len(v.Chain)+1)
			for _, sc := range v.Chain {
				full = append(full, sc.Input)
			}
			full = append(full, v.Input)
			err, warns := checkTierB(full)
			if err != nil {
				return fmt.Errorf("[%s] must be accepted, but Tier B rejected it: %v", v.Name, err)
			}
			if strings.Join(warns, ",") != strings.Join(v.ExpectWarnings, ",") {
				return fmt.Errorf("[%s] warnings %v, want %v", v.Name, warns, v.ExpectWarnings)
			}
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
		fmt.Printf("  ok  %-34s rejected (%s)\n", nv.Name, got)
	}

	fmt.Printf("PASS: %d positive + %d negative vectors, all as expected\n", len(suite.Vectors), len(suite.Negatives))
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
