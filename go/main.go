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

	"github.com/gowebpki/jcs"
)

// sha256Empty is the canonical genesis prev_hash (SHA-256 of the empty string).
const sha256Empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// supportedFormatVersion is the highest suite format this build understands.
// Vectors carrying a higher min_format_version are skipped, not failed.
const supportedFormatVersion = 1

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
	SequenceNumber int    `json:"sequence_number"`
	StreamID       string `json:"stream_id"`
	TipHash        string `json:"tip_hash"`
}

type Checkpoint struct {
	PrevHash  string `json:"prev_hash"`
	Seq       int    `json:"seq"`
	Timestamp string `json:"timestamp"`
	Tips      []Tip  `json:"tips"`
}

// tipIdentity is the uniqueness and sort key for a tip. Task 3 widens this to
// include epoch; nothing else needs to change when it does.
func tipIdentity(t Tip) string {
	return t.StreamID
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

type Vector struct {
	Name             string     `json:"name"`
	Input            Checkpoint `json:"input"`
	Canonical        string     `json:"canonical"`
	SHA256           string     `json:"sha256"`
	Signature        string     `json:"signature"`
	MinFormatVersion int        `json:"min_format_version,omitempty"`
}

// NegativeVector is a case a conformant validator MUST reject. Expect names the
// check that should catch it ("signature" or "chain"). PrevSHA256, when set, is
// the hash the input's prev_hash is expected to chain to.
type NegativeVector struct {
	Name             string     `json:"name"`
	Expect           string     `json:"expect"`
	Reason           string     `json:"reason"`
	Input            Checkpoint `json:"input"`
	Signature        string     `json:"signature"`
	PrevSHA256       string     `json:"prev_sha256,omitempty"`
	MinFormatVersion int        `json:"min_format_version,omitempty"`
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
		Reason:     "signature is valid, but prev_hash does not equal the previous checkpoint's hash",
		Input:      bc, Signature: base64.StdEncoding.EncodeToString(bcSig),
		PrevSHA256: sha256Empty,
	})

	// 4. Two tips with the same identity: canonical bytes would depend on
	// input order, so the checkpoint is rejected before any signature check.
	dup := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-02-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 7, SequenceNumber: 7, StreamID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", TipHash: "aa" + repeat("00", 31)},
		{EntryCount: 5, SequenceNumber: 5, StreamID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", TipHash: "bb" + repeat("00", 31)},
	}}
	suite.Negatives = append(suite.Negatives, NegativeVector{
		Name: "duplicate_tip_identity", Expect: "canonical",
		Reason: "two tips share an identity, so the canonical bytes would depend on input order",
		Input:  dup, Signature: "",
	})

	return suite
}

// rejectReason returns the check that rejects a negative vector, or "" if the
// vector is (wrongly) accepted.
func rejectReason(pub ed25519.PublicKey, nv NegativeVector) string {
	cb, err := canonical(nv.Input)
	if err != nil {
		return "canonical"
	}
	sig, err := base64.StdEncoding.DecodeString(nv.Signature)
	if err != nil || !ed25519.Verify(pub, cb, sig) {
		return "signature"
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
		if i > 0 && prevExpected != "" && v.Input.PrevHash != prevExpected {
			return fmt.Errorf("[%s] chain break: prev_hash=%s expected=%s", v.Name, v.Input.PrevHash, prevExpected)
		}
		prevExpected = v.SHA256
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
