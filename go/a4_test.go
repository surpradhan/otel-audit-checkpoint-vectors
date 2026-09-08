package main

import (
	"encoding/hex"
	"testing"
)

// checkEncoding is the raw-bytes pre-parse step A4 requires (spec §7). These
// tests pin the two properties the spec calls out by name: an escaped
// backslash followed by literal "u..." text is not a \u escape at all, and
// the four hex digits after a real \u escape are case-insensitive, the same
// way strconv.ParseUint already treats them. Mirrors
// py/test_validate.py's test_check_encoding_* functions.

func TestCheckEncodingAcceptsOrdinaryText(t *testing.T) {
	if reason := checkEncoding([]byte(`{"stream_id":"plain ascii, no escapes"}`)); reason != "" {
		t.Errorf("ordinary text was rejected: %q", reason)
	}
}

func TestCheckEncodingRejectsInvalidUTF8(t *testing.T) {
	raw := append([]byte(`{"stream_id":"`), 0xff)
	raw = append(raw, []byte(`"}`)...)
	if reason := checkEncoding(raw); reason != "encoding" {
		t.Errorf("invalid UTF-8 byte: reason = %q, want \"encoding\"", reason)
	}
}

func TestCheckEncodingRejectsLoneHighSurrogate(t *testing.T) {
	// \ud800 with nothing pairing it: no following escape at all.
	if reason := checkEncoding([]byte(`{"stream_id":"\ud800"}`)); reason != "encoding" {
		t.Errorf("lone high surrogate: reason = %q, want \"encoding\"", reason)
	}
	// \ud800 followed by an ordinary (non-surrogate) escape, not a low surrogate.
	if reason := checkEncoding([]byte(`{"stream_id":"\ud800A"}`)); reason != "encoding" {
		t.Errorf("high surrogate followed by non-surrogate escape: reason = %q, want \"encoding\"", reason)
	}
	// \ud800 followed by another HIGH surrogate, not a low one: still not a pair.
	if reason := checkEncoding([]byte(`{"stream_id":"\ud800\ud801"}`)); reason != "encoding" {
		t.Errorf("high surrogate followed by another high surrogate: reason = %q, want \"encoding\"", reason)
	}
}

func TestCheckEncodingRejectsLoneLowSurrogate(t *testing.T) {
	// \udc00 with nothing preceding it to pair with -- the loop only ever
	// consumes a low surrogate as part of a pair started by a high one, so
	// reaching one on its own means nothing claimed it.
	if reason := checkEncoding([]byte(`{"stream_id":"\udc00"}`)); reason != "encoding" {
		t.Errorf("lone low surrogate: reason = %q, want \"encoding\"", reason)
	}
}

func TestCheckEncodingAcceptsValidSurrogatePair(t *testing.T) {
	// 😀 is U+1F600 correctly encoded as a high/low pair.
	if reason := checkEncoding([]byte(`{"stream_id":"\ud83d\ude00"}`)); reason != "" {
		t.Errorf("valid surrogate pair (as an escape sequence) was rejected: %q", reason)
	}
}

func TestCheckEncodingAcceptsOrdinaryEscape(t *testing.T) {
	// A is 'A', nowhere near the surrogate range -- must not be treated
	// as one just because it starts with \u.
	if reason := checkEncoding([]byte(`{"stream_id":"A"}`)); reason != "" {
		t.Errorf("an ordinary (non-surrogate) \\u escape was rejected: %q", reason)
	}
}

// TestCheckEncodingDistinguishesEscapedBackslashFromRealEscape pins spec §7's
// own example: "an escaped backslash followed by ud800 is not an escape."
// `\\ud800` in raw JSON text is an escaped backslash (`\\`, one literal `\`
// character) followed by the four plain characters `u`, `d`, `8`, `0`, `0` --
// NOT a `\u` escape sequence, because the backslash that would have started
// it was already consumed pairing with the backslash before it. A scanner
// that merely searched for the substring "\u" without tracking escape
// pairing would misfire on this and reject text that is not a surrogate
// escape at all.
func TestCheckEncodingDistinguishesEscapedBackslashFromRealEscape(t *testing.T) {
	// Raw text: "\\ud800" -- an escaped backslash, then literal "ud800".
	if reason := checkEncoding([]byte(`{"stream_id":"\\ud800"}`)); reason != "" {
		t.Errorf(`an escaped backslash followed by literal "ud800" was rejected: %q`, reason)
	}
	// Contrast: one MORE backslash and it IS a real escape again -- three
	// backslashes is an escaped backslash followed by the start of a real
	// \u escape, which must still be caught as a lone surrogate.
	if reason := checkEncoding([]byte(`{"stream_id":"\\\ud800"}`)); reason != "encoding" {
		t.Errorf(`escaped backslash followed by a real lone-surrogate escape was accepted: %q`, reason)
	}
}

// TestCheckEncodingIsCaseInsensitiveForSurrogateHexDigits pins spec §7's
// "case variants": \uD800 (uppercase hex digits) is the same surrogate as
// \ud800, and a validator that only matched the lowercase form would miss
// it.
func TestCheckEncodingIsCaseInsensitiveForSurrogateHexDigits(t *testing.T) {
	if reason := checkEncoding([]byte(`{"stream_id":"\uD800"}`)); reason != "encoding" {
		t.Errorf("uppercase lone high surrogate \\uD800: reason = %q, want \"encoding\"", reason)
	}
	if reason := checkEncoding([]byte(`{"stream_id":"\uDC00"}`)); reason != "encoding" {
		t.Errorf("uppercase lone low surrogate \\uDC00: reason = %q, want \"encoding\"", reason)
	}
	// A valid pair in uppercase, and one mixed-case, must both still be accepted.
	if reason := checkEncoding([]byte(`{"stream_id":"\uD83D\uDE00"}`)); reason != "" {
		t.Errorf("uppercase valid surrogate pair was rejected: %q", reason)
	}
	if reason := checkEncoding([]byte(`{"stream_id":"\uD83d\udE00"}`)); reason != "" {
		t.Errorf("mixed-case valid surrogate pair was rejected: %q", reason)
	}
}

func TestCheckEncodingRejectsTruncatedEscape(t *testing.T) {
	for _, raw := range []string{
		`{"stream_id":"\`,        // backslash with nothing after it
		`{"stream_id":"\u12`,     // \u with fewer than 4 hex digits before EOF
		`{"stream_id":"\uZZZZ"}`, // \u followed by non-hex characters
	} {
		if reason := checkEncoding([]byte(raw)); reason != "encoding" {
			t.Errorf("truncated/malformed escape %q: reason = %q, want \"encoding\"", raw, reason)
		}
	}
}

// TestCheckEncodingRejectsPermissiveHexDigitVariants pins that strconv.ParseUint's
// own strictness for the \uXXXX window rejects everything a more permissive
// numeric parser might accept -- a sign, an underscore digit-group separator,
// a 0x prefix, or embedded whitespace. Found in review: Python's stdlib
// int(x, 16) is a permissive superset of what this accepts here, so the
// Python reference needed an explicit strict-hex-digit gate (_hex4_value) to
// match; this pins the Go side already had the tighter behavior by
// construction, not by accident.
func TestCheckEncodingRejectsPermissiveHexDigitVariants(t *testing.T) {
	for _, raw := range []string{
		`{"stream_id":"\u+800"}`, // leading sign
		`{"stream_id":"\uD_00"}`, // digit-group separator
		`{"stream_id":"\u-800"}`, // leading sign
		`{"stream_id":"\u 800"}`, // embedded whitespace
		`{"stream_id":"\u0x12"}`, // 0x prefix -- 'x' is not a hex digit at any position
	} {
		if reason := checkEncoding([]byte(raw)); reason != "encoding" {
			t.Errorf("permissive-parser-only hex variant %q: reason = %q, want \"encoding\"", raw, reason)
		}
	}
}

// resolveInput is what actually wires checkEncoding into the pipeline; these
// tests exercise it directly rather than only through a published vector.
func TestResolveInputPassesThroughWhenNoRawHex(t *testing.T) {
	cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{}}
	got, reason := resolveInput(cp, "")
	if reason != "" {
		t.Fatalf("reason = %q, want \"\"", reason)
	}
	if got.Seq != 1 || got.Timestamp != "2026-01-01T00:00:00Z" {
		t.Errorf("resolveInput did not pass Input through unchanged: %+v", got)
	}
}

func TestResolveInputRejectsInvalidHex(t *testing.T) {
	_, reason := resolveInput(Checkpoint{}, "not valid hex!!")
	if reason != "schema" {
		t.Errorf("invalid hex: reason = %q, want \"schema\"", reason)
	}
}

// TestResolveInputRejectsWhitespaceInOtherwiseValidHex pins a real
// accept/reject divergence found in review: Python's stdlib bytes.fromhex()
// silently ignores embedded whitespace, which encoding/hex.DecodeString
// (used here) does not -- proven against the actual committed
// valid_surrogate_pair vector's own input_raw_hex with one space spliced in:
// this rejects it as "schema", while the pre-fix Python reference decoded
// it to byte-identical content and accepted it. This test uses a
// synthetic (not the real vector's) hex string so it stays meaningful even
// if valid_surrogate_pair's own bytes ever change.
func TestResolveInputRejectsWhitespaceInOtherwiseValidHex(t *testing.T) {
	raw := []byte(`{"prev_hash":"` + sha256Empty + `","seq":1,"timestamp":"2026-01-01T00:00:00Z","tips":[]}`)
	clean := hex.EncodeToString(raw)
	spaced := clean[:10] + " " + clean[10:]
	if _, reason := resolveInput(Checkpoint{}, clean); reason != "" {
		t.Fatalf("clean hex: reason = %q, want \"\" (test setup is broken)", reason)
	}
	if _, reason := resolveInput(Checkpoint{}, spaced); reason != "schema" {
		t.Errorf("hex with one embedded space: reason = %q, want \"schema\"", reason)
	}
}

func TestResolveInputRejectsEncodingFailureBeforeParsing(t *testing.T) {
	raw := []byte(`{"prev_hash":"` + sha256Empty + `","seq":1,"timestamp":"2026-01-01T00:00:00Z","tips":[{"entry_count":1,"epoch":0,"sequence_number":1,"stream_id":"\ud800","tip_hash":"aa"}]}`)
	_, reason := resolveInput(Checkpoint{}, hex.EncodeToString(raw))
	if reason != "encoding" {
		t.Errorf("reason = %q, want \"encoding\"", reason)
	}
}

func TestResolveInputParsesValidRawHex(t *testing.T) {
	raw := []byte(`{"prev_hash":"` + sha256Empty + `","seq":1,"timestamp":"2026-01-01T00:00:00Z","tips":[]}`)
	got, reason := resolveInput(Checkpoint{}, hex.EncodeToString(raw))
	if reason != "" {
		t.Fatalf("reason = %q, want \"\"", reason)
	}
	if got.Seq != 1 || got.PrevHash != sha256Empty {
		t.Errorf("resolveInput did not correctly parse raw hex: %+v", got)
	}
}
