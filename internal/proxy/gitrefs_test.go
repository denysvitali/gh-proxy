package proxy

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// pktLen encodes the 4-hex-digit pkt-line length prefix for n bytes of
// payload (so total packet is 4 + n).
func pktLen(n int) string {
	const hex = "0123456789abcdef"
	s := [4]byte{hex[(n+4)>>12&0xF], hex[(n+4)>>8&0xF], hex[(n+4)>>4&0xF], hex[(n+4)&0xF]}
	return string(s[:])
}

func TestParseReceivePackHappyPath(t *testing.T) {
	// Two push lines followed by a flush. The parser should collect
	// both refnames before terminating on the flush packet.
	//   <old> <new> <refname>\0capability\n
	push1Line := pktLen(len("old1 new1 refs/heads/main\x00report-status\n")) +
		"old1 new1 refs/heads/main\x00report-status\n"
	push2Line := pktLen(len("old2 new2 refs/heads/feature/x\x00\n")) +
		"old2 new2 refs/heads/feature/x\x00\n"
	flush := "0000"

	body := push1Line + push2Line + flush

	refs, err := ParseReceivePackRefs(bytes.NewReader([]byte(body)), int64(len(body)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("got %d refs, want 2: %+v", len(refs), refs)
	}
	if refs[0] != "refs/heads/main" || refs[1] != "refs/heads/feature/x" {
		t.Fatalf("unexpected refs: %+v", refs)
	}
}

func TestParseReceivePackEmptyBody(t *testing.T) {
	refs, err := ParseReceivePackRefs(bytes.NewReader(nil), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("expected 0 refs, got %+v", refs)
	}
}

func TestParseReceivePackFlushOnly(t *testing.T) {
	body := "0000"
	refs, err := ParseReceivePackRefs(bytes.NewReader([]byte(body)), int64(len(body)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("expected 0 refs, got %+v", refs)
	}
}

func TestParseReceivePackBadHex(t *testing.T) {
	// "ZZZZ" is not valid hex.
	body := "ZZZZabcdef"
	_, err := ParseReceivePackRefs(bytes.NewReader([]byte(body)), int64(len(body)))
	if !errors.Is(err, errInvalidPktLine) {
		t.Fatalf("expected errInvalidPktLine, got %v", err)
	}
}

func TestParseReceivePackLengthMismatch(t *testing.T) {
	// pkt-line claims 1 byte of payload ("0005" = 5 total, 1 payload)
	// but the body ends immediately after the length prefix.
	body := "0005"
	_, err := ParseReceivePackRefs(bytes.NewReader([]byte(body)), int64(len(body)))
	if !errors.Is(err, errInvalidPktLine) {
		t.Fatalf("expected errInvalidPktLine, got %v", err)
	}
}

func TestParseReceivePackSkipDelim(t *testing.T) {
	// A "delim" packet (0001) is part of v2 — we should treat it like a
	// flush and keep scanning for real ref-update lines.
	pushLine := pktLen(len("aaa bbb refs/heads/dev\x00\n")) +
		"aaa bbb refs/heads/dev\x00\n"
	body := "0001" + pushLine
	refs, err := ParseReceivePackRefs(bytes.NewReader([]byte(body)), int64(len(body)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 1 || refs[0] != "refs/heads/dev" {
		t.Fatalf("got %+v", refs)
	}
}

func TestParseReceivePackMixedValidInvalid(t *testing.T) {
	// A valid push line followed by a corrupted line. The parser should
	// either return what it had so far OR an error — but it must NOT
	// silently swallow a syntax error and keep going. We choose to
	// return errInvalidPktLine so the caller can fall back to allow.
	pushLine := pktLen(len("a b refs/heads/main\x00\n")) + "a b refs/heads/main\x00\n"
	body := pushLine + "0003xy" // length says 3 bytes but only 2 follow
	_, err := ParseReceivePackRefs(bytes.NewReader([]byte(body)), int64(len(body)))
	if !errors.Is(err, errInvalidPktLine) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestParseReceivePackTooLarge(t *testing.T) {
	pushLine := pktLen(len("a b refs/heads/main\x00\n")) + "a b refs/heads/main\x00\n"
	// The body is small, but the configured cap is 0 → "no bytes allowed".
	_, err := ParseReceivePackRefs(bytes.NewReader([]byte(pushLine)), 0)
	if !errors.Is(err, errBodyTooLarge) {
		t.Fatalf("expected errBodyTooLarge, got %v", err)
	}
}

func TestMatchRef(t *testing.T) {
	cases := []struct {
		pat, ref string
		want     bool
	}{
		{"refs/heads/feature/*", "refs/heads/feature/foo", true},
		{"refs/heads/feature/*", "refs/heads/feature/foo/bar", false},
		{"refs/heads/feature/*", "refs/heads/main", false},
		{"refs/heads/main", "refs/heads/main", true},
		{"refs/heads/*", "refs/heads/feature/x", false},
		{"refs/tags/v*", "refs/tags/v1.2.3", true},
		{"refs/tags/v*", "refs/tags/release/v1", false},
	}
	for _, c := range cases {
		if got := matchRef(c.pat, c.ref); got != c.want {
			t.Errorf("matchRef(%q, %q) = %v, want %v", c.pat, c.ref, got, c.want)
		}
	}
}

func TestFilterPushRefs(t *testing.T) {
	allow := []string{"refs/heads/feature/*", "refs/heads/fix/*"}
	deny := []string{"refs/heads/wip/*"}
	protected := []string{"master", "main"}

	cases := []struct {
		ref  string
		want bool // want allowed
	}{
		{"refs/heads/feature/x", true},
		{"refs/heads/fix/y", true},
		{"refs/heads/wip/x", false},   // denied
		{"refs/heads/master", false},  // protected
		{"refs/heads/main", false},    // protected
		{"refs/tags/v1", false},       // not in allow list
		{"refs/heads/feature", false}, // not in allow (no segment after feature/)
	}
	for _, c := range cases {
		if got := filterRef(allow, deny, protected, c.ref); got != c.want {
			t.Errorf("filterRef(%q) = %v, want %v", c.ref, got, c.want)
		}
	}
}
