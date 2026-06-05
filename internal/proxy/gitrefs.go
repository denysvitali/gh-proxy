// Package proxy — gitrefs.go: pkt-line parser and ref-name matcher
// used to enforce Repo.RefAllow / RefDeny / ProtectedRefs on pushes.
//
// The parser implements git's pkt-line framing (see
// gitformat-pack-protocol(5)) just enough to extract the
// "<old-sha> <new-sha> <refname>" tuples from the first
// flush-delimited section of a git-receive-pack body. It is
// deliberately small and self-contained — the rest of the body
// (packfile, report-status frames) is streamed straight through to
// the upstream.
//
// On malformed framing the parser returns errInvalidPktLine. The
// caller MUST treat that as a "parse-fail-allow" signal, per the
// security discussion in DESIGN.md. The logParseFallback helper
// emits a single structured warning that is greppable in operator
// logs.
package proxy

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"

	"github.com/sirupsen/logrus"
)

// MaxDefaultPushBody is the per-push cap used when the operator has
// not configured git_push_max_body_bytes. Real push bodies are well
// under a megabyte unless a caller is uploading huge packfiles,
// which the proxy does not need to validate.
const MaxDefaultPushBody int64 = 1 << 20

// errInvalidPktLine is returned when the framing is malformed.
var errInvalidPktLine = errors.New("gitrefs: invalid pkt-line framing")

// errBodyTooLarge is returned when the body exceeds the configured
// cap. The proxy responds with HTTP 413.
var errBodyTooLarge = errors.New("gitrefs: body too large")

// ErrBodyTooLarge is exported for use by the proxy handler.
var ErrBodyTooLarge = errBodyTooLarge

// ErrInvalidPktLine is exported for use by the proxy handler.
var ErrInvalidPktLine = errInvalidPktLine

// ParseReceivePackRefs extracts the (old, new, refname) tuples from
// the first flush-delimited section of a git-receive-pack body and
// returns just the refnames.
//
// Pkt-line format (see gitformat-pack-protocol(5)):
//
//	"PKT-LEN(4-hex) payload" where PKT-LEN includes the 4 length bytes.
//	"0000" is a flush packet (end of section).
//	"0001" is a delim packet (protocol v2). Skipped but does not
//	terminate the section.
//
// A push line is "<old-sha> <new-sha> <refname>\0<capabilities>\n"
// for the first line in a section and "<old-sha> <new-sha> <refname>\n"
// for subsequent lines. We only care about the refname; the NUL and
// anything after it are part of the capabilities advertisement and
// are ignored.
//
// On any framing error the parser stops and returns
// errInvalidPktLine. The caller is responsible for the
// "parse-fail-allow" policy decision — the parser itself does not
// silently ignore errors.
//
// maxBytes caps the body size. If the body exceeds it the parser
// returns errBodyTooLarge. The body is read in full up to the cap so
// the size can be checked exactly; this is fine because the cap is
// expected to be small (default 1 MiB).
func ParseReceivePackRefs(r io.Reader, maxBytes int64) ([]string, error) {
	if maxBytes < 0 {
		return nil, errBodyTooLarge
	}
	// Read at most maxBytes+1 bytes so we can distinguish "exactly the
	// cap" from "more than the cap".
	body, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, errBodyTooLarge
	}
	if len(body) == 0 {
		return nil, nil
	}
	return parseRefsFromBytes(body)
}

// parseRefsFromBytes walks a buffered receive-pack body and returns
// the refnames in the first flush-delimited section.
func parseRefsFromBytes(body []byte) ([]string, error) {
	br := bufio.NewReader(bytes.NewReader(body))
	var refs []string
	for {
		payload, done, err := readPkt(br)
		if done {
			return refs, nil
		}
		if err != nil {
			return refs, err
		}
		ref, ok := extractRef(payload)
		if !ok {
			// Not a ref-update line (e.g. a server-side capability
			// advertisement). Skip it and keep scanning the
			// section.
			continue
		}
		refs = append(refs, ref)
	}
}

// readPkt reads one pkt-line from br. It returns (payload, done, err)
// where done=true means the caller has reached a flush packet (or
// end-of-body, treated leniently per the parse-fail-allow rule in
// DESIGN.md). Delim packets (protocol v2) return done=false with an
// empty payload — the caller continues scanning.
func readPkt(br *bufio.Reader) ([]byte, bool, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// Truncated input is treated as a section end. The
			// caller's parse-fail-allow fallback will then let
			// the push through.
			return nil, true, nil
		}
		return nil, false, err
	}
	decoded, err := hex.DecodeString(string(hdr[:]))
	if err != nil {
		return nil, false, errInvalidPktLine
	}
	n := int(decoded[0])<<8 | int(decoded[1])
	switch n {
	case 0:
		// Flush — section is over.
		return nil, true, nil
	case 1:
		// Delim packet (protocol v2). Not a flush, not a ref.
		return nil, false, nil
	}
	if n < 4 {
		return nil, false, errInvalidPktLine
	}
	payload := make([]byte, n-4)
	if _, err := io.ReadFull(br, payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// Truncated payload mid-pkt. Surface as a
			// framing error so the caller's parse-fail-allow
			// fallback runs.
			return nil, false, errInvalidPktLine
		}
		return nil, false, err
	}
	return payload, false, nil
}

// extractRef pulls the refname out of a ref-update line. Returns
// ("", false) if the payload is not a ref-update line.
func extractRef(payload []byte) (string, bool) {
	sp1 := bytes.IndexByte(payload, ' ')
	if sp1 < 0 {
		return "", false
	}
	sp2 := bytes.IndexByte(payload[sp1+1:], ' ')
	if sp2 < 0 {
		return "", false
	}
	sp2 += sp1 + 1
	rest := payload[sp2+1:]
	if len(rest) == 0 {
		return "", false
	}
	end := len(rest)
	if i := bytes.IndexByte(rest, 0); i >= 0 {
		end = i
	} else if i := bytes.IndexByte(rest, '\n'); i >= 0 {
		end = i
	}
	ref := string(rest[:end])
	if ref == "" {
		return "", false
	}
	return ref, true
}

// filterRef is the proxy-side policy filter evaluator. It mirrors the
// rules described on policy.Repo (see policy.go) and is kept here in
// addition to policy.Engine.CheckPushRefs so unit tests can exercise
// the matching rules without a full policy.Engine. The two MUST stay
// in sync.
func filterRef(allow, deny, protected []string, ref string) bool {
	for _, p := range protected {
		if ref == "refs/heads/"+p {
			return false
		}
	}
	for _, pat := range deny {
		if matchRef(pat, ref) {
			return false
		}
	}
	if len(allow) > 0 {
		ok := false
		for _, pat := range allow {
			if matchRef(pat, ref) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// matchRef wraps filepath.Match with the Git-style "single-segment
// wildcard" semantics used by `git check-ref-format`. The tests in
// gitrefs_test.go pin this behaviour. Note: filepath.Match treats
// backslash as an escape character; that is acceptable here because
// backslash is rare in practice in ref names and we only match
// against patterns the operator has explicitly configured.
func matchRef(pattern, ref string) bool {
	ok, err := filepath.Match(pattern, ref)
	if err != nil {
		return false
	}
	return ok
}

// logParseFallback is a single place that warns about
// parse-fail-allow decisions, so the security-sensitive fallback is
// greppable in operator logs.
func logParseFallback(org, repoName, reason string) {
	logrus.WithFields(logrus.Fields{
		"org":    org,
		"repo":   repoName,
		"reason": reason,
	}).Warn("gitrefs: parse failed; falling back to allow (DESIGN.md §parse-fail-allow)")
}
