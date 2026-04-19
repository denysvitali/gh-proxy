package token

import (
	"testing"

	"github.com/denysvitali/gh-proxy/internal/policy"
)

type fakeLookup map[string]*policy.Consumer

func (f fakeLookup) Consumer(id string) (*policy.Consumer, bool) {
	c, ok := f[id]
	return c, ok
}

func TestVerifyRoundTrip(t *testing.T) {
	h, err := Hash("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(fakeLookup{"ci": {ID: "ci", Tenant: "acme", TokenHashes: []string{h}}})
	claims, err := v.Verify("ci.s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Tenant != "acme" || claims.Consumer != "ci" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestVerifyMalformed(t *testing.T) {
	v := NewVerifier(fakeLookup{})
	for _, tok := range []string{"", "nodot", ".", "ci.", ".secret"} {
		if _, err := v.Verify(tok); err == nil {
			t.Fatalf("%q: expected error", tok)
		}
	}
}

func TestVerifyUnknownConsumer(t *testing.T) {
	v := NewVerifier(fakeLookup{})
	if _, err := v.Verify("ghost.sec"); err != ErrUnknownConsumer {
		t.Fatalf("got %v want ErrUnknownConsumer", err)
	}
}

func TestVerifyBadSecret(t *testing.T) {
	h, _ := Hash("right")
	v := NewVerifier(fakeLookup{"ci": {ID: "ci", Tenant: "acme", TokenHashes: []string{h}}})
	if _, err := v.Verify("ci.wrong"); err != ErrBadSecret {
		t.Fatalf("got %v want ErrBadSecret", err)
	}
}

func TestVerifyMultipleHashes(t *testing.T) {
	h1, _ := Hash("old")
	h2, _ := Hash("new")
	v := NewVerifier(fakeLookup{"ci": {ID: "ci", Tenant: "acme", TokenHashes: []string{h1, h2}}})
	if _, err := v.Verify("ci.new"); err != nil {
		t.Fatalf("new secret: %v", err)
	}
	if _, err := v.Verify("ci.old"); err != nil {
		t.Fatalf("old secret: %v", err)
	}
}
