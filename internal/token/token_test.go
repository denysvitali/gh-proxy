package token

import (
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	i := NewIssuer([]byte("secret"), time.Minute)
	tok, _, err := i.Issue("acme", "ci")
	if err != nil {
		t.Fatal(err)
	}
	c, err := i.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Tenant != "acme" || c.Consumer != "ci" {
		t.Fatalf("unexpected claims: %+v", c)
	}
}

func TestExpired(t *testing.T) {
	i := NewIssuer([]byte("secret"), time.Minute)
	fixed := time.Unix(1_700_000_000, 0)
	i.now = func() time.Time { return fixed }
	tok, _, _ := i.Issue("acme", "ci")
	i.now = func() time.Time { return fixed.Add(2 * time.Minute) }
	if _, err := i.Verify(tok); err == nil {
		t.Fatal("expected expiry error")
	}
}

func TestTampered(t *testing.T) {
	i := NewIssuer([]byte("secret"), time.Minute)
	tok, _, _ := i.Issue("acme", "ci")
	bad := tok[:len(tok)-1] + "A"
	if _, err := i.Verify(bad); err == nil {
		t.Fatal("expected bad signature")
	}
}

func TestWrongKey(t *testing.T) {
	a := NewIssuer([]byte("k1"), time.Minute)
	b := NewIssuer([]byte("k2"), time.Minute)
	tok, _, _ := a.Issue("acme", "ci")
	if _, err := b.Verify(tok); err == nil {
		t.Fatal("expected signature mismatch across keys")
	}
}
