// Coverage goal: cover the cache eviction branch in
// (*Client).InstallationToken without doing a real network round-trip.
// The test is white-box: it constructs a *Client with the httptest
// server as its apiBaseURL, pre-populates the in-memory cache with an
// already-expired token, and asserts that the next call re-fetches
// (proving the eviction branch fires).
package ghapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func writePEMKeyForTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "app.pem")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	if err := os.WriteFile(p, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestInstallationToken_CacheEviction drives the eviction branch by
// pre-populating the cache with an already-expired token. We expect the
// next call to hit the (fake) HTTP server, NOT return the stale token.
//
// The spec from the coverage work item asks for "set a token expiring in
// 30s, assert it is NOT in the cache 60s later". We avoid real-time
// sleeping by directly inserting a token whose expiry is in the past
// (`time.Until(expires)` is negative, which is not > 1 minute), which
// is the same code path the 30s/60s scenario would take.
func TestInstallationToken_CacheEviction(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(InstallationToken{
			Token:     "fresh_token",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		})
	}))
	t.Cleanup(srv.Close)

	c, err := NewClient(1, writePEMKeyForTest(t), srv.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Pre-populate the cache with an expired token.
	c.mu.Lock()
	c.cache[42] = cachedToken{token: "stale", expires: time.Now().Add(-1 * time.Minute)}
	c.mu.Unlock()

	tok, err := c.InstallationToken(context.Background(), 42)
	if err != nil {
		t.Fatalf("InstallationToken: %v", err)
	}
	if tok == "stale" {
		t.Fatal("cache should have been evicted; got stale token")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits=%d, want 1 (cache was poisoned?)", got)
	}
}

// TestInstallationToken_CacheHit confirms the positive path: a token
// whose expiry is comfortably in the future is served from the cache
// without a network round-trip.
func TestInstallationToken_CacheHit(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(InstallationToken{
			Token:     "first",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		})
	}))
	t.Cleanup(srv.Close)

	c, err := NewClient(1, writePEMKeyForTest(t), srv.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Populate the cache with a fresh token.
	c.mu.Lock()
	c.cache[42] = cachedToken{token: "cached", expires: time.Now().Add(1 * time.Hour)}
	c.mu.Unlock()

	tok, err := c.InstallationToken(context.Background(), 42)
	if err != nil {
		t.Fatalf("InstallationToken: %v", err)
	}
	if tok != "cached" {
		t.Fatalf("token=%q, want cached", tok)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("upstream hits=%d, want 0 (cache should have served)", got)
	}
}

func TestInvalidateInstallation(t *testing.T) {
	c, err := NewClient(1, writePEMKeyForTest(t), "http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	// Seed the cache.
	c.mu.Lock()
	c.cache[7] = cachedToken{token: "x", expires: time.Now().Add(1 * time.Hour)}
	c.mu.Unlock()
	c.InvalidateInstallation(7)
	c.mu.Lock()
	_, ok := c.cache[7]
	c.mu.Unlock()
	if ok {
		t.Fatal("InvalidateInstallation should have removed the entry")
	}
	// Invalidate on a missing ID is a no-op (must not panic).
	c.InvalidateInstallation(99)
}

func TestAppJWT_NonEmpty(t *testing.T) {
	c, err := NewClient(123, writePEMKeyForTest(t), "http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := c.AppJWT()
	if err != nil {
		t.Fatalf("AppJWT: %v", err)
	}
	if tok == "" {
		t.Fatal("AppJWT returned empty string")
	}
}
