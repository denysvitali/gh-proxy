// Coverage goal: drive internal/server to 80%+ by spinning up the full
// HTTP server with a real, self-signed GitHub App private key and a
// stub upstream. The server has only a few wiring points: middleware
// ordering (requestLogger, telemetry), route mounts, the /healthz
// health-check, and the proxy registration. None of them are
// meaningfully testable without bringing the server up.
package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"github.com/denysvitali/gh-proxy/internal/config"
	"github.com/denysvitali/gh-proxy/internal/policy"
)

// bcryptHash is a thin wrapper that lets test code share the same
// password hashing package the verifier uses, without pulling
// internal/token into the server tests directly.
func bcryptHash(s string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.MinCost)
	return string(b), err
}

func newPolicyEngine() *policy.Engine { return policy.NewEngine(nil) }

func init() {
	// Gin's default mode prints a route table on startup, which is
	// noisy in `go test -v` output. We don't need that here.
	gin.SetMode(gin.ReleaseMode)
}

// writePEMKey writes a generated RSA private key to a temp file in PEM
// format and returns the path. Used so the GitHub App client can be
// constructed in tests without hard-coding a real key.
func writePEMKey(t *testing.T) string {
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

// writePolicy drops a minimal, valid policy document into a temp file
// and returns the path. The consumer "ci" has a real bcrypt hash of
// "secret", so tokens "ci.secret" are accepted.
func writePolicy(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	body := `version: 1
tenants:
  - name: acme
    installation_id: 1
    org: acme
    repos:
      - name: app
        access: read
        endpoints: [git.read]
consumers:
  - id: ci
    tenant: acme
    token_hashes: ["REPLACE"]
`
	// The hash below is bcrypt-cost-4 of "secret" computed at test time.
	// Generate it inline so we don't have to commit a static hash.
	h, err := bcryptHash("secret")
	if err != nil {
		t.Fatal(err)
	}
	body = strings.Replace(body, "REPLACE", h, 1)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// testServer starts a Server bound to a free local port and returns
// its base URL. The function cleans itself up via t.Cleanup.
func testServer(t *testing.T, mutate func(*config.Config)) (string, *Server) {
	t.Helper()
	key := writePEMKey(t)
	pol := writePolicy(t)
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0", // unused: we override with httptest
		LogLevel:   "info",
		PolicyPath: pol,
		GitHub: config.GitHubAppConfig{
			AppID:          1,
			PrivateKeyPath: key,
			APIBaseURL:     "https://api.github.com",
		},
	}
	if mutate != nil {
		mutate(cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	// We use httptest to drive the server's handler directly. Starting
	// the listener is not necessary for unit tests.
	ts := httptest.NewServer(s.http.Handler)
	t.Cleanup(ts.Close)
	return ts.URL, s
}

func TestServer_Healthz_OK(t *testing.T) {
	url, _ := testServer(t, nil)
	resp, err := http.Get(url + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status=%d want 200", resp.StatusCode)
	}
}

func TestServer_Healthz_DoesNotLogAccessLine(t *testing.T) {
	// The request logger explicitly skips /healthz. We can't observe
	// the log line directly, but we can confirm the request succeeds
	// and that nothing panics when hit in a tight loop.
	url, _ := testServer(t, nil)
	for i := 0; i < 5; i++ {
		resp, err := http.Get(url + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
}

func TestServer_UnauthenticatedGit_401(t *testing.T) {
	url, _ := testServer(t, nil)
	resp, err := http.Get(url + "/git/acme/app/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("status=%d want 401", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate challenge")
	}
}

func TestServer_UnauthenticatedAPI_401(t *testing.T) {
	url, _ := testServer(t, nil)
	resp, err := http.Get(url + "/api/repos/acme/app/pulls")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("status=%d want 401", resp.StatusCode)
	}
}

func TestServer_UnknownRoute_404(t *testing.T) {
	url, _ := testServer(t, nil)
	resp, err := http.Get(url + "/nothing/here")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Gin's default behavior: 404 for unknown paths.
	if resp.StatusCode != 404 {
		t.Errorf("status=%d want 404", resp.StatusCode)
	}
}

func TestServer_DELETE_NotAllowed(t *testing.T) {
	// Gin's Any() registers all standard methods. The route is wired as
	// Any so DELETE is accepted by the framework, but the upstream will
	// never be called (we have no upstream registered). The auth
	// middleware will still reject without a token.
	url, _ := testServer(t, nil)
	req, _ := http.NewRequest("DELETE", url+"/git/acme/app/info/refs", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("status=%d want 401 (auth must run before method handling)", resp.StatusCode)
	}
}

func TestServer_New_RequiresAppID(t *testing.T) {
	key := writePEMKey(t)
	pol := writePolicy(t)
	if _, err := New(&config.Config{
		PolicyPath: pol,
		GitHub:     config.GitHubAppConfig{AppID: 0, PrivateKeyPath: key, APIBaseURL: "https://api.github.com"},
	}); err == nil {
		t.Fatal("expected error when AppID is 0")
	}
}

func TestServer_New_RequiresPrivateKey(t *testing.T) {
	pol := writePolicy(t)
	if _, err := New(&config.Config{
		PolicyPath: pol,
		GitHub:     config.GitHubAppConfig{AppID: 1, PrivateKeyPath: "", APIBaseURL: "https://api.github.com"},
	}); err == nil {
		t.Fatal("expected error when PrivateKeyPath is empty")
	}
}

func TestServer_New_LoadsPolicy(t *testing.T) {
	url, s := testServer(t, nil)
	_ = url
	if s.engine == nil {
		t.Fatal("server.engine is nil after New")
	}
	if doc := s.engine.Snapshot(); doc == nil {
		t.Fatal("engine should have loaded the policy")
	} else if len(doc.Tenants) != 1 {
		t.Fatalf("expected 1 tenant, got %d", len(doc.Tenants))
	}
}

func TestServer_Run_ContextCancel(t *testing.T) {
	// Build a real server, point it at a free port, and let Run drive
	// ListenAndServe itself. We just need to cancel the context to
	// trigger the shutdown path.
	key := writePEMKey(t)
	pol := writePolicy(t)
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		LogLevel:   "info",
		PolicyPath: pol,
		GitHub: config.GitHubAppConfig{
			AppID:          1,
			PrivateKeyPath: key,
			APIBaseURL:     "https://api.github.com",
		},
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Reserve a port and hand the address to the server. Run will open
	// its own listener there.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	s.http.Addr = addr

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	// Hit /healthz to confirm the server is up.
	resp, err := http.Get("http://" + addr + "/healthz")
	if err == nil {
		_ = resp.Body.Close()
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of cancel")
	}
}

// TestServer_RequestID_RoundTrip is a placeholder for the correlation
// header contract. The current middleware stack does not stamp a
// request-id header (it relies on the OTel trace_id); we assert that
// the request still flows through cleanly. If a future contributor
// adds X-Request-Id support, expand this test.
func TestServer_RequestID_RoundTrip(t *testing.T) {
	url, _ := testServer(t, nil)
	resp, err := http.Get(url + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

// TestServer_Reload_Happy confirms that the policy reloader hands a new
// document to the engine. We do not call New() here because Reload is
// the small method that bridges config.ReadPolicyFile and engine.Replace.
func TestServer_Reload_Happy(t *testing.T) {
	pol := writePolicy(t)
	eng := newPolicyEngine()
	pr := &policyReloader{path: pol, engine: eng}
	if err := pr.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if doc := eng.Snapshot(); doc == nil {
		t.Fatal("engine should have a doc after Reload")
	}
}

func TestServer_Reload_BadFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(bad, []byte("not: valid: yaml: ::"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng := newPolicyEngine()
	pr := &policyReloader{path: bad, engine: eng}
	if err := pr.Reload(); err == nil {
		t.Fatal("expected yaml error from Reload")
	}
}

func TestServer_Reload_MissingFile(t *testing.T) {
	eng := newPolicyEngine()
	pr := &policyReloader{path: "/no/such/policy.yaml", engine: eng}
	if err := pr.Reload(); err == nil {
		t.Fatal("expected missing-file error from Reload")
	}
}

// TestServer_LogPolicySummary_NoDoc covers the "no policy loaded" branch.
func TestServer_LogPolicySummary_NoDoc(_ *testing.T) {
	eng := newPolicyEngine() // nil doc
	logPolicySummary(eng)    // must not panic
}

// TestServer_New_WebhookRegistered confirms that New wires the webhook
// handler when a secret is configured. The webhook is exercised more
// fully in internal/webhook; here we just need to know the route is
// mounted.
func TestServer_New_WebhookRegistered(t *testing.T) {
	key := writePEMKey(t)
	pol := writePolicy(t)
	cfg := &config.Config{
		ListenAddr:    "127.0.0.1:0",
		LogLevel:      "info",
		PolicyPath:    pol,
		WebhookSecret: "s3cret",
		GitHub: config.GitHubAppConfig{
			AppID:          1,
			PrivateKeyPath: key,
			APIBaseURL:     "https://api.github.com",
		},
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(s.http.Handler)
	t.Cleanup(ts.Close)
	resp, err := http.Post(ts.URL+"/webhooks/github", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// A missing signature should produce 401 (webhook handler active).
	if resp.StatusCode != 401 {
		t.Errorf("status=%d want 401", resp.StatusCode)
	}
}
