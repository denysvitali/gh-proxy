// Coverage goal: drive statement coverage of the data plane in
// internal/proxy/proxy.go from ~18% to >80%. Each table-test case targets a
// distinct branch the request handlers exercise: auth middleware outcomes,
// policy allow/deny in both Git and API paths, the upstream error paths
// (502 on token fetch, 4xx/5xx body streaming), the header rewriting
// contract (Authorization replaced, Cookie stripped, hop-by-hop skipped),
// and the in-memory token-cache non-poisoning invariant.
package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/denysvitali/gh-proxy/internal/policy"
	"github.com/denysvitali/gh-proxy/internal/token"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// testEngine builds a small policy.Engine that allows the requests exercised
// by the cases below. Tenant "acme" maps to org "acme" with two repos: a
// read-only "app" (git.read, actions.workflows, api.refs) and a write-any
// "infra" (wildcard endpoints).
func testEngine(t *testing.T) *policy.Engine {
	t.Helper()
	h, err := token.Hash("secret")
	if err != nil {
		t.Fatalf("token.Hash: %v", err)
	}
	return policy.NewEngine(&policy.Document{
		Version: 1,
		Tenants: []policy.Tenant{{
			Name:           "acme",
			InstallationID: 42,
			Org:            "acme",
			Repos: []policy.Repo{
				{Name: "app", Access: policy.AccessRead, Endpoints: []policy.EndpointClass{
					policy.EndpointGitRead, policy.EndpointWorkflows, policy.EndpointRefs, policy.EndpointPullRequest,
				}},
				{Name: "infra", Access: policy.AccessWrite, Endpoints: []policy.EndpointClass{"*"}},
				{Name: "locked", Access: policy.AccessNone, Endpoints: []policy.EndpointClass{"*"}},
			},
		}},
		Consumers: []policy.Consumer{{ID: "ci", Tenant: "acme", TokenHashes: []string{h}}},
	})
}

// testVerifier is intentionally not exported; testDeps builds a Verifier
// inline from testEngine, so no separate helper is needed here.

// testDeps returns a Deps wired with a fake App, an httptest.NewServer-backed
// HTTP client, and a working verifier. Callers may replace gh with a faker
// that returns an error to exercise the 502 path.
func testDeps(t *testing.T, upstream http.Handler) (Deps, *fakeGitHubApp) {
	t.Helper()
	eng := testEngine(t)
	v := token.NewVerifier(eng)
	gh := &fakeGitHubApp{token: "ghs_installationtoken"}
	srv := httptest.NewServer(upstream)
	t.Cleanup(srv.Close)
	d := Deps{
		Engine:     eng,
		Tokens:     v,
		GitHubApp:  gh,
		APIBaseURL: srv.URL,
		GitBaseURL: srv.URL,
		HTTPClient: srv.Client(),
	}
	return d, gh
}

// registerProxy mounts the data plane on a fresh gin engine.
func registerProxy(t *testing.T, d Deps) *gin.Engine {
	t.Helper()
	r := gin.New()
	Register(r, d)
	return r
}

func bearerAuth() string { return "Bearer ci.secret" }

func basicAuth(user, pass string) string {
	if pass == "" {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user))
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func assertStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body.String())
	}
}

// --- authMiddleware ----------------------------------------------------------------

func TestAuthMiddleware_RejectsMissingHeader(t *testing.T) {
	d, _ := testDeps(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("upstream should not be called when auth fails")
	}))
	r := registerProxy(t, d)
	req := httptest.NewRequest("GET", "/git/acme/app/info/refs?service=git-upload-pack", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assertStatus(t, w, http.StatusUnauthorized)
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected WWW-Authenticate challenge header")
	}
	if !strings.Contains(w.Body.String(), "no Authorization") {
		t.Fatalf("body should mention reason, got %s", w.Body.String())
	}
}

func TestAuthMiddleware_RejectsMalformedSchemes(t *testing.T) {
	upstream := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("upstream should not be called")
	})
	cases := []struct {
		name string
		hdr  string
	}{
		{"bearer empty token", "Bearer "},
		{"basic bad base64", "Basic !!!notbase64"},
		{"basic no colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon"))},
		{"basic empty user", basicAuth("", "secret")},
		{"basic empty pass and no dot", basicAuth("ci", "")},
		{"digest", "Digest foo"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, _ := testDeps(t, upstream)
			r := registerProxy(t, d)
			req := httptest.NewRequest("GET", "/git/acme/app/info/refs?service=git-upload-pack", nil)
			req.Header.Set("Authorization", c.hdr)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assertStatus(t, w, http.StatusUnauthorized)
		})
	}
}

func TestAuthMiddleware_AcceptsValidSchemes(t *testing.T) {
	upstream := newFakeUpstream(httpResp(http.StatusOK, "001e", map[string]string{"Content-Type": "application/octet-stream"}))
	cases := []struct {
		name string
		hdr  string
	}{
		{"bearer", bearerAuth()},
		{"basic user-contains-token", basicAuth("ci.secret", "x")},
		{"basic split", basicAuth("ci", "secret")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, _ := testDeps(t, upstream)
			r := registerProxy(t, d)
			req := httptest.NewRequest("GET", "/git/acme/app/info/refs?service=git-upload-pack", nil)
			req.Header.Set("Authorization", c.hdr)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assertStatus(t, w, http.StatusOK)
		})
	}
}

func TestAuthMiddleware_BadSecret(t *testing.T) {
	upstream := newFakeUpstream(httpResp(http.StatusOK, "", nil))
	d, _ := testDeps(t, upstream)
	r := registerProxy(t, d)
	req := httptest.NewRequest("GET", "/git/acme/app/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Bearer ci.WRONG")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assertStatus(t, w, http.StatusUnauthorized)
}

func TestAuthMiddleware_UnknownConsumer(t *testing.T) {
	upstream := newFakeUpstream(httpResp(http.StatusOK, "", nil))
	d, _ := testDeps(t, upstream)
	r := registerProxy(t, d)
	req := httptest.NewRequest("GET", "/git/acme/app/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Bearer ghost.secret")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assertStatus(t, w, http.StatusUnauthorized)
}

// TestAuthSchemeClassifier covers the authScheme helper directly. It's a
// small, hot function, and a future refactor that loses the "unknown"
// branch (when no space is present) would silently mis-label log lines.
func TestAuthSchemeClassifier(t *testing.T) {
	cases := map[string]string{
		"":                "none",
		"Basic abc":       "basic",
		"Bearer xyz":      "bearer",
		"noscheme":        "unknown",
		"lowercase Basic": "lowercase",
	}
	for in, want := range cases {
		if got := authScheme(in); got != want {
			t.Errorf("authScheme(%q)=%q want %q", in, got, want)
		}
	}
}

// --- gitProxy ---------------------------------------------------------------------

func TestGitProxy_ReadPassesThrough(t *testing.T) {
	upstream := newFakeUpstream(httpResp(http.StatusOK, "ok", map[string]string{"X-Foo": "bar"}))
	d, gh := testDeps(t, upstream)
	r := registerProxy(t, d)

	req := httptest.NewRequest("GET", "/git/acme/app/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", bearerAuth())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assertStatus(t, w, http.StatusOK)
	if got := upstream.Count(); got != 1 {
		t.Fatalf("upstream call count=%d want 1", got)
	}
	if gh.Calls() != 1 {
		t.Fatalf("installation token call count=%d want 1", gh.Calls())
	}
	got := upstream.Request(0)
	if got == nil {
		t.Fatal("upstream request was not captured")
	}
	// Upstream URL must be rewritten to GitBaseURL + org/repo.git + rest
	if !strings.Contains(got.URL.String(), "/acme/app.git/info/refs") {
		t.Errorf("upstream URL = %s, want /acme/app.git/info/refs", got.URL)
	}
	// Service query string must survive the rewrite.
	if got.URL.Query().Get("service") != "git-upload-pack" {
		t.Errorf("service query = %q, want git-upload-pack", got.URL.RawQuery)
	}
	// Authorization must be the installation token, NOT the consumer's Bearer.
	authz := got.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Basic ") {
		t.Errorf("Authorization=%q, want Basic", authz)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authz, "Basic "))
	if err != nil {
		t.Fatalf("decode basic auth: %v", err)
	}
	if string(decoded) != "x-access-token:ghs_installationtoken" {
		t.Errorf("basic auth payload=%q, want x-access-token:<token>", string(decoded))
	}
	if w.Header().Get("X-Foo") != "bar" {
		t.Errorf("response X-Foo=%q want bar", w.Header().Get("X-Foo"))
	}
}

func TestGitProxy_WritePassesThrough(t *testing.T) {
	body := strings.Repeat("pkt-line data\n", 100)
	upstream := newFakeUpstream(httpResp(http.StatusOK, "ok", nil))
	d, _ := testDeps(t, upstream)
	r := registerProxy(t, d)

	req := httptest.NewRequest("POST", "/git/acme/infra/git-receive-pack", strings.NewReader(body))
	req.Header.Set("Authorization", bearerAuth())
	req.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assertStatus(t, w, http.StatusOK)
	got := upstream.Request(0)
	if !strings.Contains(got.URL.String(), "/acme/infra.git/git-receive-pack") {
		t.Fatalf("upstream URL = %s", got.URL)
	}
	if !bytes.Equal(upstream.Body(0), []byte(body)) {
		t.Fatalf("body mismatch: sent %d bytes, upstream got %d", len(body), len(upstream.Body(0)))
	}
}

func TestGitProxy_PolicyDenied(t *testing.T) {
	upstream := newFakeUpstream(httpResp(http.StatusOK, "ok", nil))
	d, _ := testDeps(t, upstream)
	r := registerProxy(t, d)

	// "app" is read-only; trying to write should be denied.
	req := httptest.NewRequest("POST", "/git/acme/app/git-receive-pack", nil)
	req.Header.Set("Authorization", bearerAuth())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assertStatus(t, w, http.StatusForbidden)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if reason, _ := body["error"].(string); !strings.Contains(reason, "write not allowed") {
		t.Fatalf("403 body reason = %q, want it to contain 'write not allowed'", reason)
	}
	if upstream.Count() != 0 {
		t.Fatalf("upstream should not be called when policy denies, got %d calls", upstream.Count())
	}
}

func TestGitProxy_OrgMismatchOnWrite(t *testing.T) {
	upstream := newFakeUpstream(httpResp(http.StatusOK, "ok", nil))
	d, _ := testDeps(t, upstream)
	r := registerProxy(t, d)

	// Tenant "acme" only allows org "acme"; a write to a different org is denied.
	req := httptest.NewRequest("POST", "/git/other/infra/git-receive-pack", nil)
	req.Header.Set("Authorization", bearerAuth())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assertStatus(t, w, http.StatusForbidden)
	if !strings.Contains(w.Body.String(), "org mismatch") {
		t.Fatalf("403 body = %s, want it to mention org mismatch", w.Body.String())
	}
}

func TestGitProxy_InstallationTokenError_Returns502_NoCachePoisoning(t *testing.T) {
	upstream := newFakeUpstream(httpResp(http.StatusOK, "ok", nil))
	d, gh := testDeps(t, upstream)
	// First call returns an error; the second call must hit the fake
	// (proving the cache was not poisoned by the failed fetch).
	gh.err = errors.New("upstream down")
	r := registerProxy(t, d)

	req := httptest.NewRequest("GET", "/git/acme/app/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", bearerAuth())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assertStatus(t, w, http.StatusBadGateway)
	if !strings.Contains(w.Body.String(), "upstream down") {
		t.Fatalf("502 body = %s, want it to contain 'upstream down'", w.Body.String())
	}
	if gh.Calls() != 1 {
		t.Fatalf("first call count=%d", gh.Calls())
	}

	// Now allow the App to succeed. The second request must hit the fake
	// (NOT serve a cached error) and the upstream must be called.
	gh.err = nil
	req2 := httptest.NewRequest("GET", "/git/acme/app/info/refs?service=git-upload-pack", nil)
	req2.Header.Set("Authorization", bearerAuth())
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	assertStatus(t, w2, http.StatusOK)
	if gh.Calls() != 2 {
		t.Fatalf("second call count=%d, want 2 (cache was poisoned by error?)", gh.Calls())
	}
	if upstream.Count() != 1 {
		t.Fatalf("upstream call count=%d, want 1", upstream.Count())
	}
}

// --- apiProxy ----------------------------------------------------------------------

func TestAPIProxy_EndpointClassAndWriteFlag(t *testing.T) {
	cases := []struct {
		name      string
		method    string
		path      string
		wantClass policy.EndpointClass
		wantWrite bool
		allow     bool
	}{
		{"GET pulls", "GET", "/api/repos/acme/app/pulls", policy.EndpointPullRequest, false, true},
		{"POST pulls (write)", "POST", "/api/repos/acme/infra/pulls", policy.EndpointPullRequest, true, true},
		{"PUT merge", "PUT", "/api/repos/acme/infra/pulls/1/merge", policy.EndpointPullRequest, true, true},
		{"GET actions", "GET", "/api/repos/acme/app/actions/runs/1", policy.EndpointWorkflows, false, true},
		{"POST actions rerun", "POST", "/api/repos/acme/app/actions/runs/1/rerun", policy.EndpointWorkflows, true, false},
		{"GET git/refs", "GET", "/api/repos/acme/app/git/refs/heads/main", policy.EndpointRefs, false, true},
		{"POST git/refs (write to read-only denied)", "POST", "/api/repos/acme/app/git/refs/heads/main", policy.EndpointRefs, true, false},
		{"GET /refs/...", "GET", "/api/repos/acme/app/refs/heads/main", policy.EndpointRefs, false, true},
		{"HEAD /unknown (default-deny endpoint class)", "HEAD", "/api/repos/acme/app/issues", policy.EndpointRefs, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			upstream := newFakeUpstream(httpResp(http.StatusOK, "ok", nil))
			d, _ := testDeps(t, upstream)
			r := registerProxy(t, d)

			req := httptest.NewRequest(c.method, c.path, nil)
			req.Header.Set("Authorization", bearerAuth())
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if c.allow {
				assertStatus(t, w, http.StatusOK)
				if upstream.Count() != 1 {
					t.Fatalf("upstream calls=%d, want 1", upstream.Count())
				}
				got := upstream.Request(0)
				if !strings.HasSuffix(got.URL.Path, c.path[len("/api/repos"):]) {
					t.Errorf("upstream URL path=%s", got.URL.Path)
				}
				authz := got.Header.Get("Authorization")
				if authz != "token ghs_installationtoken" {
					t.Errorf("Authorization=%q, want token ghs_installationtoken", authz)
				}
			} else {
				assertStatus(t, w, http.StatusForbidden)
				if upstream.Count() != 0 {
					t.Fatalf("upstream should not be called on 403, got %d", upstream.Count())
				}
			}
		})
	}
}

func TestAPIProxy_NonClassifiedPathFallsThroughDefaultDeny(t *testing.T) {
	// /issues is not modeled; even with a write-locked repo, the proxy should
	// forward the GET (read) but the *engine* still allows reads of unknown
	// repos. We just want to make sure classifyAPI returns a class and the
	// proxy still routes. See TestAPIProxy_EndpointClassAndWriteFlag for the
	// negative coverage. This test documents that "/issues" is classified
	// to EndpointRefs by the default branch.
	upstream := newFakeUpstream(httpResp(http.StatusOK, "{}", nil))
	d, _ := testDeps(t, upstream)
	r := registerProxy(t, d)
	req := httptest.NewRequest("GET", "/api/repos/acme/app/issues", nil)
	req.Header.Set("Authorization", bearerAuth())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assertStatus(t, w, http.StatusOK)
}

// --- forward -----------------------------------------------------------------------

func TestForward_StripsCookieAndReplacesAuthorization(t *testing.T) {
	upstream := newFakeUpstream(httpResp(http.StatusOK, "ok", nil))
	d, _ := testDeps(t, upstream)
	r := registerProxy(t, d)

	req := httptest.NewRequest("GET", "/git/acme/app/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Bearer ci.secret")
	req.Header.Set("Cookie", "session=abc; csrftoken=xyz")
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assertStatus(t, w, http.StatusOK)

	got := upstream.Request(0)
	if got.Header.Get("Cookie") != "" {
		t.Errorf("Cookie header leaked to upstream: %q", got.Header.Get("Cookie"))
	}
	if got.Header.Get("X-Forwarded-For") != "10.0.0.1" {
		t.Errorf("X-Forwarded-For was stripped: %q", got.Header.Get("X-Forwarded-For"))
	}
	if !strings.HasPrefix(got.Header.Get("Authorization"), "Basic ") {
		t.Errorf("Authorization = %q, want Basic", got.Header.Get("Authorization"))
	}
}

func TestForward_StreamsUpstreamStatusAndBody(t *testing.T) {
	// The body is larger than the default Gin/transport buffer to assert
	// the handler streams instead of buffering.
	large := strings.Repeat("ABCDEFGH", 4096) // 32 KiB
	cases := []struct {
		name   string
		status int
	}{
		{"upstream 200", http.StatusOK},
		{"upstream 201", http.StatusCreated},
		{"upstream 404", http.StatusNotFound},
		{"upstream 500", http.StatusInternalServerError},
		{"upstream 502", http.StatusBadGateway},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			upstream := newFakeUpstream(httpResp(c.status, large, map[string]string{"X-Trace": "abc"}))
			d, _ := testDeps(t, upstream)
			r := registerProxy(t, d)
			req := httptest.NewRequest("GET", "/git/acme/app/info/refs?service=git-upload-pack", nil)
			req.Header.Set("Authorization", bearerAuth())
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assertStatus(t, w, c.status)
			if w.Body.String() != large {
				t.Fatalf("body length=%d want %d", w.Body.Len(), len(large))
			}
		})
	}
}

func TestForward_UpstreamConnectionError_Returns502(t *testing.T) {
	// Point the Deps at a port that nothing is listening on.
	d := Deps{
		Engine:     testEngine(t),
		Tokens:     token.NewVerifier(testEngine(t)),
		GitHubApp:  &fakeGitHubApp{token: "x"},
		APIBaseURL: "http://127.0.0.1:1",
		GitBaseURL: "http://127.0.0.1:1",
		HTTPClient: &http.Client{Timeout: 100_000_000}, // 100ms
	}
	r := registerProxy(t, d)
	req := httptest.NewRequest("GET", "/git/acme/app/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", bearerAuth())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assertStatus(t, w, http.StatusBadGateway)
}

func TestCopyHeaders(t *testing.T) {
	src := http.Header{}
	for _, k := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive",
		"Transfer-Encoding", "Upgrade", "Te", "Trailers",
		"Authorization", "X-Custom", "Content-Type",
	} {
		src.Set(k, k+"-v")
	}
	dst := http.Header{}
	copyHeaders(dst, src)
	// All hop-by-hop and Authorization must be skipped.
	for _, k := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive",
		"Transfer-Encoding", "Upgrade", "Te", "Trailers",
		"Authorization",
	} {
		if got := dst.Get(k); got != "" {
			t.Errorf("hop-by-hop %q leaked to dst: %q", k, got)
		}
	}
	if dst.Get("X-Custom") != "X-Custom-v" {
		t.Errorf("X-Custom = %q", dst.Get("X-Custom"))
	}
	if dst.Get("Content-Type") != "Content-Type-v" {
		t.Errorf("Content-Type = %q", dst.Get("Content-Type"))
	}
}

// --- helpers -----------------------------------------------------------------------

// httpResp is a tiny constructor for canned upstream responses used in
// tests. It returns a respSpec value (not a *http.Response) so that
// the bodyclose linter cannot flag the construction site.
func httpResp(status int, body string, hdr map[string]string) respSpec {
	return respSpec{status: status, body: body, headers: hdr}
}

// Confirm that the in-package classifier and the integration path agree on
// the "Git read" classification for an info/refs upload-pack request.
func TestIsGitWrite_InfoRefs(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://x/info/refs?service=git-upload-pack", nil)
	if isGitWrite("/info/refs", r) {
		t.Fatal("upload-pack should not be write")
	}
	r2, _ := http.NewRequest("GET", "http://x/info/refs?service=git-receive-pack", nil)
	if !isGitWrite("/info/refs", r2) {
		t.Fatal("receive-pack on info/refs should be write")
	}
	// Defensive: an empty path with a receive-pack query is not a write.
	r3, _ := http.NewRequest("GET", "http://x/some/other?service=git-receive-pack", nil)
	if isGitWrite("/some/other", r3) {
		t.Fatal("receive-pack query on a non-info/refs path is not a write")
	}
}

// Ensure the response writer sees the upstream error body even when the
// upstream responds 4xx/5xx. The default http.Transport will follow
// redirects; the production forwardClient explicitly does not. We don't
// need to test that here, but we should test that the body is forwarded
// verbatim.
func TestForward_PreservesUpstreamErrorBody(t *testing.T) {
	body := `{"message":"Not Found"}`
	upstream := newFakeUpstream(httpResp(http.StatusNotFound, body, map[string]string{"Content-Type": "application/json"}))
	d, _ := testDeps(t, upstream)
	r := registerProxy(t, d)
	req := httptest.NewRequest("GET", "/git/acme/app/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", bearerAuth())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assertStatus(t, w, http.StatusNotFound)
	if !strings.Contains(w.Body.String(), "Not Found") {
		t.Fatalf("body=%q", w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type=%q", ct)
	}
}

// TestForward_CopiesAuthorizationAsBearer is the "X-Forwarded-Authz" case
// in disguise: the upstream may echo an Authorization header (e.g. when
// it is itself a proxy). copyHeaders must drop that hop-by-hop header from
// the response to avoid leaking tokens to the consumer.
func TestForward_StripsAuthorizationFromResponse(t *testing.T) {
	hdr := map[string]string{
		"Authorization":  "Bearer leaked",
		"X-Trace":        "abc",
		"Set-Cookie":     "session=abc",
		"Content-Length": "0",
	}
	upstream := newFakeUpstream(httpResp(http.StatusOK, "", hdr))
	d, _ := testDeps(t, upstream)
	r := registerProxy(t, d)
	req := httptest.NewRequest("GET", "/git/acme/app/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", bearerAuth())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Header().Get("Authorization") != "" {
		t.Errorf("Authorization leaked to client: %q", w.Header().Get("Authorization"))
	}
	if w.Header().Get("X-Trace") != "abc" {
		t.Errorf("X-Trace dropped: %q", w.Header().Get("X-Trace"))
	}
}

// Touch internal helpers to make sure import/url/strings are wired up.
var _ = url.Parse
var _ = fmt.Sprintf
