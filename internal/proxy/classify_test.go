package proxy

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/denysvitali/gh-proxy/internal/policy"
	"github.com/gin-gonic/gin"
)

type rotatingTokenSource struct {
	token         string
	invalidations int
	requests      int
}

func (s *rotatingTokenSource) InstallationToken(context.Context, int64) (string, error) {
	s.requests++
	return s.token, nil
}

func (s *rotatingTokenSource) InvalidateInstallation(int64) {
	s.invalidations++
}

func TestExtractToken(t *testing.T) {
	basic := func(s string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(s))
	}
	cases := []struct {
		name   string
		header string
		want   string
		ok     bool
	}{
		{"bearer", "Bearer ci.secret", "ci.secret", true},
		{"bearer empty", "Bearer ", "", false},
		{"basic user-contains-token", basic("ci.secret:x"), "ci.secret", true},
		{"basic split", basic("ci:secret"), "ci.secret", true},
		{"basic no pass", basic("ci:"), "", false},
		{"basic no user", basic(":secret"), "", false},
		{"none", "", "", false},
		{"unknown scheme", "Digest xxx", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := extractToken(c.header)
			if ok != c.ok || got != c.want {
				t.Fatalf("got (%q,%v) want (%q,%v)", got, ok, c.want, c.ok)
			}
		})
	}
}

func TestClassifyAPI(t *testing.T) {
	cases := []struct {
		method string
		rest   string
		want   policy.EndpointClass
	}{
		// Existing behavior, now method-aware.
		{"GET", "/actions/runs", policy.EndpointWorkflows},
		{"GET", "/pulls", policy.EndpointPullRequest},
		{"GET", "/pulls/42", policy.EndpointPullRequest},
		{"GET", "/git/refs/heads/m", policy.EndpointRefs},
		{"GET", "/contents/README", policy.EndpointRefs},

		// PR create / merge / review split.
		{"POST", "/pulls", policy.EndpointPullsCreate},
		{"PATCH", "/pulls/42", policy.EndpointPullsCreate},
		{"PUT", "/pulls/42/merge", policy.EndpointPullsMerge},
		{"POST", "/pulls/42/merge", policy.EndpointPullsMerge},
		{"POST", "/pulls/42/reviews", policy.EndpointPullsReview},
		{"POST", "/pulls/42/reviews/7", policy.EndpointPullsReview},
		{"POST", "/pulls/42/comments", policy.EndpointPullsReview},
		{"POST", "/pulls/42/reviews/7/events", policy.EndpointPullsMerge},
		// Other writes under /pulls/{id}/* bucket to create.
		{"PUT", "/pulls/42/update_branch", policy.EndpointPullsCreate},
		{"GET", "/pulls/42/files", policy.EndpointPullRequest},
	}
	for _, c := range cases {
		got := classifyAPI(c.method, c.rest)
		if got != c.want {
			t.Errorf("%s %s: got %s want %s", c.method, c.rest, got, c.want)
		}
	}
}

func TestShouldRefreshArtifactToken(t *testing.T) {
	cases := []struct {
		method string
		rest   string
		want   bool
	}{
		{http.MethodGet, "/actions/artifacts/123", true},
		{http.MethodGet, "/actions/artifacts/123/zip", true},
		{http.MethodHead, "/actions/artifacts/123/zip", true},
		{http.MethodDelete, "/actions/artifacts/123", false},
		{http.MethodGet, "/actions/runs/123/artifacts", false},
	}
	for _, c := range cases {
		if got := shouldRefreshArtifactToken(c.method, c.rest); got != c.want {
			t.Errorf("%s %s: got %v want %v", c.method, c.rest, got, c.want)
		}
	}
}

func TestForwardArtifactRefreshesTokenAndRetries404(t *testing.T) {
	gin.SetMode(gin.TestMode)
	upstreamRequests := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests++
		if got := r.Header.Get("Authorization"); got == "token stale" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Authorization"); got != "token fresh" {
			t.Errorf("unexpected Authorization header %q", got)
		}
		w.Header().Set("X-Test-Token", "fresh")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("artifact"))
	}))
	defer upstream.Close()

	tokens := &rotatingTokenSource{token: "fresh"}
	d := Deps{GitHubApp: tokens, HTTPClient: upstream.Client()}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/repos/o/r/actions/artifacts/123?attempt=1", nil)
	target, err := url.Parse(upstream.URL + "/repos/o/r/actions/artifacts/123")
	if err != nil {
		t.Fatal(err)
	}

	d.forwardArtifact(c, target, 99, "stale")

	if recorder.Code != http.StatusOK || recorder.Body.String() != "artifact" {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("X-Test-Token") != "fresh" {
		t.Fatal("fresh response headers were not forwarded")
	}
	if upstreamRequests != 2 || tokens.invalidations != 1 || tokens.requests != 1 {
		t.Fatalf("requests=%d invalidations=%d token requests=%d", upstreamRequests, tokens.invalidations, tokens.requests)
	}
}

func TestIsGitWrite(t *testing.T) {
	r := &http.Request{URL: &url.URL{}}
	if !isGitWrite("/git-receive-pack", r) {
		t.Fatal("receive-pack should be write")
	}
	r.URL.RawQuery = "service=git-receive-pack"
	r.URL, _ = url.Parse("http://x/info/refs?service=git-receive-pack")
	if !isGitWrite("/info/refs", r) {
		t.Fatal("info/refs with receive-pack should be write")
	}
	r.URL, _ = url.Parse("http://x/info/refs?service=git-upload-pack")
	if isGitWrite("/info/refs", r) {
		t.Fatal("upload-pack should be read")
	}
}
