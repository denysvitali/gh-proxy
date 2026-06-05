package proxy

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/denysvitali/gh-proxy/internal/policy"
)

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
