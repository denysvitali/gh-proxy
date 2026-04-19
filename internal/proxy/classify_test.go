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
	cases := map[string]policy.EndpointClass{
		"/actions/runs":     policy.EndpointWorkflows,
		"/pulls/42":         policy.EndpointPullRequest,
		"/git/refs/heads/m": policy.EndpointRefs,
		"/contents/README":  policy.EndpointRefs,
	}
	for in, want := range cases {
		if got := classifyAPI(in); got != want {
			t.Fatalf("%s: got %s want %s", in, got, want)
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
