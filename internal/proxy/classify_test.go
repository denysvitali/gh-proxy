package proxy

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/denysvitali/gh-proxy/internal/policy"
)

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
