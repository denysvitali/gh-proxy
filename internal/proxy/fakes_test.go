package proxy

import (
	"context"
	"io"
	"net/http"
	"sync"
)

// fakeGitHubApp is a controllable stand-in for *ghapp.Client used by
// proxy tests. It tracks the number of token requests so tests can assert
// that an erroring token fetch does NOT poison the cache (the next call
// must re-hit the fake).
type fakeGitHubApp struct {
	mu       sync.Mutex
	token    string
	err      error
	calls    int
	invalIDs []int64
}

func (f *fakeGitHubApp) InstallationToken(_ context.Context, _ int64) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.token, f.err
}

func (f *fakeGitHubApp) InvalidateInstallation(id int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invalIDs = append(f.invalIDs, id)
}

func (f *fakeGitHubApp) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// fakeUpstream is a request-capturing http.Handler used to assert the
// shape of the request that the proxy forwards to GitHub.
type fakeUpstream struct {
	mu        sync.Mutex
	requests  []*http.Request
	bodies    [][]byte
	responses []respSpec
	respIdx   int
}

// respSpec is a tiny value type used to construct canned upstream
// responses in tests. We avoid *http.Response literals here because
// their Body field is hard for static analysers to track (the
// bodyclose linter would flag every call site as missing a Close()).
type respSpec struct {
	status  int
	body    string
	headers map[string]string
}

func newFakeUpstream(responses ...respSpec) *fakeUpstream {
	return &fakeUpstream{responses: responses}
}

func (f *fakeUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	f.requests = append(f.requests, r.Clone(r.Context()))
	f.bodies = append(f.bodies, body)
	if f.respIdx < len(f.responses) {
		spec := f.responses[f.respIdx]
		f.respIdx++
		for k, v := range spec.headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(spec.status)
		_, _ = w.Write([]byte(spec.body))
		return
	}
	// Default: 200 with empty body.
	w.WriteHeader(http.StatusOK)
}

func (f *fakeUpstream) Request(idx int) *http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	if idx >= len(f.requests) {
		return nil
	}
	return f.requests[idx]
}

func (f *fakeUpstream) Body(idx int) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if idx >= len(f.bodies) {
		return nil
	}
	return append([]byte(nil), f.bodies[idx]...)
}

func (f *fakeUpstream) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}
