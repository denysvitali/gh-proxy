package webhook

import (
	"bytes"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
)

type fakeInval struct{ id atomic.Int64 }

func (f *fakeInval) InvalidateInstallation(id int64) { f.id.Store(id) }

// fakeReloader is a PolicyReloader spy used to ensure webhook handlers
// can route to one. Not all tests need it, but the type keeps the
// handler's interface compatibility obvious to readers.
type fakeReloader struct{ called atomic.Int32 }

func (f *fakeReloader) Reload() error { f.called.Add(1); return nil }

// keep the unused-import linter happy.
var _ PolicyReloader = (*fakeReloader)(nil)

func TestWebhookSignatureAndDispatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fi := &fakeInval{}
	h := &Handler{Secret: []byte("s3cret"), Inval: fi}
	r := gin.New()
	h.Register(r)

	body := []byte(`{"action":"created","installation":{"id":99}}`)
	sig := Compute(h.Secret, body)

	req := httptest.NewRequest("POST", "/webhooks/github", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "installation")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}
	if fi.id.Load() != 99 {
		t.Fatalf("invalidator not called, id=%d", fi.id.Load())
	}
}

func TestWebhookBadSignature(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &Handler{Secret: []byte("s3cret")}
	r := gin.New()
	h.Register(r)

	req := httptest.NewRequest("POST", "/webhooks/github", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
	req.Header.Set("X-GitHub-Event", "installation")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestVerifySignature_Branches covers the four error paths in
// verifySignature: no secret configured, missing/malformed prefix,
// bad hex encoding, and signature mismatch.
func TestVerifySignature_Branches(t *testing.T) {
	body := []byte(`{}`)
	cases := []struct {
		name    string
		secret  []byte
		header  string
		wantSub string
	}{
		{"no secret", nil, "sha256=" + "00", "secret not configured"},
		{"missing prefix", []byte("s"), "deadbeef", "missing or malformed"},
		{"bad hex", []byte("s"), "sha256=zz", "bad signature encoding"},
		{"mismatch", []byte("s"), "sha256=00000000000000000000000000000000", "signature mismatch"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := verifySignature(c.secret, c.header, body)
			if err == nil {
				t.Fatal("expected error")
			}
			if !bytes.Contains([]byte(err.Error()), []byte(c.wantSub)) {
				t.Fatalf("err = %q, want substring %q", err.Error(), c.wantSub)
			}
		})
	}
}

func TestVerifySignature_OK(t *testing.T) {
	body := []byte(`{"a":1}`)
	sig := Compute([]byte("s"), body)
	if err := verifySignature([]byte("s"), sig, body); err != nil {
		t.Fatalf("verifySignature: %v", err)
	}
}

func TestWebhook_PingEvent_NoOp(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fi := &fakeInval{}
	h := &Handler{Secret: []byte("s3cret"), Inval: fi}
	r := gin.New()
	h.Register(r)
	body := []byte(`{"zen":"hello"}`)
	sig := Compute(h.Secret, body)
	req := httptest.NewRequest("POST", "/webhooks/github", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "ping")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if fi.id.Load() != 0 {
		t.Fatalf("ping should not invalidate; got id=%d", fi.id.Load())
	}
}

func TestWebhook_UnsupportedEvent_Still200(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &Handler{Secret: []byte("s3cret")}
	r := gin.New()
	h.Register(r)
	body := []byte(`{}`)
	sig := Compute(h.Secret, body)
	req := httptest.NewRequest("POST", "/webhooks/github", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "push")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d want 200 (unknown events should be acknowledged)", w.Code)
	}
}

func TestWebhook_InstallationRepositories_AlsoInvalidates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fi := &fakeInval{}
	h := &Handler{Secret: []byte("s3cret"), Inval: fi}
	r := gin.New()
	h.Register(r)
	body := []byte(`{"action":"added","installation":{"id":7},"repositories_added":[{"id":1}]}`)
	sig := Compute(h.Secret, body)
	req := httptest.NewRequest("POST", "/webhooks/github", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "installation_repositories")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if fi.id.Load() != 7 {
		t.Fatalf("invalidator id=%d, want 7", fi.id.Load())
	}
}

func TestWebhook_NoInstallationPayload_Still200(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fi := &fakeInval{}
	h := &Handler{Secret: []byte("s3cret"), Inval: fi}
	r := gin.New()
	h.Register(r)
	// installation event with no installation field
	body := []byte(`{"action":"created"}`)
	sig := Compute(h.Secret, body)
	req := httptest.NewRequest("POST", "/webhooks/github", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "installation")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	if fi.id.Load() != 0 {
		t.Fatalf("no installation payload should not call invalidator, got %d", fi.id.Load())
	}
}

func TestIdOrZero(t *testing.T) {
	if got := idOrZero(payload{}); got != 0 {
		t.Errorf("idOrZero(empty) = %d, want 0", got)
	}
	p := payload{Installation: &struct {
		ID int64 `json:"id"`
	}{ID: 42}}
	if got := idOrZero(p); got != 42 {
		t.Errorf("idOrZero(with id) = %d, want 42", got)
	}
}

func TestRegister_AddsRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &Handler{Secret: []byte("s3cret")}
	r := gin.New()
	h.Register(r)
	// The route should be mounted; any POST without a body should
	// reach the signature check and 401.
	req := httptest.NewRequest("POST", "/webhooks/github", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("status=%d want 401", w.Code)
	}
}
