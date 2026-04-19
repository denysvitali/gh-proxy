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
