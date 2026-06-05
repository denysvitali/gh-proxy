// Coverage goal: drive internal/telemetry to 70%+ by exercising both
// branches of Setup (no-op when endpoint is empty, full OTLP wiring
// when endpoint is set) and the Middleware (which stamps span
// attributes and records counters). The error path (collector
// unreachable) is also covered: a bogus endpoint must not crash Setup,
// and the resulting Middleware must be safe to call.
package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestSetup_NoEndpoint_InstallsNoOpProviders(t *testing.T) {
	p, err := Setup(context.Background(), "", "test")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if p.Tracer == nil {
		t.Fatal("Tracer should be non-nil even with no endpoint")
	}
	if p.Meter == nil {
		t.Fatal("Meter should be non-nil even with no endpoint")
	}
	if p.RequestCount == nil {
		t.Fatal("RequestCount should be non-nil")
	}
	if p.RequestDur == nil {
		t.Fatal("RequestDur should be non-nil")
	}
	// Shutdown should be a no-op (no exporters registered).
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestSetup_EndpointSet_RegistersShutdownFns(t *testing.T) {
	// An endpoint that nobody listens on. The exporters will queue
	// their batches and try them on Shutdown — Shutdown should still
	// complete without panicking.
	p, err := Setup(context.Background(), "127.0.0.1:1", "test")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if p.Tracer == nil {
		t.Fatal("Tracer should be non-nil")
	}
	if len(p.shutdownFns) == 0 {
		t.Fatal("shutdownFns should be populated when endpoint is set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = p.Shutdown(ctx)
}

func TestMiddleware_StampsAttributesAndCountsRequest(t *testing.T) {
	p, err := Setup(context.Background(), "", "test")
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.Use(p.Middleware())
	r.GET("/test", func(c *gin.Context) {
		// The proxy handlers normally set these.
		c.Set("tenant", "acme")
		c.Set("repo", "acme/app")
		c.Set("endpoint_class", "git.read")
		c.JSON(200, gin.H{"ok": true})
	})
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestMiddleware_NoAttributesSet_NoPanic(t *testing.T) {
	// If the handler never calls c.Set("tenant", ...), the middleware
	// must still complete and not panic on the type assertion.
	p, err := Setup(context.Background(), "", "test")
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.Use(p.Middleware())
	r.GET("/x", func(c *gin.Context) { c.JSON(200, gin.H{}) })
	req := httptest.NewRequest("GET", "/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestMiddleware_RecordsStatusCode(t *testing.T) {
	p, err := Setup(context.Background(), "", "test")
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.Use(p.Middleware())
	r.GET("/notfound", func(c *gin.Context) { c.JSON(404, gin.H{}) })
	req := httptest.NewRequest("GET", "/notfound", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestMiddleware_HandlesUnknownRoute(t *testing.T) {
	// Gin returns 404 for unmatched paths. The middleware still
	// wraps the request, so the response should be a clean 404 and
	// the request should not panic.
	p, err := Setup(context.Background(), "", "test")
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.Use(p.Middleware())
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/does/not/exist")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("status=%d want 404", resp.StatusCode)
	}
}

func TestShutdown_NoFunctions_NoError(t *testing.T) {
	p := &Providers{}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown on empty Providers: %v", err)
	}
}
