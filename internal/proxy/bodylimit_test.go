package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestBodyLimitAllowsUnderCap(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/x", BodyLimit(1024), func(c *gin.Context) {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		c.Data(http.StatusOK, "text/plain", body)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/x", bytes.NewReader([]byte("hello")))
	r.ServeHTTP(w, req)
	if w.Code != 200 || w.Body.String() != "hello" {
		t.Fatalf("got %d %q, want 200 hello", w.Code, w.Body.String())
	}
}

func TestBodyLimitRejectsOverCap(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/x", BodyLimit(4), func(c *gin.Context) {
		c.String(http.StatusOK, "should not see this")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/x", bytes.NewReader([]byte("hello world")))
	req.ContentLength = 11
	r.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d, want 413", w.Code)
	}
}

func TestBodyLimitRejectsChunkedOverCap(t *testing.T) {
	// No Content-Length set: simulate a chunked upload.
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/x", BodyLimit(4), func(c *gin.Context) {
		_, err := io.ReadAll(c.Request.Body)
		if err == nil {
			c.String(http.StatusOK, "should not see this")
			return
		}
		c.String(http.StatusBadRequest, err.Error())
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/x", bytes.NewReader([]byte("hello world")))
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	r.ServeHTTP(w, req)
	// MaxBytesReader surfaces an error to the handler (which
	// returns 400) rather than aborting with 413. That is
	// acceptable: the request is still rejected, just with a
	// different status. The important guarantee is that the
	// handler does NOT receive the full oversized body.
	if w.Code == 200 {
		t.Fatalf("got 200, want non-200")
	}
	if strings.Contains(w.Body.String(), "hello world") {
		t.Fatalf("body leaked: %q", w.Body.String())
	}
}

func TestPerPathBodyLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(PerPathBodyLimit(8, 4))
	r.POST("/api/x", func(c *gin.Context) { c.String(200, "api") })
	r.POST("/git/x", func(c *gin.Context) { c.String(200, "git") })

	cases := []struct {
		path string
		body string
		want int
	}{
		{"/api/x", "12345678", 200},
		{"/api/x", "123456789", 413},
		{"/git/x", "1234", 200},
		{"/git/x", "12345", 413},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", c.path, bytes.NewReader([]byte(c.body)))
		req.ContentLength = int64(len(c.body))
		r.ServeHTTP(w, req)
		if w.Code != c.want {
			t.Errorf("%s body=%q: got %d, want %d", c.path, c.body, w.Code, c.want)
		}
	}
}
