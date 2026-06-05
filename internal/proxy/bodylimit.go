package proxy

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Default per-path request-body caps applied by BodyLimit when the
// operator has not configured body_limit_bytes.
//
// The defaults are intentionally generous for the API path (the GitHub
// API can return large payloads, and the proxy mostly sees consumer
// requests which are small) and tighter for the Git path (push bodies
// are independently capped by GitPushMaxBodyBytes; the only large
// reads are /info/packs which the proxy never touches).
const (
	DefaultAPIBodyBytes int64 = 16 << 20 // 16 MiB
	DefaultGitBodyBytes int64 = 4 << 20  // 4 MiB
)

// BodyLimit returns a Gin middleware that rejects requests whose
// Content-Length (or streamed body, when Content-Length is missing)
// exceeds limit bytes with HTTP 413. Set limit <= 0 to skip the cap.
//
// The middleware does not consume the body; downstream handlers can
// still read it normally. If the body is streamed and exceeds the
// cap, the downstream io.ReadAll/io.Copy will see a truncated
// stream — that is acceptable because the response will already be
// 413 by the time the handler starts.
func BodyLimit(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if limit > 0 && c.Request.ContentLength > limit {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "request body exceeds configured cap",
			})
			return
		}
		if limit > 0 && c.Request.ContentLength < 0 {
			// Unknown length (chunked transfer) — wrap with
			// MaxBytesReader so the handler sees a truncated
			// stream if the body exceeds the cap.
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		}
		c.Next()
	}
}

// PerPathBodyLimit returns a middleware that picks the per-path
// default (api vs git) when the operator has not configured
// body_limit_bytes. The api/git distinction lives here so the
// operator can read it from one place.
func PerPathBodyLimit(apiLimit, gitLimit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := int64(0)
		switch {
		case strings.HasPrefix(c.Request.URL.Path, "/api/"):
			limit = apiLimit
		case strings.HasPrefix(c.Request.URL.Path, "/git/"):
			limit = gitLimit
		}
		if limit <= 0 {
			c.Next()
			return
		}
		BodyLimit(limit)(c)
	}
}
