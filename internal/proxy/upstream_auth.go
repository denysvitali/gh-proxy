package proxy

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// UpstreamAuth guards /v1/tokens. In v1 we support a simple shared-header
// check (e.g. set by an auth-proxy sidecar or an ingress mTLS terminator).
// When ExpectedHeader is empty, the guard is disabled and requests are
// allowed through — config loading refuses to start in that state unless
// explicitly opted out.
type UpstreamAuth struct {
	Header         string // e.g. "X-Forwarded-Identity"
	ExpectedPrefix string // e.g. "spiffe://" — require the header value has this prefix
	SharedToken    string // alternative: match this static token exactly
	TokenHeader    string // header name for SharedToken (default Authorization)
}

// Middleware returns a Gin handler that rejects unauthenticated callers.
func (u UpstreamAuth) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if u.SharedToken != "" {
			name := u.TokenHeader
			if name == "" {
				name = "Authorization"
			}
			got := c.GetHeader(name)
			got = strings.TrimPrefix(got, "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(u.SharedToken)) != 1 {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "upstream auth required"})
				return
			}
		} else if u.Header != "" {
			v := c.GetHeader(u.Header)
			if v == "" || (u.ExpectedPrefix != "" && !strings.HasPrefix(v, u.ExpectedPrefix)) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "upstream identity header missing"})
				return
			}
			c.Set("upstream_identity", v)
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "upstream auth not configured"})
			return
		}
		c.Next()
	}
}
