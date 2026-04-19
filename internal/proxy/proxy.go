// Package proxy wires Git smart-HTTP and GitHub API requests through
// per-tenant policy and installation tokens.
package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/denysvitali/gh-proxy/internal/ghapp"
	"github.com/denysvitali/gh-proxy/internal/policy"
	"github.com/denysvitali/gh-proxy/internal/token"
)

// Deps bundles the collaborators needed by handlers.
type Deps struct {
	Engine     *policy.Engine
	Tokens     *token.Issuer
	GitHubApp  *ghapp.Client
	APIBaseURL string
	GitBaseURL string // e.g. https://github.com
	HTTPClient *http.Client
}

// Register attaches proxy routes to the router.
func Register(r *gin.Engine, d Deps) {
	r.POST("/v1/tokens", d.issueToken)

	authed := r.Group("/", d.authMiddleware())
	authed.Any("/git/:org/:repo/*rest", d.gitProxy)
	authed.Any("/api/repos/:org/:repo/*rest", d.apiProxy)
}

type issueReq struct {
	Tenant   string `json:"tenant" binding:"required"`
	Consumer string `json:"consumer" binding:"required"`
}

func (d Deps) issueToken(c *gin.Context) {
	// NOTE: authentication of the identity requesting a token is expected to
	// be handled by an upstream mechanism (mTLS, OIDC, k8s SA token). This
	// endpoint assumes that upstream check succeeded.
	var req issueReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, ok := d.Engine.Tenant(req.Tenant); !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown tenant"})
		return
	}
	tok, claims, err := d.Tokens.Issue(req.Tenant, req.Consumer)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": tok, "expires_at": claims.Expiry})
}

type ctxKey string

const claimsKey ctxKey = "claims"

func (d Deps) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		claims, err := d.Tokens.Verify(strings.TrimPrefix(h, "Bearer "))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		c.Set(string(claimsKey), claims)
		c.Next()
	}
}

func (d Deps) gitProxy(c *gin.Context) {
	claims := c.MustGet(string(claimsKey)).(token.Claims)
	org := c.Param("org")
	repo := strings.TrimSuffix(c.Param("repo"), ".git")
	rest := c.Param("rest")

	write := isGitWrite(rest, c.Request)
	endpoint := policy.EndpointGitRead
	if write {
		endpoint = policy.EndpointGitWrite
	}

	if dec := d.Engine.Evaluate(policy.Request{
		Tenant: claims.Tenant, Org: org, Repo: repo, Write: write, Endpoint: endpoint,
	}); !dec.Allowed {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": dec.Reason})
		return
	}

	tenant, _ := d.Engine.Tenant(claims.Tenant)
	instToken, err := d.GitHubApp.InstallationToken(c.Request.Context(), tenant.InstallationID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	target, _ := url.Parse(fmt.Sprintf("%s/%s/%s.git%s", strings.TrimRight(d.GitBaseURL, "/"), org, repo, rest))
	d.forward(c, target, "x-access-token", instToken)
}

func (d Deps) apiProxy(c *gin.Context) {
	claims := c.MustGet(string(claimsKey)).(token.Claims)
	org := c.Param("org")
	repo := c.Param("repo")
	rest := c.Param("rest")

	endpoint := classifyAPI(rest)
	write := c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead
	if dec := d.Engine.Evaluate(policy.Request{
		Tenant: claims.Tenant, Org: org, Repo: repo, Write: write, Endpoint: endpoint,
	}); !dec.Allowed {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": dec.Reason})
		return
	}

	tenant, _ := d.Engine.Tenant(claims.Tenant)
	instToken, err := d.GitHubApp.InstallationToken(c.Request.Context(), tenant.InstallationID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	target, _ := url.Parse(fmt.Sprintf("%s/repos/%s/%s%s", strings.TrimRight(d.APIBaseURL, "/"), org, repo, rest))
	d.forward(c, target, "token", instToken)
}

func (d Deps) forward(c *gin.Context, target *url.URL, scheme, token string) {
	target.RawQuery = c.Request.URL.RawQuery
	client := d.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	out, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, target.String(), c.Request.Body)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	copyHeaders(out.Header, c.Request.Header)
	out.Header.Set("Authorization", scheme+" "+token)
	out.Header.Del("Cookie")

	resp, err := client.Do(out)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	copyHeaders(c.Writer.Header(), resp.Header)
	c.Writer.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(c.Writer, resp.Body)
}

func copyHeaders(dst, src http.Header) {
	hop := map[string]bool{
		"Connection": true, "Proxy-Connection": true, "Keep-Alive": true,
		"Transfer-Encoding": true, "Upgrade": true, "Te": true, "Trailers": true,
		"Authorization": true,
	}
	for k, vs := range src {
		if hop[k] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// isGitWrite is a best-effort classifier for Git smart HTTP requests.
// A push corresponds to service=git-receive-pack.
func isGitWrite(path string, r *http.Request) bool {
	if strings.HasSuffix(path, "/git-receive-pack") {
		return true
	}
	if strings.HasSuffix(path, "/info/refs") && r.URL.Query().Get("service") == "git-receive-pack" {
		return true
	}
	return false
}

// classifyAPI maps a trailing API path to an endpoint class.
func classifyAPI(rest string) policy.EndpointClass {
	switch {
	case strings.HasPrefix(rest, "/actions"):
		return policy.EndpointWorkflows
	case strings.HasPrefix(rest, "/pulls"):
		return policy.EndpointPullRequest
	case strings.HasPrefix(rest, "/git/refs"), strings.HasPrefix(rest, "/refs"):
		return policy.EndpointRefs
	default:
		return policy.EndpointRefs
	}
}

// Ensure context import is kept for future streaming work.
var _ = context.Background
