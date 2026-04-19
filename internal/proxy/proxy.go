// Package proxy wires Git smart-HTTP and GitHub API requests through
// per-tenant policy and installation tokens.
package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/denysvitali/gh-proxy/internal/ghapp"
	"github.com/denysvitali/gh-proxy/internal/policy"
	"github.com/denysvitali/gh-proxy/internal/token"
)

// Deps bundles the collaborators needed by handlers.
type Deps struct {
	Engine     *policy.Engine
	Tokens     *token.Verifier
	GitHubApp  *ghapp.Client
	APIBaseURL string
	GitBaseURL string // e.g. https://github.com
	HTTPClient *http.Client
}

// Register attaches proxy routes to the router.
func Register(r *gin.Engine, d Deps) {
	authed := r.Group("/", d.authMiddleware())
	authed.Any("/git/:org/:repo/*rest", d.gitProxy)
	authed.Any("/api/repos/:org/:repo/*rest", d.apiProxy)
}

type ctxKey string

const claimsKey ctxKey = "claims"

func (d Deps) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		scheme := authScheme(h)
		c.Set("auth_scheme", scheme)

		tok, ok := extractToken(h)
		if !ok {
			reason := "no Authorization header"
			if h != "" {
				reason = fmt.Sprintf("unsupported or malformed %q credential", scheme)
			}
			logrus.WithFields(logrus.Fields{
				"remote_addr": c.ClientIP(),
				"path":        c.Request.URL.Path,
				"auth_scheme": scheme,
				"reason":      reason,
			}).Warn("auth: rejected")
			c.Set("auth_reason", reason)
			// Challenge the client so Git (and other HTTP clients) will retry
			// with Basic credentials from their credential helper.
			c.Header("WWW-Authenticate", `Basic realm="gh-proxy"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": reason})
			return
		}

		// Split out the consumer id for logging, so failures point at a name.
		id, _, _ := strings.Cut(tok, ".")
		c.Set("consumer", id)

		claims, err := d.Tokens.Verify(tok)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"remote_addr": c.ClientIP(),
				"path":        c.Request.URL.Path,
				"auth_scheme": scheme,
				"consumer":    id,
				"reason":      err.Error(),
			}).Warn("auth: rejected")
			c.Set("auth_reason", err.Error())
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		c.Set(string(claimsKey), claims)
		c.Set("tenant", claims.Tenant)
		c.Set("consumer", claims.Consumer)
		c.Next()
	}
}

func authScheme(h string) string {
	if h == "" {
		return "none"
	}
	if i := strings.IndexByte(h, ' '); i > 0 {
		return strings.ToLower(h[:i])
	}
	return "unknown"
}

// extractToken returns the "<id>.<secret>" token carried by the Authorization
// header. Bearer is preferred. Basic is supported for Git over HTTP, which
// turns `https://<user>:<pass>@host/…` into `Authorization: Basic …` and has
// no native way to send a Bearer.
//
// Basic decoding rules:
//   - If the username already contains a ".", the username is taken as the
//     full token (this is what Git produces from `https://<id>.<secret>@host`).
//   - Otherwise the token is reconstructed as `<user>.<pass>`, letting
//     credential helpers store the consumer id and secret in the canonical
//     user/password fields.
func extractToken(h string) (string, bool) {
	switch {
	case strings.HasPrefix(h, "Bearer "):
		t := strings.TrimPrefix(h, "Bearer ")
		return t, t != ""
	case strings.HasPrefix(h, "Basic "):
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Basic "))
		if err != nil {
			return "", false
		}
		user, pass, ok := strings.Cut(string(raw), ":")
		if !ok || user == "" {
			return "", false
		}
		if strings.Contains(user, ".") {
			return user, true
		}
		if pass == "" {
			return "", false
		}
		return user + "." + pass, true
	}
	return "", false
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
	c.Set("tenant", claims.Tenant)
	c.Set("repo", org+"/"+repo)
	c.Set("endpoint_class", string(endpoint))

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
	c.Set("tenant", claims.Tenant)
	c.Set("repo", org+"/"+repo)
	c.Set("endpoint_class", string(endpoint))
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
	defer func() { _ = resp.Body.Close() }()
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
