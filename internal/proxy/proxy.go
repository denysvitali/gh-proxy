// Package proxy wires Git smart-HTTP and GitHub API requests through
// per-tenant policy and installation tokens.
package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/denysvitali/gh-proxy/internal/policy"
	"github.com/denysvitali/gh-proxy/internal/token"
)

// InstallationTokenSource supplies and invalidates GitHub App installation
// tokens. The interface keeps proxy request handling independently testable.
type InstallationTokenSource interface {
	InstallationToken(context.Context, int64) (string, error)
	InvalidateInstallation(int64)
}

// Deps bundles the collaborators needed by handlers.
type Deps struct {
	Engine     *policy.Engine
	Tokens     *token.Verifier
	GitHubApp  InstallationTokenSource
	APIBaseURL string
	GitBaseURL string // e.g. https://github.com
	HTTPClient *http.Client

	// GitPushMaxBodyBytes caps the size of a git-receive-pack body
	// that the proxy will read in order to enforce the per-repo
	// ref-name filter (Repo.RefAllow / RefDeny / ProtectedRefs). A
	// push whose body exceeds this cap is rejected with HTTP 413.
	// Zero or negative means use proxy.MaxDefaultPushBody.
	GitPushMaxBodyBytes int64

	// APIBodyLimitBytes is the global request-body cap applied to
	// /api/* routes. Zero means use DefaultAPIBodyBytes.
	APIBodyLimitBytes int64

	// GitBodyLimitBytes is the global request-body cap applied to
	// /git/* routes. Zero means use DefaultGitBodyBytes.
	GitBodyLimitBytes int64
}

// pushBodyCap returns the effective per-push body cap.
func (d Deps) pushBodyCap() int64 {
	if d.GitPushMaxBodyBytes > 0 {
		return d.GitPushMaxBodyBytes
	}
	return MaxDefaultPushBody
}

// Register attaches proxy routes to the router.
func Register(r *gin.Engine, d Deps) {
	apiLimit := d.APIBodyLimitBytes
	if apiLimit <= 0 {
		apiLimit = DefaultAPIBodyBytes
	}
	gitLimit := d.GitBodyLimitBytes
	if gitLimit <= 0 {
		gitLimit = DefaultGitBodyBytes
	}
	// Per-route body limit so the cap can differ for /api/* (16 MiB)
	// and /git/* (4 MiB). Requests over the cap are rejected with
	// 413 before the auth middleware runs.
	apiGroup := r.Group("/api", BodyLimit(apiLimit))
	gitGroup := r.Group("/git", BodyLimit(gitLimit))
	authedAPI := apiGroup.Group("/", d.authMiddleware())
	authedGit := gitGroup.Group("/", d.authMiddleware())
	authedAPI.Any("/repos/:org/:repo/*rest", d.apiProxy)
	authedGit.Any("/:org/:repo/*rest", d.gitProxy)
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
		// Per-consumer IP allowlist. Empty list = no restriction.
		// The lookup is a re-read of the consumer entry, but the
		// policy.Engine is RW-lock protected and Consumer returns
		// by value, so the read is cheap and lock-free on the hot
		// path.
		if cons, ok := d.Engine.Consumer(claims.Consumer); ok && len(cons.IPAllow) > 0 {
			if !policy.IPAllowed(cons.IPAllow, net.ParseIP(c.ClientIP())) {
				logrus.WithFields(logrus.Fields{
					"remote_addr": c.ClientIP(),
					"path":        c.Request.URL.Path,
					"consumer":    claims.Consumer,
					"ip_allow":    cons.IPAllow,
				}).Warn("auth: ip not in allowlist")
				c.Set("auth_reason", "ip not allowed for consumer")
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "ip not allowed for consumer"})
				return
			}
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
		denyPolicy(c, claims, org, repo, endpoint, write, dec.Reason)
		return
	}

	// For push operations, enforce the per-repo ref-name filter
	// (Repo.RefAllow / RefDeny / ProtectedRefs). The body is
	// consumed into a buffer so it can be re-sent upstream — the
	// cap is small (default 1 MiB) so memory is bounded. On any
	// framing error the request is allowed through and a warning
	// is logged; this is the "parse-fail-allow" fallback documented
	// in DESIGN.md.
	var bodyBytes []byte
	if write {
		buf, err := io.ReadAll(io.LimitReader(c.Request.Body, d.pushBodyCap()+1))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		if int64(len(buf)) > d.pushBodyCap() {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "git push body exceeds configured cap"})
			return
		}
		bodyBytes = buf
		if denied := d.checkPushRefs(claims.Tenant, repo, bodyBytes); denied != "" {
			logrus.WithFields(logrus.Fields{
				"tenant":   claims.Tenant,
				"consumer": claims.Consumer,
				"org":      org,
				"repo":     repo,
				"ref":      denied,
			}).Warn("policy: push ref denied")
			c.Set("auth_reason", "push ref denied: "+denied)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "push ref denied: " + denied})
			return
		}
	}

	tenant, _ := d.Engine.Tenant(claims.Tenant)
	instToken, err := d.GitHubApp.InstallationToken(c.Request.Context(), tenant.InstallationID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	target, _ := url.Parse(fmt.Sprintf("%s/%s/%s.git%s", strings.TrimRight(d.GitBaseURL, "/"), org, repo, rest))
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + instToken))
	d.forwardGit(c, target, "Basic "+basic, bodyBytes)
}

// checkPushRefs parses the receive-pack body and returns the first
// pushed refname that is forbidden by the repo's ref filter, or "" if
// every ref is permitted (or no filter is configured). On a framing
// error it logs a warning and returns "" — the "parse-fail-allow"
// fallback, see DESIGN.md.
func (d Deps) checkPushRefs(tenant, repo string, body []byte) string {
	refs, err := ParseReceivePackRefs(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			// Already enforced upstream of this function; we
			// shouldn't get here. Be safe and fail closed
			// (forbid) so the request is rejected, not silently
			// passed.
			return "body too large"
		}
		logParseFallback("", repo, err.Error())
		return ""
	}
	return d.Engine.CheckPushRefs(tenant, repo, refs)
}

func denyPolicy(c *gin.Context, claims token.Claims, org, repo string, endpoint policy.EndpointClass, write bool, reason string) {
	logrus.WithFields(logrus.Fields{
		"tenant":         claims.Tenant,
		"consumer":       claims.Consumer,
		"org":            org,
		"repo":           repo,
		"endpoint_class": string(endpoint),
		"write":          write,
		"reason":         reason,
	}).Warn("policy: denied")
	c.Set("auth_reason", reason)
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": reason})
}

func (d Deps) apiProxy(c *gin.Context) {
	claims := c.MustGet(string(claimsKey)).(token.Claims)
	org := c.Param("org")
	repo := c.Param("repo")
	rest := c.Param("rest")

	endpoint := classifyAPI(c.Request.Method, rest)
	write := c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead
	c.Set("tenant", claims.Tenant)
	c.Set("repo", org+"/"+repo)
	c.Set("endpoint_class", string(endpoint))
	if dec := d.Engine.Evaluate(policy.Request{
		Tenant: claims.Tenant, Org: org, Repo: repo, Write: write, Endpoint: endpoint,
	}); !dec.Allowed {
		denyPolicy(c, claims, org, repo, endpoint, write, dec.Reason)
		return
	}

	tenant, _ := d.Engine.Tenant(claims.Tenant)
	instToken, err := d.GitHubApp.InstallationToken(c.Request.Context(), tenant.InstallationID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	target, _ := url.Parse(fmt.Sprintf("%s/repos/%s/%s%s", strings.TrimRight(d.APIBaseURL, "/"), org, repo, rest))
	if shouldRefreshArtifactToken(c.Request.Method, rest) {
		d.forwardArtifact(c, target, tenant.InstallationID, instToken)
		return
	}
	d.forward(c, target, "token "+instToken)
}

// forwardArtifact retries a read-only artifact request once with a freshly
// minted installation token when GitHub answers 404. Installation tokens keep
// the repository and permission scope they had when they were created, so an
// otherwise valid cached token can temporarily make a newly granted artifact
// look absent. A second 404 is forwarded unchanged.
func (d Deps) forwardArtifact(c *gin.Context, target *url.URL, installationID int64, instToken string) {
	resp, err := d.doRequest(c, target, "token "+instToken, c.Request.Body)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()
		d.GitHubApp.InvalidateInstallation(installationID)
		instToken, err = d.GitHubApp.InstallationToken(c.Request.Context(), installationID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		resp, err = d.doRequest(c, target, "token "+instToken, http.NoBody)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
	}
	d.writeResponse(c, resp)
}

func shouldRefreshArtifactToken(method, rest string) bool {
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	return strings.HasPrefix(rest, "/actions/artifacts/")
}

func (d Deps) forward(c *gin.Context, target *url.URL, authz string) {
	d.forwardWithBody(c, target, authz, c.Request.Body)
}

// forwardGit forwards a git smart-HTTP request to upstream.
//
// The body is taken from the supplied buffer when one is provided — this
// is the write path, where the push handler has already drained
// c.Request.Body into a []byte in order to run the ref-filter check
// (see gitProxy).
//
// When body is nil, the inbound request body is forwarded as-is. This is
// the read path (GET /info/refs, GET /git-upload-pack), where no
// buffering has occurred and any body the client sent — even on a GET,
// in principle — must be preserved end-to-end rather than silently
// dropped.
//
// If both body and c.Request.Body are nil, http.NoBody is used as an
// explicit no-body sentinel; net/http treats nil and NoBody equivalently
// on input, but NoBody avoids any nil-deref risk in transport code.
//
// Callers must not consume c.Request.Body upstream of this call on the
// read path; doing so would leave an empty body to forward.
func (d Deps) forwardGit(c *gin.Context, target *url.URL, authz string, body []byte) {
	var r io.Reader
	switch {
	case body != nil:
		r = bytes.NewReader(body)
	case c.Request.Body != nil:
		r = c.Request.Body
	default:
		r = http.NoBody
	}
	d.forwardWithBody(c, target, authz, r)
}

func (d Deps) forwardWithBody(c *gin.Context, target *url.URL, authz string, body io.Reader) {
	resp, err := d.doRequest(c, target, authz, body)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	d.writeResponse(c, resp)
}

func (d Deps) doRequest(c *gin.Context, target *url.URL, authz string, body io.Reader) (*http.Response, error) {
	target.RawQuery = c.Request.URL.RawQuery
	client := d.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	out, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, target.String(), body)
	if err != nil {
		return nil, err
	}
	copyHeaders(out.Header, c.Request.Header)
	out.Header.Set("Authorization", authz)
	out.Header.Del("Cookie")

	resp, err := client.Do(out)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (d Deps) writeResponse(c *gin.Context, resp *http.Response) {
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

// classifyAPI maps a (method, rest-path) pair to an endpoint class. The
// PR sub-tree is method-aware so that POST /pulls (create), POST
// /pulls/{id}/reviews (review), and PUT /pulls/{id}/merge (merge) can be
// authorized independently.
func classifyAPI(method, rest string) policy.EndpointClass {
	switch {
	case strings.HasPrefix(rest, "/actions"):
		return policy.EndpointWorkflows
	case strings.HasPrefix(rest, "/pulls"):
		return classifyPulls(method, rest)
	case strings.HasPrefix(rest, "/git/refs"), strings.HasPrefix(rest, "/refs"):
		return policy.EndpointRefs
	default:
		return policy.EndpointRefs
	}
}

// classifyPulls handles the /pulls sub-tree. It assumes rest has the
// "/pulls" prefix; callers should only invoke it from classifyAPI.
//
//	/pulls                           (GET)    -> api.pulls
//	/pulls                           (POST)   -> api.pulls.create
//	/pulls/{id}                      (GET)    -> api.pulls
//	/pulls/{id}                      (PATCH)  -> api.pulls.create
//	/pulls/{id}/merge                (PUT/POST) -> api.pulls.merge
//	/pulls/{id}/reviews              (POST)   -> api.pulls.review
//	/pulls/{id}/comments             (POST)   -> api.pulls.review
//	/pulls/{id}/reviews/{rid}/events (POST)   -> api.pulls.merge (approve/request-changes)
//	/pulls/{id}/*                    (other)  -> api.pulls.create
func classifyPulls(method, rest string) policy.EndpointClass {
	isRead := method == http.MethodGet || method == http.MethodHead
	if rest == "/pulls" {
		if isRead {
			return policy.EndpointPullRequest
		}
		return policy.EndpointPullsCreate
	}
	after, ok := strings.CutPrefix(rest, "/pulls/")
	if !ok {
		return policy.EndpointPullRequest
	}
	id, subpath, _ := strings.Cut(after, "/")
	if id == "" {
		return policy.EndpointPullRequest
	}
	if subpath == "" {
		// /pulls/{id}
		if isRead {
			return policy.EndpointPullRequest
		}
		return policy.EndpointPullsCreate
	}
	if isRead {
		return policy.EndpointPullRequest
	}
	first := subpath
	if i := strings.IndexByte(subpath, '/'); i >= 0 {
		first = subpath[:i]
	}
	switch first {
	case "merge":
		// GitHub accepts PUT (and historically POST) on /merge. Anything
		// else (e.g. DELETE /merge) falls through to the generic write
		// bucket.
		if method == http.MethodPut || method == http.MethodPost {
			return policy.EndpointPullsMerge
		}
		return policy.EndpointPullsCreate
	case "reviews":
		// POST /pulls/{id}/reviews/{rid}/events is the approve /
		// request-changes submission path. It MUST be classified as
		// merge-class so an AI consumer that can comment cannot
		// self-approve.
		if method == http.MethodPost && strings.HasSuffix(subpath, "/events") {
			return policy.EndpointPullsMerge
		}
		return policy.EndpointPullsReview
	case "comments":
		return policy.EndpointPullsReview
	default:
		return policy.EndpointPullsCreate
	}
}
