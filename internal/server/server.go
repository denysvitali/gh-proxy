// Package server assembles the HTTP server, policy engine, and proxy handlers.
package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/denysvitali/gh-proxy/internal/config"
	"github.com/denysvitali/gh-proxy/internal/ghapp"
	"github.com/denysvitali/gh-proxy/internal/policy"
	"github.com/denysvitali/gh-proxy/internal/proxy"
	"github.com/denysvitali/gh-proxy/internal/telemetry"
	"github.com/denysvitali/gh-proxy/internal/token"
	"github.com/denysvitali/gh-proxy/internal/webhook"
)

// Server wraps the HTTP server and its collaborators.
type Server struct {
	cfg    *config.Config
	engine *policy.Engine
	gh     *ghapp.Client
	tele   *telemetry.Providers
	http   *http.Server
}

// policyReloader adapts the config layer to webhook.PolicyReloader.
type policyReloader struct {
	path   string
	engine *policy.Engine
}

func (p *policyReloader) Reload() error {
	doc, err := config.ReadPolicyFile(p.path)
	if err != nil {
		return err
	}
	p.engine.Replace(doc)
	return nil
}

// New constructs a Server from config.
func New(cfg *config.Config) (*Server, error) {
	engine := policy.NewEngine(nil)
	if cfg.PolicyPath != "" {
		doc, err := config.ReadPolicyFile(cfg.PolicyPath)
		if err != nil {
			return nil, err
		}
		engine.Replace(doc)
	}
	logPolicySummary(engine)

	verifier := token.NewVerifier(engine)

	if cfg.GitHub.AppID == 0 {
		return nil, fmt.Errorf("github.app_id is required")
	}
	if cfg.GitHub.PrivateKeyPath == "" {
		return nil, fmt.Errorf("github.private_key_path is required")
	}
	gh, err := ghapp.NewClient(cfg.GitHub.AppID, cfg.GitHub.PrivateKeyPath, cfg.GitHub.APIBaseURL)
	if err != nil {
		return nil, err
	}

	tele, err := telemetry.Setup(context.Background(), cfg.OTelEndpoint, "gh-proxy")
	if err != nil {
		return nil, err
	}

	r := gin.New()
	r.Use(gin.Recovery(), requestLogger(), tele.Middleware())
	r.GET("/healthz", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	// Transparent HTTP client: do not follow redirects. Upstream endpoints
	// like /actions/runs/{id}/logs return a 302 to a presigned blob URL,
	// and callers (e.g. go-github) rely on receiving that 302 verbatim.
	forwardClient := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	proxy.Register(r, proxy.Deps{
		Engine:     engine,
		Tokens:     verifier,
		GitHubApp:  gh,
		APIBaseURL: cfg.GitHub.APIBaseURL,
		GitBaseURL: "https://github.com",
		HTTPClient: forwardClient,
	})

	if cfg.WebhookSecret != "" {
		wh := &webhook.Handler{
			Secret:   []byte(cfg.WebhookSecret),
			Inval:    gh,
			Reloader: &policyReloader{path: cfg.PolicyPath, engine: engine},
			Log:      logrus.StandardLogger(),
		}
		wh.Register(r)
	}

	return &Server{
		cfg:    cfg,
		engine: engine,
		gh:     gh,
		tele:   tele,
		http:   &http.Server{Addr: cfg.ListenAddr, Handler: r, ReadHeaderTimeout: 10 * time.Second},
	}, nil
}

// logPolicySummary emits a concise startup summary of who can do what, to
// make 401/403 debugging easier.
func logPolicySummary(e *policy.Engine) {
	doc := e.Snapshot()
	if doc == nil {
		logrus.Warn("no policy loaded; all requests will fail with 401/403")
		return
	}
	for _, t := range doc.Tenants {
		repos := make([]string, 0, len(t.Repos))
		for _, r := range t.Repos {
			repos = append(repos, fmt.Sprintf("%s (%s)", r.Name, r.Access))
		}
		logrus.WithFields(logrus.Fields{
			"tenant":          t.Name,
			"org":             t.Org,
			"installation_id": t.InstallationID,
			"repos":           repos,
		}).Info("policy: tenant loaded")
	}
	for _, c := range doc.Consumers {
		logrus.WithFields(logrus.Fields{
			"consumer":    c.ID,
			"tenant":      c.Tenant,
			"token_count": len(c.TokenHashes),
		}).Info("policy: consumer loaded")
	}
}

// Run starts the server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		logrus.WithField("addr", s.http.Addr).Info("gh-proxy listening")
		if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.tele.Shutdown(shutdown)
		return s.http.Shutdown(shutdown)
	case err := <-errCh:
		return err
	}
}

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		if c.Request.URL.Path == "/healthz" {
			return
		}
		fields := logrus.Fields{
			"method":      c.Request.Method,
			"path":        c.Request.URL.Path,
			"status":      c.Writer.Status(),
			"latency":     time.Since(start).String(),
			"remote_addr": c.ClientIP(),
		}
		for _, k := range []string{"tenant", "consumer", "repo", "endpoint_class", "auth_reason"} {
			if v, ok := c.Get(k); ok {
				fields[k] = v
			}
		}
		logrus.WithFields(fields).Info("request")
	}
}
