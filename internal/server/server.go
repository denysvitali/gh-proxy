// Package server assembles the HTTP server, policy engine, and proxy handlers.
package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/denysvitali/gh-proxy/internal/config"
	"github.com/denysvitali/gh-proxy/internal/ghapp"
	"github.com/denysvitali/gh-proxy/internal/policy"
	"github.com/denysvitali/gh-proxy/internal/proxy"
	"github.com/denysvitali/gh-proxy/internal/token"
)

// Server wraps the HTTP server and its collaborators.
type Server struct {
	cfg    *config.Config
	log    *logrus.Logger
	engine *policy.Engine
	http   *http.Server
}

// New constructs a Server from config.
func New(cfg *config.Config, log *logrus.Logger) (*Server, error) {
	engine := policy.NewEngine(nil)
	if cfg.PolicyPath != "" {
		doc, err := config.ReadPolicyFile(cfg.PolicyPath)
		if err != nil {
			return nil, err
		}
		engine.Replace(doc)
	}

	issuer := token.NewIssuer([]byte(cfg.TokenSigningKey), 15*time.Minute)

	var gh *ghapp.Client
	if cfg.GitHub.AppID != 0 {
		c, err := ghapp.NewClient(cfg.GitHub.AppID, cfg.GitHub.PrivateKeyPath, cfg.GitHub.APIBaseURL)
		if err != nil {
			return nil, err
		}
		gh = c
	}

	r := gin.New()
	r.Use(gin.Recovery(), requestLogger(log))
	r.GET("/healthz", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	proxy.Register(r, proxy.Deps{
		Engine:     engine,
		Tokens:     issuer,
		GitHubApp:  gh,
		APIBaseURL: cfg.GitHub.APIBaseURL,
		GitBaseURL: "https://github.com",
	})

	return &Server{
		cfg:    cfg,
		log:    log,
		engine: engine,
		http:   &http.Server{Addr: cfg.ListenAddr, Handler: r, ReadHeaderTimeout: 10 * time.Second},
	}, nil
}

// Run starts the server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.WithField("addr", s.http.Addr).Info("gh-proxy listening")
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
		return s.http.Shutdown(shutdown)
	case err := <-errCh:
		return err
	}
}

func requestLogger(log *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.WithFields(logrus.Fields{
			"method":  c.Request.Method,
			"path":    c.Request.URL.Path,
			"status":  c.Writer.Status(),
			"latency": time.Since(start).String(),
		}).Info("request")
	}
}
