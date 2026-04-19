// Package webhook receives GitHub App webhook events and invalidates caches
// or reloads policy. Signature verification follows the standard
// X-Hub-Signature-256 HMAC-SHA256 scheme.
package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// Invalidator is implemented by anything that caches installation-scoped state.
type Invalidator interface {
	InvalidateInstallation(id int64)
}

// PolicyReloader reloads the policy document from disk.
type PolicyReloader interface {
	Reload() error
}

// Handler is a Gin handler factory.
type Handler struct {
	Secret   []byte
	Inval    Invalidator
	Reloader PolicyReloader
	Log      *logrus.Logger
}

// Register mounts the webhook endpoint on r.
func (h *Handler) Register(r *gin.Engine) {
	r.POST("/webhooks/github", h.serve)
}

type payload struct {
	Action       string `json:"action"`
	Installation *struct {
		ID int64 `json:"id"`
	} `json:"installation"`
}

func (h *Handler) serve(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := verifySignature(h.Secret, c.GetHeader("X-Hub-Signature-256"), body); err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	event := c.GetHeader("X-GitHub-Event")
	var p payload
	_ = json.Unmarshal(body, &p)

	switch event {
	case "installation", "installation_repositories":
		if p.Installation != nil && h.Inval != nil {
			h.Inval.InvalidateInstallation(p.Installation.ID)
		}
		if h.Log != nil {
			h.Log.WithField("installation", idOrZero(p)).Info("installation event; cache invalidated")
		}
	case "ping":
		// no-op
	default:
		// Unknown events are accepted (2xx) but ignored — GitHub will retry on 5xx.
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func idOrZero(p payload) int64 {
	if p.Installation == nil {
		return 0
	}
	return p.Installation.ID
}

// verifySignature validates the X-Hub-Signature-256 header against secret.
func verifySignature(secret []byte, header string, body []byte) error {
	if len(secret) == 0 {
		return errors.New("webhook: secret not configured")
	}
	const prefix = "sha256="
	if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
		return errors.New("webhook: missing or malformed signature")
	}
	want, err := hex.DecodeString(header[len(prefix):])
	if err != nil {
		return errors.New("webhook: bad signature encoding")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	got := mac.Sum(nil)
	if !hmac.Equal(want, got) {
		return errors.New("webhook: signature mismatch")
	}
	return nil
}

// Compute is a helper exposed for tests.
func Compute(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

var _ = bytes.NewReader // keep import for future streaming body replay
