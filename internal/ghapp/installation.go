// Package ghapp authenticates as a GitHub App and fetches short-lived
// installation access tokens. Tokens are cached in-memory per installation.
package ghapp

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Client is a minimal GitHub App client: it signs app JWTs and exchanges
// them for installation access tokens.
type Client struct {
	appID      int64
	key        *rsa.PrivateKey
	apiBaseURL string
	http       *http.Client

	mu    sync.Mutex
	cache map[int64]cachedToken
}

type cachedToken struct {
	token   string
	expires time.Time
}

// InstallationToken is what GitHub returns for POST /app/installations/:id/access_tokens.
type InstallationToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewClient builds a client from a PEM-encoded private key on disk.
func NewClient(appID int64, keyPath, apiBaseURL string) (*Client, error) {
	if keyPath == "" {
		return nil, errors.New("ghapp: private key path required")
	}
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ghapp: no PEM block in key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8.
		k, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("ghapp: parse key: %w", err)
		}
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("ghapp: key is not RSA")
		}
		key = rsaKey
	}
	return &Client{
		appID:      appID,
		key:        key,
		apiBaseURL: apiBaseURL,
		http:       &http.Client{Timeout: 15 * time.Second},
		cache:      map[int64]cachedToken{},
	}, nil
}

// AppJWT returns a short-lived JWT signed as the App.
func (c *Client) AppJWT() (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Add(-30 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": c.appID,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return t.SignedString(c.key)
}

// InstallationToken returns a cached installation token or fetches a fresh one.
func (c *Client) InstallationToken(ctx context.Context, installationID int64) (string, error) {
	c.mu.Lock()
	if ct, ok := c.cache[installationID]; ok && time.Until(ct.expires) > time.Minute {
		c.mu.Unlock()
		return ct.token, nil
	}
	c.mu.Unlock()

	jwtStr, err := c.AppJWT()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", c.apiBaseURL, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ghapp: installation token %d: %s", resp.StatusCode, string(body))
	}
	var it InstallationToken
	if err := json.NewDecoder(resp.Body).Decode(&it); err != nil {
		return "", err
	}

	c.mu.Lock()
	c.cache[installationID] = cachedToken{token: it.Token, expires: it.ExpiresAt}
	c.mu.Unlock()
	return it.Token, nil
}
