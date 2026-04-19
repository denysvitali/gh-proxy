// Package token issues and validates short-lived consumer tokens.
//
// Tokens are opaque to GitHub: they carry only the tenant and consumer
// identity plus an expiry, and are signed with an HMAC key held by the proxy.
// Consumers never receive GitHub App credentials or installation tokens.
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Claims is the payload embedded in a consumer token.
type Claims struct {
	Tenant   string `json:"t"`
	Consumer string `json:"c"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
	Nonce    string `json:"n,omitempty"`
}

// Valid reports whether the claims are non-empty and unexpired at now.
func (c Claims) Valid(now time.Time) error {
	if c.Tenant == "" || c.Consumer == "" {
		return errors.New("token: missing tenant or consumer")
	}
	if c.Expiry == 0 || now.Unix() >= c.Expiry {
		return errors.New("token: expired")
	}
	return nil
}

// Issuer signs Claims into tokens and verifies tokens back to Claims.
type Issuer struct {
	key []byte
	ttl time.Duration
	now func() time.Time
}

// NewIssuer constructs an Issuer. ttl must be positive.
func NewIssuer(key []byte, ttl time.Duration) *Issuer {
	return &Issuer{key: key, ttl: ttl, now: time.Now}
}

// Issue mints a token for a consumer of a tenant.
func (i *Issuer) Issue(tenant, consumer string) (string, Claims, error) {
	now := i.now()
	claims := Claims{
		Tenant:   tenant,
		Consumer: consumer,
		IssuedAt: now.Unix(),
		Expiry:   now.Add(i.ttl).Unix(),
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", claims, err
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	sig := i.sign(payload)
	return payload + "." + sig, claims, nil
}

// Verify parses and validates a token, returning its claims on success.
func (i *Issuer) Verify(tok string) (Claims, error) {
	var claims Claims
	dot := -1
	for idx := 0; idx < len(tok); idx++ {
		if tok[idx] == '.' {
			dot = idx
			break
		}
	}
	if dot < 0 {
		return claims, errors.New("token: malformed")
	}
	payload, sig := tok[:dot], tok[dot+1:]
	want := i.sign(payload)
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return claims, errors.New("token: bad signature")
	}
	body, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return claims, fmt.Errorf("token: decode: %w", err)
	}
	if err := json.Unmarshal(body, &claims); err != nil {
		return claims, fmt.Errorf("token: parse: %w", err)
	}
	if err := claims.Valid(i.now()); err != nil {
		return claims, err
	}
	return claims, nil
}

func (i *Issuer) sign(payload string) string {
	m := hmac.New(sha256.New, i.key)
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
