// Package token validates static bearer tokens presented by consumers.
//
// Tokens are opaque to GitHub. Each token has the form "<consumer-id>.<secret>".
// Consumers are defined in the policy document and carry one or more bcrypt
// hashes of their secret; the verifier looks the consumer up by id and
// constant-time-compares the presented secret against each stored hash.
package token

import (
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/denysvitali/gh-proxy/internal/policy"
)

// Claims is the identity extracted from a verified token.
type Claims struct {
	Tenant   string
	Consumer string
}

// ConsumerLookup resolves a consumer id to its policy entry.
type ConsumerLookup interface {
	Consumer(id string) (*policy.Consumer, bool)
}

// Verifier validates presented tokens against consumers in the policy.
type Verifier struct {
	lookup ConsumerLookup
}

// NewVerifier returns a Verifier backed by the given lookup.
func NewVerifier(lookup ConsumerLookup) *Verifier {
	return &Verifier{lookup: lookup}
}

// ErrMalformed is returned when the token does not contain a "." separator.
var ErrMalformed = errors.New("token: malformed")

// ErrUnknownConsumer is returned when the token's consumer id is not in policy.
var ErrUnknownConsumer = errors.New("token: unknown consumer")

// ErrBadSecret is returned when no stored hash matches the presented secret.
var ErrBadSecret = errors.New("token: bad secret")

// Verify parses the token and returns its Claims on success.
func (v *Verifier) Verify(tok string) (Claims, error) {
	id, secret, ok := strings.Cut(tok, ".")
	if !ok || id == "" || secret == "" {
		return Claims{}, ErrMalformed
	}
	c, ok := v.lookup.Consumer(id)
	if !ok {
		return Claims{}, ErrUnknownConsumer
	}
	for _, h := range c.TokenHashes {
		if err := bcrypt.CompareHashAndPassword([]byte(h), []byte(secret)); err == nil {
			return Claims{Tenant: c.Tenant, Consumer: c.ID}, nil
		}
	}
	return Claims{}, ErrBadSecret
}

// Hash returns a bcrypt hash of secret at the default cost. Exposed for the
// `hash-token` helper command.
func Hash(secret string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
