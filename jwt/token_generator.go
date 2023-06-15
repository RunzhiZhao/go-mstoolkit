// Path: jwt/token_parser.go
package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultExpires = time.Hour * 24 * 7
)

// Option is a token generator option
type Option func(*TokenGenerator)

// WithExpires set expires for token
func WithExpires(expires time.Duration) Option {
	return func(t *TokenGenerator) {
		t.expires = expires
	}
}

// TokenGenerator token generator
type TokenGenerator struct {
	signer  *Signer
	expires time.Duration
}

// NewTokenGenerator new token generator
func NewTokenGenerator(signingMethod SigningMethod, privateKey []byte, opts ...Option) (*TokenGenerator, error) {
	signer, err := newSigner(signingMethod, privateKey)
	if err != nil {
		return nil, err
	}
	g := &TokenGenerator{
		signer:  signer,
		expires: defaultExpires,
	}

	for _, opt := range opts {
		opt(g)
	}

	return g, nil
}

// Generate generate token
func (g *TokenGenerator) Generate(info TokenInfo) (string, error) {
	claims := TokenClaims{
		info,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(g.expires)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}
	return jwt.NewWithClaims(g.signer.signingMethod, claims).SignedString(g.signer.privateKey)
}
