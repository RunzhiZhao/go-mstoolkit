package jwt

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("invalid token")
)

// TokenVerifier token verifier
type TokenVerifier struct {
	parser *Parser
}

// NewTokenVerifier new a token verifier
func NewTokenVerifier(signingMethod SigningMethod, publicKey []byte) (*TokenVerifier, error) {
	parser, err := newParser(signingMethod, publicKey)
	if err != nil {
		return nil, err
	}
	return &TokenVerifier{
		parser: parser,
	}, nil
}

// Verify verify token
func (v *TokenVerifier) Verify(tokenStr string) (*TokenInfo, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		return v.parser.publicKey, nil
	})
	if err != nil {
		return nil, ErrInvalidToken
	}

	if c, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return &c.TokenInfo, nil
	}

	return nil, ErrInvalidToken
}
