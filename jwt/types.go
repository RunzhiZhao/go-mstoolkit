package jwt

import "github.com/golang-jwt/jwt/v5"

// TokenInfo token info
type TokenInfo struct {
	UserID uint `json:"user_id,omitempty"`
	RoleID uint `json:"role_id,omitempty"`
}

// TokenClaims token claims
type TokenClaims struct {
	TokenInfo
	jwt.RegisteredClaims
}
