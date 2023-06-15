package jwt

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidPrivateKey    = errors.New("invalid private key")
	ErrUnknownSigningMethod = errors.New("unknown signing method")
)

// SigningMethod 签名方法
type SigningMethod string

const (
	// SigningMethodEdDSA EdDSA ed25519
	SigningMethodEdDSA SigningMethod = "EdDSA"

	// SigningMethodRS256 rsa 256
	SigningMethodRS256 SigningMethod = "RS256"
	// SigningMethodRS384 rsa 384
	SigningMethodRS384 SigningMethod = "RS384"
	// SigningMethodRS512 rsa 512
	SigningMethodRS512 SigningMethod = "RS512"

	// SigningMethodES256 ecdsa 256
	SigningMethodES256 SigningMethod = "ES256"
	// SigningMethodES384 ecdsa 384
	SigningMethodES384 SigningMethod = "ES384"
	// SigningMethodES512 ecdsa 512
	SigningMethodES512 SigningMethod = "ES512"

	// SigningMethodHS256 hmac sha256
	SigningMethodHS256 SigningMethod = "HS256"
	// SigningMethodHS384 hmac sha384
	SigningMethodHS384 SigningMethod = "HS384"
	// SigningMethodHS512 hmac sha512
	SigningMethodHS512 SigningMethod = "HS512"
)

// Signer .
type Signer struct {
	signingMethod jwt.SigningMethod
	privateKey    interface{}
}

func newSigner(signingMethod SigningMethod, pkByte []byte) (*Signer, error) {
	var privateKey interface{}
	var err error
	var jwtSigningMethod jwt.SigningMethod

	switch signingMethod {
	case SigningMethodEdDSA:
		jwtSigningMethod = jwt.SigningMethodEdDSA
		privateKey, err = jwt.ParseEdPrivateKeyFromPEM(pkByte)

	case SigningMethodRS256, SigningMethodRS384, SigningMethodRS512:
		jwtSigningMethod = jwt.SigningMethodRS256
		privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(pkByte)

	case SigningMethodES256, SigningMethodES384, SigningMethodES512:
		jwtSigningMethod = jwt.SigningMethodES256
		privateKey, err = jwt.ParseECPrivateKeyFromPEM(pkByte)

	case SigningMethodHS256, SigningMethodHS384, SigningMethodHS512:
		jwtSigningMethod = jwt.SigningMethodHS256
		privateKey = pkByte

	default:
		return nil, ErrUnknownSigningMethod
	}

	if err != nil {
		return nil, ErrInvalidPrivateKey
	}

	return &Signer{
		signingMethod: jwtSigningMethod,
		privateKey:    privateKey,
	}, nil
}
