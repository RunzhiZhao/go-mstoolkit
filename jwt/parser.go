package jwt

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidPublicKey = errors.New("invalid public key")
)

type Parser struct {
	signingMethod SigningMethod
	publicKey     interface{}
}

func newParser(signingMethod SigningMethod, publicKey []byte) (*Parser, error) {
	var pk interface{}
	var err error

	switch signingMethod {
	case SigningMethodEdDSA:
		pk, err = jwt.ParseEdPublicKeyFromPEM(publicKey)

	case SigningMethodRS256, SigningMethodRS384, SigningMethodRS512:
		pk, err = jwt.ParseRSAPublicKeyFromPEM(publicKey)

	case SigningMethodES256, SigningMethodES384, SigningMethodES512:
		pk, err = jwt.ParseECPublicKeyFromPEM(publicKey)

	case SigningMethodHS256, SigningMethodHS384, SigningMethodHS512:
		pk = publicKey

	default:
		return nil, ErrUnknownSigningMethod
	}

	if err != nil {
		return nil, ErrInvalidPublicKey
	}

	return &Parser{
		signingMethod: signingMethod,
		publicKey:     pk,
	}, nil
}
