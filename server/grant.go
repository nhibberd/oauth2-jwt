package server

import (
	"crypto"
	"fmt"
	"time"

	"formation.engineering/library/lib/telemetry/v1"
	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

type Config struct {
	PrivateKey crypto.PrivateKey
}

type TenantID = string

type BearerToken = string

type BearerResponse struct {
	Token     string `json:"access_token"`
	TokenType string `json:"token_type"`
	ExpiresIn int64  `json:"expires_in"`
}

func Grant(b telemetry.Builder, x Config, tenant TenantID, requestDuration *int64) (*BearerResponse, error) {
	signer, err :=
		jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: x.PrivateKey}, (&jose.SignerOptions{}))
	if err != nil {
		return nil, errors.WithMessage(err, "creating server signer")
	}

	grantDuration := GrantDuration

	if requestDuration != nil {
		grantDuration = time.Duration(*requestDuration) * time.Second
	}

	now := time.Now()
	registeredClaims := jwt.Claims{
		Issuer:    "formation",
		Subject:   "",
		Audience:  jwt.Audience{"formation"},
		NotBefore: jwt.NewNumericDate(time.Time{}),
		IssuedAt:  jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(grantDuration)),
	}
	scope := fmt.Sprintf("tenant:%s", tenant)
	privateClaims := struct {
		Scope []string `json:"scope,omitempty"`
	}{
		Scope: []string{scope},
	}

	clientShortJWT, err := jwt.Signed(signer).Claims(registeredClaims).Claims(privateClaims).CompactSerialize()
	if err != nil {
		return nil, errors.WithMessage(err, "signing token")
	}

	b.Float("expires_in", grantDuration.Seconds())

	res := BearerResponse{
		Token:     clientShortJWT,
		TokenType: "bearer",
		ExpiresIn: int64(grantDuration.Seconds()),
	}

	return &res, nil

}
