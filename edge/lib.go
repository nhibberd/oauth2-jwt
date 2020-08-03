package edge

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"strings"
	"time"

	"formation.engineering/library/lib/telemetry/v1"
	"formation.engineering/oauth2-jwt/server/admin"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2/jwt"
)

const bearer = "BEARER "

func TokenFromBearer(s string) (string, bool) {
	if strings.HasPrefix(strings.ToLower(s), "bearer ") && len(s) > len(bearer) {
		return s[len(bearer):], true
	}

	return "", false
}

func VerifyRequest(b telemetry.Builder, key crypto.PublicKey, r *http.Request) (*string, error) {
	token, ok := TokenFromBearer(r.Header.Get("Authorization"))
	if !ok {
		return nil, errors.New("missing header")
	}

	return Verify(b, key, token)
}

func LoadPublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	return admin.LoadPublicKey(raw)
}

func Verify(b telemetry.Builder, key crypto.PublicKey, token string) (*string, error) {
	return VerifyWithLeeway(b, key, token, jwt.DefaultLeeway)
}

func VerifyWithLeeway(b telemetry.Builder, key crypto.PublicKey, token string, leeway time.Duration) (*string, error) {
	var err error
	parsedJWT, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, errors.WithMessage(err, "parse signed token")
	}

	type privateClaim struct {
		Scope []string `json:"scope,omitempty"`
	}

	var privateClaims privateClaim
	var verifiedClaims jwt.Claims
	err = parsedJWT.Claims(key, &verifiedClaims, &privateClaims)
	if err != nil {
		return nil, errors.WithMessage(err, "decode claims")
	}

	expected := jwt.Expected{
		Issuer:   "formation",
		Subject:  "",
		Audience: jwt.Audience{"formation"},
		ID:       "",
		Time:     time.Now(),
	}

	b.String("expiry", verifiedClaims.Expiry.Time().String())

	err = verifiedClaims.ValidateWithLeeway(expected, leeway)
	if err != nil {
		return nil, errors.WithMessage(err, "invalid")
	}

	if len(privateClaims.Scope) == 0 {
		return nil, fmt.Errorf("no private claims decoded")
	}

	tenantScope := privateClaims.Scope[0]

	if !strings.HasPrefix(tenantScope, "tenant:") {
		return nil, fmt.Errorf("malformed tenant scope")
	}

	tenant := strings.TrimPrefix(tenantScope, "tenant:")

	return &tenant, nil
}
