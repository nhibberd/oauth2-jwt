package server

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"formation.engineering/library/lib/telemetry/v1"
	"formation.engineering/oauth2-jwt/store"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Authorized struct {
	TenantID        string
	RequestDuration *int64
}

var NotAuthorized = errors.New("unauthorized")

func AuthorizeRequest(b telemetry.Builder, x store.ReadOnlyStore, r *http.Request) (*Authorized, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read body: %s: %w", err.Error(), NotAuthorized)
	}
	return AuthorizeBody(b, x, string(body))
}

func AuthorizeBody(b telemetry.Builder, x store.ReadOnlyStore, body string) (*Authorized, error) {
	values, err := url.ParseQuery(body)
	if err != nil {
		return nil, fmt.Errorf("unable to parse body: %s: %w", err.Error(), NotAuthorized)
	}
	gt := values.Get("grant_type")
	as := values.Get("assertion")

	// TODO error not supported
	if gt != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		return nil, fmt.Errorf("Unsupported 'grant_type' [%s]: %w", gt, NotAuthorized)
	}

	if as == "" {
		return nil, fmt.Errorf("Unsupported empty 'assertion': %w", NotAuthorized)
	}

	res, err := Authorize(b, x, as, time.Now())
	if err != nil {
		return nil, fmt.Errorf("authorization failure: %v: %w", err.Error(), NotAuthorized)
	}
	return res, nil
}

// https://tools.ietf.org/html/rfc7523#section-3
func Authorize(b telemetry.Builder, x store.ReadOnlyStore, token string, now time.Time) (*Authorized, error) {
	var err error
	parsedJWT, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	// TODO validation
	parsedKeyID := parsedJWT.Headers[0].KeyID

	b.String("key_id", parsedKeyID)

	var keyInfo *store.KeyInfo
	//	fmt.Printf("Using key [%s]\n", parsedKeyID)
	keyInfo, err = x.GetKey(parsedKeyID)
	if err != nil {
		return nil, fmt.Errorf("getting key: %w", err)
	} else if keyInfo == nil {
		return nil, fmt.Errorf("keyInfo is empty: %w", NotAuthorized)
	}

	b.String("tenant_id", keyInfo.TenantID)
	b.String("identity_id", keyInfo.IdentityID)

	// Verify and decode Claims
	var verifiedJwtClaims jwt.Claims
	var extraClaims extraClaims
	err = parsedJWT.Claims(keyInfo.PublicKey, &verifiedJwtClaims, &extraClaims)
	if err != nil {
		return nil, fmt.Errorf("failed public key decode: %w", err)
	}

	expected := jwt.Expected{
		Issuer:   keyInfo.IdentityID,
		Subject:  "",
		Audience: jwt.Audience{"formation"}, // TODO audience
		ID:       "",
		Time:     now,
	}

	err = verifiedJwtClaims.Validate(expected)
	if err != nil {
		return nil, fmt.Errorf("jwt claim validation failure: %w", err)
	}

	if extraClaims.RequestDuration > int64(GrantDuration.Seconds()) {
		return nil, fmt.Errorf("specified 'request_duration' is larger then the maximum allowed: %d > %d", extraClaims.RequestDuration, int64(GrantDuration.Seconds()))
	}

	if extraClaims.RequestDuration > 0 {
		b.Int("request_duration", int(extraClaims.RequestDuration))
		return &Authorized{
			TenantID:        keyInfo.TenantID,
			RequestDuration: &extraClaims.RequestDuration,
		}, nil
	}

	return &Authorized{
		TenantID:        keyInfo.TenantID,
		RequestDuration: nil,
	}, nil
}

type extraClaims struct {
	RequestDuration int64 `json:"request_duration"` // seconds
}
