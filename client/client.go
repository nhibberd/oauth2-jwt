package client

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	oauth2JWT "golang.org/x/oauth2/jwt"

	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"

	fctx "formation.engineering/library/lib/telemetry/context"
)

type Credentials struct {
	Key        []byte
	IdentityID string
	KeyID      string
}

func ExtractKey(privateJWK []byte) (*Credentials, error) {
	var err error
	var rawJWK map[string]string
	err = json.Unmarshal(privateJWK, &rawJWK)
	if err != nil {
		return nil, errors.WithMessage(err, "json parsing raw token")
	}
	identityId, ok := rawJWK["formation/identity-id"]
	if !ok {
		return nil, errors.New("No 'formation/identity-id' key present in credentials")
	}

	var parsedJWK jose.JSONWebKey
	err = parsedJWK.UnmarshalJSON(privateJWK)
	if err != nil {
		return nil, errors.WithMessage(err, "decode jwk")
	}

	//	var priv *rsa.PrivateKey
	priv, ok := parsedJWK.Key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("Invalid credentials")
	}

	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	out := Credentials{
		Key:        privBytes,
		KeyID:      parsedJWK.KeyID,
		IdentityID: identityId,
	}

	return &out, nil
}

func OAuth2Source(ctx0 context.Context, url string, creds Credentials, scope string) oauth2.TokenSource {
	ctx := ctx0
	ctx1, err := updateContext(ctx0)
	if err == nil {
		ctx = ctx1
	}

	config := oauth2JWT.Config{
		Email:         creds.IdentityID,
		PrivateKey:    creds.Key,
		PrivateKeyID:  creds.KeyID,
		Subject:       "",
		Scopes:        []string{scope},
		TokenURL:      fmt.Sprintf("%s/token", url),
		Expires:       1 * time.Minute,
		Audience:      "formation",
		PrivateClaims: nil,
		UseIDToken:    false,
	}
	return config.TokenSource(ctx)
}

func updateContext(ctx0 context.Context) (context.Context, error) {
	trace, ok := fctx.GetTraceID(ctx0)
	if !ok {
		return nil, fmt.Errorf("No trace_id information specified in ctx")
	}

	span, ok := fctx.GetSpanID(ctx0)
	if !ok {
		return nil, fmt.Errorf("No span_id information specified in ctx")
	}

	tr := withHeader{
		traceID: trace,
		spanID:  span,
		rt:      http.DefaultTransport,
	}
	c := &http.Client{Transport: tr}
	return context.WithValue(ctx0, oauth2.HTTPClient, c), nil
}

type withHeader struct {
	traceID string
	spanID  string
	rt      http.RoundTripper
}

func (x withHeader) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add(fctx.TraceIDOverrideHeader, x.traceID)
	req.Header.Add(fctx.ParentSpanIDOverrideHeader, x.spanID)
	return x.rt.RoundTrip(req)
}

func OAuth2Transport(ctx context.Context, url string, creds Credentials, scope string) *oauth2.Transport {
	source := OAuth2Source(ctx, url, creds, scope)
	transport := oauth2.Transport{
		Source: source,
		Base:   http.DefaultTransport,
	}
	return &transport
}

func OAuth2TransportFromSource(source oauth2.TokenSource) *oauth2.Transport {
	return &oauth2.Transport{
		Source: source,
		Base:   http.DefaultTransport,
	}
}
