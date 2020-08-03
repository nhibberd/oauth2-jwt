package edge

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"formation.engineering/library/lib/telemetry/v1"
	"formation.engineering/oauth2-jwt/edge"
	"github.com/aws/aws-lambda-go/events"
)

type Request struct {
	TenantID       string
	Headers        map[string]string
	Body           string
	PathParameters map[string]string
}

var NotAuthorized = errors.New("unauthorized")

type AuthorizeKey = crypto.PublicKey

func LoadPublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	return edge.LoadPublicKey(raw)
}

func tryHTTPGateway(
	b telemetry.Builder,
	key AuthorizeKey,
	oauthExpiryLeeway *time.Duration,
	request events.APIGatewayV2HTTPRequest,
) (*Request, error) {
	headers := FixHeaders(request.Headers)

	b.String("content_type", headers["Content-Type"])

	rawHeader, ok := headers["Authorization"]
	if !ok {
		b.Bool("authorization_header_missing", true)
		return nil, fmt.Errorf("missing 'Authorization' header: %w", NotAuthorized)
	}

	token, ok := edge.TokenFromBearer(rawHeader)
	if !ok {
		b.Bool("authorization_header_invalid", true)
		b.String("authorization_header_raw", rawHeader)
		return nil, fmt.Errorf("invalid 'Authorization' header: %w", NotAuthorized)
	}

	var err error
	var tenant *string

	b.Timed("authorize_duration_ms", func() {
		if oauthExpiryLeeway != nil {
			tenant, err = edge.VerifyWithLeeway(b, key, token, *oauthExpiryLeeway)
		} else {
			tenant, err = edge.Verify(b, key, token)
		}
	})

	if err != nil {
		b.Bool("authorization_failure", true)
		b.String("authorization_failure_message", err.Error())
		return nil, fmt.Errorf("verify failure: %v: %w", err, NotAuthorized)
	}

	var body string
	if request.IsBase64Encoded {
		raw, err := base64.StdEncoding.DecodeString(request.Body)
		b.Bool("request_body_base64", true)
		if err != nil {
			b.String("decode_body_base64_failure", err.Error())
			return nil, fmt.Errorf("decode body: %v: %w", err, NotAuthorized)
		}
		body = string(raw)
	} else {
		b.Bool("request_body_base64", false)
		body = request.Body
	}

	req := Request{
		TenantID:       *tenant,
		Headers:        headers,
		Body:           body,
		PathParameters: request.PathParameters,
	}

	return &req, nil
}

func FixHeaders(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[http.CanonicalHeaderKey(k)] = v

	}
	return out
}
