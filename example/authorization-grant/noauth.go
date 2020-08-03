package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-lambda-go/events"

	fctx "formation.engineering/library/lib/telemetry/context"
	"formation.engineering/library/lib/telemetry/v1"

	"formation.engineering/oauth2-jwt/example/edge"
)

type UnauthenticatedRequest struct {
	Headers        map[string]string
	Body           string
	PathParameters map[string]string
}

func RunUnauthenticatedV2(
	ctx context.Context,
	b telemetry.Builder,
	in json.RawMessage,
	f func(context.Context, telemetry.Builder, UnauthenticatedRequest) Response,
) (json.RawMessage, error) {
	var err error

	var request events.APIGatewayV2HTTPRequest
	err = json.Unmarshal(in, &request)
	if err != nil {
		b.Bool("httpgw_decode_failure", true)
	}
	if err != nil {
		return json.Marshal(Forbidden())
	}

	headers := edge.FixHeaders(request.Headers)

	b.String("content_type", headers["content-type"])

	tracingCtx := ctx
	if err == nil {
		tracingCtx = fctx.TracingContext(ctx, in)
	}

	var body string

	if request.IsBase64Encoded {
		raw, err := base64.StdEncoding.DecodeString(request.Body)
		b.Bool("request_body_base64", true)
		if err != nil {
			b.String("decode_body_base64_failure", err.Error())
			return nil, fmt.Errorf("decode body: %v: %w", err, edge.NotAuthorized)
		}
		body = string(raw)
	} else {
		b.Bool("request_body_base64", false)
		body = request.Body
	}

	r := UnauthenticatedRequest{
		Headers:        headers,
		Body:           body,
		PathParameters: request.PathParameters,
	}

	resp := f(tracingCtx, b, r)
	resp.Event(b)

	return json.Marshal(resp)
}
