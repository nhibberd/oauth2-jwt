package main

import (
	"context"
	"encoding/json"

	"formation.engineering/library/lib/lambda/v2"
	"formation.engineering/library/lib/telemetry/v1"
	"formation.engineering/oauth2-jwt/example/admin/lib"
)

func main() {
	lambda.StartJSON("main", "admin", lib.Setup, handler)
}

func handler(
	ienv interface{},
	ctx context.Context,
	b telemetry.Builder,
	raw json.RawMessage,
) (json.RawMessage, error) {
	cfg, ok := ienv.(lib.Config)
	if !ok {
		return nil, lambda.FailedEnvironmentCastError(ienv)
	}

	return lib.Run(cfg, ctx, b, raw)
}
