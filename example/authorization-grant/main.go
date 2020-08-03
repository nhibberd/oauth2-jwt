package main

import (
	"context"
	"encoding/json"
	"errors"

	"formation.engineering/library/lib/env"
	"formation.engineering/library/lib/lambda/v2"
	"formation.engineering/library/lib/secrets"
	"formation.engineering/library/lib/telemetry/v1"
	"formation.engineering/oauth2-jwt/server"
	"formation.engineering/oauth2-jwt/server/admin"
	"formation.engineering/oauth2-jwt/store"
	"formation.engineering/oauth2-jwt/store/dynamodb"
)

func main() {
	lambda.StartJSON("main", "authorization-grant", setup, handler)
}

type Config struct {
	Config server.Config
	Store  store.ReadOnlyStore
}

func setup(b telemetry.Builder) (interface{}, error) {
	secretsConfig := secrets.Load()
	arn, err := env.Lookup("PRIVATE_KEY_ARN", "authorization-grant")
	if err != nil {
		return nil, err
	}

	rawPrivateKey, err := secretsConfig.GetSecretString(*arn)
	if err != nil {
		return nil, err
	}

	privateKey, err := admin.LoadPrivateKey([]byte(*rawPrivateKey))
	if err != nil {
		return nil, err
	}

	region, err := env.LookupRegion("authorization-grant")
	if err != nil {
		return nil, err
	}

	keysTable, err := env.Lookup("KEYS_TABLE_NAME", "authorization")
	if err != nil {
		return nil, err
	}

	c := Config{
		Config: server.Config{
			PrivateKey: privateKey,
		},
		Store: dynamodb.NewReadOnlyStore(*region, *keysTable),
	}
	return c, nil
}

func handler(
	ienv interface{},
	ctx context.Context,
	b telemetry.Builder,
	raw json.RawMessage,
) (json.RawMessage, error) {
	cfg, ok := ienv.(Config)
	if !ok {
		return nil, lambda.FailedEnvironmentCastError(ienv)
	}

	return RunUnauthenticatedV2(ctx, b, raw, runner(cfg))
}

func runner(cfg Config) func(context.Context, telemetry.Builder, UnauthenticatedRequest) Response {
	return func(ctx context.Context, b telemetry.Builder, req UnauthenticatedRequest) Response {

		res, err := server.AuthorizationGrant(b, cfg.Config, cfg.Store, req.Body)
		if errors.Is(err, server.NotAuthorized) {
			b.Bool("unauthorized", true)
			b.String("unauthorized_error", err.Error())
			return Forbidden()
		}

		if err != nil {
			b.Bool("error", true)
			b.String("error_message", err.Error())
			return Forbidden()
		}

		return Ok(string(res))
	}
}
