package lib

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"formation.engineering/library/lib/env"
	"formation.engineering/library/lib/telemetry/v1"
	"formation.engineering/oauth2-jwt/server/client"
	"formation.engineering/oauth2-jwt/store"
	"formation.engineering/oauth2-jwt/store/dynamodb"
	"github.com/pkg/errors"
)

type Config struct {
	Store store.Store
}

func Setup(b telemetry.Builder) (interface{}, error) {
	region, err := env.LookupRegion("admin")
	if err != nil {
		return nil, err
	}

	stateTable, err := env.Lookup("STATE_TABLE_NAME", "authorization")
	if err != nil {
		return nil, err
	}

	keysTable, err := env.Lookup("KEYS_TABLE_NAME", "authorization")
	if err != nil {
		return nil, err
	}

	c := Config{
		Store: dynamodb.NewStore(*region, *stateTable, *keysTable),
	}
	return c, nil
}

func Run(
	cfg Config,
	ctx context.Context,
	b telemetry.Builder,
	raw json.RawMessage,
) (json.RawMessage, error) {
	var req Request
	err := json.Unmarshal(raw, &req)
	if err != nil {
		return encodeParseError(errors.Wrap(err, "unmarshaling request"))
	}

	fmt.Println(req)

	if req.CreateKey != nil {
		input := *req.CreateKey
		if input.TenantID == "" {
			return encodeParseError(errors.New("tenant_id must not be empty"))
		}
		if input.TenantName == "" {
			return encodeParseError(errors.New("tenant_name must not be empty"))
		}
		if input.ApplicationName == "" {
			return encodeParseError(errors.New("application_name must not be empty"))
		}
		if input.CreatedBy == "" {
			return encodeParseError(errors.New("created_by must not be empty"))
		}

		clientReq := client.Request{
			TenantID:        input.TenantID,
			TenantName:      input.TenantName,
			ApplicationName: input.ApplicationName,
			CreatedBy:       input.CreatedBy,
		}

		creds, err := client.NewCredentials(b, cfg.Store, client.RSAGenerator{}, clientReq)
		if err != nil {
			return encodeInternalError(err)
		}
		output := struct {
			StatusCode int64          `json:"statusCode"`
			Body       CreateResponse `json:"body"`
		}{
			StatusCode: 200,
			Body: CreateResponse{
				KeyID:      (*creds).KeyID,
				PrivateKey: (*creds).PrivateKey,
			},
		}
		bytes, err := json.Marshal(output)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal response")
		}
		return bytes, nil
	}

	if req.DeleteKey != nil {
		input := *req.DeleteKey
		if input.KeyID == "" {
			return encodeParseError(errors.New("key_id must not be empty"))
		}

		err := cfg.Store.DeleteKey(input.KeyID)
		return nil, err
	}

	return encodeParseError(errors.New("no request was specified"))
}

func encodeParseError(err error) (json.RawMessage, error) {
	result := struct {
		StatusCode int64  `json:"statusCode"`
		Body       string `json:"body"`
	}{
		StatusCode: 400,
		Body:       err.Error(),
	}

	bytes, encodeError := json.Marshal(result)
	if encodeError != nil {
		return nil, errors.Wrap(encodeError, "Failed to marshal result message")
	}
	return bytes, nil
}

func encodeInternalError(err error) (json.RawMessage, error) {
	result := struct {
		StatusCode int64  `json:"statusCode"`
		Body       string `json:"body"`
	}{
		StatusCode: 500,
		Body:       err.Error(),
	}

	bytes, encodeError := json.Marshal(result)
	if encodeError != nil {
		return nil, errors.Wrap(encodeError, "Failed to marshal result message")
	}
	return bytes, nil
}

type Request struct {
	//	CreateApplication string `json:"create-application"`
	//	ListApplication   string `json:"list-application"`
	//	UpdateApplication string `json:"list-application"`
	//	DeleteApplication string `json:"create-application"`
	//	List   *ListRequest   `json:"list-keys"`
	CreateKey *CreateRequest `json:"create-key"`
	DeleteKey *DeleteRequest `json:"delete-key"`
}

type CreateRequest struct {
	TenantID        string `json:"tenant_id"`
	TenantName      string `json:"tenant_name"`
	ApplicationName string `json:"application_name"`
	CreatedBy       string `json:"created_by"`
}

type CreateResponse struct {
	KeyID      string `json:"key_id"`
	PrivateKey []byte `json:"private_key"`
}

type DeleteRequest struct {
	KeyID string `json:"key_id"`
}

type APIKey struct {
	//	APIKeyMetadata
}

type APIKeyMetadata struct {
	Name            string    `json:"name"`
	CreatedDate     time.Time `json:"created_date"`
	CreatedBy       string    `json:"created_by"`
	ApplicationName string    `json:"application_id"`
}
