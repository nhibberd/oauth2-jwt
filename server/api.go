package server

import (
	"encoding/json"
	"errors"
	"fmt"

	"formation.engineering/library/lib/telemetry/v1"
	"formation.engineering/oauth2-jwt/store"
)

func AuthorizationGrant(
	b telemetry.Builder,
	c Config,
	x store.ReadOnlyStore,
	requestBody string,
) (json.RawMessage, error) {
	auth, err := AuthorizeBody(b, x, requestBody)

	if errors.Is(err, NotAuthorized) {
		return nil, fmt.Errorf("todo unauthorized: %v", err)
	} else if err != nil {
		return nil, fmt.Errorf("authorize: %v", err)
	}

	res, err := Grant(b, c, auth.TenantID, auth.RequestDuration)
	if err != nil {
		return nil, fmt.Errorf("grant: %v", err)
	}

	payload, err := json.Marshal(*res)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %v", err)
	}

	return payload, nil
}
