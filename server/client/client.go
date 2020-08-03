package client

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pkg/errors"

	"formation.engineering/library/lib/loglevel"
	"formation.engineering/library/lib/telemetry/v1"
	"formation.engineering/oauth2-jwt/store"
	jose "gopkg.in/square/go-jose.v2"
)

type Credentials struct {
	KeyID      string
	IdentityID string
	PrivateKey []byte
	CryptoKey  crypto.PrivateKey
}

type GenerateKey interface {
	Generate() (crypto.PrivateKey, error)
	Algorithm() string
}

type Request struct {
	TenantID        string
	TenantName      string
	ApplicationName string
	CreatedBy       string
}

// Generate a long lived set of Credentials (API Key)
func NewCredentials(
	b telemetry.Builder,
	keyStore store.Store,
	gen GenerateKey,
	req Request,
) (*Credentials, error) {
	generateTimer := time.Now()

	var err error
	var privKey crypto.PrivateKey

	var creds []byte

	// Generate key
	privKey, err = gen.Generate()
	if err != nil {
		return nil, errors.WithMessage(err, "generate")
	}

	// Construct JWK
	kid := "" // TODO
	priv := jose.JSONWebKey{
		Key:       privKey,
		KeyID:     kid,
		Algorithm: gen.Algorithm(),
	}

	// Generate a canonical kid based on RFC 7638
	thumb, err := priv.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to compute thumbprint")
	}
	kid = base64.URLEncoding.EncodeToString(thumb)
	priv.KeyID = kid

	// Validate keys
	pub := priv.Public()
	if priv.IsPublic() || !pub.IsPublic() || !priv.Valid() || !pub.Valid() {
		return nil, errors.New("Invariant. created invalid credentials")
	}

	// Store key
	keyInfo := store.AddKey{
		PublicKey:       store.Key(pub),
		TenantID:        req.TenantID,
		TenantName:      req.TenantName,
		ApplicationName: req.ApplicationName,
		CreatedBy:       req.CreatedBy,
	}
	identityID, err := keyStore.AddKey(kid, keyInfo)
	if err != nil {
		return nil, errors.WithMessage(err, "store add key")
	}

	// Add 'identity-id'
	privJSON, err := priv.MarshalJSON()
	if err != nil {
		return nil, errors.WithMessage(err, "adding identity-id marshal")
	}
	hold := make(map[string]interface{})
	err = json.Unmarshal(privJSON, &hold)
	if err != nil {
		return nil, errors.WithMessage(err, "adding identity-id unmarshal")
	}
	hold["formation/identity-id"] = identityID
	creds, err = json.Marshal(hold)
	if err != nil {
		return nil, errors.WithMessage(err, "adding identity-id marshal final")
	}

	if loglevel.Level == loglevel.Debug {
		pubJSON, err := pub.MarshalJSON()
		if err == nil {
			b.String("public_jwt", string(pubJSON))
		}

		var parsedJWK jose.JSONWebKey
		err = parsedJWK.UnmarshalJSON(creds)
		if err == nil {
			b.String("private_parsed_jwk", fmt.Sprintf("%v", parsedJWK))
			b.String("public_parsed_jwk", fmt.Sprintf("%v", parsedJWK.Public()))
		}
	}

	b.Duration("generate_credentials_duration_ms", time.Since(generateTimer))

	r := Credentials{
		KeyID:      kid,
		IdentityID: *identityID,
		PrivateKey: creds,
		CryptoKey:  privKey,
	}

	return &r, nil
}
