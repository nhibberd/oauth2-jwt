package dynamodb

import (
	"crypto"
	"fmt"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	jose "gopkg.in/square/go-jose.v2"
)

type PublicKeyDynamodb struct{ Key crypto.PublicKey }

func (t PublicKeyDynamodb) MarshalDynamoDBAttributeValue(av *dynamodb.AttributeValue) error {
	// rsa
	//	publicBytes, err := x509.MarshalPKIXPublicKey(t.Key)

	// jwk
	key, ok := t.Key.(jose.JSONWebKey)
	if !ok {
		return fmt.Errorf("unsupported key type %T", t.Key)
	}

	bytes, err := key.MarshalJSON()
	if err != nil {
		return fmt.Errorf("jose marshal: %v", err)
	}

	av.B = bytes
	return nil
}

func (t *PublicKeyDynamodb) UnmarshalDynamoDBAttributeValue(av *dynamodb.AttributeValue) error {
	if av.B == nil {
		return nil
	}

	// rsa
	/*
		pub, err := x509.ParsePKIXPublicKey([]byte(av.B))
		if err != nil {
			return err
		}

		verified, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("marshal: data was not an rsa public key")
		}
		t.Key = verified
	*/

	// jwk
	var jwk jose.JSONWebKey
	err := jwk.UnmarshalJSON(av.B)
	if err != nil {
		return fmt.Errorf("decode jwk: %v", err)
	}

	if !jwk.Valid() {
		return fmt.Errorf("invalid jwk")
	}

	t.Key = jwk

	return nil
}
