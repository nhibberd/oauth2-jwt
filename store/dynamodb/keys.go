package dynamodb

import (
	"fmt"
	"time"

	"formation.engineering/oauth2-jwt/store"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/pkg/errors"
)

type table struct {
	// Metadata
	Created time.Time `dynamodbav:"created"`

	// Used for authorization
	KeyID      string            `dynamodbav:"key_id"`
	IdentityID string            `dynamodbav:"identity_id"`
	TenantID   string            `dynamodbav:"tenant_id"`
	PublicKey  PublicKeyDynamodb `dynamodbav:"public_key"`

	// UI Applicable
	TenantName      string `dynamodbav:"tenant_name"`
	ApplicationName string `dynamodbav:"application_name"`
	CreatedBy       string `dynamodbav:"created_by"`
}

type authorizationKeys struct {
	KeyID      string            `dynamodbav:"key_id"`
	IdentityID string            `dynamodbav:"identity_id"`
	TenantID   string            `dynamodbav:"tenant_id"`
	PublicKey  PublicKeyDynamodb `dynamodbav:"public_key"`
}

const (
	iKeyID      = "key_id"
	kPublicKey  = "public_key"
	kTenantID   = "tenant_id"
	kIdentityID = "identity_id"
)

var Conflict = errors.New("conflict")

func (x *DynamoStore) AddKey(kid store.KeyID, in store.AddKey) (*store.IdentityID, error) {
	identity, err := x.newIdentity()
	if err != nil {
		return nil, fmt.Errorf("new identity: %v", err)
	}

	r := table{
		Created:    time.Now().UTC(),
		KeyID:      kid,
		IdentityID: *identity,
		TenantID:   in.TenantID,
		PublicKey:  PublicKeyDynamodb{in.PublicKey},

		TenantName:      in.TenantName,
		ApplicationName: in.ApplicationName,
		CreatedBy:       in.CreatedBy,
	}

	av, err := dynamodbattribute.MarshalMap(r)
	if err != nil {
		return nil, fmt.Errorf("failed to DynamoDB marshal Record, %v", err)
	}

	req := &dynamodb.PutItemInput{
		TableName:           aws.String(x.KeysTable),
		ConditionExpression: aws.String("attribute_not_exists(key_id)"),
		Item:                av,
	}

	_, err = x.Config.PutItem(req)

	if ConditionalCheckFailed(err) {
		return nil, fmt.Errorf("offer already exists %s: %w", kid, Conflict)
	}

	if err != nil {
		return nil, err
	}

	return identity, nil
}

func ConditionalCheckFailed(err error) bool {
	aerr, ok := err.(awserr.Error)
	return ok && aerr.Code() == dynamodb.ErrCodeConditionalCheckFailedException
}

func (x *DynamoStore) GetKey(kid store.KeyID) (*store.KeyInfo, error) {
	return getKey(x.Config, x.KeysTable, kid)
}

func (x *DynamoReadOnlyStore) GetKey(kid store.KeyID) (*store.KeyInfo, error) {
	return getKey(x.Config, x.KeysTable, kid)
}

func getKey(client *dynamodb.DynamoDB, table string, kid store.KeyID) (*store.KeyInfo, error) {
	proj := expression.NamesList(
		expression.Name(iKeyID),
		expression.Name(kPublicKey),
		expression.Name(kIdentityID),
		expression.Name(kTenantID),
	)

	expr, err := expression.NewBuilder().WithProjection(proj).Build()
	if err != nil {
		return nil, fmt.Errorf("builder: %v", err)
	}

	req := dynamodb.GetItemInput{
		TableName: aws.String(table),
		Key: map[string]*dynamodb.AttributeValue{
			iKeyID: {
				S: aws.String(kid),
			},
		},
		ProjectionExpression:     expr.Projection(),
		ExpressionAttributeNames: expr.Names(),
		ConsistentRead:           aws.Bool(true),
	}

	getItem, err := client.GetItem(&req)

	if err != nil {
		return nil, fmt.Errorf("get item: %v", err)
	}

	var hold authorizationKeys
	err = dynamodbattribute.UnmarshalMap(getItem.Item, &hold)
	if err != nil {
		return nil, fmt.Errorf("unmarshal map: %v", err)
	}

	if hold.KeyID == "" {
		return nil, nil
	}

	info := store.KeyInfo{
		PublicKey:  hold.PublicKey.Key,
		IdentityID: hold.IdentityID,
		TenantID:   hold.TenantID,
	}

	return &info, nil
}
