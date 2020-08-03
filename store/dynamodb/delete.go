package dynamodb

import (
	"formation.engineering/oauth2-jwt/store"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

func (x *DynamoStore) DeleteKey(kid store.KeyID) error {
	var err error
	req := &dynamodb.DeleteItemInput{
		TableName: aws.String(x.KeysTable),
		Key: map[string]*dynamodb.AttributeValue{
			"key_id": {
				S: aws.String(kid),
			},
		},
	}

	_, err = x.Config.DeleteItem(req)
	return err
}
