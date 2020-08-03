package dynamodb

import (
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

func (x *DynamoStore) newIdentity() (*string, error) {
	input := &dynamodb.UpdateItemInput{
		TableName:    aws.String(x.StateTable),
		ReturnValues: aws.String("UPDATED_NEW"),
		Key: map[string]*dynamodb.AttributeValue{
			"unique": {
				S: aws.String("gator"),
			},
		},
		UpdateExpression: aws.String("ADD identity_id :s"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":s": &dynamodb.AttributeValue{
				N: aws.String("1"),
			},
		},
	}

	res, err := x.Config.UpdateItem(input)
	if err != nil {
		return nil, err
	}

	hold := struct {
		IdentityID int `dynamodbav:"identity_id"`
	}{}
	err = dynamodbattribute.UnmarshalMap(res.Attributes, &hold)
	if err != nil {
		return nil, fmt.Errorf("unmarshal map: %v", err)
	}

	out := strconv.Itoa(hold.IdentityID)
	return &out, nil
}
