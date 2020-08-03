package dynamodb

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

type DynamoStore struct {
	StateTable string
	KeysTable  string
	Config     *dynamodb.DynamoDB
}

func NewStore(region, stateTable, keysTable string) *DynamoStore {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	return NewStoreWithSession(sess, region, stateTable, keysTable)
}

func NewStoreWithSession(sess *session.Session, region, stateTable, keysTable string) *DynamoStore {
	dyn := dynamodb.New(sess, &aws.Config{Region: aws.String(region)})
	store := DynamoStore{StateTable: stateTable, KeysTable: keysTable, Config: dyn}
	return &store
}

type DynamoReadOnlyStore struct {
	KeysTable string
	Config    *dynamodb.DynamoDB
}

func NewReadOnlyStore(region, keysTable string) *DynamoReadOnlyStore {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	dyn := dynamodb.New(sess, &aws.Config{Region: aws.String(region)})
	store := DynamoReadOnlyStore{KeysTable: keysTable, Config: dyn}
	return &store
}
