// todo delete
package dynamodb

import (
	"testing"

	x "formation.engineering/oauth2-jwt/store/testing"
)

const (
	region     = "us-west-2"
	stateTable = "ci-test-state"
	keysTable  = "ci-test-gator-keys"
)

func TestIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping dynamo test")
	}
	store := NewStore(region, stateTable, keysTable)
	r0, err := store.newIdentity()
	if err != nil {
		t.Fatal(err.Error())
	}
	r1, err := store.newIdentity()
	if err != nil {
		t.Fatal(err.Error())
	}
	if *r0 == *r1 {
		t.Fatalf("Identities match [%s:%s]", *r0, *r1)
	}

}

func TestDynamoStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping dynamo test")
	}
	store := NewStore(region, stateTable, keysTable)
	x.TestStore(t, store)
}
