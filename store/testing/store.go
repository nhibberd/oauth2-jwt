package testing

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"formation.engineering/oauth2-jwt/store"
	jose "gopkg.in/square/go-jose.v2"
)

var (
	priv1, _ = rsa.GenerateKey(rand.Reader, 2048)
	priv2, _ = rsa.GenerateKey(rand.Reader, 2048)
	priv1jwk = jose.JSONWebKey{Key: priv1, Algorithm: "RS256"}
	priv2jwk = jose.JSONWebKey{Key: priv2, Algorithm: "RS256"}
)

func TestStore(t *testing.T, s store.Store) {
	var err error
	pub1 := priv1jwk.Public()
	pub2 := priv2jwk.Public()

	keyID1 := "1"
	addKey1 := store.AddKey{
		PublicKey:       pub1,
		TenantID:        "9999",
		TenantName:      "1",
		ApplicationName: "foo",
		CreatedBy:       "gary",
	}
	addKey2 := store.AddKey{
		PublicKey:       pub2,
		TenantID:        "9999",
		TenantName:      "1",
		ApplicationName: "foo",
		CreatedBy:       "gary",
	}

	cleanup := func() {
		_ = s.DeleteKey(keyID1)
	}
	defer cleanup()

	var emptyInfo *store.KeyInfo
	emptyInfo, err = s.GetKey(keyID1)
	if err != nil {
		t.Fatalf("get key [keyID1] failure:\n%s", err.Error())
	}
	if emptyInfo != nil {
		fmt.Println(emptyInfo)
		t.Fatal("get key [keyID1] failure: expected key to not exist")
	}

	id0, err := s.AddKey(keyID1, addKey1)
	if err != nil {
		t.Fatalf("add key failure:\n%s", err.Error())
	}
	_, err = s.AddKey(keyID1, addKey2)
	if err == nil {
		t.Fatal("expected add key failure, succeeded")
	}

	var key *store.KeyInfo
	key, err = s.GetKey(keyID1)
	if err != nil {
		t.Fatalf("get key [keyID1] failure:\n%s", err.Error())
	}

	if key == nil {
		t.Fatal("get key [keyID1] missing")
	}

	k := *key
	if k.IdentityID != *id0 {
		t.Fatal("get key [keyID1] failure: mismatch on IdentityID")
	}

	if k.TenantID != addKey1.TenantID {
		t.Fatal("get key [keyID1] failure: mismatch on IdentityID")
	}

	// Public key comparison
	var j1 []byte
	var j2 []byte
	if x1, ok := k.PublicKey.(jose.JSONWebKey); ok {
		j1, err = x1.MarshalJSON()
		if err != nil {
			t.Fatal(err.Error())
		}
	}
	j2, err = pub1.MarshalJSON()
	if err != nil {
		t.Fatal(err.Error())
	}

	if !bytes.Equal(j1, j2) {
		t.Errorf("%s\n", j1)
		t.Errorf("%s\n", j2)
		t.Fatal("public key mismatch")
	}

}

/*
func (pub *rsa.PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*rsa.PublicKey)
	if !ok {
		return false
	}
	return pub.N.Cmp(xx.N) == 0 && pub.E == xx.E
}
*/
