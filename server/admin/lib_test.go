package admin

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"
)

func TestServerCredentials(t *testing.T) {
	creds, err := GenerateServerCredentials()
	if err != nil {
		t.Fatal(err.Error())
	}

	bytes := creds.RenderPublicKey()

	loaded, err := LoadPublicKey(bytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	hashed := []byte("testing")

	r, s, err := ecdsa.Sign(rand.Reader, creds.PrivateKey, hashed)
	if err != nil {
		t.Fatal(err.Error())
	}

	if !ecdsa.Verify(loaded, hashed, r, s) {
		t.Errorf("%s: Verify failed", "asd")
	}
}
