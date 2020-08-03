package edge

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

var rsaTestKey2048, _ = rsa.GenerateKey(rand.Reader, 2048)
var rsaTestKey4096, _ = rsa.GenerateKey(rand.Reader, 4096)

var ecTestKey256, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
var ecTestKey384, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
var ecTestKey521, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

func BenchmarkElliptic(b *testing.B) {
	// RSASSA-PKCS#1v1.5
	b.Run("RS2048-RS256", runTest(jose.RS256, rsaTestKey2048, rsaTestKey2048.Public()))
	b.Run("RS2048-RS512", runTest(jose.RS512, rsaTestKey2048, rsaTestKey2048.Public()))
	b.Run("RS4096-RS256", runTest(jose.RS256, rsaTestKey4096, rsaTestKey4096.Public()))
	b.Run("RS4096-RS512", runTest(jose.RS512, rsaTestKey4096, rsaTestKey4096.Public()))
	// ECDSA
	b.Run("P256", runTest(jose.ES256, ecTestKey256, ecTestKey256.Public()))
	b.Run("P384", runTest(jose.ES384, ecTestKey384, ecTestKey384.Public()))
	b.Run("P521", runTest(jose.ES512, ecTestKey521, ecTestKey521.Public()))
}

// Kinda dumb, just pass in one and pick the other
func runTest(alg jose.SignatureAlgorithm, priv crypto.PrivateKey, pub crypto.PublicKey) func(b *testing.B) {
	return func(b *testing.B) {
		b.StopTimer()
		var err error

		token := sign(alg, priv)

		parsedJWT, err := jwt.ParseSigned(token)
		if err != nil {
			b.Fatal("unable to parse signed: " + err.Error())
		}

		b.StartTimer()

		b.Run("without-verification", verifyWithoutVerification(parsedJWT))
		b.Run("with-verification", verifyWithVerification(pub, parsedJWT))
	}
}

func sign(alg jose.SignatureAlgorithm, priv crypto.PrivateKey) string {
	serverSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: priv}, (&jose.SignerOptions{}))
	if err != nil {
		panic("failed to create signer:" + err.Error())
	}

	claims := struct {
		Test string `json:"test"`
	}{
		Test: "key",
	}

	clientShortJWT, err := jwt.Signed(serverSigner).Claims(claims).CompactSerialize()
	if err != nil {
		panic("failed to sign:" + err.Error())
	}

	return clientShortJWT
}

func verifyWithoutVerification(token *jwt.JSONWebToken) func(b *testing.B) {
	return func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var foo interface{}
			var bar interface{}
			var cool map[string]interface{}
			err := token.UnsafeClaimsWithoutVerification(&foo, &bar, &cool)
			if err != nil {
				b.Fatal("parsing claims without verification: " + err.Error())
			}
		}
	}
}

func verifyWithVerification(pub crypto.PublicKey, parsedJWT *jwt.JSONWebToken) func(b *testing.B) {
	return func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var out interface{}
			err := parsedJWT.Claims(pub, &out)
			if err != nil {
				b.Fatal("parsing claims: " + err.Error())
			}
		}
	}
}
