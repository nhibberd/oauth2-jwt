package server

import (
	"errors"
	"testing"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"formation.engineering/library/lib/telemetry/v1"
	"formation.engineering/oauth2-jwt/server/client"
	"formation.engineering/oauth2-jwt/store"
	"formation.engineering/oauth2-jwt/store/memory"
)

var emptyStore = memory.NewMemoryStore()

func TestAuthorize(t *testing.T) {
	fail(t, emptyStore, "")

	fail(t, emptyStore, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InV1UGpvVFl1MUs0MlY5TFVyUFNMM3pyYkhUZjFKcG9PNmZOQzd6T2xRYUE9In0.eyJpc3MiOiJ0ZXN0LWlkZW50aXR5Iiwic2NvcGUiOiJzY29wZSIsImF1ZCI6ImZvcm1hdGlvbiIsImV4cCI6MTU4NzA2MDY2MCwiaWF0IjoxNTg3MDU3MDUwfQ.Arjoj0N8jmDsw3xeNKL-5wC1nkEKuz2uCFovZt27iScwxDqyr_Pnbu7AbGee-drNDxFu4FSa3p_7isEJ2W3pRCF6zp12P_nFJbQxdfoqGEwaK8_7_vZDgHIe-q9tb5MQ4t8059NKNW1bOHcGA-bSoPK111Fsq3DT-WhvlxCpf7WgfZp9-Nc2MAw1gJUY0Veqed4tU3zUQfGpuN4zu8L-kcJyfg2Ms5U0W4HAlwyYpUNWNya2MivdgP8OQAkRWj8a80bc6H3syiSIZMAfe02wAp-MOTkRAXY8OWjrFnv8RqvqrajHwMaPHTqqrp-2L1ThnJrCwmvXdDNrOh8U9kCuI")

	fail(t, emptyStore, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
}

func fail(t *testing.T, x store.ReadOnlyStore, token string) {
	_, err := Authorize(telemetry.NewTestingBuilder(t), x, token, time.Now())
	if err == nil {
		t.Fatal(err.Error())
	}
}

func TestInvalidClaims(t0 *testing.T) {
	// Setup
	b := telemetry.NewTestingBuilder(t0)
	s1 := memory.NewMemoryStore()
	req := client.Request{"tenant", "name", "application", "darren"}
	creds, _ := client.NewCredentials(b, s1, client.TestRSAGenerator{}, req)

	validSigningKey := jose.SigningKey{
		Algorithm: jose.RS256,
		Key: &jose.JSONWebKey{
			KeyID:     (*creds).KeyID,
			Algorithm: "RSA",
			Key:       (*creds).CryptoKey,
		},
	}

	validJwtSig, _ := jose.NewSigner(validSigningKey, (&jose.SignerOptions{}).WithType("JWT"))

	xtime := time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)

	t0.Run("Validate success", func(t *testing.T) {
		cl := jwt.Claims{
			Subject:   "",
			Issuer:    creds.IdentityID,
			NotBefore: jwt.NewNumericDate(xtime),
			Audience:  jwt.Audience{"formation"},
		}
		token, _ := jwt.Signed(validJwtSig).Claims(cl).CompactSerialize()
		_, err := Authorize(b, s1, token, xtime)
		if err != nil {
			t.Fatal(err)
		}
	})

	t0.Run("Validate nbf", func(t *testing.T) {
		cl := jwt.Claims{
			Subject:   "",
			Issuer:    creds.IdentityID,
			NotBefore: jwt.NewNumericDate(xtime),
			Audience:  jwt.Audience{"formation"},
		}
		token, _ := jwt.Signed(validJwtSig).Claims(cl).CompactSerialize()
		failWith(t, b, s1, token, xtime.Add(-2*time.Minute), jwt.ErrNotValidYet)
	})

	t0.Run("Validate aud", func(t *testing.T) {
		cl := jwt.Claims{
			Subject:   "",
			Issuer:    creds.IdentityID,
			NotBefore: jwt.NewNumericDate(xtime),
			Audience:  jwt.Audience{"wrong-audience"},
		}
		token, _ := jwt.Signed(validJwtSig).Claims(cl).CompactSerialize()
		failWith(t, b, s1, token, xtime, jwt.ErrInvalidAudience)
	})

	t0.Run("Validate exp", func(t *testing.T) {
		cl := jwt.Claims{
			Subject:  "",
			Issuer:   creds.IdentityID,
			Expiry:   jwt.NewNumericDate(xtime),
			Audience: jwt.Audience{"formation"},
		}
		token, _ := jwt.Signed(validJwtSig).Claims(cl).CompactSerialize()
		failWith(t, b, s1, token, xtime.Add(2*time.Minute), jwt.ErrExpired)
	})

	t0.Run("Validate iat", func(t *testing.T) {
		cl := jwt.Claims{
			Subject:  "",
			Issuer:   creds.IdentityID,
			IssuedAt: jwt.NewNumericDate(xtime),
			Audience: jwt.Audience{"formation"},
		}
		token, _ := jwt.Signed(validJwtSig).Claims(cl).CompactSerialize()
		failWith(t, b, s1, token, xtime.Add(-2*time.Minute), jwt.ErrIssuedInTheFuture)
	})

	t0.Run("Validate iss", func(t *testing.T) {
		cl := jwt.Claims{
			Subject:  "",
			Issuer:   "not-true",
			IssuedAt: jwt.NewNumericDate(xtime),
			Audience: jwt.Audience{"formation"},
		}
		token, _ := jwt.Signed(validJwtSig).Claims(cl).CompactSerialize()
		failWith(t, b, s1, token, xtime, jwt.ErrInvalidIssuer)
	})

	t0.Run("Validate missing kid", func(t *testing.T) {
		invalidSigningKey := jose.SigningKey{
			Algorithm: jose.RS256,
			Key: &jose.JSONWebKey{
				Algorithm: "RSA",
				Key:       (*creds).CryptoKey,
			},
		}
		invalidJwtSig, _ := jose.NewSigner(invalidSigningKey, (&jose.SignerOptions{}).WithType("JWT"))
		cl := jwt.Claims{
			Issuer:   creds.IdentityID,
			IssuedAt: jwt.NewNumericDate(xtime),
			Audience: jwt.Audience{"formation"},
		}
		token, _ := jwt.Signed(invalidJwtSig).Claims(cl).CompactSerialize()
		failWith(t, b, s1, token, xtime, NotAuthorized)
	})
}

func failWith(
	t *testing.T,
	b telemetry.Builder,
	s1 store.Store,
	token string,
	authorizeTime time.Time,
	check error,
) {
	_, err := Authorize(b, s1, token, authorizeTime)
	if !errors.Is(err, check) {
		t.Fatal(err.Error())
	}
}
