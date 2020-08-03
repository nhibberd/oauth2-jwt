//nolint:errcheck
package client

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"formation.engineering/library/lib/telemetry/v1"
	server "formation.engineering/oauth2-jwt/server/client"
	"formation.engineering/oauth2-jwt/store/memory"
)

func TestJWTFetch_JSONResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "90d64460d14870c08c81352a05dedd3465940a7c",
			"scope": "user",
			"token_type": "bearer",
			"expires_in": 3600
		}`))
	}))
	defer ts.Close()

	b := telemetry.NewBuilder(&telemetry.NoOp{})
	req := server.Request{"tenant", "name", "application", "darren"}
	creds, err := server.NewCredentials(b, memory.NewMemoryStore(), server.TestRSAGenerator{}, req)
	if err != nil {
		log.Fatal(err.Error())
	}

	key, err := ExtractKey((*creds).PrivateKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	source := OAuth2Source(context.Background(), ts.URL, *key, "scope")

	tok, err := source.Token()
	if err != nil {
		t.Fatal(err)
	}
	if !tok.Valid() {
		t.Errorf("got invalid token: %v", tok)
	}
	if got, want := tok.AccessToken, "90d64460d14870c08c81352a05dedd3465940a7c"; got != want {
		t.Errorf("access token = %q; want %q", got, want)
	}
	if got, want := tok.TokenType, "bearer"; got != want {
		t.Errorf("token type = %q; want %q", got, want)
	}
	if got := tok.Expiry.IsZero(); got {
		t.Errorf("token expiry = %v, want none", got)
	}
	scope := tok.Extra("scope")
	if got, want := scope, "user"; got != want {
		t.Errorf("scope = %q; want %q", got, want)
	}
}
