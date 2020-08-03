//nolint:errcheck
package integrations

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"formation.engineering/library/lib/telemetry/v1"
	"formation.engineering/oauth2-jwt/client"
	"formation.engineering/oauth2-jwt/edge"
	token "formation.engineering/oauth2-jwt/server"
	"formation.engineering/oauth2-jwt/server/admin"
	server "formation.engineering/oauth2-jwt/server/client"
	"formation.engineering/oauth2-jwt/store"
	"formation.engineering/oauth2-jwt/store/dynamodb"
	"formation.engineering/oauth2-jwt/store/memory"
)

func TestAuthFlow(t *testing.T) {
	t.Run("memory", func(y *testing.T) {
		flow(y, memory.NewMemoryStore())
	})
	if testing.Short() {
		t.Skip("skipping dynamo test")
	}
	t.Run("dynamodb", func(y *testing.T) {
		flow(y, dynamodb.NewStore("us-west-2", "ci-test-state", "ci-test-gator-keys"))
	})
}

func flow(t *testing.T, xstore store.Store) {
	b := telemetry.NewTestingBuilder(t)
	// 	b := telemetry.NewBuilder(&telemetry.NoOp{})

	serverCreds, err := admin.GenerateServerCredentials()
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err := admin.LoadPrivateKey(serverCreds.RenderPrivateKey())
	if err != nil {
		t.Fatal(err)
	}

	c := token.Config{privateKey}
	tenant := "fake-tenant"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Println(err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		res, err := token.AuthorizationGrant(b, c, xstore, string(body))
		if err != nil {
			//			fmt.Println(err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(res)
	}))
	defer ts.Close()

	req := server.Request{tenant, "name", "application", "darren"}
	creds, err := server.NewCredentials(b, xstore, server.TestRSAGenerator{}, req)
	if err != nil {
		log.Fatal(err.Error())
	}

	// Client sign
	key, err := client.ExtractKey((*creds).PrivateKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	source := client.OAuth2Source(context.Background(), ts.URL, *key, "scope")
	tok, err := source.Token()
	if err != nil {
		t.Fatal(err)
	}
	if !tok.Valid() {
		t.Errorf("got invalid token: %v", tok)
	}
	if tok.AccessToken == "" {
		t.Fatal("Execpted access token not empty")
	}
	if got, want := tok.TokenType, "bearer"; got != want {
		t.Errorf("token type = %q; want %q", got, want)
	}
	if got := tok.Expiry.IsZero(); got {
		t.Errorf("token expiry = %v, want none", got)
	}

	publicKey, err := admin.LoadPublicKey(serverCreds.RenderPublicKey())
	if err != nil {
		t.Fatal(err.Error())
	}

	// Define test edge service
	xs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out, err := edge.VerifyRequest(b, publicKey, r)
		if err != nil {
			fmt.Println(err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if *out != tenant {
			t.Errorf("Incorrect tenant scope verifed [%s]", *out)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer xs.Close()

	client := &http.Client{Transport: client.OAuth2TransportFromSource(source)}
	res, err := client.Get(xs.URL)

	if err != nil {
		t.Fatal(err)
	}

	if res.Status != "200 OK" {
		t.Errorf("Unexpected status code [%s]", res.Status)
	}

	err = xstore.DeleteKey((*creds).KeyID)

	if err != nil {
		t.Fatal(err)
	}
}
