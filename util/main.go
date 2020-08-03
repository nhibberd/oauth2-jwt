//nolint
package main

import (
	"fmt"
	"log"
	"os"

	"formation.engineering/library/lib/loglevel"
	"formation.engineering/library/lib/secrets"
	"formation.engineering/library/lib/telemetry/v1"
	"formation.engineering/oauth2-jwt/server"
	"formation.engineering/oauth2-jwt/server/admin"
	"formation.engineering/oauth2-jwt/server/client"
	"formation.engineering/oauth2-jwt/store/memory"
)

func main() {
	jsonWriter := telemetry.NewNaiveJSONStd()
	if jsonWriter == nil {
		log.Print("Failed to initialize naive JSON logger!")
		os.Exit(1)
	}

	b := telemetry.NewBuilder(jsonWriter)

	if len(os.Args) < 2 {
		log.Fatal("expected create subcommand to be set")
	}

	switch os.Args[1] {
	case "create":
		req := client.Request{"tenant", "name", "application", "darren"}
		creds, err := client.NewCredentials(b, memory.NewMemoryStore(), client.RSAGenerator{}, req)
		if err != nil {
			log.Fatal(err.Error())
		}
		fmt.Printf("%s\n", string((*creds).PrivateKey))

	case "server-bootstrap":
		creds, err := admin.GenerateServerCredentials()
		if err != nil {
			log.Fatal(err.Error())
			os.Exit(1)
		}
		fmt.Printf("%s\n", creds.RenderPublicKey())
		fmt.Printf("%s\n", creds.RenderPrivateKey())

	case "unsafe-grant":
		if len(os.Args) < 3 {
			log.Fatal("Not enough arguments to sign")
		}
		tenant := os.Args[2]
		arn := os.Args[3]

		secretsConfig := secrets.Load()
		rawPrivateKey, err := secretsConfig.GetSecretString(arn)
		if err != nil {
			log.Fatal(err.Error())
		}

		privateKey, err := admin.LoadPrivateKey([]byte(*rawPrivateKey))
		if err != nil {
			log.Fatal(err.Error())
		}

		res, err := server.Grant(b, server.Config{PrivateKey: privateKey}, tenant, nil)
		if err != nil {
			log.Fatal(err.Error())
		}
		fmt.Printf("curl -H 'Authorization: Bearer %s' -I https://api.helium.frmn-ops.com/v2/authenticate\n", res.Token)
	default:
		log.Fatalf("unexpected subcommand %s, expected one of 'create', 'server-bootstrap' or 'unsafe-grant'", os.Args[1])
	}

	if loglevel.Level == loglevel.Debug {
		b.Push()
	}
}
