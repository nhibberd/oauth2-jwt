package client

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

type RSAGenerator struct{}

func (x RSAGenerator) Generate() (crypto.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

func (x RSAGenerator) Algorithm() string {
	return "RS256"
}

type TestRSAGenerator struct{}

func (x TestRSAGenerator) Generate() (crypto.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func (x TestRSAGenerator) Algorithm() string {
	return "RS256"
}
