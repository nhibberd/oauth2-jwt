package admin

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type ServerCredentials struct {
	PrivateKey *ecdsa.PrivateKey
	privateKey []byte
	PublicKey  crypto.PublicKey
	publicKey  []byte
}

func (x ServerCredentials) RenderPublicKey() []byte {
	return x.publicKey
}

func (x ServerCredentials) RenderPrivateKey() []byte {
	return x.privateKey
}

func GenerateServerCredentials() (*ServerCredentials, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	publicBytes, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}

	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicBytes,
	}

	privateBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	privateBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateBytes,
	}

	creds := ServerCredentials{
		PrivateKey: key,
		privateKey: pem.EncodeToMemory(privateBlock),
		PublicKey:  key.Public(),
		publicKey:  pem.EncodeToMemory(publicBlock),
	}

	return &creds, nil
}

func LoadPrivateKey(raw []byte) (*ecdsa.PrivateKey, error) {
	var skippedTypes []string
	var block *pem.Block

	for {
		block, raw = pem.Decode(raw)

		if block == nil {
			return nil, fmt.Errorf("failed to find EC PRIVATE KEY in PEM data after skipping types %v", skippedTypes)
		}

		if block.Type == "EC PRIVATE KEY" {
			break
		} else {
			skippedTypes = append(skippedTypes, block.Type)
			continue
		}
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

func LoadPublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("marshal: could not decode PEM block type %s", block.Type)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("marshal: data was not an X public key")
	}

	return ecdsaPub, nil
}
