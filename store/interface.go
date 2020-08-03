package store

import "crypto"

type Key = crypto.PublicKey

type KeyID = string

type IdentityID = string

type Store interface {
	AddKey(keyid KeyID, info AddKey) (*IdentityID, error)
	GetKey(keyid KeyID) (*KeyInfo, error)

	// For Testing
	DeleteKey(keyid KeyID) error
}

type ReadOnlyStore interface {
	GetKey(keyid KeyID) (*KeyInfo, error)
}

type AddKey struct {
	PublicKey Key
	//	IdentityID string
	TenantID        string
	TenantName      string
	ApplicationName string
	CreatedBy       string
}

type KeyInfo struct {
	PublicKey  Key
	IdentityID string
	TenantID   string
}
