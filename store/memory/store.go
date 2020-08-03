package memory

import (
	"fmt"
	"strconv"

	"formation.engineering/oauth2-jwt/store"
	"github.com/pkg/errors"
)

type MemoryStore struct {
	identity int
	db       map[store.KeyID]*store.KeyInfo
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		identity: 0,
		db:       make(map[store.KeyID]*store.KeyInfo),
	}
}

func (x *MemoryStore) newIdentity() string {
	x.identity++
	return strconv.Itoa(x.identity)
}

func (x *MemoryStore) initialize() {
	if x.db == nil {
		x.db = make(map[store.KeyID]*store.KeyInfo)
	}
}

func (x *MemoryStore) AddKey(keyid store.KeyID, in store.AddKey) (*store.IdentityID, error) {
	x.initialize()

	identity := x.newIdentity()

	tmp, err := x.GetKey(keyid)
	if err != nil {
		return nil, errors.WithMessage(err, "add-key")
	}
	if tmp != nil {
		return nil, fmt.Errorf("conflict - existing KeyID [%s]", keyid)
	}

	x.db[keyid] = &store.KeyInfo{
		PublicKey:  in.PublicKey,
		IdentityID: identity,
		TenantID:   in.TenantID,
	}
	return &identity, nil
}

func (x *MemoryStore) GetKey(keyid store.KeyID) (*store.KeyInfo, error) {
	x.initialize()
	res, ok := x.db[keyid]
	if !ok {
		return nil, nil
	}
	return res, nil
}

func (x *MemoryStore) DeleteKey(keyid store.KeyID) error {
	delete(x.db, keyid)
	return nil
}
