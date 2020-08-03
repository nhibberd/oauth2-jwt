package memory

import (
	"testing"

	x "formation.engineering/oauth2-jwt/store/testing"
)

func TestIdentity(t *testing.T) {
	store := NewMemoryStore()
	r0 := store.newIdentity()
	r1 := store.newIdentity()
	if r0 == r1 {
		t.Fatalf("Identities match [%s:%s]", r0, r1)
	}
}

func TestMemoryStore(t *testing.T) {
	store := NewMemoryStore()
	x.TestStore(t, store)
}
