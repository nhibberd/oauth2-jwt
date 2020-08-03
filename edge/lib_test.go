package edge

import "testing"

func TestTokenBearer(t *testing.T) {
	x, ok := TokenFromBearer("Bearer asd")
	if !ok {
		t.Fatal("Unexpected tokenFromBearer failure")
	}

	if x != "asd" {
		t.Fatalf("Unexpected tokenFromBearer result [%s]", x)
	}

	failure(t, "Bearerasd")
	failure(t, "Bearer ")
	failure(t, "Bearer")
	failure(t, "asd")
}

func failure(t *testing.T, s string) {
	x, ok := TokenFromBearer(s)
	if ok {
		t.Fatalf("Unexpected tokenFromBearer success [%s]", x)
	}
}
