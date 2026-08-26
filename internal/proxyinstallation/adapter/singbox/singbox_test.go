package singbox

import (
	"encoding/base64"
	"regexp"
	"testing"
)

func TestAdapterPreparesValidUniqueClientIdentities(t *testing.T) {
	adapter := New()
	first, err := adapter.PrepareIdentity()
	if err != nil || !adapter.ValidIdentity(first) {
		t.Fatalf("first identity = %#v, %v", first, err)
	}
	second, err := adapter.PrepareIdentity()
	if err != nil || !adapter.ValidIdentity(second) || first == second {
		t.Fatalf("second identity = %#v, %v", second, err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(first.UUID) || !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(first.ShortID) {
		t.Fatalf("identity formats = %#v", first)
	}
	for name, value := range map[string]string{"private": first.PrivateKey, "public": first.PublicKey} {
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			t.Fatalf("%s key = %q, %v", name, value, err)
		}
	}
}
