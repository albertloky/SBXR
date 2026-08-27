package singbox

import (
	"encoding/base64"
	"encoding/json"
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

func TestAdapterEncodesTheProtectedPackagedServerConfiguration(t *testing.T) {
	adapter := New()
	identity, err := adapter.PrepareIdentity()
	if err != nil {
		t.Fatal(err)
	}
	body, err := adapter.EncodeServerConfiguration(identity, "microsoft.com:443", "microsoft.com")
	if err != nil || !json.Valid(body) {
		t.Fatalf("EncodeServerConfiguration() = %q, %v", body, err)
	}
	text := string(body)
	for _, required := range []string{`"type":"vless"`, `"listen":"::"`, `"listen_port":443`, `"flow":"xtls-rprx-vision"`, `"server":"microsoft.com"`, `"server_port":443`, `"server_name":"microsoft.com"`, `"private_key":"` + identity.PrivateKey + `"`, `"short_id":["` + identity.ShortID + `"]`} {
		if !regexp.MustCompile(regexp.QuoteMeta(required)).MatchString(text) {
			t.Errorf("configuration missing %s: %s", required, text)
		}
	}
}
