package singbox

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
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

func TestAdapterReplacesOnlyTheVLESSClientIdentity(t *testing.T) {
	adapter := New()
	identity, err := adapter.PrepareIdentity()
	if err != nil {
		t.Fatal(err)
	}
	source, err := adapter.EncodeServerConfiguration(identity, "microsoft.com:443", "microsoft.com")
	if err != nil {
		t.Fatal(err)
	}
	target, err := adapter.ReplaceClientIdentity(source)
	if err != nil || bytes.Equal(source, target) {
		t.Fatalf("ReplaceClientIdentity() changed nothing: %v", err)
	}

	var before, after map[string]any
	if json.Unmarshal(source, &before) != nil || json.Unmarshal(target, &after) != nil {
		t.Fatal("replacement configuration is not JSON")
	}
	beforeUser := before["inbounds"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	afterUser := after["inbounds"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	if beforeUser["uuid"] == afterUser["uuid"] {
		t.Fatal("VLESS UUID was not replaced")
	}
	afterUser["uuid"] = beforeUser["uuid"]
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("replacement changed non-UUID fields\nbefore: %s\nafter:  %s", source, target)
	}
	if _, err := adapter.CurrentConnectionFacts(target, "8.8.8.8"); err != nil {
		t.Fatalf("replacement configuration refused: %v", err)
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

func TestAdapterEncodesTheOfficialOutsideClientConfiguration(t *testing.T) {
	adapter := New()
	identity, err := adapter.PrepareIdentity()
	if err != nil {
		t.Fatal(err)
	}
	server, err := adapter.EncodeServerConfiguration(identity, "microsoft.com:443", "microsoft.com")
	if err != nil {
		t.Fatal(err)
	}

	body, err := adapter.EncodeClientConfiguration(server, "8.8.8.8")
	if err != nil || !json.Valid(body) {
		t.Fatalf("EncodeClientConfiguration() = %q, %v", body, err)
	}
	text := string(body)
	for _, required := range []string{
		`"type":"mixed"`, `"listen":"127.0.0.1"`, `"listen_port":2080`,
		`"type":"vless"`, `"server":"8.8.8.8"`, `"server_port":443`,
		`"uuid":"` + identity.UUID + `"`, `"flow":"xtls-rprx-vision"`,
		`"server_name":"microsoft.com"`, `"utls":{"enabled":true,"fingerprint":"chrome"}`,
		`"public_key":"` + identity.PublicKey + `"`, `"short_id":"` + identity.ShortID + `"`,
	} {
		if !regexp.MustCompile(regexp.QuoteMeta(required)).MatchString(text) {
			t.Errorf("configuration missing %s: %s", required, text)
		}
	}
	if regexp.MustCompile(regexp.QuoteMeta(identity.PrivateKey)).MatchString(text) {
		t.Fatalf("client configuration disclosed the REALITY private key: %s", text)
	}
}
