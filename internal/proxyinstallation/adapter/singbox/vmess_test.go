package singbox

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestVMessWebSocketPreservesRealityAndRotatesBothCredentials(t *testing.T) {
	a := New()
	id, err := a.PrepareIdentity()
	if err != nil {
		t.Fatal(err)
	}
	source, err := a.EncodeServerConfiguration(id, "google.com:443", "google.com")
	if err != nil {
		t.Fatal(err)
	}
	body, err := a.WithVMessWebSocket(source, "tunnel.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]any
	json.Unmarshal(source, &before)
	json.Unmarshal(body, &after)
	inbounds := after["inbounds"].([]any)
	if len(inbounds) != 2 || !reflect.DeepEqual(before["inbounds"].([]any)[0], inbounds[0]) {
		t.Fatal("optional VMess changed the REALITY inbound")
	}
	vmess := inbounds[1].(map[string]any)
	if vmess["listen"] != "127.0.0.1" || vmess["listen_port"] != float64(10000) || vmess["type"] != "vmess" || vmess["tls"] != nil || vmess["transport"].(map[string]any)["path"] != "/sbxr-vmess" {
		t.Fatal("VMess must use the fixed loopback WebSocket origin without TLS")
	}
	facts, err := a.CurrentConnectionFacts(body, "8.8.8.8")
	if err != nil || facts.VMessHostname != "tunnel.example.com" {
		t.Fatal("missing VMess client facts", err)
	}
	client, err := a.EncodeClientConfiguration(body, "8.8.8.8")
	if err != nil || bytes.Contains(client, []byte(id.PrivateKey)) {
		t.Fatal("unsafe client configuration", err)
	}
	var configuration struct{ Outbounds []map[string]any }
	if json.Unmarshal(client, &configuration) != nil || len(configuration.Outbounds) != 2 {
		t.Fatal("missing client outbounds")
	}
	out := configuration.Outbounds[1]
	if out["type"] != "vmess" || out["server"] != facts.VMessHostname || out["server_port"] != float64(443) || out["uuid"] != id.UUID || out["security"] != "auto" || out["tls"].(map[string]any)["server_name"] != facts.VMessHostname || out["transport"].(map[string]any)["headers"].(map[string]any)["Host"] != facts.VMessHostname {
		t.Fatal("incorrect VMess TLS/WebSocket client fields")
	}
	target, err := a.ReplaceClientIdentity(body)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := a.CurrentConnectionFacts(target, "8.8.8.8")
	if err != nil || fresh.UUID == facts.UUID || fresh.VMessHostname != facts.VMessHostname {
		t.Fatal("rotation did not preserve VMess", err)
	}
	var rotated map[string]any
	json.Unmarshal(target, &rotated)
	for index := range inbounds {
		user := rotated["inbounds"].([]any)[index].(map[string]any)["users"].([]any)[0].(map[string]any)
		if user["uuid"] != fresh.UUID {
			t.Fatal("rotation left an old credential")
		}
		user["uuid"] = id.UUID
	}
	if !reflect.DeepEqual(after, rotated) {
		t.Fatal("rotation changed noncredential fields")
	}
}

func TestVMessWebSocketRejectsUnsafeOptionsAndUnexpectedInbounds(t *testing.T) {
	a := New()
	id, _ := a.PrepareIdentity()
	source, _ := a.EncodeServerConfiguration(id, "google.com:443", "google.com")
	for _, hostname := range []string{"", "example", "127.0.0.1", "https://tunnel.example.com", "tunnel.example.com:443", "a..com", "-a.example.com", "a.example.com\n", "a.example.com/path", "*.example.com", "A.example.com"} {
		if _, err := a.WithVMessWebSocket(source, hostname); err == nil {
			t.Errorf("accepted invalid hostname %q", hostname)
		}
	}
	body, _ := a.WithVMessWebSocket(source, "tunnel.example.com")
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) { v["listen"] = "::" },
		func(v map[string]any) { v["listen_port"] = 443 },
		func(v map[string]any) { v["tag"] = "foreign" },
		func(v map[string]any) {
			v["users"].([]any)[0].(map[string]any)["uuid"] = "00000000-0000-4000-8000-000000000000"
		},
		func(v map[string]any) { v["users"].([]any)[0].(map[string]any)["alterId"] = 1 },
		func(v map[string]any) { v["transport"].(map[string]any)["path"] = "/foreign" },
		func(v map[string]any) { v["tls"] = map[string]any{"enabled": true} },
	} {
		var config map[string]any
		json.Unmarshal(body, &config)
		mutate(config["inbounds"].([]any)[1].(map[string]any))
		changed, _ := json.Marshal(config)
		if _, err := a.CurrentConnectionFacts(changed, "8.8.8.8"); err == nil {
			t.Error("accepted an unmanaged VMess inbound")
		}
		if _, err := a.ReplaceClientIdentity(changed); err == nil {
			t.Error("rotated an unmanaged VMess inbound")
		}
	}
}

func TestVMessWebSocketRefusesNoncanonicalInboundFieldWithoutPanicking(t *testing.T) {
	a := New()
	id, err := a.PrepareIdentity()
	if err != nil {
		t.Fatal(err)
	}
	source, err := a.EncodeServerConfiguration(id, "google.com:443", "google.com")
	if err != nil {
		t.Fatal(err)
	}
	source = bytes.Replace(source, []byte(`"inbounds"`), []byte(`"Inbounds"`), 1)
	if _, err := a.WithVMessWebSocket(source, "tunnel.example.com"); err == nil {
		t.Fatal("accepted a noncanonical inbound field")
	}
}

func TestVMessProbeHasOneRouteAndNoInfrastructureSecret(t *testing.T) {
	a := New()
	id, _ := a.PrepareIdentity()
	source, _ := a.EncodeServerConfiguration(id, "google.com:443", "google.com")
	source, _ = a.WithVMessWebSocket(source, "tunnel.example.com")
	body, err := a.EncodeVMessProbeConfiguration(source, 12345, "probe-user", "probe-password")
	if err != nil || bytes.Contains(body, []byte(id.PrivateKey)) {
		t.Fatal("unsafe probe encoding", err)
	}
	var config struct {
		Log       map[string]any
		Inbounds  []map[string]any
		Outbounds []map[string]any
		Route     map[string]any
	}
	if json.Unmarshal(body, &config) != nil || len(config.Inbounds) != 1 || len(config.Outbounds) != 1 || config.Outbounds[0]["type"] != "vmess" || config.Outbounds[0]["uuid"] != id.UUID || config.Route["final"] != "vmess-ws-out" || config.Log["disabled"] != true || config.Inbounds[0]["listen"] != "127.0.0.1" {
		t.Fatal("probe permits an unexpected route or exposure")
	}
	for _, port := range []int{0, 65536} {
		if _, err := a.EncodeVMessProbeConfiguration(source, port, "u", "p"); err == nil {
			t.Fatal("unsafe port accepted")
		}
	}
}
