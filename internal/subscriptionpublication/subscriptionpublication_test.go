package subscriptionpublication_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/state"
)

type clientAccessReader map[state.ClientAccessValue]string

func (reader clientAccessReader) ReadClientAccessValue(value state.ClientAccessValue) string {
	return reader[value]
}

func access(reader clientAccessReader, value string) state.ClientAccessValue {
	protected := state.NewClientAccessValue(value)
	reader[protected] = value
	return protected
}

func sixProfileSource(t *testing.T, address string) (connectionprofiles.PublicationSource, clientAccessReader) {
	t.Helper()
	reader := clientAccessReader{}
	profiles := []connectionprofiles.PublicationProfile{
		{ID: connectionprofiles.VLESSRealityVisionProfileID, Name: "VLESS REALITY Vision", Address: address, Port: 443, ServerName: "direct.example.com", Transport: "RAW", Security: "REALITY", UUID: access(reader, "11111111-1111-4111-8111-111111111111"), ShortID: access(reader, "0123456789abcdef"), PublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", Fingerprint: "chrome", Flow: "xtls-rprx-vision"},
		{ID: connectionprofiles.VLESSXHTTPProfileID, Name: "VLESS XHTTP 香港", Address: "xhttp.example.com", Hostname: "xhttp.example.com", Port: 443, Transport: "XHTTP", Security: "TLS", UUID: access(reader, "22222222-2222-4222-8222-222222222222"), Path: access(reader, "/xhttp path?雪"), XHTTPServerMode: state.XHTTPPacketUp},
		{ID: connectionprofiles.VLESSWebSocketProfileID, Name: "VLESS WebSocket", Address: "ws.example.com", Hostname: "ws.example.com", Port: 443, Transport: "WebSocket", Security: "TLS", UUID: access(reader, "33333333-3333-4333-8333-333333333333"), Path: access(reader, "/ws path?獨立"), HTTPHost: "origin.example.com", TLSName: "ws.example.com"},
		{ID: connectionprofiles.Hysteria2ProfileID, Name: "Hysteria2", Address: address, Port: 4443, ServerName: "direct.example.com", Transport: "QUIC", Security: "TLS", Password: access(reader, "hy:p@ss /雪")},
		{ID: connectionprofiles.TUICProfileID, Name: "TUIC", Address: address, Port: 8443, ServerName: "direct.example.com", Transport: "QUIC", Security: "TLS", UUID: access(reader, "55555555-5555-4555-8555-555555555555"), Password: access(reader, "tuic:p@ss /密碼"), CongestionControl: "cubic"},
		{ID: connectionprofiles.AnyTLSProfileID, Name: "AnyTLS", Address: address, Port: 9443, ServerName: "direct.example.com", Transport: "TCP", Security: "TLS", Password: access(reader, "any:p@ss /秘密")},
	}
	source, err := connectionprofiles.NewPublicationSource(profiles, nil)
	if err != nil {
		t.Fatal(err)
	}
	return source, reader
}

func TestRenderProducesDeterministicRawBase64AndV2RayN(t *testing.T) {
	source, reader := sixProfileSource(t, "198.51.100.10")
	module := newAcceptingTestModule()

	first, err := module.Render(t.Context(), source, reader)
	if err != nil {
		t.Fatal(err)
	}
	second, err := module.Render(t.Context(), source, reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Raw, second.Raw) || !bytes.Equal(first.Base64, second.Base64) || !bytes.Equal(first.V2RayN, second.V2RayN) {
		t.Fatal("Render() changed bytes for the same typed source")
	}
	for _, rendered := range []string{fmt.Sprint(first), fmt.Sprintf("%+v", first), fmt.Sprintf("%#v", first)} {
		if strings.Contains(rendered, "hy:p@ss /雪") || strings.Contains(rendered, "11111111-1111-4111-8111-111111111111") {
			t.Fatalf("default artifact formatting exposed a Client Access Value: %s", rendered)
		}
	}
	if encoded, marshalErr := json.Marshal(first); marshalErr == nil || strings.Contains(string(encoded), "hy:p@ss /雪") {
		t.Fatalf("json.Marshal(Artifacts) = %s, %v", encoded, marshalErr)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(first.Base64))
	if err != nil || !bytes.Equal(decoded, first.Raw) || !bytes.Equal(first.Base64, first.V2RayN) {
		t.Fatalf("base64/v2rayN do not encode the exact raw bytes: %v", err)
	}
	lines := strings.Split(string(first.Raw), "\n")
	if len(lines) != 6 || bytes.Contains(first.Raw, []byte{'\r'}) || first.ProfileCount != 6 || len(first.Omissions) != 0 {
		t.Fatalf("Render() metadata = count %d, omissions %v; raw has %d lines", first.ProfileCount, first.Omissions, len(lines))
	}

	want := []struct {
		scheme, username, password, host, fragment string
		query                                      url.Values
	}{
		{"vless", "11111111-1111-4111-8111-111111111111", "", "198.51.100.10:443", "VLESS REALITY Vision", url.Values{"encryption": {"none"}, "flow": {"xtls-rprx-vision"}, "security": {"reality"}, "sni": {"direct.example.com"}, "fp": {"chrome"}, "pbk": {"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}, "sid": {"0123456789abcdef"}, "type": {"tcp"}}},
		{"vless", "22222222-2222-4222-8222-222222222222", "", "xhttp.example.com:443", "VLESS XHTTP 香港", url.Values{"encryption": {"none"}, "security": {"tls"}, "sni": {"xhttp.example.com"}, "type": {"xhttp"}, "host": {"xhttp.example.com"}, "path": {"/xhttp path?雪"}, "mode": {"auto"}}},
		{"vless", "33333333-3333-4333-8333-333333333333", "", "ws.example.com:443", "VLESS WebSocket", url.Values{"encryption": {"none"}, "security": {"tls"}, "sni": {"ws.example.com"}, "type": {"ws"}, "host": {"origin.example.com"}, "path": {"/ws path?獨立"}}},
		{"hysteria2", "hy:p@ss /雪", "", "198.51.100.10:4443", "Hysteria2", url.Values{"sni": {"direct.example.com"}, "insecure": {"0"}}},
		{"tuic", "55555555-5555-4555-8555-555555555555", "tuic:p@ss /密碼", "198.51.100.10:8443", "TUIC", url.Values{"sni": {"direct.example.com"}, "congestion_control": {"cubic"}, "insecure": {"0"}}},
		{"anytls", "any:p@ss /秘密", "", "198.51.100.10:9443", "AnyTLS", url.Values{"security": {"tls"}, "sni": {"direct.example.com"}, "type": {"tcp"}, "insecure": {"0"}}},
	}
	for index, raw := range lines {
		parsed, parseErr := url.Parse(raw)
		if parseErr != nil {
			t.Fatalf("URI %d: %v", index, parseErr)
		}
		password, _ := parsed.User.Password()
		got := want[index]
		if parsed.Scheme != got.scheme || parsed.User.Username() != got.username || password != got.password || parsed.Host != got.host || parsed.Fragment != got.fragment || !slices.EqualFunc(sortedValues(parsed.Query()), sortedValues(got.query), func(a, b string) bool { return a == b }) {
			t.Fatalf("URI %d = %q; parsed as scheme=%q user=%q password=%q host=%q query=%v fragment=%q", index, raw, parsed.Scheme, parsed.User.Username(), password, parsed.Host, parsed.Query(), parsed.Fragment)
		}
	}
}

func sortedValues(values url.Values) []string {
	return strings.Split(values.Encode(), "&")
}

func TestRenderBracketsIPv6AndOmitsDisabledProfile(t *testing.T) {
	source, reader := sixProfileSource(t, "2001:db8::10")
	profiles := source.Profiles()
	profiles = slices.Delete(profiles, 1, 2)
	source, err := connectionprofiles.NewPublicationSource(profiles, []connectionprofiles.PublicationOmission{{ID: connectionprofiles.VLESSXHTTPProfileID, Name: "VLESS XHTTP", Lifecycle: state.ProfileDisabled}})
	if err != nil {
		t.Fatal(err)
	}

	result, err := newAcceptingTestModule().Render(t.Context(), source, reader)
	if err != nil {
		t.Fatal(err)
	}
	if result.ProfileCount != 5 || len(result.Omissions) != 1 || result.Omissions[0].ID != connectionprofiles.VLESSXHTTPProfileID || strings.Contains(string(result.Raw), "22222222-2222-4222-8222-222222222222") || strings.Contains(string(result.Raw), "VLESS%20XHTTP") || !strings.Contains(string(result.Raw), "@[2001:db8::10]:443") {
		t.Fatalf("Render() did not preserve IPv6/omission facts: count=%d omissions=%v raw=%s", result.ProfileCount, result.Omissions, result.Raw)
	}
}

func TestRenderRefusesIncompleteSourceWithoutLeakingSecrets(t *testing.T) {
	source, reader := sixProfileSource(t, "198.51.100.10")
	profiles := source.Profiles()
	profiles[3].ServerName = ""
	source, err := connectionprofiles.NewPublicationSource(profiles, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = newAcceptingTestModule().Render(t.Context(), source, reader)
	if err == nil || strings.Contains(err.Error(), "hy:p@ss /雪") {
		t.Fatalf("Render() error = %v", err)
	}
}
