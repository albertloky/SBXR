package subscriptionserving

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestServeReturnsEveryPublishedRepresentationExactly(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "all enabled", true: "WebSocket disabled"}[disabled], func(t *testing.T) {
			server, roots, token, _ := testServer(t, "127.0.0.1")
			artifacts := installPublicationFixture(t, server, "2001:db8::10", disabled)
			listener, cancel := startServer(t, server, "tcp4", "127.0.0.1:0")
			defer cancel()
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: testTLSConfig(roots, "127.0.0.1")}}
			base := "https://" + listener.Addr().String() + "/s/" + token
			checks := []struct {
				suffix, identity, contentType string
				body                          []byte
				omitsXHTTP                    bool
			}{
				{"/base64", "base64-uri-list", "text/plain; charset=utf-8", artifacts.Base64, false},
				{"/raw", "raw-uri-list", "text/plain; charset=utf-8", artifacts.Raw, false},
				{"/v2rayn", "v2rayn-base64-uri-list", "text/plain; charset=utf-8", artifacts.V2RayN, false},
				{"/shadowrocket", "shadowrocket-candidate", "text/plain; charset=utf-8", artifacts.Shadowrocket, false},
				{"/karing", "karing-sing-box-json", "application/json", artifacts.Karing.Body, true},
				{"/mihomo", "mihomo-yaml", "application/yaml", artifacts.Mihomo, false},
				{"/sing-box", "sing-box-json", "application/json", artifacts.SingBox.Body, true},
			}
			for _, check := range checks {
				request, _ := http.NewRequest(http.MethodGet, base+check.suffix, nil)
				request.Header.Set("User-Agent", "v2rayN/7.15")
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()
				if response.StatusCode != http.StatusOK || !bytes.Equal(body, check.body) {
					t.Fatalf("GET %s = %d, exact body %t", check.suffix, response.StatusCode, bytes.Equal(body, check.body))
				}
				if response.Header.Get("Content-Type") != check.contentType || response.Header.Get("X-SBXR-Representation") != check.identity || response.Header.Get("Vary") != "" {
					t.Fatalf("GET %s headers = Content-Type %q, representation %q, Vary %q", check.suffix, response.Header.Get("Content-Type"), response.Header.Get("X-SBXR-Representation"), response.Header.Get("Vary"))
				}
				if got := response.Header.Get("X-SBXR-Omitted-Profile"); (got == "vless-xhttp") != check.omitsXHTTP {
					t.Fatalf("GET %s omitted profile = %q", check.suffix, got)
				}
				for name, want := range map[string]string{"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"} {
					if response.Header.Get(name) != want {
						t.Fatalf("GET %s %s = %q", check.suffix, name, response.Header.Get(name))
					}
				}
			}
			wantCount := 6
			if disabled {
				wantCount = 5
			}
			if artifacts.ProfileCount != wantCount || strings.Count(string(artifacts.Raw), "\n")+1 != wantCount || artifacts.SingBox.ProfileCount != wantCount-1 || artifacts.Karing.ProfileCount != wantCount-1 {
				t.Fatalf("published counts = raw %d, sing-box %d, Karing %d", artifacts.ProfileCount, artifacts.SingBox.ProfileCount, artifacts.Karing.ProfileCount)
			}
			if disabled {
				for _, body := range [][]byte{artifacts.Raw, artifacts.Mihomo, artifacts.SingBox.Body, artifacts.Karing.Body} {
					if bytes.Contains(body, []byte("33333333-3333-4333-8333-333333333333")) {
						t.Fatal("disabled WebSocket profile was served")
					}
				}
			} else {
				decoded, err := base64.StdEncoding.DecodeString(string(artifacts.Base64))
				if err != nil || !bytes.Equal(decoded, artifacts.Raw) || !bytes.Contains(artifacts.Raw, []byte("@[2001:db8::10]:443")) || !bytes.Contains(artifacts.Raw, []byte("VLESS%20XHTTP%20%E9%A6%99%E6%B8%AF")) || len(artifacts.SingBox.Omissions) != 1 || len(artifacts.Karing.Omissions) != 1 {
					t.Fatal("published bytes lost base64, IPv6, percent encoding, or XHTTP omission facts")
				}
			}
		})
	}
}

func TestServeNegotiatesOnlyTheUnsuffixedRoute(t *testing.T) {
	server, roots, token, _ := testServer(t, "127.0.0.1")
	artifacts := installPublicationFixture(t, server, "2001:db8::10", false)
	listener, cancel := startServer(t, server, "tcp4", "127.0.0.1:0")
	defer cancel()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: testTLSConfig(roots, "127.0.0.1")}}
	base := "https://" + listener.Addr().String() + "/s/" + token
	checks := []struct {
		name, userAgent, identity string
		body                      []byte
	}{
		{"v2rayN", "v2rayN/7.15", "v2rayn-base64-uri-list", artifacts.V2RayN},
		{"mixed case Mihomo", "MiHoMo/1.19", "mihomo-yaml", artifacts.Mihomo},
		{"ClashMeta", "ClAsHmEtA/1.19", "mihomo-yaml", artifacts.Mihomo},
		{"Clash Meta", "ClAsH MeTa/1.19", "mihomo-yaml", artifacts.Mihomo},
		{"sing-box", "sing-box/1.12", "sing-box-json", artifacts.SingBox.Body},
		{"unknown", "curl/8.7", "base64-uri-list", artifacts.Base64},
		{"generic v2ray", "v2ray/5.0", "base64-uri-list", artifacts.Base64},
		{"ambiguous", "v2rayN/7.15 sing-box/1.12", "base64-uri-list", artifacts.Base64},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodGet, base, nil)
			request.Header.Set("User-Agent", check.userAgent)
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusOK || !bytes.Equal(body, check.body) || response.Header.Get("X-SBXR-Representation") != check.identity || response.Header.Get("Vary") != "User-Agent" {
				t.Fatalf("GET base = %d, exact body %t, representation %q, Vary %q", response.StatusCode, bytes.Equal(body, check.body), response.Header.Get("X-SBXR-Representation"), response.Header.Get("Vary"))
			}
		})
	}
}

type servingTestSecrets map[state.ClientAccessValue]string

func (secrets servingTestSecrets) ReadClientAccessValue(value state.ClientAccessValue) string {
	return secrets[value]
}

func servingTestAccess(secrets servingTestSecrets, value string) state.ClientAccessValue {
	protected := state.NewClientAccessValue(value)
	secrets[protected] = value
	return protected
}

type acceptingServingValidator struct{}

func (acceptingServingValidator) ValidateMihomo(context.Context, io.Reader) error  { return nil }
func (acceptingServingValidator) ValidateSingBox(context.Context, io.Reader) error { return nil }

var publicationFixtureSHA256 = map[bool]map[string]string{
	false: {
		"base64": "eb267eeb4a13c417d4f1d96713c436bf9a1ec0057e47206fffc7e1433c5939a4", "raw": "f764c0d2e6cdf1e09a6a6f41ea8e3c44ba2a28c6f202092a3fd8ce83b48a75d6",
		"v2rayn": "eb267eeb4a13c417d4f1d96713c436bf9a1ec0057e47206fffc7e1433c5939a4", "shadowrocket": "eb267eeb4a13c417d4f1d96713c436bf9a1ec0057e47206fffc7e1433c5939a4",
		"karing": "938533488b165fe16145c09e5180c4e7771eea7e3d775d6dd5f6e5ba71f55336", "mihomo": "a0f2294295f85df703861e8014d4f6e4e989b625c25affb2f8525b294ec10ff2",
		"sing-box": "938533488b165fe16145c09e5180c4e7771eea7e3d775d6dd5f6e5ba71f55336", "metadata": "237c1ee3c27de70439e30f15465a445abca66919d61f0877d3170181bdd9a4f9",
	},
	true: {
		"base64": "17aec15e5148867995b6068cc86abba6f669e739dac3d770c6768e1847b68c1d", "raw": "a43d2631593f429c543417b4f5226fa17b755b6b14e3bf5136d1ed144b37f727",
		"v2rayn": "17aec15e5148867995b6068cc86abba6f669e739dac3d770c6768e1847b68c1d", "shadowrocket": "17aec15e5148867995b6068cc86abba6f669e739dac3d770c6768e1847b68c1d",
		"karing": "13f2177e1fdb4ce9e8675bcc5c58619c168fc127c94c08cadfb3b127c28db6a6", "mihomo": "345581358d199c2213ef3cd470eaf7017c3335be2507280b07a0f522dbdc793d",
		"sing-box": "13f2177e1fdb4ce9e8675bcc5c58619c168fc127c94c08cadfb3b127c28db6a6", "metadata": "e6185b6e8012fa0dc3f487fa917f82af189801169cb4e058b766c569bf002d36",
	},
}

func installPublicationFixture(t *testing.T, server Server, address string, disableWebSocket bool) subscriptionpublication.Artifacts {
	t.Helper()
	secrets := servingTestSecrets{}
	profiles := []connectionprofiles.PublicationProfile{
		{ID: connectionprofiles.VLESSRealityVisionProfileID, Name: "VLESS REALITY Vision", Address: address, Port: 443, ServerName: "direct.example.com", Transport: "RAW", Security: "REALITY", UUID: servingTestAccess(secrets, "11111111-1111-4111-8111-111111111111"), ShortID: servingTestAccess(secrets, "0123456789abcdef"), PublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", Fingerprint: "chrome", Flow: "xtls-rprx-vision"},
		{ID: connectionprofiles.VLESSXHTTPProfileID, Name: "VLESS XHTTP 香港", Address: "xhttp.example.com", Hostname: "xhttp.example.com", Port: 443, Transport: "XHTTP", Security: "TLS", UUID: servingTestAccess(secrets, "22222222-2222-4222-8222-222222222222"), Path: servingTestAccess(secrets, "/xhttp path?雪"), XHTTPServerMode: state.XHTTPPacketUp},
		{ID: connectionprofiles.VLESSWebSocketProfileID, Name: "VLESS WebSocket", Address: "ws.example.com", Hostname: "ws.example.com", Port: 443, Transport: "WebSocket", Security: "TLS", UUID: servingTestAccess(secrets, "33333333-3333-4333-8333-333333333333"), Path: servingTestAccess(secrets, "/ws path?獨立"), HTTPHost: "origin.example.com", TLSName: "ws.example.com"},
		{ID: connectionprofiles.Hysteria2ProfileID, Name: "Hysteria2", Address: address, Port: 4443, ServerName: "direct.example.com", Transport: "QUIC", Security: "TLS", Password: servingTestAccess(secrets, "hy:p@ss /雪")},
		{ID: connectionprofiles.TUICProfileID, Name: "TUIC", Address: address, Port: 8443, ServerName: "direct.example.com", Transport: "QUIC", Security: "TLS", UUID: servingTestAccess(secrets, "55555555-5555-4555-8555-555555555555"), Password: servingTestAccess(secrets, "tuic:p@ss /密碼"), CongestionControl: "cubic"},
		{ID: connectionprofiles.AnyTLSProfileID, Name: "AnyTLS", Address: address, Port: 9443, ServerName: "direct.example.com", Transport: "TCP", Security: "TLS", Password: servingTestAccess(secrets, "any:p@ss /秘密")},
	}
	omissions := []connectionprofiles.PublicationOmission(nil)
	if disableWebSocket {
		profiles = append(profiles[:2], profiles[3:]...)
		omissions = []connectionprofiles.PublicationOmission{{ID: connectionprofiles.VLESSWebSocketProfileID, Name: "VLESS WebSocket", Lifecycle: state.ProfileDisabled}}
	}
	source, err := connectionprofiles.NewPublicationSource(profiles, omissions)
	if err != nil {
		t.Fatal(err)
	}
	module := subscriptionpublication.New(acceptingServingValidator{}, acceptingServingValidator{})
	artifacts, err := module.Render(t.Context(), source, secrets)
	if err != nil {
		t.Fatal(err)
	}
	token := servingTestAccess(secrets, strings.Repeat("t", 32))
	result := module.Plan(t.Context(), subscriptionpublication.PlanRequest{
		Source: source, Secrets: secrets, Subscription: state.SubscriptionSettings{Token: token, ListenPort: 10443, CertificateID: "ip-certificate"},
		ChangeSet: "serve-fixture", StartingState: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 1, SHA256: strings.Repeat("c", 64)},
		DesiredStateRevision: 2, DesiredStateSHA256: strings.Repeat("d", 64), ManagedInputsSHA256: strings.Repeat("e", 64),
		RelevantChecksums:       subscriptionpublication.RelevantChecksums{ConnectionProfiles: strings.Repeat("f", 64), Subscription: strings.Repeat("1", 64)},
		CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, SelectedAddress: address,
		ReleaseIdentity: state.ReleaseIdentity{Repository: "github.com/albertloky/SBXR", Tag: "v1.0.0", Commit: strings.Repeat("a", 40), ReleaseIndexSHA256: strings.Repeat("b", 64)},
	})
	if result.Plan == nil || result.Finding != nil {
		t.Fatalf("Plan() = %+v", result.Finding)
	}
	bundle, err := result.Plan.PrepareSubscriptionPublication()
	if err != nil {
		t.Fatal(err)
	}
	set, err := subscriptionpublication.DecodePreparedArtifactSet(bytes.NewReader(bundle))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range set.Files() {
		if got := fmt.Sprintf("%x", sha256.Sum256(file.Body)); got != publicationFixtureSHA256[disableWebSocket][file.Name] {
			t.Fatalf("immutable Publication fixture %s SHA-256 = %s", file.Name, got)
		}
		if err := os.WriteFile(filepath.Join(server.root, artifactPath, file.Name), file.Body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return artifacts
}
