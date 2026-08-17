package subscriptionpublication_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
)

func TestPrepareClientAccessMutationRotatesOne256BitTokenWithoutRevokingProfiles(t *testing.T) {
	current := clientAccessDesiredState()
	source := clientAccessPublicationSource(t, current, "198.51.100.10")
	mutation, err := subscriptionpublication.PrepareClientAccessMutation(subscriptionpublication.RotateSubscriptionToken, "198.51.100.10", current.Subscription, current.ConnectionProfiles, source)
	if err != nil {
		t.Fatal(err)
	}
	if mutation.Subscription().Token == current.Subscription.Token || mutation.ConnectionProfiles() != current.ConnectionProfiles {
		t.Fatal("token-only rotation did not preserve all Connection Profile credentials and settings")
	}
	if mutation.Effect() != "future downloads at the prior URL are revoked; already downloaded Connection Profile credentials remain valid" {
		t.Fatalf("effect = %q", mutation.Effect())
	}
	assertClientAccessRoute(t, mutation, "198.51.100.10", "")
	ipv6Source := clientAccessPublicationSource(t, current, "2001:db8::10")
	ipv6Mutation, err := subscriptionpublication.PrepareClientAccessMutation(subscriptionpublication.RotateSubscriptionToken, "2001:db8::10", current.Subscription, current.ConnectionProfiles, ipv6Source)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []subscriptionpublication.RepresentationIdentity{
		subscriptionpublication.Base64Representation, subscriptionpublication.RawRepresentation, subscriptionpublication.V2RayNRepresentation,
		subscriptionpublication.ShadowrocketRepresentation, subscriptionpublication.KaringRepresentation, subscriptionpublication.MihomoRepresentation,
		subscriptionpublication.SingBoxRepresentation,
	} {
		assertClientAccessRoute(t, ipv6Mutation, "2001:db8::10", string(suffix))
	}
	if _, err := mutation.Route("/unsupported"); err == nil {
		t.Fatal("unsupported route suffix was accepted")
	}
	second, err := subscriptionpublication.PrepareClientAccessMutation(subscriptionpublication.RotateSubscriptionToken, "198.51.100.10", current.Subscription, current.ConnectionProfiles, source)
	if err != nil || second.Subscription().Token == mutation.Subscription().Token {
		t.Fatal("independent token rotation did not produce a fresh token")
	}
	for _, rendered := range []string{fmt.Sprint(mutation), fmt.Sprintf("%+v", mutation), fmt.Sprintf("%#v", mutation)} {
		if strings.Contains(rendered, "/s/") {
			t.Fatalf("mutation formatting exposed a complete access route: %s", rendered)
		}
	}
	if encoded, err := json.Marshal(mutation); err == nil || strings.Contains(string(encoded), "/s/") {
		t.Fatalf("json.Marshal(mutation) = %s, %v", encoded, err)
	}
}

func TestPrepareClientAccessMutationRevokesAllSixProfilesWithoutChangingSettings(t *testing.T) {
	current := clientAccessDesiredState()
	current.ConnectionProfiles.VLESSXHTTP.Enabled = false
	source := clientAccessPublicationSource(t, current, "198.51.100.10")
	mutation, err := subscriptionpublication.PrepareClientAccessMutation(subscriptionpublication.RevokeAllClientAccess, "198.51.100.10", current.Subscription, current.ConnectionProfiles, source)
	if err != nil {
		t.Fatal(err)
	}
	if mutation.Subscription().Token == current.Subscription.Token {
		t.Fatal("subscription token was preserved")
	}
	if mutation.ConnectionProfiles().VLESSXHTTP.Enabled {
		t.Fatal("disabled Connection Profile was re-enabled")
	}
	assertProfileCredentialsReplaced(t, current.ConnectionProfiles, mutation.ConnectionProfiles())
	withoutCredentials := func(profiles state.ConnectionProfiles) state.ConnectionProfiles {
		profiles.VLESSRealityVision.UUID, profiles.VLESSRealityVision.PrivateKey, profiles.VLESSRealityVision.PublicKey, profiles.VLESSRealityVision.ShortID = state.ClientAccessValue{}, state.InfrastructureSecret{}, "", state.ClientAccessValue{}
		profiles.VLESSXHTTP.UUID, profiles.VLESSXHTTP.Path = state.ClientAccessValue{}, state.ClientAccessValue{}
		profiles.VLESSWebSocket.UUID, profiles.VLESSWebSocket.Path = state.ClientAccessValue{}, state.ClientAccessValue{}
		profiles.Hysteria2.Password, profiles.Hysteria2.ObfuscationSecret = state.ClientAccessValue{}, state.ClientAccessValue{}
		profiles.TUIC.UUID, profiles.TUIC.Password = state.ClientAccessValue{}, state.ClientAccessValue{}
		profiles.AnyTLS.Password = state.ClientAccessValue{}
		return profiles
	}
	if !reflect.DeepEqual(withoutCredentials(mutation.ConnectionProfiles()), withoutCredentials(current.ConnectionProfiles)) {
		t.Fatal("revoke all changed Connection Profile settings")
	}
	if mutation.Effect() != "future downloads and all six prior Connection Profile credentials are revoked together" {
		t.Fatalf("effect = %q", mutation.Effect())
	}
}

func assertClientAccessRoute(t *testing.T, mutation *subscriptionpublication.ClientAccessMutation, address, suffix string) {
	t.Helper()
	route, err := mutation.Route(suffix)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(route)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != address || parsed.Port() != "10443" {
		t.Fatalf("route = %q, %v", route, err)
	}
	parts := strings.Split(strings.TrimPrefix(parsed.EscapedPath(), "/s/"), "/")
	decoded, decodeErr := hex.DecodeString(parts[0])
	if decodeErr != nil || len(decoded) != 32 || strings.Join(parts[1:], "/") != strings.TrimPrefix(suffix, "/") {
		t.Fatalf("route path = %q, token bytes = %d, decode = %v", parsed.EscapedPath(), len(decoded), decodeErr)
	}
}

func assertProfileCredentialsReplaced(t *testing.T, current, candidate state.ConnectionProfiles) {
	t.Helper()
	checks := []struct {
		name string
		old  any
		new  any
	}{
		{"REALITY UUID", current.VLESSRealityVision.UUID, candidate.VLESSRealityVision.UUID},
		{"REALITY private key", current.VLESSRealityVision.PrivateKey, candidate.VLESSRealityVision.PrivateKey},
		{"REALITY public key", current.VLESSRealityVision.PublicKey, candidate.VLESSRealityVision.PublicKey},
		{"REALITY short ID", current.VLESSRealityVision.ShortID, candidate.VLESSRealityVision.ShortID},
		{"XHTTP UUID", current.VLESSXHTTP.UUID, candidate.VLESSXHTTP.UUID},
		{"XHTTP path", current.VLESSXHTTP.Path, candidate.VLESSXHTTP.Path},
		{"WebSocket UUID", current.VLESSWebSocket.UUID, candidate.VLESSWebSocket.UUID},
		{"WebSocket path", current.VLESSWebSocket.Path, candidate.VLESSWebSocket.Path},
		{"Hysteria2 password", current.Hysteria2.Password, candidate.Hysteria2.Password},
		{"Hysteria2 obfuscation secret", current.Hysteria2.ObfuscationSecret, candidate.Hysteria2.ObfuscationSecret},
		{"TUIC UUID", current.TUIC.UUID, candidate.TUIC.UUID},
		{"TUIC password", current.TUIC.Password, candidate.TUIC.Password},
		{"AnyTLS password", current.AnyTLS.Password, candidate.AnyTLS.Password},
	}
	for _, check := range checks {
		if reflect.DeepEqual(check.old, check.new) {
			t.Errorf("%s was preserved", check.name)
		}
	}
}

func clientAccessDesiredState() state.DesiredState {
	access := func(value string) state.ClientAccessValue { return state.NewClientAccessValue(value) }
	return state.DesiredState{
		ConnectionProfiles: state.ConnectionProfiles{
			VLESSRealityVision: state.VLESSRealityVision{Enabled: true, Port: 443, UUID: access("old-reality-uuid"), PrivateKey: state.NewInfrastructureSecret("old-private"), PublicKey: "old-public", ShortID: access("old-short"), Target: "example.com:443", ServerName: "example.com", Fingerprint: "chrome"},
			VLESSXHTTP:         state.VLESSXHTTP{Enabled: true, UUID: access("old-xhttp-uuid"), Path: access("old-xhttp-path"), Hostname: "x.example.com", OriginAddress: "127.0.0.1", OriginPort: 10001, Mode: state.XHTTPPacketUp},
			VLESSWebSocket:     state.VLESSWebSocket{Enabled: true, UUID: access("old-websocket-uuid"), Path: access("old-websocket-path"), Hostname: "ws.example.com", OriginAddress: "127.0.0.1", OriginPort: 10002},
			Hysteria2:          state.Hysteria2{Enabled: true, Port: 8443, Password: access("old-hysteria-password"), ServerName: "direct.example.com", CertificateID: "domain-certificate", MasqueradeURL: "https://example.com", Obfuscation: true, ObfuscationSecret: access("old-obfuscation")},
			TUIC:               state.TUIC{Enabled: true, Port: 9443, UUID: access("old-tuic-uuid"), Password: access("old-tuic-password"), ServerName: "direct.example.com", CertificateID: "domain-certificate", CongestionControl: state.CongestionBBR},
			AnyTLS:             state.AnyTLS{Enabled: true, Port: 10444, Password: access("old-anytls-password"), ServerName: "direct.example.com", CertificateID: "domain-certificate", PaddingScheme: "stop=8"},
		},
		Subscription: state.SubscriptionSettings{Token: access("old-subscription-token"), ListenPort: 10443, CertificateID: "ip-certificate"},
	}
}

func clientAccessPublicationSource(t *testing.T, desired state.DesiredState, address string) connectionprofiles.PublicationSource {
	t.Helper()
	profiles := desired.ConnectionProfiles
	all := []struct {
		enabled bool
		profile connectionprofiles.PublicationProfile
	}{
		{profiles.VLESSRealityVision.Enabled, connectionprofiles.PublicationProfile{ID: connectionprofiles.VLESSRealityVisionProfileID, Name: "VLESS REALITY Vision", Address: address, Port: profiles.VLESSRealityVision.Port, ServerName: profiles.VLESSRealityVision.ServerName, Transport: "RAW", Security: "REALITY", UUID: profiles.VLESSRealityVision.UUID, ShortID: profiles.VLESSRealityVision.ShortID, PublicKey: profiles.VLESSRealityVision.PublicKey, Fingerprint: profiles.VLESSRealityVision.Fingerprint, Flow: "xtls-rprx-vision"}},
		{profiles.VLESSXHTTP.Enabled, connectionprofiles.PublicationProfile{ID: connectionprofiles.VLESSXHTTPProfileID, Name: "VLESS XHTTP", Address: profiles.VLESSXHTTP.Hostname, Hostname: profiles.VLESSXHTTP.Hostname, Port: 443, Transport: "XHTTP", Security: "TLS", UUID: profiles.VLESSXHTTP.UUID, Path: profiles.VLESSXHTTP.Path, XHTTPServerMode: profiles.VLESSXHTTP.Mode}},
		{profiles.VLESSWebSocket.Enabled, connectionprofiles.PublicationProfile{ID: connectionprofiles.VLESSWebSocketProfileID, Name: "VLESS WebSocket", Address: profiles.VLESSWebSocket.Hostname, Hostname: profiles.VLESSWebSocket.Hostname, Port: 443, Transport: "WebSocket", Security: "TLS", UUID: profiles.VLESSWebSocket.UUID, Path: profiles.VLESSWebSocket.Path, HTTPHost: profiles.VLESSWebSocket.Hostname, TLSName: profiles.VLESSWebSocket.Hostname}},
		{profiles.Hysteria2.Enabled, connectionprofiles.PublicationProfile{ID: connectionprofiles.Hysteria2ProfileID, Name: "Hysteria2", Address: address, Port: profiles.Hysteria2.Port, ServerName: profiles.Hysteria2.ServerName, Transport: "QUIC", Security: "TLS", Password: profiles.Hysteria2.Password, Obfuscation: profiles.Hysteria2.Obfuscation, ObfuscationSecret: profiles.Hysteria2.ObfuscationSecret}},
		{profiles.TUIC.Enabled, connectionprofiles.PublicationProfile{ID: connectionprofiles.TUICProfileID, Name: "TUIC", Address: address, Port: profiles.TUIC.Port, ServerName: profiles.TUIC.ServerName, Transport: "QUIC", Security: "TLS", UUID: profiles.TUIC.UUID, Password: profiles.TUIC.Password, CongestionControl: profiles.TUIC.CongestionControl}},
		{profiles.AnyTLS.Enabled, connectionprofiles.PublicationProfile{ID: connectionprofiles.AnyTLSProfileID, Name: "AnyTLS", Address: address, Port: profiles.AnyTLS.Port, ServerName: profiles.AnyTLS.ServerName, Transport: "TCP", Security: "TLS", Password: profiles.AnyTLS.Password}},
	}
	var enabled []connectionprofiles.PublicationProfile
	var omissions []connectionprofiles.PublicationOmission
	for _, item := range all {
		if item.enabled {
			enabled = append(enabled, item.profile)
		} else {
			omissions = append(omissions, connectionprofiles.PublicationOmission{ID: item.profile.ID, Name: item.profile.Name, Lifecycle: state.ProfileDisabled})
		}
	}
	source, err := connectionprofiles.NewPublicationSource(enabled, omissions)
	if err != nil {
		t.Fatal(err)
	}
	return source
}
