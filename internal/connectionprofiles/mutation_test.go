package connectionprofiles_test

import (
	"testing"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/state"
)

func TestPrepareRegistryMutationCoversTheFourReviewedProfileChanges(t *testing.T) {
	fixture, err := connectionprofiles.NewQualificationFixture()
	if err != nil {
		t.Fatal(err)
	}
	current := profilesFromPublication(fixture.PublicationSource())

	tests := []struct {
		name    string
		action  connectionprofiles.RegistryMutationAction
		profile connectionprofiles.ProfileID
		check   func(*testing.T, state.ConnectionProfiles, connectionprofiles.PublicationSource)
	}{
		{"disable", connectionprofiles.DisableProfile, connectionprofiles.VLESSXHTTPProfileID, func(t *testing.T, candidate state.ConnectionProfiles, source connectionprofiles.PublicationSource) {
			if candidate.VLESSXHTTP.Enabled || candidate.VLESSXHTTP.Lifecycle != state.ProfileDisabled || candidate.VLESSXHTTP.UUID != current.VLESSXHTTP.UUID || len(source.Omissions()) != 1 || source.Omissions()[0].ID != connectionprofiles.VLESSXHTTPProfileID {
				t.Fatalf("disabled candidate = %+v omissions=%+v", candidate.VLESSXHTTP, source.Omissions())
			}
		}},
		{"enable", connectionprofiles.EnableProfile, connectionprofiles.VLESSXHTTPProfileID, func(t *testing.T, candidate state.ConnectionProfiles, source connectionprofiles.PublicationSource) {
			if !candidate.VLESSXHTTP.Enabled || candidate.VLESSXHTTP.Lifecycle != state.ProfileEnabled || !connectionprofiles.PublicationInputsMatch(source, candidate) {
				t.Fatalf("enabled candidate did not agree with publication")
			}
		}},
		{"rotate one", connectionprofiles.RotateProfileCredential, connectionprofiles.AnyTLSProfileID, func(t *testing.T, candidate state.ConnectionProfiles, source connectionprofiles.PublicationSource) {
			if candidate.AnyTLS.Password == current.AnyTLS.Password || candidate.TUIC.Password != current.TUIC.Password || !connectionprofiles.PublicationInputsMatch(source, candidate) {
				t.Fatalf("single-profile rotation changed the wrong credential")
			}
		}},
		{"rotate all", connectionprofiles.RotateEveryProfileCredential, "", func(t *testing.T, candidate state.ConnectionProfiles, source connectionprofiles.PublicationSource) {
			if candidate.VLESSRealityVision.UUID == current.VLESSRealityVision.UUID || candidate.VLESSXHTTP.UUID == current.VLESSXHTTP.UUID || candidate.VLESSWebSocket.UUID == current.VLESSWebSocket.UUID || candidate.Hysteria2.Password == current.Hysteria2.Password || candidate.TUIC.Password == current.TUIC.Password || candidate.AnyTLS.Password == current.AnyTLS.Password || !connectionprofiles.PublicationInputsMatch(source, candidate) {
				t.Fatalf("all-profile rotation was incomplete")
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := current
			if test.action == connectionprofiles.EnableProfile {
				base.VLESSXHTTP.Enabled = false
			}
			source, err := connectionprofiles.PublicationSourceFor("192.0.2.10", base)
			if err != nil {
				t.Fatal(err)
			}
			mutation, err := connectionprofiles.PrepareRegistryMutation(test.action, test.profile, "192.0.2.10", base, source)
			if err != nil {
				t.Fatal(err)
			}
			test.check(t, mutation.ConnectionProfiles(), mutation.PublicationSource())
		})
	}
}

func TestPrepareRegistryMutationRefusesAmbiguousAndRepeatedChanges(t *testing.T) {
	fixture, err := connectionprofiles.NewQualificationFixture()
	if err != nil {
		t.Fatal(err)
	}
	current := profilesFromPublication(fixture.PublicationSource())
	source, err := connectionprofiles.PublicationSourceFor("192.0.2.10", current)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct {
		action  connectionprofiles.RegistryMutationAction
		profile connectionprofiles.ProfileID
	}{
		{connectionprofiles.EnableProfile, connectionprofiles.VLESSXHTTPProfileID},
		{connectionprofiles.DisableProfile, connectionprofiles.ProfileID("unknown")},
		{connectionprofiles.RotateEveryProfileCredential, connectionprofiles.AnyTLSProfileID},
	} {
		if mutation, err := connectionprofiles.PrepareRegistryMutation(request.action, request.profile, "192.0.2.10", current, source); err == nil || mutation != nil {
			t.Fatalf("invalid mutation accepted: action=%q profile=%q", request.action, request.profile)
		}
	}
}

func profilesFromPublication(source connectionprofiles.PublicationSource) state.ConnectionProfiles {
	var candidate state.ConnectionProfiles
	for _, profile := range source.Profiles() {
		switch profile.ID {
		case connectionprofiles.VLESSRealityVisionProfileID:
			candidate.VLESSRealityVision = state.VLESSRealityVision{Enabled: true, Port: profile.Port, UUID: profile.UUID, PrivateKey: state.NewInfrastructureSecret("qualification-private-key"), PublicKey: profile.PublicKey, ShortID: profile.ShortID, Target: "edge.example.net:443", ServerName: profile.ServerName, Fingerprint: profile.Fingerprint}
		case connectionprofiles.VLESSXHTTPProfileID:
			candidate.VLESSXHTTP = state.VLESSXHTTP{Enabled: true, UUID: profile.UUID, Path: profile.Path, Hostname: profile.Hostname, OriginAddress: "127.0.0.1", OriginPort: 11080, Mode: profile.XHTTPServerMode}
		case connectionprofiles.VLESSWebSocketProfileID:
			candidate.VLESSWebSocket = state.VLESSWebSocket{Enabled: true, UUID: profile.UUID, Path: profile.Path, Hostname: profile.Hostname, OriginAddress: "127.0.0.1", OriginPort: 11081}
		case connectionprofiles.Hysteria2ProfileID:
			candidate.Hysteria2 = state.Hysteria2{Enabled: true, Port: profile.Port, Password: profile.Password, ServerName: profile.ServerName, CertificateID: "qualification", MasqueradeURL: "https://example.com/", Obfuscation: profile.Obfuscation, ObfuscationSecret: profile.ObfuscationSecret}
		case connectionprofiles.TUICProfileID:
			candidate.TUIC = state.TUIC{Enabled: true, Port: profile.Port, UUID: profile.UUID, Password: profile.Password, ServerName: profile.ServerName, CertificateID: "qualification", CongestionControl: profile.CongestionControl}
		case connectionprofiles.AnyTLSProfileID:
			candidate.AnyTLS = state.AnyTLS{Enabled: true, Port: profile.Port, Password: profile.Password, ServerName: profile.ServerName, CertificateID: "qualification"}
		}
	}
	return candidate
}
