package subscriptionpublication_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
)

func TestRenderProducesSixURIShadowrocketCandidate(t *testing.T) {
	source, reader := sixProfileSource(t, "198.51.100.10")
	first, err := newAcceptingTestModule().Render(t.Context(), source, reader)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newAcceptingTestModule().Render(t.Context(), source, reader)
	if err != nil {
		t.Fatal(err)
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(string(first.Shadowrocket))
	if decodeErr != nil || !bytes.Equal(first.Shadowrocket, first.Base64) || !bytes.Equal(first.Shadowrocket, second.Shadowrocket) || !bytes.Equal(decoded, first.Raw) || len(strings.Split(string(decoded), "\n")) != 6 {
		t.Fatalf("Shadowrocket candidate changed the six-URI base64 artifact: decode=%v stable=%t", decodeErr, bytes.Equal(first.Shadowrocket, second.Shadowrocket))
	}
}

func TestArtifactsMapEveryRepresentationIdentityToValidatedBody(t *testing.T) {
	source, reader := sixProfileSource(t, "198.51.100.10")
	artifacts, err := newAcceptingTestModule().Render(t.Context(), source, reader)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		identity subscriptionpublication.RepresentationIdentity
		body     []byte
	}{
		{subscriptionpublication.Base64Representation, artifacts.Base64},
		{subscriptionpublication.RawRepresentation, artifacts.Raw},
		{subscriptionpublication.V2RayNRepresentation, artifacts.V2RayN},
		{subscriptionpublication.ShadowrocketRepresentation, artifacts.Shadowrocket},
		{subscriptionpublication.KaringRepresentation, artifacts.Karing.Body},
		{subscriptionpublication.MihomoRepresentation, artifacts.Mihomo},
		{subscriptionpublication.SingBoxRepresentation, artifacts.SingBox.Body},
	}
	for _, expected := range want {
		body, ok := artifacts.RepresentationBody(expected.identity)
		if !ok || !bytes.Equal(body, expected.body) {
			t.Fatalf("RepresentationBody(%q) did not return its validated artifact", expected.identity)
		}
		if len(body) != 0 {
			body[0] ^= 0xff
			fresh, _ := artifacts.RepresentationBody(expected.identity)
			if bytes.Equal(body, fresh) {
				t.Fatalf("RepresentationBody(%q) returned mutable stored bytes", expected.identity)
			}
		}
	}
	if body, ok := artifacts.RepresentationBody("/unknown"); ok || body != nil {
		t.Fatalf("RepresentationBody(/unknown) = %q, %t", body, ok)
	}
}

func TestViewReturnsSecretSafeRepresentationCatalog(t *testing.T) {
	source, _ := sixProfileSource(t, "198.51.100.10")
	stateSHA256 := strings.Repeat("a", 64)
	result := newAcceptingTestModule().View(subscriptionpublication.ViewRequest{
		Source:                  source,
		SubscriptionAddress:     "https://198.51.100.10:10443",
		DesiredStateRevision:    7,
		DesiredStateSHA256:      stateSHA256,
		PublishedRevision:       7,
		PublishedStateSHA256:    stateSHA256,
		CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition,
		PublishedCompatibility:  subscriptionpublication.CurrentCompatibilityDefinition,
	})

	want := []struct {
		identity subscriptionpublication.RepresentationIdentity
		name     string
		count    int
	}{
		{subscriptionpublication.Base64Representation, "Base64", 6},
		{subscriptionpublication.RawRepresentation, "Raw", 6},
		{subscriptionpublication.V2RayNRepresentation, "v2rayN", 6},
		{subscriptionpublication.ShadowrocketRepresentation, "Shadowrocket", 6},
		{subscriptionpublication.KaringRepresentation, "Karing", 5},
		{subscriptionpublication.MihomoRepresentation, "Mihomo", 6},
		{subscriptionpublication.SingBoxRepresentation, "sing-box", 5},
	}
	if result.Status != subscriptionpublication.PublicationCurrent || !result.AgreesWithDesiredState || result.SubscriptionAddress != "https://198.51.100.10:10443" || result.CompatibilityDefinition != subscriptionpublication.CurrentCompatibilityDefinition || result.UnknownClientFallback != subscriptionpublication.Base64Representation || !strings.Contains(result.UnknownClientFallbackReason, "not authentication, authorization, or compatibility proof") || len(result.Representations) != len(want) {
		t.Fatalf("View() header = %#v", result)
	}
	for index, expected := range want {
		got := result.Representations[index]
		if got.Identity != expected.identity || got.Name != expected.name || got.ProfileCount != expected.count {
			t.Fatalf("View() representation %d = %#v", index, got)
		}
	}
	shadowrocket := result.Representations[3]
	if !shadowrocket.Candidate || len(shadowrocket.Omissions) != 0 || !slices.Equal(shadowrocket.OwnerAcceptancePending, []connectionprofiles.ProfileID{
		connectionprofiles.VLESSRealityVisionProfileID,
		connectionprofiles.VLESSXHTTPProfileID,
		connectionprofiles.VLESSWebSocketProfileID,
		connectionprofiles.Hysteria2ProfileID,
		connectionprofiles.TUICProfileID,
		connectionprofiles.AnyTLSProfileID,
	}) {
		t.Fatalf("Shadowrocket catalog entry = %#v", shadowrocket)
	}
	karing := result.Representations[4]
	if karing.Candidate || len(karing.Omissions) != 1 || karing.Omissions[0].ID != connectionprofiles.VLESSXHTTPProfileID || karing.Omissions[0].Status != subscriptionpublication.NotOffered || len(karing.OwnerAcceptancePending) != 5 {
		t.Fatalf("Karing catalog entry = %#v", karing)
	}
	encoded, err := json.Marshal(result)
	if err != nil || strings.Contains(string(encoded), "11111111-1111-4111-8111-111111111111") || strings.Contains(fmt.Sprintf("%#v", result), "11111111-1111-4111-8111-111111111111") {
		t.Fatalf("View() exposed a Client Access Value: json=%s error=%v", encoded, err)
	}
}

func TestViewReportsDisabledConnectionProfileWithoutSubstitution(t *testing.T) {
	source, reader := sixProfileSource(t, "198.51.100.10")
	profiles := slices.Delete(source.Profiles(), 2, 3)
	source, err := connectionprofiles.NewPublicationSource(profiles, []connectionprofiles.PublicationOmission{{ID: connectionprofiles.VLESSWebSocketProfileID, Name: "VLESS WebSocket", Lifecycle: state.ProfileDisabled}})
	if err != nil {
		t.Fatal(err)
	}
	stateSHA256 := strings.Repeat("b", 64)
	result := newAcceptingTestModule().View(subscriptionpublication.ViewRequest{
		Source: source, SubscriptionAddress: "https://198.51.100.10:10443",
		DesiredStateRevision: 8, DesiredStateSHA256: stateSHA256,
		PublishedRevision: 8, PublishedStateSHA256: stateSHA256,
		CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition,
		PublishedCompatibility:  subscriptionpublication.CurrentCompatibilityDefinition,
	})
	shadowrocket, karing, singBox := result.Representations[3], result.Representations[4], result.Representations[6]
	if result.Status != subscriptionpublication.PublicationCurrent || shadowrocket.ProfileCount != 5 || len(shadowrocket.Omissions) != 1 || shadowrocket.Omissions[0].ID != connectionprofiles.VLESSWebSocketProfileID || shadowrocket.Omissions[0].Status != subscriptionpublication.Disabled || slices.Contains(shadowrocket.OwnerAcceptancePending, connectionprofiles.VLESSWebSocketProfileID) || karing.ProfileCount != 4 || singBox.ProfileCount != 4 || len(karing.Omissions) != 2 || len(singBox.Omissions) != 2 {
		t.Fatalf("disabled Connection Profile catalog = %#v", result)
	}
	artifacts, err := newAcceptingTestModule().Render(t.Context(), source, reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(artifacts.Shadowrocket, artifacts.Base64) || bytes.Contains(artifacts.Shadowrocket, []byte("33333333-3333-4333-8333-333333333333")) || bytes.Contains(artifacts.Shadowrocket, []byte("VLESS%20WebSocket")) {
		t.Fatal("Shadowrocket candidate substituted or retained the disabled Connection Profile")
	}
}

func TestViewReportsDisabledXHTTPAsDisabledInEveryRepresentation(t *testing.T) {
	source, _ := sixProfileSource(t, "198.51.100.10")
	profiles := slices.Delete(source.Profiles(), 1, 2)
	source, err := connectionprofiles.NewPublicationSource(profiles, []connectionprofiles.PublicationOmission{{ID: connectionprofiles.VLESSXHTTPProfileID, Name: "VLESS XHTTP", Lifecycle: state.ProfileDisabled}})
	if err != nil {
		t.Fatal(err)
	}
	stateSHA256 := strings.Repeat("e", 64)
	result := newAcceptingTestModule().View(subscriptionpublication.ViewRequest{
		Source: source, SubscriptionAddress: "https://198.51.100.10:10443",
		DesiredStateRevision: 10, DesiredStateSHA256: stateSHA256,
		PublishedRevision: 10, PublishedStateSHA256: stateSHA256,
		CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition,
		PublishedCompatibility:  subscriptionpublication.CurrentCompatibilityDefinition,
	})
	for _, index := range []int{3, 4, 6} {
		entry := result.Representations[index]
		if len(entry.Omissions) != 1 || entry.Omissions[0].ID != connectionprofiles.VLESSXHTTPProfileID || entry.Omissions[0].Status != subscriptionpublication.Disabled || entry.Omissions[0].Reason != "The Connection Profile is deliberately disabled" {
			t.Fatalf("disabled XHTTP representation %q = %#v", entry.Identity, entry)
		}
	}
}

func TestViewMarksStaleCompatibilityDefinitionForRegeneration(t *testing.T) {
	source, _ := sixProfileSource(t, "198.51.100.10")
	stateSHA256 := strings.Repeat("c", 64)
	for _, change := range []func(*subscriptionpublication.ViewRequest){
		func(request *subscriptionpublication.ViewRequest) {
			request.CompatibilityDefinition = "stale-definition"
		},
		func(request *subscriptionpublication.ViewRequest) {
			request.PublishedCompatibility = "stale-definition"
		},
	} {
		request := subscriptionpublication.ViewRequest{
			Source: source, SubscriptionAddress: "https://198.51.100.10:10443",
			DesiredStateRevision: 9, DesiredStateSHA256: stateSHA256,
			PublishedRevision: 9, PublishedStateSHA256: stateSHA256,
			CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition,
			PublishedCompatibility:  subscriptionpublication.CurrentCompatibilityDefinition,
		}
		change(&request)
		result := newAcceptingTestModule().View(request)
		if result.Status != subscriptionpublication.PublicationNeedsRegeneration || result.AgreesWithDesiredState || len(result.Representations) != 7 {
			t.Fatalf("View() stale compatibility result = %#v", result)
		}
	}
}

func TestViewRefusesSecretBearingOrMalformedSubscriptionAddress(t *testing.T) {
	source, _ := sixProfileSource(t, "198.51.100.10")
	for _, address := range []string{"https://198.51.100.10:10443/s/SUBSCRIPTION-TOKEN-MARKER", "://malformed"} {
		result := newAcceptingTestModule().View(subscriptionpublication.ViewRequest{Source: source, SubscriptionAddress: address, DesiredStateRevision: 7, DesiredStateSHA256: strings.Repeat("d", 64)})
		if result.Status != subscriptionpublication.PublicationUnavailable || strings.Contains(fmt.Sprintf("%#v", result), "SUBSCRIPTION-TOKEN-MARKER") {
			t.Fatalf("View() unsafe address result = %#v", result)
		}
	}
}
