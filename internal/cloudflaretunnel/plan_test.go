package cloudflaretunnel

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/networkpolicy"
)

func TestPlanBindsOneSecretSafeXHTTPCreation(t *testing.T) {
	token, err := NewManagementToken("cfat_PLAN-SECRET-MARKER-000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	api := &planningAPI{Observation: healthyAuthorityObservation(), Mutation: MutationObservation{Digest: strings.Repeat("a", 64)}}
	module := New(api, &controlledPlanClock{})
	request := PlanRequest{
		Authority: ViewRequest{AccountID: testAccountID, ZoneID: testZoneID, ZoneName: "example.com", Token: token, NetworkPath: networkpolicy.CloudflareTunnelPath{HTTPS: networkpolicy.ProofPassed, TCP7844: networkpolicy.ProofPassed, UDP7844: networkpolicy.ProofPassed}},
		ChangeSet: "cloudflare-change-0001", StartingRevision: 0, DesiredStateSHA256: strings.Repeat("b", 64),
		TunnelName: "sbxr-main", XHTTPHostname: "xhttp.example.com", CloudflaredVersion: "2026.7.3",
	}
	first := module.Plan(context.Background(), request)
	second := module.Plan(context.Background(), request)
	if first.Health.Outcome != Healthy || first.Plan == nil || second.Plan == nil || first.Plan.SHA256() != second.Plan.SHA256() || first.Plan.Identity() != second.Plan.Identity() {
		t.Fatalf("deterministic Plan = first %+v second %+v", first, second)
	}
	preview := fmt.Sprintf("%+v %#v %s", first, first.Plan, first.Plan)
	if strings.Contains(preview, "PLAN-SECRET-MARKER") || !strings.Contains(preview, "http://127.0.0.1:11080") || !strings.Contains(preview, "HTTP 404 catch-all") || !strings.Contains(preview, "cloudflared.service") || !strings.Contains(preview, "--token-file /etc/sbxr/cloudflared/token") {
		t.Fatalf("unsafe or incomplete preview: %s", preview)
	}
	if len(first.Plan.Steps()) != 4 {
		t.Fatalf("steps = %+v", first.Plan.Steps())
	}
}

func TestPlanRefusesConflictsAndChangedObservations(t *testing.T) {
	token, _ := NewManagementToken("cfat_PLAN-SECRET-MARKER-000000000000000000000")
	request := PlanRequest{Authority: ViewRequest{AccountID: testAccountID, ZoneID: testZoneID, ZoneName: "example.com", Token: token, NetworkPath: networkpolicy.CloudflareTunnelPath{HTTPS: networkpolicy.ProofPassed, TCP7844: networkpolicy.ProofPassed, UDP7844: networkpolicy.ProofPassed}}, ChangeSet: "cloudflare-change-0001", DesiredStateSHA256: strings.Repeat("b", 64), TunnelName: "sbxr-main", XHTTPHostname: "xhttp.example.com", CloudflaredVersion: "2026.7.3"}
	for _, conflict := range []MutationObservation{{Digest: strings.Repeat("a", 64), Tunnels: []OwnedResource{{ID: testTunnelID, Name: "sbxr-main"}}}, {Digest: strings.Repeat("a", 64), DNSRecords: []OwnedResource{{ID: testDNSID, Name: "xhttp.example.com"}}}} {
		result := New(&planningAPI{Observation: healthyAuthorityObservation(), Mutation: conflict}, &controlledPlanClock{}).Plan(context.Background(), request)
		if result.Health.Outcome != Failed || result.Plan != nil || strings.Contains(result.String(), "PLAN-SECRET-MARKER") {
			t.Fatalf("conflict Plan = %+v", result)
		}
	}
}

const (
	testAccountID = "11111111111111111111111111111111"
	testZoneID    = "22222222222222222222222222222222"
	testTunnelID  = "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415"
	testDNSID     = "33333333333333333333333333333333"
)

type planningAPI struct {
	Observation Observation
	Mutation    MutationObservation
}

func (api *planningAPI) Observe(context.Context, ObservationRequest) (Observation, error) {
	return api.Observation, nil
}

func (api *planningAPI) ObserveMutation(context.Context, MutationRequest) (MutationObservation, error) {
	return api.Mutation, nil
}

type controlledPlanClock struct{ elapsed time.Duration }

func (clock *controlledPlanClock) Now() time.Time {
	return time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC).Add(clock.elapsed)
}
func (clock *controlledPlanClock) Sleep(_ context.Context, duration time.Duration) error {
	clock.elapsed += duration
	return nil
}

func healthyAuthorityObservation() Observation {
	return Observation{Account: AccountObservation{ID: testAccountID}, Zone: ZoneObservation{ID: testZoneID, AccountID: testAccountID, Name: "example.com", Status: "active", AssignedNameServers: []string{"a.ns.cloudflare.com"}, ObservedNameServers: []string{"a.ns.cloudflare.com"}}, Token: TokenObservation{ID: "44444444444444444444444444444444", Status: "active"}, Policies: []TokenPolicy{{Effect: "allow", PermissionGroups: []string{"Account API Tokens Read", "Cloudflare Tunnel Edit"}, Resources: map[string]string{"com.cloudflare.api.account." + testAccountID: "*"}}, {Effect: "allow", PermissionGroups: []string{"DNS Write"}, Resources: map[string]string{"com.cloudflare.api.account.zone." + testZoneID: "*"}}}}
}
