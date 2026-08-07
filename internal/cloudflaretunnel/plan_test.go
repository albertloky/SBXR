package cloudflaretunnel

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

const (
	testAccountID = "11111111111111111111111111111111"
	testZoneID    = "22222222222222222222222222222222"
	testTunnelID  = "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415"
	testDNSID     = "33333333333333333333333333333333"
)

func TestPlanBindsCompleteSecretSafeCloudflareInstallation(t *testing.T) {
	module, request := plannedModule(t)
	first, second := module.Plan(context.Background(), request), module.Plan(context.Background(), request)
	if first.Plan == nil || second.Plan == nil || first.Health.Outcome != Healthy || first.Plan.Identity() != second.Plan.Identity() || first.Plan.SHA256() != second.Plan.SHA256() {
		t.Fatalf("deterministic Plan = first %+v second %+v", first, second)
	}
	preview := fmt.Sprintf("%+v %#v %s", first, first.Plan, first.Plan)
	for _, required := range []string{xhttpOrigin, webSocketOrigin, "HTTP 404 fallback", "cloudflared.service", "--token-file " + cloudflaredTokenPath} {
		if !strings.Contains(preview, required) {
			t.Fatalf("Plan omitted %q: %s", required, preview)
		}
	}
	if strings.Contains(preview, "PLAN-SECRET-MARKER") {
		t.Fatalf("Plan leaked token: %s", preview)
	}
	steps := first.Plan.Steps()
	if len(steps) != 7 {
		t.Fatalf("steps = %d, want Tunnel, routes, three DNS records, and service", len(steps))
	}
	for index, step := range steps {
		change, ok := step.CloudflareChange()
		if index == len(steps)-1 {
			if ok || step.Owner() != systemchanges.CloudflareModule || step.Forward() != systemchanges.ActivatePreparedConfiguration {
				t.Fatalf("last step is not protected cloudflared activation: %#v", step)
			}
			continue
		}
		if !ok {
			t.Fatalf("step %d has no typed Cloudflare contract", index+1)
		}
		if change.TunnelIDFromStep > 0 && change.TunnelIDFromStep >= index+1 {
			t.Fatalf("step %d references non-durable evidence", index+1)
		}
	}
	routes, _ := steps[1].CloudflareChange()
	if len(routes.Routes) != 3 || routes.Routes[2].Origin != "http_status:404" {
		t.Fatalf("routes = %#v", routes.Routes)
	}
	if _, _, _, ok := first.Plan.StateDeferredCloudflare(); !ok {
		t.Fatal("State finalization authority unavailable")
	}
}

func TestPlanRefusesUnownedConflictAndUnqualifiedCloudflared(t *testing.T) {
	module, request := plannedModule(t)
	api := module.api.(*planningAPI)
	api.suffixFree = true
	api.mutation = MutationObservation{Digest: strings.Repeat("a", 64), DNSRecords: []OwnedResource{{ID: testDNSID, Name: request.XHTTPHostname}}}
	if result := module.Plan(context.Background(), request); result.Plan != nil || result.Health.Code != "CLOUDFLARE-UNOWNED-CONFLICT" || len(result.SuggestedHostnames) != 1 || result.SuggestedHostnames[0] == request.XHTTPHostname || !strings.HasSuffix(result.SuggestedHostnames[0], ".example.com") {
		t.Fatalf("conflict Plan = %+v", result)
	}
	request.CloudflaredVersion = "2026.7.2"
	if result := module.Plan(context.Background(), request); result.Plan != nil {
		t.Fatalf("unqualified cloudflared Plan = %+v", result)
	}
}

func TestPlanApplyRefusesDifferentStartingRevision(t *testing.T) {
	module, request := plannedModule(t)
	plan := module.Plan(context.Background(), request).Plan
	result := plan.Apply(systemchanges.Interface{}, &fakePreparedState{}, systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 1, SHA256: strings.Repeat("a", 64)}, strings.Repeat("b", 64), systemchanges.DiskRequirement{})
	if result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-CHANGE-SET-REQUIRED" {
		t.Fatalf("changed revision Apply = %+v", result)
	}
}

func plannedModule(t *testing.T) (Interface, PlanRequest) {
	t.Helper()
	token, err := NewManagementToken("cfat_PLAN-SECRET-MARKER-000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	api := &planningAPI{observation: healthyAuthorityObservation(), mutation: MutationObservation{Digest: strings.Repeat("a", 64)}}
	request := PlanRequest{Authority: ViewRequest{AccountID: testAccountID, ZoneID: testZoneID, ZoneName: "example.com", Token: token, NetworkPath: networkpolicy.CloudflareTunnelPath{HTTPS: networkpolicy.ProofPassed, TCP7844: networkpolicy.ProofPassed, UDP7844: networkpolicy.ProofPassed}}, ChangeSet: "cloudflare-change-0001", DesiredStateSHA256: strings.Repeat("b", 64), TunnelName: "sbxr-main", XHTTPHostname: "xhttp.example.com", WebSocketHostname: "ws.example.com", DirectHostname: "direct.example.com", PublicIPv4: "192.0.2.10", PublicIPv6: "2001:db8::10", CloudflaredVersion: qualifiedCloudflaredVersion}
	return New(api, &planClock{}), request
}

type planningAPI struct {
	observation Observation
	mutation    MutationObservation
	suffixFree  bool
}

func (api *planningAPI) Observe(context.Context, ObservationRequest) (Observation, error) {
	return api.observation, nil
}

func (api *planningAPI) ObserveMutation(_ context.Context, request MutationRequest) (MutationObservation, error) {
	if api.suffixFree && strings.Contains(strings.Split(request.Hostname, ".")[0], "-") {
		return MutationObservation{Digest: strings.Repeat("c", 64)}, nil
	}
	return api.mutation, nil
}

type planClock struct{ elapsed time.Duration }

func (clock *planClock) Now() time.Time {
	return time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC).Add(clock.elapsed)
}
func (clock *planClock) Sleep(_ context.Context, duration time.Duration) error {
	clock.elapsed += duration
	return nil
}

func healthyAuthorityObservation() Observation {
	return Observation{Account: AccountObservation{ID: testAccountID}, Zone: ZoneObservation{ID: testZoneID, AccountID: testAccountID, Name: "example.com", Status: "active", AssignedNameServers: []string{"a.ns.cloudflare.com"}, ObservedNameServers: []string{"a.ns.cloudflare.com"}}, Token: TokenObservation{ID: "44444444444444444444444444444444", Status: "active"}, Policies: []TokenPolicy{{Effect: "allow", PermissionGroups: []string{"Account API Tokens Read", "Cloudflare Tunnel Edit"}, Resources: map[string]string{"com.cloudflare.api.account." + testAccountID: "*"}}, {Effect: "allow", PermissionGroups: []string{"DNS Write"}, Resources: map[string]string{"com.cloudflare.api.account.zone." + testZoneID: "*"}}}}
}

var _ systemchanges.PreparedStateCommit = (*fakePreparedState)(nil)

type fakePreparedState struct{}

func (*fakePreparedState) SystemChangesPreparedState() (string, uint64, string, string, string, string, bool) {
	return "", 0, "", "", "", "", false
}
func (*fakePreparedState) SystemChangesConsume(any, string, string) (any, error) { return nil, nil }
