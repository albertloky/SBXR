package cloudflaretunnel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestExecutorRechecksPlanAndNeverDeletesWithoutJournaledID(t *testing.T) {
	_, request := plannedModule(t)
	api := &executorFixture{planningAPI: planningAPI{observation: healthyAuthorityObservation(), mutation: MutationObservation{Digest: strings.Repeat("a", 64)}}}
	result := New(api, &planClock{}).Plan(context.Background(), request)
	if result.Plan == nil {
		t.Fatalf("Plan = %+v", result.Health)
	}
	executor, err := result.Plan.Executor(api)
	if err != nil {
		t.Fatal(err)
	}
	api.mutation.Digest = strings.Repeat("b", 64)
	if _, err := executor.Execute(result.Plan.Steps()[0], "", time.Minute); err == nil || api.creates != 0 {
		t.Fatal("stale provider observation reached mutation")
	}
	api.mutation.Digest = strings.Repeat("a", 64)
	step := result.Plan.Steps()[0]
	if _, err := executor.Reverse(step, systemchanges.StepEvidence{}, strings.NewReader(`{"management_token":"cfat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`), time.Minute); err == nil || api.deletedTunnel != "" {
		t.Fatal("rollback deleted by name without journaled ownership")
	}
}

func TestExecutorWholeTunnelCheckUsesJournaledIdentifiers(t *testing.T) {
	_, request := plannedModule(t)
	api := &executorFixture{planningAPI: planningAPI{observation: healthyAuthorityObservation(), mutation: MutationObservation{Digest: strings.Repeat("a", 64)}}}
	result := New(api, &planClock{}).Plan(context.Background(), request)
	executor, err := result.Plan.Executor(api)
	if err != nil {
		t.Fatal(err)
	}
	evidence := make([]systemchanges.StepEvidence, len(result.Plan.Steps()))
	evidence[0] = systemchanges.StepEvidence{ResourceType: string(systemchanges.CloudflareTunnelResource), ResourceID: testTunnelID}
	evidence[2] = systemchanges.StepEvidence{ResourceType: string(systemchanges.CloudflareDNSRecordResource), ResourceID: strings.Repeat("3", 32)}
	evidence[3] = systemchanges.StepEvidence{ResourceType: string(systemchanges.CloudflareDNSRecordResource), ResourceID: strings.Repeat("4", 32)}
	evidence[4] = systemchanges.StepEvidence{ResourceType: string(systemchanges.CloudflareDNSRecordResource), ResourceID: strings.Repeat("5", 32)}
	evidence[5] = systemchanges.StepEvidence{ResourceType: string(systemchanges.CloudflareDNSRecordResource), ResourceID: strings.Repeat("6", 32)}
	api.whole = WholeTunnelObservation{TunnelID: testTunnelID, Connected: true, Routes: []Route{{Hostname: request.XHTTPHostname, Service: xhttpOrigin}, {Hostname: request.WebSocketHostname, Service: webSocketOrigin}, {Service: "http_status:404"}}, DNSRecords: []DNSObservation{{ID: strings.Repeat("3", 32), Name: request.XHTTPHostname, Type: "CNAME", Content: testTunnelID + ".cfargotunnel.com", Proxied: true}, {ID: strings.Repeat("4", 32), Name: request.WebSocketHostname, Type: "CNAME", Content: testTunnelID + ".cfargotunnel.com", Proxied: true}, {ID: strings.Repeat("5", 32), Name: request.DirectHostname, Type: "A", Content: request.PublicIPv4}, {ID: strings.Repeat("6", 32), Name: request.DirectHostname, Type: "AAAA", Content: request.PublicIPv6}}, XHTTPOriginReachable: true, WebSocketOriginReachable: true}
	if status, err := executor.CheckWholeTunnel(evidence, time.Minute); err != nil || status != systemchanges.Healthy {
		t.Fatalf("whole-Tunnel check = %s, %v", status, err)
	}
}

type executorFixture struct {
	planningAPI
	creates       int
	deletedTunnel string
	whole         WholeTunnelObservation
}

func (api *executorFixture) CreateTunnel(context.Context, CreateTunnelRequest) (CreatedTunnel, error) {
	api.creates++
	return NewCreatedTunnelResult(testTunnelID, "sbxr-main", "RUN-TOKEN-MARKER")
}
func (*executorFixture) PutConfiguration(_ context.Context, request PutConfigurationRequest) (Configuration, error) {
	return Configuration{TunnelID: request.TunnelID, Version: 1, Routes: request.Routes}, nil
}
func (*executorFixture) CreateDNSRecord(_ context.Context, request CreateDNSRecordRequest) (OwnedResource, error) {
	return OwnedResource{ID: testDNSID, Name: request.Name}, nil
}
func (api *executorFixture) ObserveWholeTunnel(context.Context, WholeTunnelRequest) (WholeTunnelObservation, error) {
	return api.whole, nil
}
func (*executorFixture) DeleteDNSRecord(context.Context, DeleteDNSRecordRequest) error { return nil }
func (api *executorFixture) DeleteTunnel(_ context.Context, request DeleteTunnelRequest) error {
	api.deletedTunnel = request.ID
	return nil
}
