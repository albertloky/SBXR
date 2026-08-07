package cloudflaretunnel

import (
	"context"
	"net/netip"
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

func TestExecutorExposesCertificateDNSFactsWithoutProviderAuthority(t *testing.T) {
	_, request := plannedModule(t)
	want := CertificateDNSFacts{Hostname: request.DirectHostname, Addresses: []netip.Addr{netip.MustParseAddr(request.PublicIPv4), netip.MustParseAddr(request.PublicIPv6)}, EffectiveCAA: EffectiveCAA{Name: request.Authority.ZoneName, Records: []CAARecord{{Tag: "issue", Value: "letsencrypt.org; validationmethods=http-01"}}}}
	api := &executorFixture{planningAPI: planningAPI{observation: healthyAuthorityObservation(), mutation: MutationObservation{Digest: strings.Repeat("a", 64)}}, certificateFacts: want}
	result := New(api, &planClock{}).Plan(context.Background(), request)
	executor, err := result.Plan.Executor(api)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.CertificateDNSFacts(context.Background(), nil); err == nil {
		t.Fatal("Certificate DNS handoff accepted no journaled Direct record IDs")
	}
	evidence := make([]systemchanges.StepEvidence, len(result.Plan.Steps()))
	evidence[4] = systemchanges.StepEvidence{ResourceType: string(systemchanges.CloudflareDNSRecordResource), ResourceID: strings.Repeat("5", 32)}
	evidence[5] = systemchanges.StepEvidence{ResourceType: string(systemchanges.CloudflareDNSRecordResource), ResourceID: strings.Repeat("6", 32)}
	got, err := executor.CertificateDNSFacts(context.Background(), evidence)
	if err != nil || got.Hostname != want.Hostname || len(got.Addresses) != 2 || api.certificateRequest.Hostname != request.DirectHostname || api.certificateRequest.IPv4RecordID != strings.Repeat("5", 32) || api.certificateRequest.IPv6RecordID != strings.Repeat("6", 32) || api.certificateRequest.Token.value == "" {
		t.Fatalf("CertificateDNSFacts() = %+v, %v; request=%+v", got, err, api.certificateRequest)
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

func TestWholeTunnelWaitsForReconnectWithoutLosingEitherRoute(t *testing.T) {
	want := WholeTunnelExpected{TunnelID: testTunnelID, Routes: []Route{{Hostname: "xhttp.example.com", Service: xhttpOrigin}, {Hostname: "ws.example.com", Service: webSocketOrigin}, {Service: "http_status:404"}}, DNSRecords: []DNSExpected{{ID: "dns-x", Name: "xhttp.example.com", Type: "CNAME", Content: testTunnelID + ".cfargotunnel.com", Proxied: true}, {ID: "dns-w", Name: "ws.example.com", Type: "CNAME", Content: testTunnelID + ".cfargotunnel.com", Proxied: true}}}
	healthy := WholeTunnelObservation{TunnelID: testTunnelID, Connected: true, Routes: append([]Route(nil), want.Routes...), DNSRecords: []DNSObservation{{ID: "dns-x", Name: "xhttp.example.com", Type: "CNAME", Content: testTunnelID + ".cfargotunnel.com", Proxied: true}, {ID: "dns-w", Name: "ws.example.com", Type: "CNAME", Content: testTunnelID + ".cfargotunnel.com", Proxied: true}}, XHTTPOriginReachable: true, WebSocketOriginReachable: true}
	disconnected := healthy
	disconnected.Connected = false
	partial := healthy
	partial.Routes = partial.Routes[:2]
	api := &executorFixture{wholes: []WholeTunnelObservation{disconnected, partial, healthy}}
	clock := &planClock{}
	health := (Executor{api: api}).WaitForWholeTunnel(context.Background(), WholeTunnelRequest{}, want, clock)
	if health.Outcome != Healthy || health.Code != "CLOUDFLARE-WHOLE-TUNNEL-HEALTHY" || health.Time != clock.Now().UTC() || api.wholeCalls != 3 || clock.elapsed != 20*time.Second {
		t.Fatalf("reconnect health = %+v; calls=%d elapsed=%s", health, api.wholeCalls, clock.elapsed)
	}
}

func TestWholeTunnelRetriesOnlyTemporaryProviderFailures(t *testing.T) {
	for _, test := range []struct {
		name  string
		err   error
		code  string
		calls int
	}{
		{"contradictory", APIError{Kind: APIAmbiguous}, "CLOUDFLARE-OBSERVATION-CONTRADICTORY", 1},
		{"malformed", APIError{Kind: APIMalformed}, "CLOUDFLARE-OBSERVATION-MALFORMED", 1},
		{"permanent", APIError{Kind: APIPermanent}, "CLOUDFLARE-API-REFUSED", 1},
		{"temporary", APIError{Kind: APITemporary}, "CLOUDFLARE-CONVERGENCE-TIMEOUT", 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &executorFixture{wholeErr: test.err}
			clock := &planClock{}
			health := (Executor{api: api}).WaitForWholeTunnel(context.Background(), WholeTunnelRequest{}, WholeTunnelExpected{}, clock)
			if health.Code != test.code || health.Problem == "" || health.Evidence == "" || api.wholeCalls != test.calls {
				t.Fatalf("health = %+v; calls=%d", health, api.wholeCalls)
			}
		})
	}
}

type executorFixture struct {
	planningAPI
	creates            int
	deletedTunnel      string
	whole              WholeTunnelObservation
	wholes             []WholeTunnelObservation
	wholeCalls         int
	wholeErr           error
	certificateRequest CertificateDNSRequest
	certificateFacts   CertificateDNSFacts
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
	if api.wholeErr != nil {
		api.wholeCalls++
		return WholeTunnelObservation{}, api.wholeErr
	}
	if api.wholeCalls < len(api.wholes) {
		observed := api.wholes[api.wholeCalls]
		api.wholeCalls++
		return observed, nil
	}
	api.wholeCalls++
	return api.whole, nil
}
func (api *executorFixture) ObserveCertificateDNS(_ context.Context, request CertificateDNSRequest) (CertificateDNSFacts, error) {
	api.certificateRequest = request
	return api.certificateFacts, nil
}
func (*executorFixture) DeleteDNSRecord(context.Context, DeleteDNSRecordRequest) error { return nil }
func (api *executorFixture) DeleteTunnel(_ context.Context, request DeleteTunnelRequest) error {
	api.deletedTunnel = request.ID
	return nil
}
