package cloudflaretunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

type managementRotationAPI struct {
	MutationAPI
	current, candidate     ManagementToken
	currentID, candidateID string
	deleted                []string
	oldUnauthorized        bool
	candidateUnauthorized  bool
	candidateInvalid       bool
	deleteCandidateErr     bool
}

func (api *managementRotationAPI) Observe(_ context.Context, request ObservationRequest) (Observation, error) {
	switch request.Token.value {
	case api.current.value:
		if api.oldUnauthorized {
			return Observation{}, APIError{Kind: APIUnauthorized}
		}
		return rotationObservation(request, api.currentID), nil
	case api.candidate.value:
		if api.candidateUnauthorized {
			return Observation{}, APIError{Kind: APIUnauthorized}
		}
		observed := rotationObservation(request, api.candidateID)
		if api.candidateInvalid {
			observed.DNSListProven = false
		}
		return observed, nil
	default:
		return Observation{}, APIError{Kind: APIUnauthorized}
	}
}

func (api *managementRotationAPI) CreateManagementTokenCandidate(_ context.Context, request CreateManagementTokenCandidateRequest) (ManagementTokenCandidate, error) {
	if request.Current.value != api.current.value {
		return ManagementTokenCandidate{}, APIError{Kind: APIUnauthorized}
	}
	return ManagementTokenCandidate{id: api.candidateID, name: request.Name, requestSHA256: request.RequestSHA256, issuedOn: time.Now(), token: api.candidate, used: &atomic.Bool{}}, nil
}

func (api *managementRotationAPI) PrepareManagementTokenCandidate(_ context.Context, current ManagementToken, name string, notBefore, notAfter time.Time) (CreateManagementTokenCandidateRequest, error) {
	body := json.RawMessage(`{"name":"` + name + `","policies":[],"expires_on":null,"condition":null}`)
	digest := sha256.Sum256(body)
	return CreateManagementTokenCandidateRequest{Current: current, Name: name, RequestSHA256: hex.EncodeToString(digest[:]), CanonicalBody: body, NotBefore: notBefore, NotAfter: notAfter}, nil
}

func (api *managementRotationAPI) VerifyManagementTokenCandidateAbsent(_ context.Context, _ ReconcileManagementTokenCandidateRequest) error {
	if slices.Contains(api.deleted, api.candidateID) {
		return nil
	}
	return APIError{Kind: APIAmbiguous}
}

func (api *managementRotationAPI) ReconcileManagementTokenCandidate(_ context.Context, request ReconcileManagementTokenCandidateRequest) (ManagementTokenCandidate, error) {
	if slices.Contains(api.deleted, api.candidateID) {
		return ManagementTokenCandidate{}, APIError{Kind: APIAmbiguous}
	}
	return ManagementTokenCandidate{id: api.candidateID, name: request.Name, requestSHA256: request.RequestSHA256, issuedOn: time.Now(), used: &atomic.Bool{}}, nil
}

func (api *managementRotationAPI) DeleteManagementToken(_ context.Context, request DeleteManagementTokenRequest) error {
	api.deleted = append(api.deleted, request.ID)
	switch request.ID {
	case api.currentID:
		if request.Token.value != api.candidate.value {
			return APIError{Kind: APIForbidden}
		}
		api.oldUnauthorized = true
	case api.candidateID:
		if api.deleteCandidateErr {
			return APIError{Kind: APITemporary}
		}
		if request.Token.value != api.current.value {
			return APIError{Kind: APIForbidden}
		}
		api.candidateUnauthorized = true
	default:
		return APIError{Kind: APIAmbiguous}
	}
	return nil
}

func rotationObservation(request ObservationRequest, id string) Observation {
	return Observation{Account: AccountObservation{ID: request.AccountID}, Zone: ZoneObservation{ID: request.ZoneID, AccountID: request.AccountID, Name: request.ZoneName, Status: "active"}, Token: TokenObservation{ID: id, Status: "active"}, DNSListProven: true, TunnelListProven: true}
}

func TestManagementTokenRotationCreatesAndProvesCandidateBeforeDeletingOldToken(t *testing.T) {
	current, _ := NewManagementToken("CURRENT_USER_TOKEN_MARKER_000000000000000000")
	candidate, _ := NewManagementToken("CANDIDATE_USER_TOKEN_MARKER_0000000000000000")
	api := &managementRotationAPI{current: current, candidate: candidate, currentID: strings.Repeat("1", 32), candidateID: strings.Repeat("2", 32)}
	request := ObservationRequest{AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), ZoneName: "example.com", Token: current}
	intent, _ := api.PrepareManagementTokenCandidate(t.Context(), current, "sbxr-rotation-"+strings.Repeat("c", 32), time.Now().Add(-time.Minute), time.Now().Add(time.Minute))
	rotation, err := prepareManagementTokenRotation(t.Context(), api, request, api.currentID, intent)
	if err != nil || len(api.deleted) != 0 {
		t.Fatalf("prepare = (%+v, %v), deletions=%v", rotation, err, api.deleted)
	}
	created, err := rotation.completeForward(t.Context())
	if err != nil || created.id != api.candidateID || !api.oldUnauthorized || !slices.Equal(api.deleted, []string{api.currentID}) {
		t.Fatalf("complete = (%+v, %v), deletions=%v", created, err, api.deleted)
	}
	secret, ok := created.ConsumeInfrastructureSecret()
	if !ok || secret != candidate.value {
		t.Fatal("candidate State handoff was unavailable")
	}
	if _, reused := created.ConsumeInfrastructureSecret(); reused {
		t.Fatal("candidate State handoff was reusable")
	}
}

func TestManagementTokenRotationRollbackDeletesOnlyTheCandidate(t *testing.T) {
	current, _ := NewManagementToken("CURRENT_USER_TOKEN_MARKER_000000000000000000")
	candidate, _ := NewManagementToken("CANDIDATE_USER_TOKEN_MARKER_0000000000000000")
	api := &managementRotationAPI{current: current, candidate: candidate, currentID: strings.Repeat("1", 32), candidateID: strings.Repeat("2", 32)}
	request := ObservationRequest{AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), ZoneName: "example.com", Token: current}
	intent, _ := api.PrepareManagementTokenCandidate(t.Context(), current, "sbxr-rotation-"+strings.Repeat("c", 32), time.Now().Add(-time.Minute), time.Now().Add(time.Minute))
	rotation, err := prepareManagementTokenRotation(t.Context(), api, request, api.currentID, intent)
	if err != nil || rotation.rollback(t.Context()) != nil || !api.candidateUnauthorized || api.oldUnauthorized || !slices.Equal(api.deleted, []string{api.candidateID}) {
		t.Fatalf("rollback = %v, deletions=%v", err, api.deleted)
	}
}

func TestManagementTokenRotationExecutorPersistsCandidateBeforeRevokingOld(t *testing.T) {
	current, _ := NewManagementToken("CURRENT_USER_TOKEN_MARKER_000000000000000000")
	candidate, _ := NewManagementToken("CANDIDATE_USER_TOKEN_MARKER_0000000000000000")
	api := &managementRotationAPI{current: current, candidate: candidate, currentID: strings.Repeat("1", 32), candidateID: strings.Repeat("2", 32)}
	requestSHA := strings.Repeat("c", 64)
	executor := Executor{api: api, token: current, tokenID: api.currentID, request: PlanRequest{Authority: ViewRequest{AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), ZoneName: "example.com"}, ManagementToken: ManagementTokenChange{Action: ManagementTokenRotate, CurrentTokenID: api.currentID}}, managementRequestSHA256: requestSHA}
	step, err := systemchanges.NewCloudflareStep(systemchanges.CloudflareChange{Action: systemchanges.CloudflareManagementTokenActivate, AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), ManagementTokenID: api.currentID})
	if err != nil {
		t.Fatal(err)
	}
	var snapshot []byte
	err = executor.CaptureRollback(step, func(source io.Reader) error {
		var readErr error
		snapshot, readErr = io.ReadAll(source)
		return readErr
	})
	if err != nil || len(snapshot) == 0 || len(api.deleted) != 0 {
		t.Fatalf("capture = (%d bytes, %v), deletions=%v", len(snapshot), err, api.deleted)
	}
	var intentSnapshot []byte
	snapshot, cleanupID, err := executor.PrepareManagementTokenRotation(bytes.NewReader(snapshot), time.Minute, func(intent []byte) error { intentSnapshot = append([]byte(nil), intent...); return nil })
	if err != nil || cleanupID != api.candidateID {
		t.Fatalf("prepare = (%v, %q)", err, cleanupID)
	}
	var durableIntent rollbackRecord
	if json.Unmarshal(intentSnapshot, &durableIntent) != nil || len(durableIntent.CandidateBody) == 0 || durableIntent.CandidateSHA == requestSHA || durableIntent.CandidateSHA != fmt.Sprintf("%x", sha256.Sum256(durableIntent.CandidateBody)) {
		t.Fatalf("durable provider request intent = %+v", durableIntent)
	}
	source, err := executor.CompleteManagementTokenRotation(bytes.NewReader(snapshot), time.Minute)
	secret, ok := source.(ManagementTokenCandidate).ConsumeInfrastructureSecret()
	if err != nil || !ok || secret != candidate.value || !api.oldUnauthorized || !slices.Equal(api.deleted, []string{api.currentID}) {
		t.Fatalf("complete = (%T, %v), deletions=%v", source, err, api.deleted)
	}
}

func TestManagementTokenRotationRetainsCandidateIdentityWhenFailedVerificationCleanupIsUncertain(t *testing.T) {
	current, _ := NewManagementToken("CURRENT_USER_TOKEN_MARKER_000000000000000000")
	candidate, _ := NewManagementToken("CANDIDATE_USER_TOKEN_MARKER_0000000000000000")
	api := &managementRotationAPI{current: current, candidate: candidate, currentID: strings.Repeat("1", 32), candidateID: strings.Repeat("2", 32), candidateInvalid: true, deleteCandidateErr: true}
	request := ObservationRequest{AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), ZoneName: "example.com", Token: current}
	intent, _ := api.PrepareManagementTokenCandidate(t.Context(), current, "sbxr-rotation-"+strings.Repeat("c", 32), time.Now().Add(-time.Minute), time.Now().Add(time.Minute))
	_, err := prepareManagementTokenRotation(t.Context(), api, request, api.currentID, intent)
	var cleanup ManagementTokenCandidateCleanupError
	if !errors.As(err, &cleanup) || cleanup.CandidateID() != api.candidateID || api.oldUnauthorized {
		t.Fatalf("uncertain cleanup = %v, deletions=%v", err, api.deleted)
	}
}

func TestManagedRepairCapturesAndRestoresExactProviderPreImages(t *testing.T) {
	module, request := managedRepairRequest(t)
	planning := *module.api.(*planningAPI)
	planning.wholeTunnel = healthyWholeTunnel(request)
	planning.wholeTunnel.Routes = []Route{{Hostname: "old.example.com", Service: xhttpOrigin}, {Service: "http_status:404"}}
	planning.wholeTunnel.DNSRecords[0].Content = "old.example.com"
	api := &executorFixture{planningAPI: planning, priorConfiguration: Configuration{TunnelID: testTunnelID, Version: 4, Routes: append([]Route(nil), planning.wholeTunnel.Routes...)}, priorDNS: planning.wholeTunnel.DNSRecords[0]}
	api.whole = planning.wholeTunnel
	result := New(api, &planClock{}).Plan(t.Context(), request)
	if result.Plan == nil || len(result.Plan.Steps()) != 2 {
		t.Fatalf("repair Plan = %+v", result)
	}
	executor, err := result.Plan.Executor(api)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range result.Plan.Steps() {
		var snapshot []byte
		if err := executor.CaptureRollback(step, func(source io.Reader) error {
			var readErr error
			snapshot, readErr = io.ReadAll(source)
			return readErr
		}); err != nil {
			t.Fatal(err)
		}
		evidence, err := executor.Execute(step, "", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := executor.Reverse(step, evidence, bytes.NewReader(snapshot), time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if got := api.configurationWrites[len(api.configurationWrites)-1]; !sameRoutes(got.Routes, api.priorConfiguration.Routes) {
		t.Fatalf("restored routes = %#v", got.Routes)
	}
	if got := api.dnsWrites[len(api.dnsWrites)-1]; got != api.priorDNS {
		t.Fatalf("restored DNS = %#v, want %#v", got, api.priorDNS)
	}
}

func TestManagedRepairRefusesAStalePlanBeforeCapturingOrWriting(t *testing.T) {
	module, request := managedRepairRequest(t)
	planning := *module.api.(*planningAPI)
	planning.wholeTunnel = healthyWholeTunnel(request)
	planning.wholeTunnel.Routes = []Route{{Hostname: "old.example.com", Service: xhttpOrigin}, {Service: "http_status:404"}}
	api := &executorFixture{planningAPI: planning, whole: planning.wholeTunnel}
	module.api = api
	plan := module.Plan(t.Context(), request).Plan
	executor, err := plan.Executor(api)
	if err != nil {
		t.Fatal(err)
	}
	api.mutations[request.XHTTPHostname] = MutationObservation{Digest: strings.Repeat("f", 64), Tunnels: []OwnedResource{{ID: testTunnelID, Name: request.TunnelName}}, DNSRecords: []OwnedResource{{ID: request.ManagedRepair.XHTTPDNSRecordID, Name: request.XHTTPHostname}}}
	if err := executor.CaptureRollback(plan.Steps()[0], func(io.Reader) error { return nil }); err == nil {
		t.Fatal("stale repair Plan reached rollback capture")
	}
}

func TestManagedRepairBoundsProviderWriteRetries(t *testing.T) {
	for _, test := range []struct {
		name  string
		err   error
		calls int
		wait  time.Duration
	}{
		{name: "deterministic", err: APIError{Kind: APIPermanent}, calls: 1},
		{name: "temporary", err: APIError{Kind: APITemporary}, calls: 3, wait: time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			module, request := managedRepairRequest(t)
			planning := *module.api.(*planningAPI)
			planning.wholeTunnel = healthyWholeTunnel(request)
			planning.wholeTunnel.DNSRecords[0].Content = "old.example.com"
			api := &executorFixture{planningAPI: planning, whole: planning.wholeTunnel, dnsPutErr: test.err}
			module.api = api
			plan := module.Plan(t.Context(), request).Plan
			executor, err := plan.Executor(api)
			if err != nil {
				t.Fatal(err)
			}
			clock := &planClock{}
			executor.clock = clock
			if _, err := executor.Execute(plan.Steps()[0], "", time.Minute); err == nil || api.dnsPutCalls != test.calls || clock.elapsed != test.wait {
				t.Fatalf("write error=%v calls=%d wait=%s", err, api.dnsPutCalls, clock.elapsed)
			}
		})
	}
}

func TestExecutorRechecksPlanAndNeverDeletesWithoutJournaledID(t *testing.T) {
	_, request := plannedModule(t)
	api := &executorFixture{planningAPI: planningAPI{observation: healthyAuthorityObservation(), mutation: MutationObservation{Digest: strings.Repeat("a", 64)}}}
	result := newPlanningInterface(api).Plan(context.Background(), request)
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
	if _, err := executor.Reverse(step, systemchanges.StepEvidence{}, strings.NewReader(`{"management_token":"sbxr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`), time.Minute); err == nil || api.deletedTunnel != "" {
		t.Fatal("rollback deleted by name without journaled ownership")
	}
}

func TestExecutorExposesCertificateDNSFactsWithoutProviderAuthority(t *testing.T) {
	_, request := plannedModule(t)
	want := CertificateDNSFacts{Hostname: request.DirectHostname, Addresses: []netip.Addr{netip.MustParseAddr(request.PublicIPv4), netip.MustParseAddr(request.PublicIPv6)}, EffectiveCAA: EffectiveCAA{Name: request.Authority.ZoneName, Records: []CAARecord{{Tag: "issue", Value: "letsencrypt.org; validationmethods=http-01"}}}}
	api := &executorFixture{planningAPI: planningAPI{observation: healthyAuthorityObservation(), mutation: MutationObservation{Digest: strings.Repeat("a", 64)}}, certificateFacts: want}
	result := newPlanningInterface(api).Plan(context.Background(), request)
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
	result := newPlanningInterface(api).Plan(context.Background(), request)
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
	creates             int
	deletedTunnel       string
	whole               WholeTunnelObservation
	wholes              []WholeTunnelObservation
	wholeCalls          int
	wholeErr            error
	certificateRequest  CertificateDNSRequest
	certificateFacts    CertificateDNSFacts
	priorConfiguration  Configuration
	configurationWrites []Configuration
	priorDNS            DNSObservation
	dnsWrites           []DNSObservation
	dnsPutErr           error
	dnsPutCalls         int
}

func (api *executorFixture) GetTunnel(context.Context, GetTunnelRequest) (OwnedResource, error) {
	if api.whole.TunnelID == "" {
		return OwnedResource{}, APIError{Kind: APINotFound}
	}
	return OwnedResource{ID: api.whole.TunnelID, Name: "sbxr-main"}, nil
}

func (api *executorFixture) CreateTunnel(context.Context, CreateTunnelRequest) (CreatedTunnel, error) {
	api.creates++
	return NewCreatedTunnelResult(testTunnelID, "sbxr-main", "RUN-TOKEN-MARKER")
}
func (api *executorFixture) PutConfiguration(_ context.Context, request PutConfigurationRequest) (Configuration, error) {
	configured := Configuration{TunnelID: request.TunnelID, Version: len(api.configurationWrites) + 1, Routes: append([]Route(nil), request.Routes...)}
	api.configurationWrites = append(api.configurationWrites, configured)
	return configured, nil
}
func (api *executorFixture) GetConfiguration(_ context.Context, request GetConfigurationRequest) (Configuration, error) {
	if api.priorConfiguration.TunnelID != "" {
		return api.priorConfiguration, nil
	}
	return Configuration{TunnelID: request.TunnelID, Version: 1, Routes: []Route{{Hostname: "old.example.com", Service: xhttpOrigin}, {Service: "http_status:404"}}}, nil
}
func (*executorFixture) CreateDNSRecord(_ context.Context, request CreateDNSRecordRequest) (OwnedResource, error) {
	return OwnedResource{ID: testDNSID, Name: request.Name}, nil
}
func (api *executorFixture) GetDNSRecord(_ context.Context, request GetDNSRecordRequest) (DNSObservation, error) {
	if api.priorDNS.ID != "" {
		return api.priorDNS, nil
	}
	return DNSObservation{ID: request.ID, Name: "xhttp.example.com", Type: "CNAME", Content: "old.example.com", Proxied: true}, nil
}

func (api *executorFixture) PutDNSRecord(_ context.Context, request PutDNSRecordRequest) (OwnedResource, error) {
	api.dnsPutCalls++
	if api.dnsPutErr != nil {
		return OwnedResource{}, api.dnsPutErr
	}
	api.dnsWrites = append(api.dnsWrites, DNSObservation{ID: request.ID, Name: request.Name, Type: request.Type, Content: request.Content, Proxied: request.Proxied})
	return OwnedResource{ID: request.ID, Name: request.Name}, nil
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
