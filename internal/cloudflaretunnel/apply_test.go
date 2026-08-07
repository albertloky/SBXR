package cloudflaretunnel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/networkpolicy"
)

func TestApplyRecordsCreatedIDsBeforeLaterProviderWork(t *testing.T) {
	plan := plannedXHTTP(t)
	sequence := []string{}
	api := &applyingAPI{planningAPI: planningAPI{Observation: healthyAuthorityObservation(), Mutation: MutationObservation{Digest: strings.Repeat("a", 64)}}, sequence: &sequence}
	transaction := &recordingTransaction{sequence: &sequence}
	request := ApplyRequest{Plan: plan, DesiredStateSHA256: strings.Repeat("b", 64)}
	result := New(api, &controlledPlanClock{}).Apply(context.Background(), request, transaction)
	joined := strings.Join(sequence, ",")
	if result.Outcome != ApplyCompleted || !result.PlanConsumed || result.TunnelID != testTunnelID || result.DNSRecordID != testDNSID {
		t.Fatalf("Apply = %+v", result)
	}
	for _, ordered := range []string{"create tunnel", "record tunnel:" + testTunnelID, "put configuration", "create DNS", "record dns-record:" + testDNSID, "prepare service", "health"} {
		if !strings.Contains(joined, ordered) {
			t.Fatalf("events omitted %q: %s", ordered, joined)
		}
	}
	if eventIndex(sequence, "record tunnel:") > eventIndex(sequence, "put configuration") || eventIndex(sequence, "record dns-record:") > eventIndex(sequence, "health") {
		t.Fatalf("identifier was not durable before later provider work: %v", sequence)
	}
	if second := New(api, &controlledPlanClock{}).Apply(context.Background(), request, &recordingTransaction{sequence: &sequence}); second.Outcome != ApplyRefused {
		t.Fatalf("reused Plan = %+v", second)
	}
}

func TestApplyRollsBackOnlyRecordedCurrentChangeSetIDs(t *testing.T) {
	plan := plannedXHTTP(t)
	sequence := []string{}
	api := &applyingAPI{planningAPI: planningAPI{Observation: healthyAuthorityObservation(), Mutation: MutationObservation{Digest: strings.Repeat("a", 64)}}, healthErr: errors.New("SECRET-MARKER provider failure"), sequence: &sequence}
	transaction := &recordingTransaction{sequence: &sequence}
	result := New(api, &controlledPlanClock{}).Apply(context.Background(), ApplyRequest{Plan: plan, DesiredStateSHA256: strings.Repeat("b", 64)}, transaction)
	if result.Outcome != ApplyRollbackSucceeded || strings.Contains(result.String(), "SECRET-MARKER") || strings.Join(api.deleted, ",") != "dns-record:"+testDNSID+",tunnel:"+testTunnelID {
		t.Fatalf("failed Apply = %+v deleted=%v", result, api.deleted)
	}
}

func TestApplyBurnsPlanWhenDesiredStateChanged(t *testing.T) {
	plan := plannedXHTTP(t)
	sequence := []string{}
	api := &applyingAPI{planningAPI: planningAPI{Observation: healthyAuthorityObservation(), Mutation: MutationObservation{Digest: strings.Repeat("a", 64)}}, sequence: &sequence}
	result := New(api, &controlledPlanClock{}).Apply(context.Background(), ApplyRequest{Plan: plan, DesiredStateSHA256: strings.Repeat("c", 64)}, &recordingTransaction{sequence: &sequence})
	if result.Outcome != ApplyRefused || !result.PlanConsumed || len(sequence) != 0 {
		t.Fatalf("stale Apply = %+v events=%v", result, sequence)
	}
}

func TestCloudflaredServiceUsesOnlyProtectedTokenFileAndLoopbackHTTP(t *testing.T) {
	contract := ServiceContract{Unit: "cloudflared.service", Identity: "cloudflared", TokenPath: "/etc/sbxr/cloudflared/token", DirectoryMode: 0o750, FileMode: 0o640, RunToken: newTunnelRunToken("RUN-SECRET-MARKER")}
	unit, config := contract.UnitFile(), contract.ValidationConfig("xhttp.example.com")
	if rendered := fmt.Sprintf("%+v %#v", contract, CreatedTunnel{ID: testTunnelID, Name: "sbxr-main", RunToken: contract.RunToken}); strings.Contains(rendered, "RUN-SECRET-MARKER") {
		t.Fatalf("run token rendered: %s", rendered)
	}
	if !strings.Contains(unit, "User=cloudflared") || !strings.Contains(unit, "--token-file /etc/sbxr/cloudflared/token") || strings.Contains(unit, "RUN-SECRET-MARKER") || strings.Contains(unit, "Environment=") || strings.Contains(unit, " --token ") {
		t.Fatalf("unsafe cloudflared unit: %s", unit)
	}
	if config != "ingress:\n  - hostname: xhttp.example.com\n    service: http://127.0.0.1:11080\n  - service: http_status:404\n" {
		t.Fatalf("routing contract: %s", config)
	}
}

func TestServiceMaterialRefusesSymlinksAndWiderModes(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "etc/sbxr/cloudflared")
	if err := os.MkdirAll(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "etc/sbxr"), 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenPath, []byte("RUN-SECRET-MARKER"), 0o640); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Geteuid(), os.Getegid()
	if err := ValidateServiceMaterial(root, uid, gid, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tokenPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateServiceMaterial(root, uid, gid, gid); err == nil {
		t.Fatal("world-readable run token accepted")
	}
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", tokenPath); err != nil {
		t.Fatal(err)
	}
	if err := ValidateServiceMaterial(root, uid, gid, gid); err == nil {
		t.Fatal("run-token symlink accepted")
	}
}

type applyingAPI struct {
	planningAPI
	healthErr error
	sequence  *[]string
	deleted   []string
}

func (api *applyingAPI) event(value string) { *api.sequence = append(*api.sequence, value) }
func (api *applyingAPI) CreateTunnel(context.Context, CreateTunnelRequest) (CreatedTunnel, error) {
	api.event("create tunnel")
	return CreatedTunnel{ID: testTunnelID, Name: "sbxr-main", RunToken: newTunnelRunToken("RUN-SECRET-MARKER")}, nil
}
func (api *applyingAPI) PutConfiguration(_ context.Context, request PutConfigurationRequest) (Configuration, error) {
	api.event("put configuration")
	return Configuration{TunnelID: request.TunnelID, Version: 1, Routes: request.Routes}, nil
}
func (api *applyingAPI) CreateDNSRecord(_ context.Context, request CreateDNSRecordRequest) (OwnedResource, error) {
	api.event("create DNS")
	return OwnedResource{ID: testDNSID, Name: request.Name}, nil
}
func (api *applyingAPI) CheckXHTTP(context.Context, XHTTPHealthRequest) (bool, error) {
	api.event("health")
	return api.healthErr == nil, api.healthErr
}
func (api *applyingAPI) DeleteDNSRecord(_ context.Context, request DeleteDNSRecordRequest) error {
	api.deleted = append(api.deleted, "dns-record:"+request.ID)
	return nil
}
func (api *applyingAPI) DeleteTunnel(_ context.Context, request DeleteTunnelRequest) error {
	api.deleted = append(api.deleted, "tunnel:"+request.ID)
	return nil
}

type recordingTransaction struct{ sequence *[]string }

func (transaction *recordingTransaction) RecordCreated(kind, id string) error {
	*transaction.sequence = append(*transaction.sequence, "record "+kind+":"+id)
	return nil
}
func (transaction *recordingTransaction) PrepareCloudflared(contract ServiceContract) error {
	if contract.Unit != "cloudflared.service" || contract.Identity != "cloudflared" || contract.TokenPath != "/etc/sbxr/cloudflared/token" || contract.DirectoryMode != 0o750 || contract.FileMode != 0o640 || contract.RunToken.value == "" {
		return errors.New("invalid service")
	}
	*transaction.sequence = append(*transaction.sequence, "prepare service")
	return nil
}

func eventIndex(events []string, prefix string) int {
	for index, event := range events {
		if strings.HasPrefix(event, prefix) {
			return index
		}
	}
	return len(events)
}

func healthyNetworkPath() networkpolicy.CloudflareTunnelPath {
	return networkpolicy.CloudflareTunnelPath{HTTPS: networkpolicy.ProofPassed, TCP7844: networkpolicy.ProofPassed, UDP7844: networkpolicy.ProofPassed}
}

func plannedXHTTP(t *testing.T) *Plan {
	t.Helper()
	token, _ := NewManagementToken("cfat_PLAN-SECRET-MARKER-000000000000000000000")
	api := &planningAPI{Observation: healthyAuthorityObservation(), Mutation: MutationObservation{Digest: strings.Repeat("a", 64)}}
	changeSet := "cloudflare-" + strings.ToLower(strings.TrimPrefix(t.Name(), "TestApply"))
	result := New(api, &controlledPlanClock{}).Plan(context.Background(), PlanRequest{Authority: ViewRequest{AccountID: testAccountID, ZoneID: testZoneID, ZoneName: "example.com", Token: token, NetworkPath: healthyNetworkPath()}, ChangeSet: changeSet, DesiredStateSHA256: strings.Repeat("b", 64), TunnelName: "sbxr-main", XHTTPHostname: "xhttp.example.com", CloudflaredVersion: "2026.7.3"})
	if result.Plan == nil {
		t.Fatalf("Plan = %+v", result)
	}
	return result.Plan
}
