package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/networkpolicy"
)

func TestPrepareCommitValidatesCandidateAndSerializesLeastPrivilegeMaterial(t *testing.T) {
	candidate := completeDesiredState()
	stateModule, request, validators := managedPrepareRequest(t, candidate)
	preparation, err := stateModule.PrepareCommit(request)
	if err != nil {
		t.Fatal(err)
	}
	if preparation.releaseIdentity != testRelease || !reflect.DeepEqual(preparation.candidate, candidate) {
		t.Fatal("PrepareCommit did not preserve the complete candidate")
	}
	for _, module := range []string{"connectionprofiles", "subscriptionpublication", "cloudflaretunnel", "certificatelifecycle", "networkpolicy", "softwarelifecycle"} {
		if validators.calls[module] != 1 {
			t.Fatalf("%s validation calls = %d, want 1", module, validators.calls[module])
		}
	}
	if validators.connectionSecrets.ReadClientAccessValue(candidate.ConnectionProfiles.VLESSRealityVision.UUID) != "" || validators.subscriptionSecrets.ReadClientAccessValue(candidate.Subscription.Token) != "" || validators.cloudflareSecrets.ReadInfrastructureSecret(candidate.Cloudflare.ManagementToken) != "" {
		t.Fatal("an owning validator retained secret-reading authority after validation")
	}

	checks := []struct {
		copy        *PreparedServiceCopy
		service     string
		module      string
		group       string
		want        any
		mustHave    []string
		mustNotHave []string
	}{
		{copy: preparation.serviceCopies.Xray, service: "xray.service", module: "connectionprofiles", group: "xray", want: serviceMaterialsFor(candidate).Xray, mustHave: []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, mustNotHave: []string{"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "xhttp.example.com", "ws.example.com", "HYSTERIA2-SECRET-MARKER-00000001", "CLOUDFLARE-MANAGEMENT-SECRET-MARKER", "CLOUDFLARE-RUN-SECRET-MARKER-00001", "6666666666666666666666666666666666666666666666666666666666666666"}},
		{copy: preparation.serviceCopies.SingBox, service: "sing-box.service", module: "connectionprofiles", group: "sing-box", want: serviceMaterialsFor(candidate).SingBox, mustHave: []string{"HYSTERIA2-SECRET-MARKER-00000001", "TUIC-PASSWORD-SECRET-MARKER-00001", "ANYTLS-PASSWORD-SECRET-MARKER-01", "/var/lib/sbxr/certificates/domain/current"}, mustNotHave: []string{"domain-certificate", "11111111-1111-4111-8111-111111111111", "CLOUDFLARE-MANAGEMENT-SECRET-MARKER", "CLOUDFLARE-RUN-SECRET-MARKER-00001", "6666666666666666666666666666666666666666666666666666666666666666"}},
		{copy: preparation.serviceCopies.Cloudflared, service: "cloudflared.service", module: "cloudflaretunnel", group: "cloudflared", want: serviceMaterialsFor(candidate).Cloudflared, mustHave: []string{"CLOUDFLARE-RUN-SECRET-MARKER-00001"}, mustNotHave: []string{"CLOUDFLARE-MANAGEMENT-SECRET-MARKER", "11111111-1111-4111-8111-111111111111", "HYSTERIA2-SECRET-MARKER-00000001", "6666666666666666666666666666666666666666666666666666666666666666"}},
		{copy: preparation.serviceCopies.Subscription, service: "sbxr-subscription.service", module: "subscriptionserving", group: "sbxr-subscription", want: serviceMaterialsFor(candidate).Subscription, mustHave: []string{"6666666666666666666666666666666666666666666666666666666666666666", "/var/lib/sbxr/certificates/ip/current"}, mustNotHave: []string{"ip-certificate", "CLOUDFLARE-MANAGEMENT-SECRET-MARKER", "CLOUDFLARE-RUN-SECRET-MARKER-00001", "11111111-1111-4111-8111-111111111111", "HYSTERIA2-SECRET-MARKER-00000001"}},
	}

	for _, check := range checks {
		t.Run(check.service, func(t *testing.T) {
			if check.copy == nil {
				t.Fatal("required service copy was omitted")
			}
			manifest := check.copy.manifest
			if manifest.Service != check.service || manifest.OwningModule != check.module || manifest.CandidateRevision != 8 || manifest.ChangeSet != "change-0008" || manifest.Owner != "root" || manifest.Group != check.group || manifest.DirectoryMode != 0o750 || manifest.FileMode != 0o640 {
				t.Fatalf("manifest = %+v", manifest)
			}
			digest := sha256.Sum256(check.copy.bytes)
			if manifest.SHA256 != hex.EncodeToString(digest[:]) {
				t.Fatal("manifest checksum does not bind the prepared bytes")
			}
			decoded := reflect.New(reflect.TypeOf(check.want))
			if err := json.Unmarshal(check.copy.bytes, decoded.Interface()); err != nil || !reflect.DeepEqual(decoded.Elem().Interface(), check.want) {
				t.Fatalf("serialized material did not round-trip: %v", err)
			}
			text := string(check.copy.bytes)
			for _, marker := range check.mustHave {
				if !strings.Contains(text, marker) {
					t.Fatalf("prepared copy omitted its required value %q", marker)
				}
			}
			for _, marker := range check.mustNotHave {
				if strings.Contains(text, marker) {
					t.Fatalf("prepared copy exposed unrelated value %q", marker)
				}
			}
			if strings.Contains(text, `"enabled"`) || strings.Contains(text, "comment") || strings.Contains(text, "provenance") || strings.Contains(text, "release_identity") {
				t.Fatal("prepared copy contains comments or provenance")
			}
		})
	}
}

func TestPrepareManagementTokenChangeAcceptsOnlyTheReviewedCloudflarePlan(t *testing.T) {
	for _, action := range []cloudflaretunnel.ManagementTokenAction{cloudflaretunnel.ManagementTokenReplace, cloudflaretunnel.ManagementTokenRemove} {
		t.Run(string(action), func(t *testing.T) {
			starting := completeDesiredState()
			starting.Cloudflare.AccountID = strings.Repeat("1", 32)
			starting.Cloudflare.ZoneID = strings.Repeat("2", 32)
			storage := &mutableStateStorage{document: documentFor(t, starting)}
			stateModule := New(storage)
			loaded, err := stateModule.Load(intentManagedRequest())
			if err != nil {
				t.Fatal(err)
			}
			template := starting
			template.Cloudflare.ManagementToken = InfrastructureSecret{}
			if action == cloudflaretunnel.ManagementTokenRemove {
				template.Cloudflare.ManagementTokenRemoved = true
				template.Cloudflare.ManagementTokenState = CloudflareManagementUnmanaged
			}
			templateJSON, err := marshalProtectedJSON(template)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(templateJSON)
			templateSHA := hex.EncodeToString(digest[:])
			token := cloudflaretunnel.ManagementToken{}
			final := template
			if action == cloudflaretunnel.ManagementTokenReplace {
				token, err = cloudflaretunnel.NewManagementToken("cfat_REPLACEMENT-TOKEN-SECRET-MARKER-000000")
				if err != nil {
					t.Fatal(err)
				}
				final.Cloudflare.ManagementToken = NewInfrastructureSecret("cfat_REPLACEMENT-TOKEN-SECRET-MARKER-000000")
			}
			provider := &deferredCloudflareAPI{}
			var inventory cloudflaretunnel.ManagementTokenInventoryAuthority
			if action == cloudflaretunnel.ManagementTokenRemove {
				inventory, err = stateModule.ManagementTokenInventory(loaded)
				if err != nil {
					t.Fatal(err)
				}
			}
			planResult := cloudflaretunnel.New(provider, cloudflaretunnel.SystemClock{}).Plan(context.Background(), cloudflaretunnel.PlanRequest{
				Authority: cloudflaretunnel.ViewRequest{AccountID: starting.Cloudflare.AccountID, ZoneID: starting.Cloudflare.ZoneID, ZoneName: starting.Cloudflare.ZoneName, Token: token, NetworkPath: networkpolicy.CloudflareTunnelPath{HTTPS: networkpolicy.ProofPassed, TCP7844: networkpolicy.ProofPassed, UDP7844: networkpolicy.ProofPassed}},
				ChangeSet: "cloudflare-token-change", StartingRevision: 7, StartingStateSHA256: loaded.loaded.payloadChecksum, DesiredStateSHA256: templateSHA,
				ManagementToken: stateTestManagementTokenChange(action, inventory),
			})
			if planResult.Plan == nil {
				t.Fatalf("token Plan = %+v", planResult.Health)
			}
			request := preparedRequest(t, loaded, template, "cloudflare-token-change")
			validator := request.SemanticValidators.Cloudflare.(*validatingSeams)
			validator.want = final
			request.ServiceMaterials = serviceMaterialsFor(final)
			request.ReviewedInputs, err = NewReviewedInputs(PlanIdentity(planResult.Plan.Identity()), planResult.Plan.SHA256(), request.ReviewedInputs.managed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stateModule.PrepareCommit(request); err == nil {
				t.Fatal("ordinary PrepareCommit accepted a management-token change")
			}
			loaded, err = stateModule.Load(intentManagedRequest())
			if err != nil {
				t.Fatal(err)
			}
			request.Loaded = loaded
			prepared, err := stateModule.PrepareManagementTokenCommit(request, planResult.Plan)
			if err != nil {
				t.Fatal(err)
			}
			if prepared.candidate.Cloudflare.ManagementTokenRemoved != (action == cloudflaretunnel.ManagementTokenRemove) || prepared.candidate.Cloudflare.ManagementTokenState != final.Cloudflare.ManagementTokenState || prepared.candidate.Cloudflare.ManagementToken.value != final.Cloudflare.ManagementToken.value || strings.Contains(fmt.Sprintf("%+v %#v", prepared, planResult), "REPLACEMENT-TOKEN-SECRET-MARKER") {
				t.Fatal("State did not own the protected token change")
			}
		})
	}
}

func TestPrepareRunTokenRotationKeepsTheOldTokenOnlyInRollbackMaterial(t *testing.T) {
	starting := completeDesiredState()
	starting.Cloudflare.AccountID = strings.Repeat("1", 32)
	starting.Cloudflare.ZoneID = strings.Repeat("2", 32)
	starting.Cloudflare.TunnelID = "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415"
	starting.Cloudflare.XHTTPDNSRecordID = strings.Repeat("3", 32)
	starting.Cloudflare.WebSocketDNSRecordID = strings.Repeat("4", 32)
	starting.Cloudflare.DirectIPv4RecordID = strings.Repeat("5", 32)
	starting.Software.CloudflaredVersion = "2026.7.3"
	storage := &mutableStateStorage{document: documentFor(t, starting)}
	stateModule := New(storage)
	loaded, err := stateModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	template, err := marshalProtectedJSON(starting)
	if err != nil {
		t.Fatal(err)
	}
	templateDigest := sha256.Sum256(template)
	managementToken, err := cloudflaretunnel.NewManagementToken("cfat_ROTATION-MANAGEMENT-TOKEN-MARKER-0000")
	if err != nil {
		t.Fatal(err)
	}
	provider := &deferredCloudflareAPI{}
	planResult := cloudflaretunnel.New(provider, cloudflaretunnel.SystemClock{}).Plan(t.Context(), cloudflaretunnel.PlanRequest{
		Authority: cloudflaretunnel.ViewRequest{AccountID: starting.Cloudflare.AccountID, ZoneID: starting.Cloudflare.ZoneID, ZoneName: starting.Cloudflare.ZoneName, Token: managementToken, NetworkPath: networkpolicy.CloudflareTunnelPath{HTTPS: networkpolicy.ProofPassed, TCP7844: networkpolicy.ProofPassed, UDP7844: networkpolicy.ProofPassed}},
		ChangeSet: "cloudflare-run-token-rotation-prepare", StartingRevision: 7, StartingStateSHA256: loaded.loaded.payloadChecksum, DesiredStateSHA256: hex.EncodeToString(templateDigest[:]),
		XHTTPHostname: starting.Cloudflare.XHTTPHostname, WebSocketHostname: starting.Cloudflare.WebSocketHostname, DirectHostname: starting.Cloudflare.DirectHostname,
		PublicIPv4: starting.NetworkPolicy.PublicIPv4, CloudflaredVersion: starting.Software.CloudflaredVersion,
		RunTokenRotation: cloudflaretunnel.RunTokenRotation{TunnelID: starting.Cloudflare.TunnelID, XHTTPDNSRecordID: starting.Cloudflare.XHTTPDNSRecordID, WebSocketDNSRecordID: starting.Cloudflare.WebSocketDNSRecordID, DirectIPv4RecordID: starting.Cloudflare.DirectIPv4RecordID},
	})
	if planResult.Plan == nil {
		t.Fatalf("rotation Plan = %+v", planResult.Health)
	}
	request := preparedRequest(t, loaded, starting, "cloudflare-run-token-rotation-prepare")
	request.ReviewedInputs, err = NewReviewedInputs(PlanIdentity(planResult.Plan.Identity()), planResult.Plan.SHA256(), request.ReviewedInputs.managed)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := stateModule.PrepareRunTokenRotationCommit(request, planResult.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if request.SemanticValidators.Cloudflare.(*validatingSeams).calls["cloudflaretunnel"] == 0 {
		t.Fatal("Cloudflare did not validate the complete current candidate before the token slot was deferred")
	}
	if prepared.deferred == nil || prepared.serviceCopies.Cloudflared != nil || strings.Contains(string(prepared.preparedState), "CLOUDFLARE-RUN-SECRET-MARKER-00001") || !strings.Contains(string(prepared.starting.bytes), "CLOUDFLARE-RUN-SECRET-MARKER-00001") {
		t.Fatal("old run token was not confined to pre-checkpoint rollback material")
	}
}

func TestManagementTokenDependencyBindingRequiresEveryExactOwner(t *testing.T) {
	if !exactManagementTokenDependencies([]string{"Tunnel", "DNS", "certificate", "profile", "repair", "update"}) || exactManagementTokenDependencies([]string{"Tunnel", "DNS", "certificate", "profile", "repair", "other"}) {
		t.Fatal("State did not independently enforce the exact dependency inventory")
	}
}

func TestPrepareManagementTokenReplacementRejectsDifferentSelectedAuthority(t *testing.T) {
	starting := completeDesiredState()
	starting.Cloudflare.AccountID = strings.Repeat("1", 32)
	starting.Cloudflare.ZoneID = strings.Repeat("2", 32)
	stateModule := New(&mutableStateStorage{document: documentFor(t, starting)})
	loaded, err := stateModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	candidate := starting
	candidate.Cloudflare.AccountID = strings.Repeat("9", 32)
	candidate.Cloudflare.ManagementToken = InfrastructureSecret{}
	template, err := marshalProtectedJSON(candidate)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(template)
	token, err := cloudflaretunnel.NewManagementToken("cfat_MISMATCHED-AUTHORITY-SECRET-MARKER-000000")
	if err != nil {
		t.Fatal(err)
	}
	plan := cloudflaretunnel.New(&deferredCloudflareAPI{}, cloudflaretunnel.SystemClock{}).Plan(context.Background(), cloudflaretunnel.PlanRequest{
		Authority: cloudflaretunnel.ViewRequest{AccountID: starting.Cloudflare.AccountID, ZoneID: starting.Cloudflare.ZoneID, ZoneName: starting.Cloudflare.ZoneName, Token: token, NetworkPath: networkpolicy.CloudflareTunnelPath{HTTPS: networkpolicy.ProofPassed, TCP7844: networkpolicy.ProofPassed, UDP7844: networkpolicy.ProofPassed}},
		ChangeSet: "cloudflare-token-authority-mismatch", StartingRevision: 7, StartingStateSHA256: loaded.loaded.payloadChecksum, DesiredStateSHA256: hex.EncodeToString(digest[:]),
		ManagementToken: cloudflaretunnel.ManagementTokenChange{Action: cloudflaretunnel.ManagementTokenReplace, CurrentTokenID: strings.Repeat("5", 32)},
	})
	if plan.Plan == nil {
		t.Fatalf("mismatch regression Plan = %+v", plan.Health)
	}
	request := preparedRequest(t, loaded, candidate, "cloudflare-token-authority-mismatch")
	request.SemanticValidators.Cloudflare.(*validatingSeams).want = candidate
	request.ServiceMaterials = serviceMaterialsFor(candidate)
	request.ReviewedInputs, err = NewReviewedInputs(PlanIdentity(plan.Plan.Identity()), plan.Plan.SHA256(), request.ReviewedInputs.managed)
	if err != nil {
		t.Fatal(err)
	}
	_, err = stateModule.PrepareManagementTokenCommit(request, plan.Plan)
	var problem *Finding
	if !errors.As(err, &problem) || problem.Code != "STATE-CLOUDFLARE-TOKEN-PLAN" {
		t.Fatalf("mismatched selected authority = %v", err)
	}
}

func TestManagementTokenRemovalUsesTheCurrentStateInventory(t *testing.T) {
	starting := completeDesiredState()
	starting.Cloudflare.AccountID = strings.Repeat("1", 32)
	starting.Cloudflare.ZoneID = strings.Repeat("2", 32)
	stateModule := New(&mutableStateStorage{document: documentFor(t, starting)})
	loaded, err := stateModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := stateModule.ManagementTokenInventory(loaded)
	if err != nil {
		t.Fatal(err)
	}
	request := cloudflaretunnel.PlanRequest{
		Authority: cloudflaretunnel.ViewRequest{AccountID: starting.Cloudflare.AccountID, ZoneID: starting.Cloudflare.ZoneID, ZoneName: starting.Cloudflare.ZoneName},
		ChangeSet: "cloudflare-token-inventory", StartingRevision: 7, StartingStateSHA256: loaded.loaded.payloadChecksum, DesiredStateSHA256: testSHA('8'),
		ManagementToken: cloudflaretunnel.ManagementTokenChange{Action: cloudflaretunnel.ManagementTokenRemove, CurrentTokenID: strings.Repeat("5", 32), Inventory: inventory},
	}
	module := cloudflaretunnel.New(&deferredCloudflareAPI{}, cloudflaretunnel.SystemClock{})
	request.ManagementToken.Inventory = fakeManagementTokenInventory{}
	if fake := module.Plan(context.Background(), request); fake.Plan != nil || fake.Health.Code != "CLOUDFLARE-MANAGEMENT-TOKEN-REFUSED" {
		t.Fatalf("caller-made inventory = %+v", fake)
	}
	request.ManagementToken.Inventory = inventory
	unresolved := module.Plan(context.Background(), request)
	wantDependencies := []cloudflaretunnel.ManagementTokenDependency{cloudflaretunnel.TunnelDependency, cloudflaretunnel.DNSDependency, cloudflaretunnel.CertificateDependency, cloudflaretunnel.ProfileDependency, cloudflaretunnel.RepairDependency, cloudflaretunnel.UpdateDependency}
	if unresolved.Plan != nil || unresolved.Health.Code != "CLOUDFLARE-MANAGEMENT-TOKEN-DEPENDENCIES" || !slices.Equal(unresolved.Dependencies, wantDependencies) || !slices.Equal(unresolved.Health.NextActions, []string{"Check now", "Replace token", "Remove from SBXR"}) {
		t.Fatalf("unresolved State inventory = %+v", unresolved)
	}
	request.ManagementToken.Resolution = cloudflaretunnel.MarkDependenciesUnmanaged
	resolved := module.Plan(context.Background(), request)
	if resolved.Plan == nil || !slices.Equal(resolved.Dependencies, wantDependencies) {
		t.Fatalf("resolved State inventory = %+v", resolved)
	}
	preview := strings.Join(resolved.ResultingState, "\n")
	for _, dependency := range wantDependencies {
		if !strings.Contains(preview, string(dependency)+" becomes mark dependencies unmanaged") {
			t.Fatalf("removal preview omitted %s: %s", dependency, preview)
		}
	}
	request.ManagementToken.Inventory = &ManagementTokenInventory{revision: 7, stateSHA256: loaded.loaded.payloadChecksum, dependencies: []string{}}
	request.ManagementToken.Resolution = ""
	if empty := module.Plan(context.Background(), request); empty.Plan == nil || len(empty.Dependencies) != 0 {
		t.Fatalf("empty State inventory = %+v", empty)
	}
}

type fakeManagementTokenInventory struct{}

func (fakeManagementTokenInventory) StateManagementTokenInventory() ([]byte, bool) {
	return []byte(`{"Revision":7,"StateSHA256":"` + strings.Repeat("a", 64) + `","Dependencies":[]}`), true
}

func stateTestManagementTokenChange(action cloudflaretunnel.ManagementTokenAction, inventory cloudflaretunnel.ManagementTokenInventoryAuthority) cloudflaretunnel.ManagementTokenChange {
	change := cloudflaretunnel.ManagementTokenChange{Action: action, CurrentTokenID: strings.Repeat("5", 32), Inventory: inventory}
	if action == cloudflaretunnel.ManagementTokenRemove {
		change.Resolution = cloudflaretunnel.MarkDependenciesUnmanaged
	}
	return change
}

func TestPreparedServiceCopiesCannotBeRendered(t *testing.T) {
	candidate := completeDesiredState()
	stateModule, request, _ := managedPrepareRequest(t, candidate)
	preparation, err := stateModule.PrepareCommit(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, copy := range []*PreparedServiceCopy{preparation.serviceCopies.Xray, preparation.serviceCopies.SingBox, preparation.serviceCopies.Cloudflared, preparation.serviceCopies.Subscription} {
		if copy == nil {
			t.Fatal("required service copy was omitted")
		}
		rendered, renderErr := json.Marshal(copy)
		formatted := fmt.Sprintf("%+v %#v", copy, copy)
		if renderErr == nil || strings.Contains(string(rendered), "SECRET-MARKER") || !strings.Contains(formatted, "redacted prepared service copy") || len(formatted) > 100 {
			t.Fatal("prepared service copy exposed protected bytes through general rendering")
		}
	}
}

func TestPrepareCommitRefusesInvalidCandidateFactsAndMaterial(t *testing.T) {
	valid := completeDesiredState()
	tests := []struct {
		name   string
		change func(*PrepareRequest)
		code   string
	}{
		{name: "partial candidate", change: func(r *PrepareRequest) { r.Candidate.Subscription.Token = ClientAccessValue{} }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "missing semantic validator", change: func(r *PrepareRequest) { r.SemanticValidators.NetworkPolicy = nil }, code: "STATE-CANDIDATE-SEMANTIC"},
		{name: "missing native Connection Profiles preparer", change: func(r *PrepareRequest) {
			base := r.SemanticValidators.ConnectionProfiles.(*validatingSeams)
			r.SemanticValidators.ConnectionProfiles = connectionProfilesValidatorOnly{base}
		}, code: "STATE-SERVICE-SERIALIZATION"},
		{name: "changed Connection Profiles without their reviewed Plan", change: func(r *PrepareRequest) {
			r.Candidate.ConnectionProfiles.VLESSRealityVision.UUID = NewClientAccessValue("replacement-reality-uuid")
			r.ServiceMaterials = serviceMaterialsFor(r.Candidate)
			validator := &validatingSeams{want: r.Candidate, calls: map[string]int{}}
			r.SemanticValidators = validatorsFor(validator)
		}, code: "STATE-SERVICE-SERIALIZATION"},
		{name: "owning validator refusal", change: func(r *PrepareRequest) {
			validator := &validatingSeams{want: valid, reject: "cloudflaretunnel", calls: map[string]int{}}
			r.SemanticValidators = validatorsFor(validator)
		}, code: "STATE-CANDIDATE-SEMANTIC"},
		{name: "unrelated service value", change: func(r *PrepareRequest) {
			r.ServiceMaterials.Xray.VLESSRealityVision.UUID = r.Candidate.ConnectionProfiles.Hysteria2.Password
		}, code: "STATE-SERVICE-MATERIAL-UNRELATED"},
		{name: "omitted service material", change: func(r *PrepareRequest) { r.ServiceMaterials.Cloudflared = nil }, code: "STATE-SERVICE-MATERIAL-UNRELATED"},
		{name: "missing reviewed inputs", change: func(r *PrepareRequest) { r.ReviewedInputs = ReviewedInputs{} }, code: "STATE-REVIEW-BINDING"},
		{name: "missing Release Identity", change: func(r *PrepareRequest) { r.CandidateReleaseIdentity = ReleaseIdentity{} }, code: "STATE-SERVICE-MANIFEST"},
		{name: "invalid later Change Set", change: func(r *PrepareRequest) { r.ChangeSet = "invalid\nchange" }, code: "STATE-SERVICE-MANIFEST"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateModule, request, _ := managedPrepareRequest(t, valid)
			tt.change(&request)
			preparation, err := stateModule.PrepareCommit(request)
			var finding *Finding
			if !errors.As(err, &finding) || finding.Code != tt.code || preparation != nil {
				t.Fatalf("PrepareCommit() = (%+v, %#v), want %s refusal", preparation, err, tt.code)
			}
			for _, marker := range []string{"CLOUDFLARE-MANAGEMENT-SECRET-MARKER", "HYSTERIA2-SECRET-MARKER-00000001", "6666666666666666666666666666666666666666666666666666666666666666"} {
				if strings.Contains(err.Error(), marker) {
					t.Fatal("refusal exposed a protected value")
				}
			}
		})
	}
}

func TestPrepareCommitUsesOwningConnectionProfilesNativeConfiguration(t *testing.T) {
	candidate := completeDesiredState()
	stateModule, request, _ := managedPrepareRequest(t, candidate)
	validator := request.SemanticValidators.ConnectionProfiles.(*validatingSeams)
	native := []byte(`{"inbounds":[{"protocol":"vless","streamSettings":{"method":"raw","security":"reality"}}]}`)
	singBox, err := marshalProtectedJSON(expectedServiceMaterials(candidate).SingBox)
	if err != nil {
		t.Fatal(err)
	}
	preparer := &nativeProfilesPreparer{validatingSeams: validator, xray: native, singBox: singBox}
	request.SemanticValidators.ConnectionProfiles = preparer
	preparation, err := stateModule.PrepareCommit(request)
	if err != nil {
		t.Fatal(err)
	}
	if preparation.serviceCopies.Xray == nil || !bytes.Equal(preparation.serviceCopies.Xray.bytes, native) || preparation.serviceCopies.Xray.manifest.SHA256 != fmt.Sprintf("%x", sha256.Sum256(native)) {
		t.Fatalf("prepared Xray service copy = %+v", preparation.serviceCopies.Xray)
	}
	if preparer.secrets == nil || preparer.secrets.ReadClientAccessValue(candidate.ConnectionProfiles.VLESSRealityVision.UUID) != "" || preparer.secrets.ReadInfrastructureSecret(candidate.ConnectionProfiles.VLESSRealityVision.PrivateKey) != "" {
		t.Fatal("Connection Profiles preparation secret reader remained active")
	}
}

type nativeProfilesPreparer struct {
	*validatingSeams
	xray    []byte
	singBox []byte
	secrets ConnectionProfileSecretReader
}

type connectionProfilesValidatorOnly struct{ base *validatingSeams }

func (validator connectionProfilesValidatorOnly) ValidateConnectionProfiles(profiles ConnectionProfiles, secrets ConnectionProfileSecretReader) error {
	return validator.base.ValidateConnectionProfiles(profiles, secrets)
}

func (preparer *nativeProfilesPreparer) PrepareConnectionProfiles(_ ConnectionProfiles, secrets ConnectionProfileSecretReader) ([]byte, []byte, error) {
	preparer.secrets = secrets
	return append([]byte(nil), preparer.xray...), append([]byte(nil), preparer.singBox...), nil
}

func TestPrepareIPCertificateRenewalCommitAllowsOnlyStandingScope(t *testing.T) {
	candidate := completeDesiredState()
	candidate.Certificates.IPCertificateID = "ip-certificate-renewed"
	candidate.Certificates.IPServingPointer = "ip-serving-renewed"
	candidate.Subscription.CertificateID = candidate.Certificates.IPCertificateID
	stateModule, request, _ := managedPrepareRequest(t, candidate)
	prepared, err := stateModule.PrepareIPCertificateRenewalCommit(request)
	if err != nil || prepared == nil {
		t.Fatalf("narrow renewal preparation = (%+v, %v)", prepared, err)
	}
	if !prepared.SystemChangesIPCertificateRenewal() {
		t.Fatal("IP renewal scope was not preserved")
	}

	for _, change := range []func(*DesiredState){
		func(candidate *DesiredState) { candidate.NetworkPolicy.SSHPort++ },
		func(candidate *DesiredState) {
			candidate.Certificates.DomainCertificateID = "domain-certificate-renewed"
		},
		func(candidate *DesiredState) { candidate.Certificates.RenewalPolicy = false },
		func(candidate *DesiredState) { candidate.Subscription.CertificateID = "other-certificate" },
	} {
		changed := candidate
		change(&changed)
		stateModule, request, _ := managedPrepareRequest(t, changed)
		prepared, err := stateModule.PrepareIPCertificateRenewalCommit(request)
		var finding *Finding
		if prepared != nil || !errors.As(err, &finding) || finding.Code != "STATE-CERTIFICATE-RENEWAL-SCOPE" {
			t.Fatalf("policy escape = (%+v, %v)", prepared, err)
		}
	}
}

func TestPrepareDomainCertificateRenewalCommitAllowsOnlyStandingScope(t *testing.T) {
	candidate := completeDesiredState()
	candidate.Certificates.DomainCertificateID = "domain-certificate-renewed"
	candidate.Certificates.DomainServingPointer = "domain-serving-renewed"
	candidate.ConnectionProfiles.Hysteria2.CertificateID = candidate.Certificates.DomainCertificateID
	candidate.ConnectionProfiles.TUIC.CertificateID = candidate.Certificates.DomainCertificateID
	candidate.ConnectionProfiles.AnyTLS.CertificateID = candidate.Certificates.DomainCertificateID
	stateModule, request, _ := managedPrepareRequest(t, candidate)
	prepared, err := stateModule.PrepareDomainCertificateRenewalCommit(request)
	if err != nil || prepared == nil || !prepared.SystemChangesDomainCertificateRenewal() || prepared.SystemChangesIPCertificateRenewal() {
		t.Fatalf("narrow domain renewal preparation = (%+v, %v)", prepared, err)
	}

	for _, change := range []func(*DesiredState){
		func(candidate *DesiredState) { candidate.NetworkPolicy.SSHPort++ },
		func(candidate *DesiredState) { candidate.Certificates.IPCertificateID = "ip-certificate-renewed" },
		func(candidate *DesiredState) { candidate.Certificates.RenewalPolicy = false },
		func(candidate *DesiredState) { candidate.ConnectionProfiles.AnyTLS.CertificateID = "other-certificate" },
	} {
		changed := candidate
		change(&changed)
		stateModule, request, _ := managedPrepareRequest(t, changed)
		prepared, err := stateModule.PrepareDomainCertificateRenewalCommit(request)
		var finding *Finding
		if prepared != nil || !errors.As(err, &finding) || finding.Code != "STATE-CERTIFICATE-RENEWAL-SCOPE" {
			t.Fatalf("domain policy escape = (%+v, %v)", prepared, err)
		}
	}
}

func TestPrepareCommitRequiresOwningSemanticValidationForEverySection(t *testing.T) {
	valid := completeDesiredState()
	tests := []struct {
		name   string
		change func(*DesiredState)
	}{
		{name: "installation identity", change: func(candidate *DesiredState) { candidate.Installation.ID = "not-a-uuid" }},
		{name: "Connection Profiles", change: func(candidate *DesiredState) { candidate.ConnectionProfiles.VLESSXHTTP.OriginAddress = "0.0.0.0" }},
		{name: "subscription", change: func(candidate *DesiredState) { candidate.Subscription.ListenPort = 10444 }},
		{name: "Cloudflare", change: func(candidate *DesiredState) { candidate.Cloudflare.TunnelName = "invalid tunnel name" }},
		{name: "certificates", change: func(candidate *DesiredState) { candidate.Certificates.RenewalPolicy = false }},
		{name: "Network Policy", change: func(candidate *DesiredState) {
			candidate.NetworkPolicy.PublicIPv4 = "not-an-ip"
			candidate.NetworkPolicy.PrimarySubscriptionAddress = "not-an-ip"
		}},
		{name: "software", change: func(candidate *DesiredState) { candidate.Software.XrayVersion = "invalid version" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := valid
			tt.change(&candidate)
			validator := &validatingSeams{want: valid, calls: map[string]int{}}
			stateModule, request, _ := managedPrepareRequest(t, candidate)
			request.SemanticValidators = validatorsFor(validator)
			_, err := stateModule.PrepareCommit(request)
			var finding *Finding
			if !errors.As(err, &finding) || finding.Code != "STATE-CANDIDATE-SEMANTIC" {
				t.Fatalf("PrepareCommit() error = %#v, want STATE-CANDIDATE-SEMANTIC", err)
			}
		})
	}
}

func TestPrepareCommitRevokesSecretReaderAfterValidatorPanic(t *testing.T) {
	candidate := completeDesiredState()
	validator := &validatingSeams{want: candidate, panicModule: "subscriptionpublication", calls: map[string]int{}}
	stateModule, request, _ := managedPrepareRequest(t, candidate)
	request.SemanticValidators = validatorsFor(validator)
	_, err := stateModule.PrepareCommit(request)
	var finding *Finding
	if !errors.As(err, &finding) || finding.Code != "STATE-CANDIDATE-SEMANTIC" {
		t.Fatalf("PrepareCommit() error = %#v, want secret-safe semantic refusal", err)
	}
	if validator.subscriptionSecrets == nil || validator.subscriptionSecrets.ReadClientAccessValue(candidate.Subscription.Token) != "" {
		t.Fatal("panicking validator retained secret-reading authority")
	}
}

func TestPrepareCommitOmitsDisabledProfileCredentials(t *testing.T) {
	tests := []struct {
		name, credential, route string
		disable                 func(*ConnectionProfiles)
		service                 func(PreparedServiceCopies) *PreparedServiceCopy
	}{
		{"VLESS REALITY Vision", "11111111-1111-4111-8111-111111111111", "", func(p *ConnectionProfiles) { p.VLESSRealityVision.Enabled = false }, func(c PreparedServiceCopies) *PreparedServiceCopy { return c.Xray }},
		{"VLESS XHTTP", "22222222-2222-4222-8222-222222222222", "xhttp.example.com", func(p *ConnectionProfiles) { p.VLESSXHTTP.Enabled = false }, func(c PreparedServiceCopies) *PreparedServiceCopy { return c.Xray }},
		{"VLESS WebSocket", "33333333-3333-4333-8333-333333333333", "ws.example.com", func(p *ConnectionProfiles) { p.VLESSWebSocket.Enabled = false }, func(c PreparedServiceCopies) *PreparedServiceCopy { return c.Xray }},
		{"Hysteria2", "HYSTERIA2-SECRET-MARKER-00000001", "", func(p *ConnectionProfiles) { p.Hysteria2.Enabled = false }, func(c PreparedServiceCopies) *PreparedServiceCopy { return c.SingBox }},
		{"TUIC", "TUIC-PASSWORD-SECRET-MARKER-00001", "", func(p *ConnectionProfiles) { p.TUIC.Enabled = false }, func(c PreparedServiceCopies) *PreparedServiceCopy { return c.SingBox }},
		{"AnyTLS", "ANYTLS-PASSWORD-SECRET-MARKER-01", "", func(p *ConnectionProfiles) { p.AnyTLS.Enabled = false }, func(c PreparedServiceCopies) *PreparedServiceCopy { return c.SingBox }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := completeDesiredState()
			test.disable(&candidate.ConnectionProfiles)
			stateModule, request, _ := managedPrepareRequest(t, candidate)
			preparation, err := stateModule.PrepareCommit(request)
			if err != nil {
				t.Fatal(err)
			}
			copy := test.service(preparation.serviceCopies)
			if copy == nil || strings.Contains(string(copy.bytes), test.credential) || !strings.Contains(string(preparation.preparedState), test.credential) {
				t.Fatal("disabled profile credential was lost from Desired State or entered runtime material")
			}
			if test.route != "" && (preparation.serviceCopies.Cloudflared == nil || strings.Contains(string(preparation.serviceCopies.Cloudflared.bytes), test.route)) {
				t.Fatal("disabled Cloudflare profile remained in Tunnel service material")
			}
		})
	}
}

func TestPrepareCommitAcceptsPreparedCoreWithAllProfilesDisabled(t *testing.T) {
	tests := []struct {
		name    string
		disable func(*ConnectionProfiles)
		service func(PreparedServiceCopies) *PreparedServiceCopy
	}{
		{"Xray", func(p *ConnectionProfiles) {
			p.VLESSRealityVision.Enabled, p.VLESSXHTTP.Enabled, p.VLESSWebSocket.Enabled = false, false, false
		}, func(c PreparedServiceCopies) *PreparedServiceCopy { return c.Xray }},
		{"sing-box", func(p *ConnectionProfiles) {
			p.Hysteria2.Enabled, p.TUIC.Enabled, p.AnyTLS.Enabled = false, false, false
		}, func(c PreparedServiceCopies) *PreparedServiceCopy { return c.SingBox }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := completeDesiredState()
			test.disable(&candidate.ConnectionProfiles)
			stateModule, request, _ := managedPrepareRequest(t, candidate)
			preparation, err := stateModule.PrepareCommit(request)
			copy := test.service(preparation.serviceCopies)
			if err != nil || copy == nil || len(copy.bytes) == 0 {
				t.Fatalf("empty %s configuration = copy=%+v err=%v", test.name, copy, err)
			}
			if test.name == "Xray" && preparation.serviceCopies.Cloudflared != nil {
				t.Fatal("disabled Cloudflare-backed profiles produced Tunnel service material")
			}
		})
	}
}

type validatingSeams struct {
	want                DesiredState
	reject              string
	panicModule         string
	dynamicCloudflare   bool
	calls               map[string]int
	connectionSecrets   ConnectionProfileSecretReader
	subscriptionSecrets ClientAccessReader
	cloudflareSecrets   InfrastructureSecretReader
	planIdentity        string
	planSHA256          string
}

func (v *validatingSeams) Identity() string { return v.planIdentity }
func (v *validatingSeams) SHA256() string   { return v.planSHA256 }

func (v *validatingSeams) validate(module string, got, want any) error {
	v.calls[module]++
	if v.reject == module || !reflect.DeepEqual(got, want) {
		return errors.New("semantic refusal")
	}
	return nil
}

func (v *validatingSeams) ValidateConnectionProfiles(got ConnectionProfiles, secrets ConnectionProfileSecretReader) error {
	v.connectionSecrets = secrets
	if v.panicModule == "connectionprofiles" {
		panic("validator panic")
	}
	if secrets.ReadClientAccessValue(got.VLESSRealityVision.UUID) == "" || secrets.ReadInfrastructureSecret(got.VLESSRealityVision.PrivateKey) == "" {
		return errors.New("protected Connection Profile value unavailable")
	}
	return v.validate("connectionprofiles", got, v.want.ConnectionProfiles)
}

func (v *validatingSeams) PrepareConnectionProfiles(_ ConnectionProfiles, secrets ConnectionProfileSecretReader) ([]byte, []byte, error) {
	v.connectionSecrets = secrets
	materials := expectedServiceMaterials(v.want)
	var xray, singBox []byte
	var err error
	if materials.Xray != nil {
		xray, err = marshalProtectedJSON(materials.Xray)
		if err != nil {
			return nil, nil, err
		}
	}
	if materials.SingBox != nil {
		singBox, err = marshalProtectedJSON(materials.SingBox)
	}
	return xray, singBox, err
}

func (v *validatingSeams) ValidateSubscription(got SubscriptionSettings, secrets ClientAccessReader) error {
	v.subscriptionSecrets = secrets
	if _, broad := secrets.(InfrastructureSecretReader); broad {
		return errors.New("subscription reader exposed Infrastructure Secrets")
	}
	if v.panicModule == "subscriptionpublication" {
		panic("validator panic")
	}
	if secrets.ReadClientAccessValue(got.Token) == "" {
		return errors.New("protected subscription value unavailable")
	}
	return v.validate("subscriptionpublication", got, v.want.Subscription)
}

func (v *validatingSeams) ValidateCloudflare(got CloudflareSettings, secrets InfrastructureSecretReader) error {
	v.cloudflareSecrets = secrets
	if _, broad := secrets.(ClientAccessReader); broad {
		return errors.New("Cloudflare reader exposed Client Access Values")
	}
	if v.panicModule == "cloudflaretunnel" {
		panic("validator panic")
	}
	managementTokenValid := got.ManagementTokenRemoved && secrets.ReadInfrastructureSecret(got.ManagementToken) == "" || !got.ManagementTokenRemoved && secrets.ReadInfrastructureSecret(got.ManagementToken) != ""
	if !managementTokenValid || secrets.ReadInfrastructureSecret(got.TunnelRunToken) == "" {
		return errors.New("protected Cloudflare value unavailable")
	}
	if v.dynamicCloudflare {
		want := v.want.Cloudflare
		if got.AccountID != want.AccountID || got.ZoneID != want.ZoneID || got.TunnelName != want.TunnelName || got.XHTTPHostname != want.XHTTPHostname || got.WebSocketHostname != want.WebSocketHostname || got.DirectHostname != want.DirectHostname || got.TunnelID == "" || got.XHTTPDNSRecordID == "" || got.WebSocketDNSRecordID == "" || got.DirectIPv4RecordID == "" {
			return errors.New("finalized Cloudflare binding is incomplete")
		}
		return nil
	}
	return v.validate("cloudflaretunnel", got, v.want.Cloudflare)
}

func (v *validatingSeams) ValidateCertificates(got CertificateSettings) error {
	return v.validate("certificatelifecycle", got, v.want.Certificates)
}

func (v *validatingSeams) ValidateNetworkPolicy(got NetworkPolicyInputs) error {
	return v.validate("networkpolicy", got, v.want.NetworkPolicy)
}

func (v *validatingSeams) ValidateSoftwareLifecycle(got SoftwareLifecycleIntent) error {
	want := SoftwareLifecycleIntent{Installation: v.want.Installation, Software: v.want.Software}
	return v.validate("softwarelifecycle", got, want)
}

func validatorsFor(validator *validatingSeams) SemanticValidators {
	return SemanticValidators{ConnectionProfiles: validator, Subscription: validator, Cloudflare: validator, Certificates: validator, NetworkPolicy: validator, SoftwareLifecycle: validator}
}

func serviceMaterialsFor(candidate DesiredState) ServiceMaterials {
	return expectedServiceMaterials(candidate)
}
