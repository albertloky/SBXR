package softwarelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	lifecyclecontract "github.com/albertloky/SBXR/internal/softwarelifecycle/contract"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type installCandidateClock struct{ now time.Time }

func (clock installCandidateClock) Now() time.Time { return clock.now }

func TestInstallCandidateSuppliesOnlyQualifiedFreshCertificateCapability(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	module := certificatelifecycle.NewForFreshInstallation(controlledInstallCandidate(), installCandidateClock{now})
	view := module.View(t.Context(), certificatelifecycle.ViewRequest{
		SelectedIP: "192.0.2.10", DirectHostname: "direct.example.com", QualifiedAddresses: []string{"192.0.2.10"},
		HTTP01: certificatelifecycle.HTTP01Prerequisites{AddressQualified: true, RouteReachable: true, Port80Available: true, TimeSynchronized: true, FirewallOwned: true},
		DNS:    certificatelifecycle.DNSFacts{Status: certificatelifecycle.DNSAvailable, Hostname: "direct.example.com", Addresses: []string{"192.0.2.10"}, DNSOnly: true},
		CAA:    certificatelifecycle.CAAFacts{Status: certificatelifecycle.CAAAvailable},
	})
	if view.Health.Outcome != certificatelifecycle.Healthy || !view.Issuer.Qualified || !view.Scheduler.Qualified || view.IP.Valid || view.Domain.Valid || !view.IP.Due || !view.Domain.Due {
		t.Fatalf("fresh candidate certificate View = %+v", view)
	}
	if unavailable := certificatelifecycle.NewForFreshInstallation(InstallCandidate{}, installCandidateClock{now}).View(t.Context(), certificatelifecycle.ViewRequest{SelectedIP: "192.0.2.10", DirectHostname: "direct.example.com"}); unavailable.Health.Outcome == certificatelifecycle.Healthy {
		t.Fatal("invalid candidate supplied certificate capability")
	}
}

func TestInstallCandidateSuppliesOnlyQualifiedProxyCoreExecutables(t *testing.T) {
	request := InstallPlanRequest{Candidate: controlledInstallCandidate()}
	for _, name := range []string{"xray", "sing-box"} {
		body, version, ok := request.Candidate.QualifiedComponent(name)
		if !ok || len(body) == 0 || version == "" {
			t.Fatalf("QualifiedComponent(%q) = (%d bytes, %q, %v)", name, len(body), version, ok)
		}
	}
	if body, version, ok := request.Candidate.QualifiedComponent("cloudflared"); ok || len(body) != 0 || version != "" {
		t.Fatalf("unapproved component escaped: %d bytes, %q, %v", len(body), version, ok)
	}
}

type installNetworkAdapter struct{ observed networkpolicy.Observations }

func (adapter installNetworkAdapter) Observe(networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	return adapter.observed, nil
}

type controlledInstallApproval struct {
	recheck InstallRecheck
	err     error
	calls   int
}

func (approval *controlledInstallApproval) AuthorizeAndRecheck(context.Context) (InstallRecheck, error) {
	approval.calls++
	return approval.recheck, approval.err
}

type controlledInstallContribution struct{ proof InstallContributionProof }

func (c controlledInstallContribution) SoftwareLifecycleInstallContribution() lifecyclecontract.InstallContribution {
	return c.proof
}
func (c controlledInstallContribution) SoftwareLifecycleUpdateContribution() lifecyclecontract.UpdateContribution {
	return c.proof
}

func TestPlanInstallDisclosesTheCompleteReviewedFreshInstallation(t *testing.T) {
	candidate := controlledInstallCandidate()
	disk := systemchanges.DiskRequirement{PreparationBytes: 10, TemporaryBytes: 20, SnapshotBytes: 30, JournalBytes: 40, RollbackBytes: 50, OverheadBytes: 60}
	plan, finding := PlanInstall(InstallPlanRequest{
		Candidate: candidate, ChangeSet: "install-revision-1", DesiredStateSHA256: strings.Repeat("a", 64),
		Contributions: controlledInstallContributions(t, "install-revision-1", strings.Repeat("a", 64)), Disk: disk,
	})
	if finding != nil || plan == nil {
		t.Fatalf("PlanInstall() = (%+v, %+v)", plan, finding)
	}
	summary := plan.Summary()
	if summary.ReleaseIdentity != candidate.cell.staged.Identity || summary.Revision != 1 || summary.InstallationStatus != NotInstalled || summary.Result != Managed || summary.RollbackResult != NotInstalled || summary.Disk != disk || !summary.SudoAfterApproval || !summary.OneUse || !summary.SecretsMemoryOnly {
		t.Fatalf("summary = %+v", summary)
	}
	if !reflect.DeepEqual(summary.Files, []string{"/opt/sbxr/releases/v1.0.0-0123456789abcdef0123456789abcdef01234567-" + strings.Repeat("b", 64) + "/sbxr", "/usr/local/bin/sbxr", "/var/lib/sbxr", "/etc/sbxr", "/etc/systemd/system"}) {
		t.Fatalf("files = %#v", summary.Files)
	}
	if len(summary.Units) != 11 || len(summary.Profiles) != 6 || len(summary.SubscriptionRepresentations) != 7 || len(summary.Ports) == 0 || len(summary.Checks) == 0 || len(summary.Ownership) != 4 || len(summary.Cloudflare) != 1 || len(summary.Certificates) != 2 || summary.Interruption == "" || summary.Cancellation == "" || summary.Rollback == "" {
		t.Fatalf("incomplete review = %+v", summary)
	}
	rendered := fmt.Sprintf("%s %+v %#v", plan, plan, summary)
	if strings.Contains(rendered, "SECRET-INSTALL-MARKER") || !strings.Contains(rendered, "ordinary system sudo after approval") || !strings.Contains(rendered, "rollback to Not installed") {
		t.Fatalf("unsafe or incomplete rendering: %s", rendered)
	}
}

func TestPlanInstallPlacesOnlyReversibleProviderCreationBeforeReclamation(t *testing.T) {
	desired := strings.Repeat("a", 64)
	contributions := controlledInstallContributions(t, "install-revision-1", desired)
	for index, contribution := range contributions {
		controlled := contribution.(controlledInstallContribution)
		if InstallContributionName(controlled.proof.Name) != CloudflareInstallContribution {
			continue
		}
		create, err := systemchanges.NewCloudflareStep(systemchanges.CloudflareChange{Action: systemchanges.CloudflareTunnelCreate, AccountID: "account-123", TunnelName: "sbxr-main"})
		if err != nil {
			t.Fatal(err)
		}
		activate, err := systemchanges.NewStep(systemchanges.CloudflareModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
		if err != nil {
			t.Fatal(err)
		}
		controlled.proof.Steps = []systemchanges.Step{create, activate}
		contributions[index] = controlled
	}
	plan, finding := PlanInstall(InstallPlanRequest{
		Candidate: controlledInstallCandidate(), ChangeSet: "install-revision-1", DesiredStateSHA256: desired,
		Contributions: contributions, ReviewedReclamationSHA256: strings.Repeat("f", 64),
		Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1},
	})
	if finding != nil || plan == nil || len(plan.steps) < 3 || plan.steps[0].Forward() != systemchanges.CreateCloudflareResource || plan.steps[1].Owner() != systemchanges.SoftwareModule {
		t.Fatalf("reclamation install order = (%+v, %+v)", plan, finding)
	}
	for index, step := range plan.steps {
		if step.Owner() == systemchanges.CloudflareModule && step.Forward() == systemchanges.ActivatePreparedConfiguration && index < 2 {
			t.Fatalf("cloudflared activation crossed the reclamation boundary at step %d", index+1)
		}
	}
}

func TestNetworkInstallContributionAcceptsOnlyTheUnprivilegedCleanVPSReview(t *testing.T) {
	intent := networkpolicy.Intent{Revision: 1, Baseline: networkpolicy.Clean, PublicIPv4: "192.0.2.10", PrimarySubscriptionAddress: "192.0.2.10", CertificateHostname: "direct.example.com", SSHPort: 2222, SubscriptionPort: 10443, Profiles: networkpolicy.Profiles{VLESSRealityVision: networkpolicy.Profile{Enabled: true, Port: 443}, VLESSXHTTP: networkpolicy.Profile{Enabled: true, Address: "127.0.0.1", Port: 11080}, VLESSWebSocket: networkpolicy.Profile{Enabled: true, Address: "127.0.0.1", Port: 11081}, Hysteria2: networkpolicy.Profile{Enabled: true, Port: 443}, TUIC: networkpolicy.Profile{Enabled: true, Port: 8443}, AnyTLS: networkpolicy.Profile{Enabled: true, Port: 9443}}, Disk: networkpolicy.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}}
	observed := networkpolicy.Observations{Host: networkpolicy.HostFacts{UbuntuVersion: "24.04.3", UbuntuServer: true, Architecture: "amd64", Systemd: true, LogicalCPUs: 1, PhysicalRAM: 512 << 20}, PublicIPv4: []string{"192.0.2.10"}, SSH: networkpolicy.SSHFacts{DetectedPort: 2222, ServerAddress: "192.0.2.10", CurrentSessions: []string{"session"}}, Firewall: networkpolicy.FirewallFacts{SBXRTableState: "absent"}, Routes: networkpolicy.RouteFacts{IPv4: "default"}, Outbound: networkpolicy.OutboundFacts{DNS: true, GitHubHTTPS: true, GitHubAttestationHTTPS: true, CloudflareHTTPS: true, ACMEHTTPS: true, CertificateEndpointsHTTPS: true, TimeService: true, TunnelTCP7844: true, TunnelUDP7844: true}, Disk: networkpolicy.DiskFacts{FilesystemBytes: 20 << 30, AvailableBytes: 3 << 30}, Time: networkpolicy.TimeFacts{Synchronized: true, Owner: "systemd-timesyncd"}, OwnerFacts: networkpolicy.OwnerFacts{DNS: "fresh", Tunnel: "fresh"}, Certificate: networkpolicy.CertificateFacts{DNS: networkpolicy.DNSFacts{Hostname: "direct.example.com", IPv4: []string{"192.0.2.10"}}, CAA: networkpolicy.CAAFacts{Issuer: "letsencrypt.org", HTTP01Allowed: true}}, Checksums: map[string]string{"routes": "route", "listeners": "listeners"}}
	result := networkpolicy.New(installNetworkAdapter{observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PreApproval})
	contribution := NewNetworkInstallContribution(result, "install-revision-1", strings.Repeat("a", 64))
	proof := installContributionProof(contribution)
	if InstallContributionName(proof.Name) != NetworkInstallContribution || proof.Owner != systemchanges.NetworkPolicyModule || len(proof.Steps) != 1 || len(proof.Ports) != 8 || proof.Firewall == "" {
		t.Fatalf("network contribution = %+v; Network Policy = %+v", proof, result)
	}
	for index := range result.Findings {
		if result.Findings[index].Code == "NETWORK-PRIVILEGED-PENDING" {
			result.Findings[index].Code = "NETWORK-CALLER-BYPASS"
		}
	}
	if invalid := installContributionProof(NewNetworkInstallContribution(result, "install-revision-1", strings.Repeat("a", 64))); invalid.Name != "" {
		t.Fatalf("changed finding accepted = %+v", invalid)
	}
	privilegedObserved := observed
	privilegedObserved.Firewall.RootVerified = true
	privilegedResult := networkpolicy.New(installNetworkAdapter{privilegedObserved}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
	privilegedProof := installContributionProof(NewNetworkInstallContribution(privilegedResult, "install-revision-1", strings.Repeat("a", 64)))
	if !privilegedProof.Privileged || privilegedProof.StableSHA256 != proof.StableSHA256 || privilegedProof.SHA256 == proof.SHA256 {
		t.Fatalf("privileged recheck did not preserve reviewed facts: before=%+v after=%+v", proof, privilegedProof)
	}
	privilegedObserved.Listeners = append(privilegedObserved.Listeners, networkpolicy.Listener{Address: "0.0.0.0", Port: 9443, Protocol: networkpolicy.TCP, Process: "unrelated", Service: "unrelated.service", Ownership: networkpolicy.Unproved})
	changedResult := networkpolicy.New(installNetworkAdapter{privilegedObserved}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
	if changedProof := installContributionProof(NewNetworkInstallContribution(changedResult, "install-revision-1", strings.Repeat("a", 64))); changedProof.Name != "" {
		t.Fatalf("changed listener accepted: result=%+v proof=%+v", changedResult, changedProof)
	}
}

func TestPlanInstallRefusesMissingChangedOrCallerInventedInputs(t *testing.T) {
	const secret = "SECRET-INSTALL-MARKER"
	desired := strings.Repeat("a", 64)
	valid := func() InstallPlanRequest {
		return InstallPlanRequest{Candidate: controlledInstallCandidate(), ChangeSet: "install-revision-1", DesiredStateSHA256: desired, Contributions: controlledInstallContributions(t, "install-revision-1", desired), Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}}
	}
	tests := []struct {
		name   string
		change func(*InstallPlanRequest)
	}{
		{"missing candidate", func(r *InstallPlanRequest) { r.Candidate = InstallCandidate{} }},
		{"wrong change set", func(r *InstallPlanRequest) { r.ChangeSet = "../unsafe" }},
		{"wrong state checksum", func(r *InstallPlanRequest) { r.DesiredStateSHA256 = strings.Repeat("A", 64) }},
		{"missing disk category", func(r *InstallPlanRequest) { r.Disk.RollbackBytes = 0 }},
		{"missing contribution", func(r *InstallPlanRequest) { r.Contributions = r.Contributions[:5] }},
		{"duplicate contribution", func(r *InstallPlanRequest) { r.Contributions[5] = r.Contributions[0] }},
		{"changed contribution state", func(r *InstallPlanRequest) {
			proof := installContributionProof(r.Contributions[0])
			proof.DesiredStateSHA256 = strings.Repeat("c", 64)
			r.Contributions[0] = controlledInstallContribution{proof}
		}},
		{"caller invented module", func(r *InstallPlanRequest) {
			proof := installContributionProof(r.Contributions[0])
			proof.Name, proof.Owner = "Backup", systemchanges.StateModule
			r.Contributions[0] = controlledInstallContribution{proof}
		}},
		{"secret-like identity", func(r *InstallPlanRequest) {
			proof := installContributionProof(r.Contributions[0])
			proof.Identity = secret
			r.Contributions[0] = controlledInstallContribution{proof}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid()
			test.change(&request)
			plan, finding := PlanInstall(request)
			if plan != nil || finding == nil || finding.Code != InstallPlanRefused || strings.Contains(fmt.Sprintf("%+v", finding), secret) {
				t.Fatalf("PlanInstall() = (%+v, %+v)", plan, finding)
			}
		})
	}
}

func TestInstallCertificateContributionAllowsOnlyItsExactCrossModuleEffects(t *testing.T) {
	if !validInstallContributionOwner(IPCertificateInstallContribution, systemchanges.CertificateModule, systemchanges.NetworkPolicyModule) || !validInstallContributionOwner(DomainCertificateInstallContribution, systemchanges.CertificateModule, systemchanges.ConnectionProfilesModule) {
		t.Fatal("required certificate installation effects were refused")
	}
	for _, owner := range []systemchanges.Module{systemchanges.StateModule, systemchanges.SoftwareModule, systemchanges.CloudflareModule} {
		if validInstallContributionOwner(DomainCertificateInstallContribution, systemchanges.CertificateModule, owner) {
			t.Fatalf("unowned certificate installation effect %q accepted", owner)
		}
	}
}

func TestApplyInstallRequestsApprovalOnceThenRejectsEveryChangedFact(t *testing.T) {
	desired := strings.Repeat("a", 64)
	request := InstallPlanRequest{Candidate: controlledInstallCandidate(), ChangeSet: "install-revision-1", DesiredStateSHA256: desired, Contributions: controlledInstallContributions(t, "install-revision-1", desired), Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}}
	plan, finding := PlanInstall(request)
	if finding != nil {
		t.Fatal(finding)
	}
	rechecked := controlledInstallContributions(t, request.ChangeSet, desired)
	network := installContributionProof(rechecked[0])
	network.Privileged = true
	network.SHA256 = strings.Repeat("f", 64)
	rechecked[0] = controlledInstallContribution{network}
	approval := &controlledInstallApproval{recheck: InstallRecheck{Candidate: request.Candidate, Contributions: rechecked, PrivilegedNetworkHealthy: true}}
	changed := append([]InstallContribution(nil), rechecked...)
	proof := installContributionProof(changed[1])
	proof.StableSHA256 = strings.Repeat("e", 64)
	changed[1] = controlledInstallContribution{proof}
	approval.recheck.Contributions = changed
	result := plan.Apply(t.Context(), InstallApplyRequest{Approval: approval})
	if approval.calls != 1 || result.Outcome != systemchanges.Refused || !result.NothingChanged || !result.PlanConsumed || result.Finding == nil || result.Finding.Code != "SOFTWARE-LIFECYCLE-INSTALL-STALE" {
		t.Fatalf("Apply() = %+v; approval calls=%d", result, approval.calls)
	}
	if repeated := plan.Apply(t.Context(), InstallApplyRequest{Approval: approval}); repeated.Finding == nil || repeated.Finding.Code != "SOFTWARE-LIFECYCLE-INSTALL-PLAN-USED" || approval.calls != 1 {
		t.Fatalf("repeated Apply() = %+v; approval calls=%d", repeated, approval.calls)
	}
}

func TestApplyInstallDeniesOrDiscardsApprovalWithoutLeakingSecrets(t *testing.T) {
	request := InstallPlanRequest{Candidate: controlledInstallCandidate(), ChangeSet: "install-revision-2", DesiredStateSHA256: strings.Repeat("a", 64), Contributions: controlledInstallContributions(t, "install-revision-2", strings.Repeat("a", 64)), Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}}
	plan, _ := PlanInstall(request)
	approval := &controlledInstallApproval{err: errors.New("SECRET-INSTALL-MARKER")}
	result := plan.Apply(t.Context(), InstallApplyRequest{Approval: approval})
	if result.Finding == nil || result.Finding.Code != "SOFTWARE-LIFECYCLE-INSTALL-APPROVAL" || !result.NothingChanged || strings.Contains(fmt.Sprintf("%+v", result), "SECRET-INSTALL-MARKER") {
		t.Fatalf("approval refusal = %+v", result)
	}
}

func TestInstallCandidateHandoffRebuildsOnlyTheExactReviewedBytes(t *testing.T) {
	candidate := controlledInstallCandidate()
	handoff, ok := candidate.InstallHandoff()
	if !ok {
		t.Fatal("verified candidate handoff unavailable")
	}
	stager := &handoffStager{staged: candidate.cell.staged}
	rebuilt, err := RebuildInstallCandidate(t.Context(), handoff, stager)
	if err != nil || !sameInstallCandidate(candidate, rebuilt) || stager.calls != 1 {
		t.Fatalf("RebuildInstallCandidate() = (%+v, %v), calls=%d", rebuilt, err, stager.calls)
	}
	handoff.ApplicationArchive[0] ^= 1
	if _, err := RebuildInstallCandidate(t.Context(), handoff, stager); err == nil {
		t.Fatal("changed reviewed application bytes accepted")
	}
}

type handoffStager struct {
	staged StagedRelease
	calls  int
}

func (stager *handoffStager) Stage(_ context.Context, request StageRequest) (StagedRelease, error) {
	stager.calls++
	if !request.Authenticated() {
		return StagedRelease{}, errors.New("unauthenticated handoff")
	}
	return stager.staged, nil
}

func controlledInstallCandidate() InstallCandidate {
	identity := ReleaseIdentity{Repository: Repository, Tag: "v1.0.0", Commit: "0123456789abcdef0123456789abcdef01234567", IndexSHA256: strings.Repeat("b", 64)}
	files := componentFixtureFiles()
	manifest, _ := NewComponentManifest(AMD64, "5.4.0", files)
	components, _ := BuildComponentArchive(manifest, files)
	componentDigest := sha256.Sum256(components)
	application := []byte("authenticated archive")
	applicationDigest := sha256.Sum256(application)
	staged := StagedRelease{Identity: identity, Build: EmbeddedBuildIdentity{Repository: Repository, Tag: identity.Tag, Commit: identity.Commit, PayloadSHA256: strings.Repeat("c", 64)}, Architecture: AMD64, ExecutableSHA256: strings.Repeat("d", 64), ComponentsSHA256: hex.EncodeToString(componentDigest[:]), InstallPath: ReleaseInstallPath(identity), StateSchema: 2}
	verified := VerifiedRelease{Identity: identity, Version: "1.0.0", Sequence: 1, StateSchema: 2, MinimumUpdaterSchema: 1, Assets: []AssetProof{{Role: ApplicationAMD64, Name: "sbxr-linux-amd64.tar.gz", Size: int64(len(application)), SHA256: hex.EncodeToString(applicationDigest[:])}, {Role: ComponentsAMD64, Name: "sbxr-components-linux-amd64.tar.gz", Size: int64(len(components)), SHA256: hex.EncodeToString(componentDigest[:])}}}
	return InstallCandidate{cell: &installCandidateCell{verified: verified, staged: staged, archive: application, components: components}}
}

func controlledInstallContributions(t *testing.T, changeSet, desired string) []InstallContribution {
	t.Helper()
	names := []struct {
		name  InstallContributionName
		owner systemchanges.Module
	}{
		{NetworkInstallContribution, systemchanges.NetworkPolicyModule},
		{ProfilesInstallContribution, systemchanges.ConnectionProfilesModule},
		{CloudflareInstallContribution, systemchanges.CloudflareModule},
		{IPCertificateInstallContribution, systemchanges.CertificateModule},
		{DomainCertificateInstallContribution, systemchanges.CertificateModule},
		{SubscriptionInstallContribution, systemchanges.SubscriptionModule},
	}
	result := make([]InstallContribution, 0, len(names))
	for index, value := range names {
		step, err := systemchanges.NewStep(value.owner, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
		if value.owner == systemchanges.NetworkPolicyModule {
			step, err = systemchanges.NewFirewallPolicyStep("table inet sbxr {\n chain input {\n  type filter hook input priority filter\n  policy drop\n  tcp dport 2222 accept\n }\n}", 2222)
		}
		if err != nil {
			t.Fatal(err)
		}
		checks := []systemchanges.Check{
			{Owner: value.owner, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: fmt.Sprintf("INSTALL-%02d-PRE", index)},
			{Owner: value.owner, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: fmt.Sprintf("INSTALL-%02d-POST", index)},
		}
		proof := InstallContributionProof{Name: string(value.name), Owner: value.owner, Identity: fmt.Sprintf("component-plan-%d", index), SHA256: strings.Repeat(fmt.Sprintf("%x", index+1), 64), StableSHA256: strings.Repeat(fmt.Sprintf("%x", index+6), 64), ChangeSet: changeSet, DesiredStateSHA256: desired, Steps: []systemchanges.Step{step}, Checks: checks, Details: []string{string(value.name) + " exact install effects"}}
		if value.owner == systemchanges.NetworkPolicyModule {
			proof.Ports = []string{"SSH preservation: public 2222/TCP", "VLESS REALITY Vision: public 443/TCP"}
			proof.Firewall = "replace only table inet sbxr; preserve SSH on 2222/TCP"
		}
		result = append(result, controlledInstallContribution{proof})
	}
	return result
}

func installContributionProof(contribution InstallContribution) InstallContributionProof {
	return contribution.SoftwareLifecycleInstallContribution()
}
