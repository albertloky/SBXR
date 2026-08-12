package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
)

func TestComposedInstallBuildsAndPreparesTheCompleteRevisionOnePlan(t *testing.T) {
	request := composedInstallRequest(t)
	cloudflareAPI := composedCloudflareAPI{}
	cloudflareModule := cloudflaretunnel.New(cloudflareAPI, composedClock{})
	networkModule := networkpolicy.New(composedNetworkObserver{})
	built, err := buildInstallWith(t.Context(), request, installBuildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network:    networkModule.Evaluate,
		cloudflare: cloudflareModule.Plan,
		random:     newInstallEntropyReader(request.Entropy),
		inventory:  cloudflareAPI,
	})
	if err != nil {
		t.Fatal(err)
	}
	summary := built.plan.Summary()
	if summary.Revision != 1 || summary.InstallationStatus != softwarelifecycle.NotInstalled || summary.Result != softwarelifecycle.Managed || len(summary.Units) != 11 || len(summary.Profiles) != 6 || len(summary.SubscriptionRepresentations) != 7 || len(summary.Certificates) != 2 {
		t.Fatalf("incomplete composed install summary: %+v", summary)
	}
	prepared, err := built.prepareState(state.New(absentInstallState{}))
	if err != nil || prepared == nil {
		t.Fatalf("prepareState() = (%+v, %v)", prepared, err)
	}
	rendered := fmt.Sprintf("%+v %+v %+v", built.plan, built.wiring, prepared)
	for _, marker := range []string{request.CloudflareToken, hex.EncodeToString(request.Entropy), "COMPOSED-INSTALL-SECRET-MARKER"} {
		if strings.Contains(rendered, marker) {
			t.Fatalf("composed installation evidence exposed protected marker %q", marker)
		}
	}
}

func TestComposedInstallRoutesAReclaimableVPSToReviewBeforeProviderPlanning(t *testing.T) {
	request := composedInstallRequest(t)
	plan := &networkpolicy.ReclamationPlan{Digest: strings.Repeat("f", 64), Targets: []string{"executable /usr/local/bin/xray"}}
	providerCalled := false
	_, err := buildInstallWith(t.Context(), request, installBuildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network: func(networkpolicy.Request) networkpolicy.Result {
			return networkpolicy.Result{InstallationClass: networkpolicy.ReclaimableVPS, Reclamation: plan}
		},
		cloudflare: func(context.Context, cloudflaretunnel.PlanRequest) cloudflaretunnel.PlanResult {
			providerCalled = true
			return cloudflaretunnel.PlanResult{}
		},
		random:    newInstallEntropyReader(request.Entropy),
		inventory: composedCloudflareAPI{},
	})
	var review *reclamationReviewError
	if !errors.As(err, &review) || review.plan != plan || providerCalled {
		t.Fatalf("reclaimable routing = error %v review %+v provider-called %t", err, review, providerCalled)
	}
}

func TestComposedInstallCarriesTheExactReviewedStandaloneTargetIntoOneInstallPlan(t *testing.T) {
	request := composedInstallRequest(t)
	cloudflareAPI := composedCloudflareAPI{}
	cloudflareModule := cloudflaretunnel.New(cloudflareAPI, composedClock{})
	networkModule := networkpolicy.New(composedReclamationObserver{})
	dependencies := installBuildDependencies{stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
		return request.Candidate.Staged, nil
	}, network: networkModule.Evaluate, cloudflare: cloudflareModule.Plan, random: newInstallEntropyReader(request.Entropy), inventory: cloudflareAPI}
	_, err := buildInstallWith(t.Context(), request, dependencies)
	var review *reclamationReviewError
	if !errors.As(err, &review) || review.plan == nil {
		t.Fatalf("initial reclamation review = %v", err)
	}
	request.ReviewedReclamationSHA256 = review.plan.Digest
	built, err := buildInstallWith(t.Context(), request, dependencies)
	if err != nil || built == nil || built.plan == nil || built.plan.Summary().Result != softwarelifecycle.Managed {
		t.Fatalf("reviewed reclamation install = (%+v, %v)", built, err)
	}
	recheck, _, err := recheckInstall(t.Context(), request, built)
	if err != nil || recheck.Reclamation == nil {
		t.Fatalf("privileged reclamation recheck = (%+v, %v)", recheck, err)
	}
	kind, path, digest, _, processID, reviewDigest, valid := recheck.Reclamation.SystemChangesReclamation()
	if !valid || kind != "executable" || path != "/opt/standalone/proxy" || digest != strings.Repeat("9", 64) || processID != "4242" || reviewDigest != request.ReviewedReclamationSHA256 {
		t.Fatalf("reclamation Apply authority = (%q, %q, %q, %q, %q, %t)", kind, path, digest, processID, reviewDigest, valid)
	}
}

func TestComposedInstallRefusesAnIncompleteReclaimableInventory(t *testing.T) {
	request := composedInstallRequest(t)
	providerCalled := false
	module := networkpolicy.New(incompleteReclamationObserver{})
	_, err := buildInstallWith(t.Context(), request, installBuildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network: module.Evaluate,
		cloudflare: func(context.Context, cloudflaretunnel.PlanRequest) cloudflaretunnel.PlanResult {
			providerCalled = true
			return cloudflaretunnel.PlanResult{}
		},
		random: newInstallEntropyReader(request.Entropy), inventory: composedCloudflareAPI{},
	})
	if err == nil || providerCalled {
		t.Fatalf("incomplete reclamation inventory continued: error %v provider-called %t", err, providerCalled)
	}
}

func TestReclamationInventoryBindsExactCloudflareConflictIdentifiers(t *testing.T) {
	token, err := cloudflaretunnel.NewManagementToken("cfat_COMPOSED-INSTALL-SECRET-MARKER-000000000")
	if err != nil {
		t.Fatal(err)
	}
	facts, err := observeReclamationCloudflare(t.Context(), conflictInventoryAPI{}, strings.Repeat("a", 32), strings.Repeat("b", 32), token, "sbxr-main", []string{"xhttp.example.com", "ws.example.com"})
	if err != nil || len(facts.Conflicts) != 3 || facts.Conflicts[0].ID != "11111111-1111-4111-8111-111111111111" || facts.Conflicts[1].Name != "xhttp.example.com" || facts.Conflicts[2].Name != "ws.example.com" {
		t.Fatalf("Cloudflare reclamation facts = %+v error %v", facts, err)
	}
}

type conflictInventoryAPI struct{}

func (conflictInventoryAPI) ObserveMutation(_ context.Context, request cloudflaretunnel.MutationRequest) (cloudflaretunnel.MutationObservation, error) {
	return cloudflaretunnel.MutationObservation{Tunnels: []cloudflaretunnel.OwnedResource{{ID: "11111111-1111-4111-8111-111111111111", Name: "sbxr-main"}}, DNSRecords: []cloudflaretunnel.OwnedResource{{ID: strings.Repeat("d", 32), Name: request.Hostname}}}, nil
}

func composedInstallRequest(t *testing.T) softwareubuntu.InstallHandoffRequest {
	t.Helper()
	application := []byte("authenticated application archive")
	componentFiles := map[string][]byte{
		"xray": []byte("#!/bin/sh\nexit 0\n"), "sing-box": []byte("#!/bin/sh\nexit 0\n"), "cloudflared": []byte("#!/bin/sh\nexit 0\n"),
		"certbot/bin/certbot": softwarelifecycle.ComponentCertbotLauncher(), "certbot/pyvenv.cfg": []byte("home = /usr/bin\nversion = 3.12\n"),
		"certbot/lib/python3.12/site-packages/certbot/__init__.py": []byte("__version__ = '5.4.0'\n"),
	}
	manifest, err := softwarelifecycle.NewComponentManifest(softwarelifecycle.AMD64, "5.4.0", componentFiles)
	if err != nil {
		t.Fatal(err)
	}
	components, err := softwarelifecycle.BuildComponentArchive(manifest, componentFiles)
	if err != nil {
		t.Fatal(err)
	}
	applicationDigest, componentDigest := sha256.Sum256(application), sha256.Sum256(components)
	identity := softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: strings.Repeat("1", 40), IndexSHA256: strings.Repeat("2", 64)}
	applicationAsset := softwarelifecycle.AssetProof{Role: softwarelifecycle.ApplicationAMD64, Name: "sbxr-linux-amd64.tar.gz", Size: int64(len(application)), SHA256: hex.EncodeToString(applicationDigest[:])}
	componentAsset := softwarelifecycle.AssetProof{Role: softwarelifecycle.ComponentsAMD64, Name: "sbxr-components-linux-amd64.tar.gz", Size: int64(len(components)), SHA256: hex.EncodeToString(componentDigest[:])}
	verified := softwarelifecycle.VerifiedRelease{Identity: identity, Version: "1.0.0", Sequence: 1, StateSchema: 2, MinimumUpdaterSchema: 1, Assets: []softwarelifecycle.AssetProof{applicationAsset, componentAsset}}
	staged := softwarelifecycle.StagedRelease{Identity: identity, Build: softwarelifecycle.EmbeddedBuildIdentity{Repository: identity.Repository, Tag: identity.Tag, Commit: identity.Commit, PayloadSHA256: strings.Repeat("3", 64)}, Architecture: softwarelifecycle.AMD64, ExecutableSHA256: strings.Repeat("4", 64), ComponentsSHA256: componentAsset.SHA256, InstallPath: softwarelifecycle.ReleaseInstallPath(identity), StateSchema: 2}
	return softwareubuntu.InstallHandoffRequest{
		Schema: 1, Session: strings.Repeat("a", 64), Tag: identity.Tag, Architecture: softwarelifecycle.AMD64,
		Draft:               softwarelifecycle.InstallationDraft{Domain: "example.com", OwnerEmail: "owner@example.com", PublicIPv4: "192.0.2.10", PrimaryAddress: "192.0.2.10", SSHPort: 22, RealityPort: 443, Hysteria2Port: 443, TUICPort: 8443, AnyTLSPort: 9443, SubscriptionPort: 10443},
		CloudflareAccountID: strings.Repeat("b", 32), CloudflareZoneID: strings.Repeat("c", 32), CloudflareToken: "cfat_COMPOSED-INSTALL-SECRET-MARKER-000000000", RealityTarget: "www.microsoft.com:443", RealityServerName: "www.microsoft.com", Entropy: bytes.Repeat([]byte{0x42}, 32),
		Candidate: softwarelifecycle.InstallCandidateHandoff{Verified: verified, Staged: staged, ApplicationAsset: applicationAsset, ComponentAsset: componentAsset, ApplicationArchive: application, ComponentArchive: components},
	}
}

type composedNetworkObserver struct{}

func (composedNetworkObserver) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	return networkpolicy.Observations{
		Host:       networkpolicy.HostFacts{UbuntuVersion: "24.04.3", UbuntuServer: true, Architecture: "amd64", Systemd: true, LogicalCPUs: 1, PhysicalRAM: 1024 << 20},
		PublicIPv4: []string{"192.0.2.10"}, SSH: networkpolicy.SSHFacts{DetectedPort: 22, ServerAddress: "192.0.2.10", CurrentSessions: []string{"session-1"}}, Firewall: networkpolicy.FirewallFacts{SBXRTableState: "absent", RootVerified: request.Stage == networkpolicy.PostApproval}, Routes: networkpolicy.RouteFacts{IPv4: "default via 192.0.2.1"},
		Outbound: networkpolicy.OutboundFacts{DNS: true, GitHubHTTPS: true, GitHubAttestationHTTPS: true, CloudflareHTTPS: true, ACMEHTTPS: true, CertificateEndpointsHTTPS: true, TimeService: true, TunnelTCP7844: true, TunnelUDP7844: true},
		Disk:     networkpolicy.DiskFacts{FilesystemBytes: 20 << 30, AvailableBytes: 3 << 30}, Time: networkpolicy.TimeFacts{Synchronized: true, Owner: "systemd-timesyncd"}, OwnerFacts: networkpolicy.OwnerFacts{DNS: "fresh", Tunnel: "fresh"},
		Certificate: networkpolicy.CertificateFacts{DNS: networkpolicy.DNSFacts{Hostname: "direct.example.com"}, CAA: networkpolicy.CAAFacts{Issuer: "letsencrypt.org", HTTP01Allowed: true}}, Checksums: map[string]string{"sshd_config": "sha256:ssh", "nftables": "sha256:nft"},
		ReclamationComplete: true,
	}, nil
}

type incompleteReclamationObserver struct{ composedNetworkObserver }

func (incompleteReclamationObserver) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	observed, err := (composedNetworkObserver{}).Observe(request)
	observed.Reclamation.Docker = &networkpolicy.DockerConflict{Service: "docker.service", Status: "unknown"}
	observed.ReclamationComplete = false
	return observed, err
}

type composedReclamationObserver struct{ composedNetworkObserver }

func (composedReclamationObserver) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	observed, err := (composedNetworkObserver{}).Observe(request)
	observed.Listeners = append(observed.Listeners, networkpolicy.Listener{Address: "0.0.0.0", Port: 443, Protocol: networkpolicy.TCP, Process: "standalone-proxy", Executable: "/opt/standalone/proxy", ProcessID: "4242"})
	observed.Reclamation.Executables = []networkpolicy.FileConflict{{Path: "/opt/standalone/proxy", SHA256: strings.Repeat("9", 64), Process: "standalone-proxy", ProcessID: "4242", Mode: 0o755, Links: 1}}
	return observed, err
}

type composedCloudflareAPI struct{}

func (composedCloudflareAPI) Observe(context.Context, cloudflaretunnel.ObservationRequest) (cloudflaretunnel.Observation, error) {
	account, zone := strings.Repeat("b", 32), strings.Repeat("c", 32)
	return cloudflaretunnel.Observation{Account: cloudflaretunnel.AccountObservation{ID: account}, Zone: cloudflaretunnel.ZoneObservation{ID: zone, AccountID: account, Name: "example.com", Status: "active", AssignedNameServers: []string{"a.ns.cloudflare.com"}, ObservedNameServers: []string{"a.ns.cloudflare.com"}}, Token: cloudflaretunnel.TokenObservation{ID: strings.Repeat("d", 32), Status: "active"}, Policies: []cloudflaretunnel.TokenPolicy{{Effect: "allow", PermissionGroups: []string{"Account API Tokens Read", "Cloudflare Tunnel Edit"}, Resources: map[string]string{"com.cloudflare.api.account." + account: "*"}}, {Effect: "allow", PermissionGroups: []string{"DNS Write"}, Resources: map[string]string{"com.cloudflare.api.account.zone." + zone: "*"}}}}, nil
}

func (composedCloudflareAPI) ObserveMutation(context.Context, cloudflaretunnel.MutationRequest) (cloudflaretunnel.MutationObservation, error) {
	return cloudflaretunnel.MutationObservation{Digest: strings.Repeat("e", 64)}, nil
}

type composedClock struct{}

func (composedClock) Now() time.Time                             { return time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC) }
func (composedClock) Sleep(context.Context, time.Duration) error { return nil }

type absentInstallState struct{}

func (absentInstallState) Read() ([]byte, error) { return nil, fs.ErrNotExist }
func (absentInstallState) Publish([]byte, []byte, string) ([]byte, error) {
	return nil, errors.New("unexpected publication")
}
