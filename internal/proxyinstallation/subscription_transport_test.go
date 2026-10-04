package proxyinstallation

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type migrationTestHost struct {
	*controlledHost
	retired                                          hostadapter.HTTPSRetirementAuthority
	migrations                                       int
	failRuntime, failFinal, lateFinal, retiredUnsafe bool
}

func (h *migrationTestHost) ReadOwnership(path string) ([]byte, error) {
	if path != hostSetupSpec.OwnershipPath && path != hostSetupSpec.OwnershipNextPath {
		return nil, os.ErrNotExist
	}
	return h.controlledHost.ReadOwnership(path)
}
func (h *migrationTestHost) HTTPMigrationExecutable() bool { return true }
func (h *migrationTestHost) SnapshotHTTPSRetirement(hostadapter.ServingAuthority, hostadapter.RenewalAuthority, hostadapter.SubscriptionResourceAuthority, *hostadapter.RenewalExclusion) (hostadapter.HTTPSRetirementAuthority, bool) {
	return h.retired, true
}
func (h *migrationTestHost) AcquireHTTPSRetirementExclusion(hostadapter.HTTPSRetirementAuthority, bool) (*hostadapter.RenewalExclusion, bool) {
	return &hostadapter.RenewalExclusion{}, true
}
func (h *migrationTestHost) InspectHTTPSRetirement(hostadapter.HTTPSRetirementAuthority, bool) bool {
	return !h.retiredUnsafe
}
func (h *migrationTestHost) DiscardHTTPMigrationPublication(current, next []byte) bool {
	if !bytes.Equal(current, h.ownership) || !bytes.HasPrefix(next, h.stagedOwnership) {
		return false
	}
	h.stagedOwnership = nil
	return true
}
func (h *migrationTestHost) InspectRunning(ctx context.Context, spec hostadapter.SetupSpec, source, ownership []byte, digest, ip string) hostadapter.RunningInspection {
	facts := h.controlledHost.InspectRunning(ctx, spec, source, ownership, digest, ip)
	facts.TransactionFilesAbsent = hostadapter.Observation{Observed: true, Accepted: h.stagedOwnership == nil}
	return facts
}
func (h *migrationTestHost) MigrateHTTPSRetirement(context.Context, hostadapter.HTTPSRetirementAuthority, hostadapter.ServingAuthority, *hostadapter.RenewalExclusion) bool {
	r, ok := decodeOwnership(h.ownership)
	if !ok || !r.TransportMigrating || h.stagedOwnership != nil {
		return false
	}
	h.migrations++
	return !h.failRuntime
}
func (h *migrationTestHost) PublishOwnership(path, nextPath string, current, next []byte) error {
	r, ok := decodeOwnership(next)
	if ok && r.HTTPSRetirement != nil && !r.TransportMigrating && h.failFinal {
		h.failFinal = false
		if h.lateFinal {
			h.ownership = bytes.Clone(next)
		} else {
			h.stagedOwnership = bytes.Clone(next)
		}
		return errors.New("interrupted final publication")
	}
	return h.controlledHost.PublishOwnership(path, nextPath, current, next)
}

func migrationInstallation(t *testing.T) *migrationTestHost {
	t.Helper()
	_, host := enabledIdentityInstallation(t)
	r, ok := decodeOwnership(host.ownership)
	if !ok {
		t.Fatal("fixture authority")
	}
	r.Serving.HTTP = false
	r.Serving.CertificateGeneration = 1
	for i := range r.Serving.CertificateSHA256 {
		r.Serving.CertificateSHA256[i] = strings.Repeat(string(rune('a'+i)), 64)
	}
	renewal := hostadapter.RenewalAuthority{RecorderID: strings.Repeat("a", 32), Lineage: "sbxr-subscription", PublicIPv4: r.PublicIPv4, Invocation: hostadapter.OfficialRenewalInvocation}
	resources := hostadapter.SubscriptionResourcesForEnablement(r.PublicIPv4, hostadapter.SubscriptionPreflight{})
	r.Renewal, r.SubscriptionResources = &renewal, &resources
	updateSubscriptionResources(&r, r.Release)
	host.ownership = ownershipBytes(r)
	retired := hostadapter.HTTPSRetirementAuthority{Serving: *r.Serving, Renewal: renewal, Resources: resources, ConfigurationMode: 0600, ConfigurationSHA256: strings.Repeat("e", 64), EvidenceSHA256: strings.Repeat("f", 64)}
	if !retired.Valid() {
		t.Fatal("retirement fixture")
	}
	return &migrationTestHost{controlledHost: host, retired: retired}
}

func migrationSelectedRecord(t *testing.T, h *migrationTestHost) ownershipRecord {
	t.Helper()
	r, ok := decodeOwnership(h.ownership)
	if !ok {
		t.Fatal("fixture record")
	}
	serving := hostadapter.ServingAuthority{HTTP: true, LinkID: r.Serving.LinkID, CredentialSHA256: r.Serving.CredentialSHA256}
	resources := hostadapter.SubscriptionResourcesForEnablement(r.PublicIPv4, hostadapter.SubscriptionPreflight{HTTP: true})
	r.Serving, r.Renewal, r.SubscriptionResources = &serving, nil, &resources
	r.HTTPSRetirement, r.TransportMigrating = &h.retired, true
	updateSubscriptionResources(&r, testInstalledIdentity())
	return r
}

func TestHTTPMigrationResumesExactStagedOwnershipAndProtectsGenericOutput(t *testing.T) {
	for _, checkpoint := range []string{"initial publication", "initial partial publication", "initial empty publication", "final publication", "final partial publication", "final empty publication", "final rename before sync", "runtime interruption"} {
		t.Run(checkpoint, func(t *testing.T) {
			h := migrationInstallation(t)
			original, _ := decodeOwnership(h.ownership)
			historical := testInstalledIdentity()
			historical.Tag, historical.Commit = "v3.0.21", strings.Repeat("5", 40)
			for i, resource := range original.Resources {
				if strings.HasPrefix(resource, hostadapter.RenewalEvidencePath+" ") {
					original.ResourceCreatingReleases[i] = historical
				}
			}
			h.ownership = ownershipBytes(original)
			configuration := bytes.Clone(h.configuration)
			operations := len(h.operations)
			selected := migrationSelectedRecord(t, h)
			switch checkpoint {
			case "initial publication", "initial partial publication", "initial empty publication":
				h.stagedOwnership = ownershipBytes(selected)
				if checkpoint == "initial partial publication" {
					h.stagedOwnership = h.stagedOwnership[:len(h.stagedOwnership)/2]
				} else if checkpoint == "initial empty publication" {
					h.stagedOwnership = []byte{}
				}
			case "final publication", "final partial publication", "final empty publication":
				h.ownership = ownershipBytes(selected)
				selected.TransportMigrating = false
				updateSubscriptionResources(&selected, testInstalledIdentity())
				h.stagedOwnership = ownershipBytes(selected)
				if checkpoint == "final partial publication" {
					h.stagedOwnership = h.stagedOwnership[:len(h.stagedOwnership)/2]
				} else if checkpoint == "final empty publication" {
					h.stagedOwnership = []byte{}
				}
			case "final rename before sync":
				h.failFinal, h.lateFinal = true, true
			case "runtime interruption":
				h.failRuntime = true
				if _, ok := migrateLegacyHTTPSubscription(t.Context(), h, testInstalledIdentity(), &softwarelifecycle.MutationLockAuthority{}); ok {
					t.Fatal("interruption accepted")
				}
				h.failRuntime = false
			}
			message, ok := migrateLegacyHTTPSubscription(t.Context(), h, testInstalledIdentity(), &softwarelifecycle.MutationLockAuthority{})
			if !ok {
				t.Fatal(message)
			}
			r, valid := decodeOwnership(h.ownership)
			if !valid || r.TransportMigrating || r.HTTPSRetirement == nil || !r.Serving.HTTP || r.Serving.LinkID != original.Serving.LinkID || r.Serving.CredentialSHA256 != original.Serving.CredentialSHA256 || r.ConfigurationSHA256 != original.ConfigurationSHA256 || h.stagedOwnership != nil || !bytes.Equal(configuration, h.configuration) || len(h.operations) != operations {
				t.Fatal("migration lost exact credentials, proxy state or recovery authority")
			}
			for i, resource := range r.Resources {
				if strings.HasPrefix(resource, hostadapter.RenewalEvidencePath+" ") && r.ResourceCreatingReleases[i] != historical {
					t.Fatal("unchanged evidence lost its historical creator")
				}
			}
			if bytes.Contains([]byte(message), h.subscriptionCredential) || strings.Contains(message, "http://") || !strings.Contains(message, "confirmed View details") {
				t.Fatal("generic completion exposed bearer link")
			}
		})
	}
}

func TestHTTPMigrationRefusesForeignStagedAuthorityBeforeEffects(t *testing.T) {
	h := migrationInstallation(t)
	original := bytes.Clone(h.ownership)
	selected := migrationSelectedRecord(t, h)
	selected.SubscriptionCompromised = true
	h.stagedOwnership = ownershipBytes(selected)
	if _, ok := migrateLegacyHTTPSubscription(t.Context(), h, testInstalledIdentity(), &softwarelifecycle.MutationLockAuthority{}); ok || h.migrations != 0 || !bytes.Equal(original, h.ownership) || h.stagedOwnership == nil {
		t.Fatal("foreign publication adopted or removed")
	}
}

func TestHTTPHandoffPreservesExistingLegacyRecoveryMenu(t *testing.T) {
	for _, direction := range []string{"removal", "activation", "link rotation", "repair", "client rotation"} {
		t.Run(direction, func(t *testing.T) {
			h := migrationInstallation(t)
			r, _ := decodeOwnership(h.ownership)
			switch direction {
			case "removal":
				r.Phase, r.Direction = removalCommitted, removalRequired
				r.FinishingRelease = &r.Release
			case "activation":
				target := *r.Serving
				target.CertificateGeneration++
				r.Activation = &certificateActivation{Source: *r.Serving, Target: target, Checkpoint: activationTargetRecorded}
			case "link rotation":
				target := *r.Serving
				target.LinkID, target.CredentialSHA256 = strings.Repeat("7", 32), strings.Repeat("8", 64)
				rotation := rotationOperation(*r.Serving, target, rotationTargetAuthorized)
				r.Rotation = &rotation
			case "repair":
				target := *r.Serving
				r.Repair = &subscriptionRepair{OperationID: strings.Repeat("1", 32), Kind: "repair subscription", Direction: "forward", Correction: repairRuntime, Effects: []string{"restart owned serving runtime"}, Checkpoint: repairCommitted, Source: *r.Serving, Target: &target}
			case "client rotation":
				r.Startup = &hostadapter.ProxyStartupAuthority{DirectoryCreated: true, DropInSHA256: strings.Repeat("9", 64)}
				r.ClientRotation = &clientIdentityRotation{OperationID: strings.Repeat("1", 32), Direction: "cleanup", Effects: append([]string(nil), clientIdentityRotationEffects...), Completed: []string{}, Source: r.ConfigurationSHA256, Target: strings.Repeat("7", 64), Checkpoint: clientRotationAuthorized, Subscription: &hostadapter.ClientIdentitySubscription{Source: *r.Serving, Target: *r.Serving, SourceArtifactSHA256: strings.Repeat("2", 64), TargetArtifactSHA256: strings.Repeat("3", 64)}}
			}
			updateSubscriptionResources(&r, testInstalledIdentity())
			h.ownership = ownershipBytes(r)
			if _, valid := decodeOwnership(h.ownership); !valid {
				t.Fatal("unfinished fixture invalid")
			}
			before := bytes.Clone(h.ownership)
			if message, ok := completeHTTPSubscriptionHandoff(t.Context(), readyLifecycle{}, h); !ok || message != "" || h.migrations != 0 || !bytes.Equal(before, h.ownership) {
				t.Fatal("automatic handoff blocked existing recovery menu")
			}
		})
	}
}

func TestCleanInstallMenuDoesNotResumePendingTransportMigration(t *testing.T) {
	h := migrationInstallation(t)
	h.ownership = ownershipBytes(migrationSelectedRecord(t, h))
	before := bytes.Clone(h.ownership)
	operations := len(h.operations)
	installation := newInstalledInterface(readyLifecycle{}, h, acceptedSingBox{})
	for _, action := range []Action{StatusAction, ViewDetailsAction, CompleteRemovalAction, FinishSubscriptionChangeAction} {
		review := installation.Review(t.Context(), action)
		if review.Prepared != nil || review.Result.Code != StatusProblemDetected || !strings.Contains(review.Result.Message, "exact release and recovery procedure") || strings.Contains(review.Result.Message, "running sudo sbxr again") {
			t.Fatalf("pending historical migration review = %+v", review)
		}
	}
	if h.migrations != 0 || !bytes.Equal(before, h.ownership) || len(h.operations) != operations {
		t.Fatal("clean-install menu changed historical migration authority or resources")
	}
}

func TestHTTPSRetirementStrictAuthorityAndUpdateCapability(t *testing.T) {
	h := migrationInstallation(t)
	r := migrationSelectedRecord(t, h)
	r.TransportMigrating = false
	updateSubscriptionResources(&r, testInstalledIdentity())
	body := ownershipBytes(r)
	if _, ok := decodeOwnership(body); !ok {
		t.Fatal("final retired authority refused")
	}
	for _, bad := range [][]byte{
		bytes.Replace(body, []byte(`,"evidence_sha256":"`+h.retired.EvidenceSHA256+`"`), nil, 1),
		bytes.Replace(body, []byte(`"https_retirement":{"serving":{`), []byte(`"https_retirement":{"serving":{"http":true,`), 1),
		bytes.Replace(body, []byte(`,"certbot_created":false`), nil, 1),
		bytes.Replace(body, []byte(`"configuration_mode":384`), []byte(`"configuration_mode":511`), 1),
	} {
		if _, ok := decodeOwnership(bad); ok {
			t.Fatalf("incomplete or contradictory retained authority admitted: %s", bad)
		}
	}
	target := &softwarelifecycle.UpdateTarget{Identity: testInstalledIdentity(), Executable: []byte(expandedProxyAuthorityCapability + " " + hostadapter.LockProvisioningCapability() + " " + httpSubscriptionCapability), Support: &softwarelifecycle.ReleaseSupport{Scope: softwarelifecycle.RecurringSubscriptionUpgrade, Contract: softwarelifecycle.SubscriptionUpdateContract, Sources: []softwarelifecycle.ReleaseIdentity{testInstalledIdentity()}}}
	if AdmitSoftwareUpdate(body, testInstalledIdentity(), target) {
		t.Fatal("retired authority admitted a target without cleanup capability")
	}
	target.Executable = append(target.Executable, []byte(" "+hostadapter.HTTPSRetirementCapability())...)
	if !AdmitSoftwareUpdate(body, testInstalledIdentity(), target) {
		t.Fatal("retired capable target refused")
	}
}

func (h *migrationTestHost) RemoveHTTPSRetirement(context.Context, hostadapter.HTTPSRetirementAuthority) bool {
	h.migrations++
	if h.failRuntime {
		h.failRuntime = false
		return false
	}
	return true
}

func TestMigratedHTTPCompleteRemovalRetainsAuthorityUntilCleanupAndRetries(t *testing.T) {
	h := migrationInstallation(t)
	r := migrationSelectedRecord(t, h)
	r.TransportMigrating = false
	updateSubscriptionResources(&r, testInstalledIdentity())
	h.ownership = ownershipBytes(r)
	lifecycle := &controlledRemovalLifecycle{ready: true}
	module := newInstalledInterface(lifecycle, h, acceptedSingBox{})
	review := module.Review(t.Context(), CompleteRemovalAction)
	if review.Prepared == nil {
		t.Fatalf("removal refused: %+v", review.Result)
	}
	h.failRuntime = true
	if result := module.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != RemovalNeedsCompletion {
		t.Fatalf("partial retired cleanup: %+v", result)
	}
	committed, valid := decodeOwnership(h.ownership)
	if !valid || committed.Direction != removalRequired || committed.HTTPSRetirement == nil || !lifecycle.executable || !lifecycle.installedRecord {
		t.Fatal("interrupted cleanup lost finisher or retired authority")
	}
	review = module.Review(t.Context(), FinishRemovalAction)
	if review.Prepared == nil {
		t.Fatalf("retry refused: %+v", review.Result)
	}
	if result := module.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted || len(h.ownership) != 0 || lifecycle.executable || lifecycle.installedRecord || h.migrations != 2 {
		t.Fatalf("retired cleanup retry: %+v calls=%d", result, h.migrations)
	}
}

func TestMigratedRemovalRefusesChangedRetirementBeforeCommit(t *testing.T) {
	h := migrationInstallation(t)
	r := migrationSelectedRecord(t, h)
	r.TransportMigrating = false
	updateSubscriptionResources(&r, testInstalledIdentity())
	h.ownership = ownershipBytes(r)
	original := bytes.Clone(h.ownership)
	module := newInstalledInterface(&controlledRemovalLifecycle{ready: true}, h, acceptedSingBox{})
	review := module.Review(t.Context(), CompleteRemovalAction)
	if review.Prepared == nil {
		t.Fatal("safe retirement removal not admitted")
	}
	h.retiredUnsafe = true
	if result := module.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != ActionRefused || !bytes.Equal(h.ownership, original) || h.migrations != 0 {
		t.Fatalf("changed retained files crossed commitment: %+v", result)
	}
}
