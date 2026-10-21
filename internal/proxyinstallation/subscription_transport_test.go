package proxyinstallation

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type migrationTestHost struct {
	*controlledHost
	retired                    hostadapter.HTTPSRetirementAuthority
	migrations                 int
	failRuntime, retiredUnsafe bool
}

func (h *migrationTestHost) ReadOwnership(path string) ([]byte, error) {
	if path != hostSetupSpec.OwnershipPath && path != hostSetupSpec.OwnershipNextPath {
		return nil, os.ErrNotExist
	}
	return h.controlledHost.ReadOwnership(path)
}
func (h *migrationTestHost) AcquireHTTPSRetirementExclusion(hostadapter.HTTPSRetirementAuthority, bool) (*hostadapter.RenewalExclusion, bool) {
	return &hostadapter.RenewalExclusion{}, true
}
func (h *migrationTestHost) InspectHTTPSRetirement(hostadapter.HTTPSRetirementAuthority, bool) bool {
	return !h.retiredUnsafe
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
