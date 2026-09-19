package proxyinstallation

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type lockProvisionLifecycle struct {
	before, after softwarelifecycle.Result
}

func (l lockProvisionLifecycle) Status(context.Context) softwarelifecycle.Result { return l.before }
func (lockProvisionLifecycle) Check(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}
func (lockProvisionLifecycle) Update(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}
func (lockProvisionLifecycle) Recover(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}
func (l lockProvisionLifecycle) StatusUnderMutationLock(context.Context, *softwarelifecycle.MutationLockAuthority) softwarelifecycle.Result {
	return l.after
}

type lockProvisionHost struct{ path string }

func (h lockProvisionHost) ProvisionMutationLock(string) (*hostadapter.MutationLock, bool, error) {
	return softwarelifecycle.ProvisionMutationLockAuthority(h.path, uint32(os.Getuid()))
}

func TestBootProvisioningBindsInstalledIdentityAcrossCreation(t *testing.T) {
	identity := softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v3.1.76", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	ready := softwarelifecycle.Result{State: softwarelifecycle.Ready, Installed: &identity}
	path := filepath.Join(t.TempDir(), "sbxr.lock")
	if !provisionMutationLock(t.Context(), lockProvisionLifecycle{before: ready, after: ready}, lockProvisionHost{path}) {
		t.Fatal("exact ready identity refused")
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !provisionMutationLock(t.Context(), lockProvisionLifecycle{before: ready, after: ready}, lockProvisionHost{path}) {
		t.Fatal("safe retry refused")
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("retry replaced lock: %v", err)
	}

	changed := identity
	changed.Commit = strings.Repeat("c", 40)
	changedReady := softwarelifecycle.Result{State: softwarelifecycle.Ready, Installed: &changed}
	if provisionMutationLock(t.Context(), lockProvisionLifecycle{before: ready, after: changedReady}, lockProvisionHost{filepath.Join(t.TempDir(), "changed.lock")}) {
		t.Fatal("changed installed identity accepted")
	}
	if provisionMutationLock(t.Context(), lockProvisionLifecycle{before: softwarelifecycle.Result{State: softwarelifecycle.RecoveryRequiredState}, after: ready}, lockProvisionHost{filepath.Join(t.TempDir(), "unsafe.lock")}) {
		t.Fatal("unsafe initial lifecycle accepted")
	}
}

func TestLockProvisioningAuthorityIsNewSetupOnlyAndLegacyBytesStayCanonical(t *testing.T) {
	release := softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v3.1.76", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	record := newOwnershipRecord(release, hostadapter.Preflight{PublicIPv4: "8.8.8.8"}, destinations[0], []byte("configuration"))
	if record.LockProvisioning == nil || !record.LockProvisioning.Valid() || !validOwnership(record) {
		t.Fatal("new setup did not bind exact lock provisioning authority")
	}
	for _, resource := range record.LockProvisioning.Resources() {
		if !containsResource(record.Resources, resource) {
			t.Fatalf("new setup omitted resource %q", resource)
		}
	}

	legacy := record
	legacy.LockProvisioning = nil
	legacy.Resources = ownershipResources(legacy.ConfigurationSHA256)
	legacyBody := ownershipBytes(legacy)
	decoded, ok := decodeOwnership(legacyBody)
	if !ok || decoded.LockProvisioning != nil || !bytes.Equal(ownershipBytes(decoded), legacyBody) {
		t.Fatal("legacy authority was migrated or changed during decode")
	}
}

func containsResource(resources []string, wanted string) bool {
	for _, resource := range resources {
		if resource == wanted {
			return true
		}
	}
	return false
}
