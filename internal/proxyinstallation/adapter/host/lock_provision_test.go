package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func lockProvisionFixture(t *testing.T) Adapter {
	t.Helper()
	root := t.TempDir()
	for _, path := range []string{"etc/systemd/system/multi-user.target.wants", "run/lock"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bin := t.TempDir()
	systemctl := filepath.Join(bin, "systemctl")
	if err := os.WriteFile(systemctl, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	return Adapter{root: root}
}

func TestLockProvisioningPublishesInspectsAndRemovesExactResources(t *testing.T) {
	a := lockProvisionFixture(t)
	authority := NewLockProvisioningAuthority()
	if !a.InstallLockProvisioning(t.Context(), authority) || !a.InspectLockProvisioning(authority).Accepted {
		t.Fatal("exact boot provisioning was not installed")
	}
	unit, err := os.ReadFile(a.path(MutationLockProvisionUnitPath))
	target, targetErr := os.Readlink(a.path(MutationLockProvisionWantsPath))
	if err != nil || targetErr != nil || string(unit) != MutationLockProvisionUnit || target != "../sbxr-mutation-lock.service" {
		t.Fatalf("published resources: unit=%q target=%q errors=%v/%v", unit, target, err, targetErr)
	}
	if !a.InstallLockProvisioning(t.Context(), authority) {
		t.Fatal("idempotent installation refused")
	}
	if !a.RemoveLockProvisioning(t.Context(), authority) || !a.lockProvisioningAbsent() {
		t.Fatal("exact boot provisioning was not removed")
	}
}

func TestLockProvisioningResumesInterruptedExactPublication(t *testing.T) {
	a := lockProvisionFixture(t)
	authority := NewLockProvisioningAuthority()
	staged := a.path(MutationLockProvisionUnitPath + ".sbxr-next")
	if err := os.WriteFile(staged, []byte(MutationLockProvisionUnit), 0o644); err != nil {
		t.Fatal(err)
	}
	if !a.InstallLockProvisioning(t.Context(), authority) || !a.InspectLockProvisioning(authority).Accepted {
		t.Fatal("exact staged publication did not resume")
	}
	if _, err := os.Lstat(staged); !os.IsNotExist(err) {
		t.Fatalf("staged publication remains: %v", err)
	}
	if !a.RemoveLockProvisioning(t.Context(), authority) || !a.RemoveLockProvisioning(t.Context(), authority) {
		t.Fatal("resumed publication was not idempotently removable")
	}
}

func TestLockProvisioningRefusesUnexpectedResourcesWithoutChangingThem(t *testing.T) {
	for _, path := range []string{MutationLockProvisionUnitPath, MutationLockProvisionUnitPath + ".sbxr-next", MutationLockProvisionWantsPath} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			a := lockProvisionFixture(t)
			full := a.path(path)
			if err := os.WriteFile(full, []byte("unrelated\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(full)
			if err != nil {
				t.Fatal(err)
			}
			authority := NewLockProvisioningAuthority()
			if a.InstallLockProvisioning(t.Context(), authority) || a.RemoveLockProvisioning(t.Context(), authority) {
				t.Fatal("unexpected resource accepted")
			}
			if path == MutationLockProvisionWantsPath {
				if _, err := os.Lstat(a.path(MutationLockProvisionUnitPath)); !os.IsNotExist(err) {
					t.Fatalf("refusal partially published unit: %v", err)
				}
			}
			after, err := os.ReadFile(full)
			if err != nil || string(after) != string(before) || !strings.Contains(string(after), "unrelated") {
				t.Fatalf("unexpected resource changed: %q %v", after, err)
			}
		})
	}
}

func TestBootLockProvisioningUsesProtectedParentAndExistingOnlyRetry(t *testing.T) {
	a := lockProvisionFixture(t)
	path := a.path("/run/lock/sbxr.lock")
	lock, busy, err := a.ProvisionMutationLock("/run/lock/sbxr.lock")
	if err != nil || busy || lock == nil || !lock.Holds(path) {
		t.Fatalf("missing lock provision: lock=%v busy=%v err=%v", lock, busy, err)
	}
	lock.Release()
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	retry, busy, err := a.ProvisionMutationLock("/run/lock/sbxr.lock")
	if err != nil || busy || retry == nil {
		t.Fatalf("safe retry: lock=%v busy=%v err=%v", retry, busy, err)
	}
	retry.Release()
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("safe retry replaced the inode")
	}
	if err := os.Remove(path); err != nil || os.Chmod(filepath.Dir(path), 0o777) != nil {
		t.Fatal(err)
	}
	if lock, busy, err := a.ProvisionMutationLock("/run/lock/sbxr.lock"); err == nil || busy || lock != nil {
		t.Fatal("unsafe writable parent accepted")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("refusal created a lock")
	}
}

func TestLockProvisioningRefusesUnsafeWantsParentWithoutMutation(t *testing.T) {
	a := lockProvisionFixture(t)
	authority := NewLockProvisioningAuthority()
	if !a.InstallLockProvisioning(t.Context(), authority) {
		t.Fatal("fixture installation failed")
	}
	wants := a.path(MutationLockProvisionWantsPath)
	unit := a.path(MutationLockProvisionUnitPath)
	beforeUnit, err := os.ReadFile(unit)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(wants), 0o777); err != nil {
		t.Fatal(err)
	}
	if a.InspectLockProvisioning(authority).Accepted || a.InstallLockProvisioning(t.Context(), authority) || a.RemoveLockProvisioning(t.Context(), authority) || a.lockProvisioningAbsent() {
		t.Fatal("unsafe wants parent was accepted")
	}
	afterUnit, unitErr := os.ReadFile(unit)
	target, targetErr := os.Readlink(wants)
	if unitErr != nil || string(afterUnit) != string(beforeUnit) || targetErr != nil || target != "../sbxr-mutation-lock.service" {
		t.Fatalf("refusal changed resources: unit=%v target=%q/%v", unitErr, target, targetErr)
	}
}
