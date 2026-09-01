package host

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRuntimeStartAcrossARealChildProcess(t *testing.T) {
	if root := os.Getenv("SBXR_TEST_RUNTIME_ROOT"); root != "" {
		a := Adapter{root: root}
		borrowed, err := a.BorrowRuntimeStartLock(ServingRole)
		if err != nil || !borrowed.Holds(filepath.Join(root, "run/lock/sbxr.lock")) {
			os.Exit(4)
		}
		borrowed.Release()
		os.Exit(0)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "run/lock"), 0755); err != nil {
		t.Fatal(err)
	}
	a := Adapter{root: root}
	lock, busy, err := a.AcquireMutationLock("/run/lock/sbxr.lock")
	if err != nil || busy {
		t.Fatal("owner lock refused")
	}
	defer lock.Release()
	if !a.WithRuntimeStart(t.Context(), lock, ServingRole, func() bool {
		child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRuntimeStartAcrossARealChildProcess$")
		child.Env = append(os.Environ(), "SBXR_TEST_RUNTIME_ROOT="+root)
		return child.Run() == nil
	}) {
		t.Fatal("child process handoff failed")
	}
	other, busy, err := a.AcquireSubscriptionReviewLock("/run/lock/sbxr.lock")
	if other != nil {
		other.Release()
	}
	if err != nil || !busy {
		t.Fatal("child exit released Owner lock")
	}
}

func TestRuntimeStartBorrowsRealOwnerLockWithoutUnlockingIt(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "run/lock"), 0755); err != nil {
		t.Fatal(err)
	}
	a := Adapter{root: root}
	owner, busy, err := a.AcquireMutationLock("/run/lock/sbxr.lock")
	if err != nil || busy {
		t.Fatal("owner lock refused")
	}
	defer owner.Release()
	if !a.WithRuntimeStart(t.Context(), owner, ServingRole, func() bool {
		child, err := a.BorrowRuntimeStartLock(ServingRole)
		if err != nil || !child.Holds(filepath.Join(root, "run/lock/sbxr.lock")) {
			t.Error("child did not obtain the existing lock")
			return false
		}
		child.Release()
		other, busy, err := a.AcquireSubscriptionReviewLock("/run/lock/sbxr.lock")
		if other != nil {
			other.Release()
		}
		if err != nil || !busy {
			t.Error("child released the owner's lock")
		}
		if duplicate, err := a.BorrowRuntimeStartLock(ServingRole); err == nil {
			duplicate.Release()
			t.Error("runtime authority was reused")
		}
		return true
	}) {
		t.Fatal("authorized runtime start refused")
	}
	if _, err := a.BorrowRuntimeStartLock(ServingRole); err == nil {
		t.Fatal("runtime authority survived its scope")
	}
}
