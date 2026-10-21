package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestPackageLockContender(t *testing.T) {
	path := os.Getenv("SBXR_PACKAGE_LOCK_CONTENDER")
	if path == "" {
		return
	}
	file, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	err = syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &syscall.Flock_t{Type: syscall.F_WRLCK})
	switch {
	case err == nil:
		fmt.Println("acquired")
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EAGAIN):
		fmt.Println("blocked")
	default:
		t.Fatal(err)
	}
}

func TestRemovalInspectionRetainsPackageLocksUntilRelease(t *testing.T) {
	adapter := Adapter{root: t.TempDir(), subscriptionCommand: func(context.Context, string, ...string) (string, int, bool) {
		return "", 1, true
	}}
	for _, name := range ubuntuPackageLocks {
		path := adapter.path(name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	adapter.packageLocksAvailable = func() bool {
		for _, name := range ubuntuPackageLocks {
			if !recordLockAvailable(adapter.path(name)) {
				return false
			}
		}
		return true
	}
	locks, busy, err := adapter.AcquirePackageLocks()
	if err != nil || busy {
		t.Fatalf("acquire: %v, busy=%t", err, busy)
	}
	t.Cleanup(locks.Release)
	contend := func(want string) {
		t.Helper()
		for _, name := range ubuntuPackageLocks {
			child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestPackageLockContender$")
			child.Env = append(os.Environ(), "SBXR_PACKAGE_LOCK_CONTENDER="+adapter.path(name))
			output, err := child.CombinedOutput()
			if err != nil || !strings.HasPrefix(string(output), want+"\n") {
				t.Fatalf("%s: contender wanted %s: %s %v", name, want, output, err)
			}
		}
	}
	contend("blocked")
	facts := adapter.InspectRemoval(t.Context(), testSetupSpec(), nil, nil, "", "8.8.8.8", locks)
	if !facts.PackageLocks.Accepted {
		t.Fatalf("retained exclusion refused: %#v", facts.PackageLocks)
	}
	contend("blocked")
	locks.Release()
	contend("acquired")
	if facts := adapter.InspectRemoval(t.Context(), testSetupSpec(), nil, nil, "", "8.8.8.8", locks); facts.PackageLocks.Accepted {
		t.Fatal("released authority accepted")
	}
}
