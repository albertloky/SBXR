package proxyinstallation

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

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
)

func TestRemovalPackageLockContender(t *testing.T) {
	path := os.Getenv("SBXR_REMOVAL_LOCK_CONTENDER")
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

type packageLockedRemovalHost struct {
	*controlledHost
	check func(string)
}

func (*packageLockedRemovalHost) AcquirePackageLocks() (*hostadapter.PackageLocks, bool, error) {
	// The zero adapter resolves its fixed paths relative to t.Chdir's private
	// root. No host package-manager path is opened or locked by this fixture.
	return (hostadapter.Adapter{}).AcquirePackageLocks()
}

func (host *packageLockedRemovalHost) PublishOwnership(path, nextPath string, expected, next []byte) error {
	if record, valid := decodeOwnership(next); valid && record.Direction == removalRequired && record.RemovalCheckpoint == 0 {
		host.check("blocked")
	}
	return host.controlledHost.PublishOwnership(path, nextPath, expected, next)
}

func (host *packageLockedRemovalHost) Apply(ctx context.Context, input hostadapter.OperationInput) hostadapter.OperationResult {
	if input.Operation == hostadapter.RemovePackage {
		host.check("acquired")
	}
	return host.controlledHost.Apply(ctx, input)
}

func TestLateRemovalCommitmentReleasesPackageLocksAndRecoversFresh(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	paths := []string{"var/lib/dpkg/lock-frontend", "var/lib/dpkg/lock", "var/lib/apt/lists/lock", "var/cache/apt/archives/lock"}
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	checks := map[string]int{}
	host := &packageLockedRemovalHost{controlledHost: acceptedHost(), check: func(want string) {
		checks[want]++
		for _, path := range paths {
			child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRemovalPackageLockContender$")
			child.Env = append(os.Environ(), "SBXR_REMOVAL_LOCK_CONTENDER="+filepath.Join(root, path))
			output, err := child.CombinedOutput()
			if err != nil || !strings.HasPrefix(string(output), want+"\n") {
				t.Fatalf("%s: wanted %s: %s %v", path, want, output, err)
			}
		}
	}}
	lifecycle := &controlledRemovalLifecycle{ready: true}
	installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Code != SetupComplete {
		t.Fatalf("setup: %#v", result)
	}
	host.lateRemovalPublish = map[int]bool{0: true}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	host.cancelOn, host.cancel = hostadapter.RemovePackage, cancel
	removal := installation.Review(ctx, CompleteRemovalAction)
	result := installation.Execute(ctx, *removal.Prepared, Approved, nil)
	if result.Code != RemovalNeedsCompletion || checks["blocked"] == 0 || checks["acquired"] == 0 {
		t.Fatalf("late commitment did not release exclusion before interruption: %#v, %v", result, checks)
	}
	fresh := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	finish := fresh.Review(t.Context(), FinishRemovalAction)
	if finish.Prepared == nil {
		t.Fatalf("fresh removal recovery: %#v", finish)
	}
	if result := fresh.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted {
		t.Fatalf("fresh completion: %#v", result)
	}
}
