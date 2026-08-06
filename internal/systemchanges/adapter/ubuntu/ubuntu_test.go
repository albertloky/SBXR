package ubuntu_test

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/albertloky/SBXR/internal/systemchanges"
	"github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

func TestKernelLockIsReadOnlyToInspectAndReleasedByProcessExit(t *testing.T) {
	if os.Getenv("SBXR_LOCK_HELPER") == "1" {
		adapter := ubuntu.NewAt(os.Getenv("SBXR_LOCK_ROOT"), nil, nil)
		lock, acquired, err := adapter.TryLock()
		if err != nil || !acquired {
			os.Exit(2)
		}
		defer lock.Close()
		_, _ = os.Stdout.WriteString("locked\n")
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	}

	root := t.TempDir()
	path := filepath.Join(root, "run/sbxr/system-changes.lock")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	current := systemchanges.Observation{Status: systemchanges.Managed, LastChangeSet: "change-0007", WallTimeSynchronized: true}
	adapter := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return current, nil }, nil)
	observed, err := adapter.Observe()
	current.StateRevision = 8
	reloaded, reloadErr := adapter.Observe()
	after, statErr := os.Stat(path)
	if err != nil || reloadErr != nil || statErr != nil || observed.Lock != systemchanges.LockReleased || observed.FilesystemBytes == 0 || observed.AvailableBytes == 0 || !observed.MonotonicClock || reloaded.StateRevision != 8 || before.ModTime() != after.ModTime() || before.Size() != after.Size() {
		t.Fatalf("read-only observation = (%+v, %+v, %v, %v, %v)", observed, reloaded, err, reloadErr, statErr)
	}

	command := exec.Command(os.Args[0], "-test.run=TestKernelLockIsReadOnlyToInspectAndReleasedByProcessExit")
	command.Env = append(os.Environ(), "SBXR_LOCK_HELPER=1", "SBXR_LOCK_ROOT="+root)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if line, readErr := bufio.NewReader(stdout).ReadString('\n'); readErr != nil || line != "locked\n" {
		t.Fatalf("helper readiness = %q, %v", line, readErr)
	}
	if lock, acquired, lockErr := adapter.TryLock(); lockErr != nil || acquired || lock != nil {
		t.Fatalf("held lock = (%v, %t, %v), want unavailable", lock, acquired, lockErr)
	}
	_ = stdin.Close()
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	lock, acquired, err := adapter.TryLock()
	if err != nil || !acquired {
		t.Fatalf("lock after process exit = (%v, %t, %v)", lock, acquired, err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestKernelLockRejectsUnsafeIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(string) error
	}{
		{name: "broad mode", change: func(path string) error { return os.Chmod(path, 0o644) }},
		{name: "symbolic link", change: func(path string) error {
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Symlink("elsewhere", path)
		}},
		{name: "hard link", change: func(path string) error { return os.Link(path, path+".other") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "run/sbxr/system-changes.lock")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := test.change(path); err != nil {
				t.Fatal(err)
			}
			if lock, acquired, err := ubuntu.NewAt(root, nil, nil).TryLock(); err == nil || acquired || lock != nil {
				t.Fatalf("unsafe lock = (%v, %t, %v)", lock, acquired, err)
			}
		})
	}
}
