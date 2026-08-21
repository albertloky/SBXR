package softwarelifecycle

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestStatusUsesVerifiedProductionFileAndLockFacts(t *testing.T) {
	root := t.TempDir()
	evidence := installedEvidence(t, ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}, 17, AMD64)
	mustWriteStatusFile(t, statusPath(root, executablePath), evidence.executable, 0o755)
	mustWriteStatusFile(t, statusPath(root, installedRecordPath), evidence.installedRecord, 0o600)
	if err := os.Chmod(statusPath(root, "/var/lib/sbxr"), 0o700); err != nil {
		t.Fatal(err)
	}
	lifecycle := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())))

	if got := lifecycle.Status(context.Background()); got.State != Ready {
		t.Fatalf("valid Status() = %#v", got)
	}
	if err := os.Chmod(statusPath(root, executablePath), 0o777); err != nil {
		t.Fatal(err)
	}
	if got := lifecycle.Status(context.Background()); got.State != RecoveryRequiredState {
		t.Fatalf("unsafe Status() = %#v", got)
	}
	if err := os.Chmod(statusPath(root, executablePath), 0o755); err != nil {
		t.Fatal(err)
	}
	lockPath := statusPath(root, mutationLockPath)
	mustWriteStatusFile(t, lockPath, nil, 0o600)
	lock, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if got := lifecycle.Status(context.Background()); got.State != UpdateInProgress {
		t.Fatalf("concurrent Status() = %#v", got)
	}
}

func mustWriteStatusFile(t *testing.T, path string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func statusPath(root, name string) string {
	return filepath.Join(root, strings.TrimPrefix(name, "/"))
}
