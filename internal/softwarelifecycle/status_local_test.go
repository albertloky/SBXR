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
	lifecycle := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), nil)

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

func TestCompleteRemovalDeletesOnlyTheCommittedInstalledPairAndEmptyStateDirectory(t *testing.T) {
	root := t.TempDir()
	identity := ReleaseIdentity{Repository: Repository, Tag: "v3.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	evidence := installedEvidence(t, identity, 17, AMD64)
	writeInstalledEvidence(t, root, evidence)
	ownership := statusPath(root, "/var/lib/sbxr/proxy-ownership.json")
	mustWriteStatusFile(t, ownership, []byte("committed\n"), 0o600)
	lifecycle := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), nil)
	removal := lifecycle.(interface {
		InspectCompleteRemoval(context.Context, ReleaseIdentity) CompleteRemovalInspection
		RemoveCompleteRemovalExecutable(context.Context, ReleaseIdentity) bool
		RemoveCompleteRemovalInstalledRecord(context.Context, ReleaseIdentity) bool
	})

	wrong := identity
	wrong.Commit = strings.Repeat("c", 40)
	if removal.RemoveCompleteRemovalExecutable(t.Context(), wrong) {
		t.Fatal("wrong Release Identity removed the executable")
	}
	if !removal.RemoveCompleteRemovalExecutable(t.Context(), identity) || !removal.RemoveCompleteRemovalInstalledRecord(t.Context(), identity) {
		t.Fatal("committed installed pair was not removed")
	}
	if _, err := os.Stat(ownership); err != nil {
		t.Fatalf("Ownership Record was removed early: %v", err)
	}
	if err := os.Remove(ownership); err != nil {
		t.Fatalf("test cleanup: %v", err)
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

func TestCompleteRemovalRefusesUnsafeOrUnexplainedRemainingMaterial(t *testing.T) {
	for _, kind := range []string{"unsafe executable", "unsafe record", "unknown record field", "unknown residue", "wrong executable"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			identity := ReleaseIdentity{Repository: Repository, Tag: "v3.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
			evidence := installedEvidence(t, identity, 17, AMD64)
			writeInstalledEvidence(t, root, evidence)
			switch kind {
			case "unsafe executable":
				if err := os.Chmod(statusPath(root, executablePath), 0o777); err != nil {
					t.Fatal(err)
				}
			case "unsafe record":
				if err := os.Chmod(statusPath(root, installedRecordPath), 0o666); err != nil {
					t.Fatal(err)
				}
			case "wrong executable":
				mustWriteStatusFile(t, statusPath(root, executablePath), []byte("wrong"), 0o755)
			case "unknown residue":
				mustWriteStatusFile(t, statusPath(root, "/var/lib/sbxr/subscription-token"), []byte("unexplained"), 0o600)
			case "unknown record field":
				if err := os.Remove(statusPath(root, executablePath)); err != nil {
					t.Fatal(err)
				}
				mustWriteStatusFile(t, statusPath(root, installedRecordPath), []byte(strings.Replace(string(evidence.installedRecord), `"schema":1`, `"schema":1,"unknown":true`, 1)), 0o600)
			}
			lifecycle := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), nil).(interface {
				RemoveCompleteRemovalExecutable(context.Context, ReleaseIdentity) bool
				RemoveCompleteRemovalInstalledRecord(context.Context, ReleaseIdentity) bool
			})
			if lifecycle.RemoveCompleteRemovalExecutable(t.Context(), identity) || lifecycle.RemoveCompleteRemovalInstalledRecord(t.Context(), identity) {
				t.Fatal("unsafe removal accepted")
			}
		})
	}
}
