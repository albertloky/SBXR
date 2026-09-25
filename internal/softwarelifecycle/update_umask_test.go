package softwarelifecycle

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestUpdateFileUsesExactModeWithoutChangingExistingFiles(t *testing.T) {
	for _, mask := range []int{0, 0o022, 0o077, 0o777} {
		t.Run(fmt.Sprintf("mask-%03o", mask), func(t *testing.T) {
			path := t.TempDir()
			root, err := os.OpenRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			prior := syscall.Umask(mask)
			defer syscall.Umask(prior)
			for _, mode := range []os.FileMode{0o600, 0o755} {
				name := fmt.Sprintf("file-%03o", mode)
				if err := writeUpdateFile(root, name, []byte("original"), mode); err != nil {
					t.Fatal(err)
				}
				info, err := root.Stat(name)
				if err != nil || info.Mode().Perm() != mode {
					t.Fatalf("mode=%v error=%v; want %03o", info, err, mode)
				}
				if err := writeUpdateFile(root, name, []byte("replacement"), 0o777); err == nil {
					t.Fatal("overwrote existing file")
				}
				if err := os.Symlink(name, filepath.Join(path, "link-"+name)); err != nil {
					t.Fatal(err)
				}
				if err := writeUpdateFile(root, "link-"+name, []byte("replacement"), 0o777); err == nil {
					t.Fatal("followed existing symlink")
				}
				body, err := root.ReadFile(name)
				after, statErr := root.Stat(name)
				if err != nil || statErr != nil || string(body) != "original" || after.Mode() != info.Mode() {
					t.Fatal("refusal changed existing bytes or mode")
				}
			}
		})
	}
}

func TestUpdateAndRecoveryUnderRestrictiveUmask(t *testing.T) {
	// No parallel tests: umask is process-wide. Only the operation, not fixture
	// preparation, inherits the restrictive mask. Private records remain 0600.
	for _, action := range []string{"update", "rollback", "forward-recovery"} {
		t.Run(action, func(t *testing.T) {
			root := t.TempDir()
			prior := ReleaseIdentity{Repository: Repository, Tag: "v3.1.81", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
			target := ReleaseIdentity{Repository: Repository, Tag: "v3.1.82", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
			priorEvidence := installedEvidence(t, prior, 159, AMD64)
			writeInstalledEvidence(t, root, priorEvidence)
			candidate := updateCandidateFromEvidence(t, target, 160, AMD64, installedEvidence(t, target, 160, AMD64))
			candidate.cell.release.Support = &ReleaseSupport{Scope: RecurringSubscriptionUpgrade, Sources: []ReleaseIdentity{prior}, Contract: SubscriptionUpdateContract}
			complete := action != "forward-recovery"
			runtime := &UpdateRuntime{
				Acquire: func(context.Context, []byte, ReleaseIdentity, *UpdateTarget, *MutationLockAuthority) (func(), bool) {
					return func() {}, true
				},
				Complete: func(context.Context, []byte, ReleaseIdentity, *MutationLockAuthority) bool { return complete },
			}
			module := newInstalledInterface(filesystemInspector{root: root, uid: uint32(os.Getuid()), requireSupport: true, updateRuntime: runtime}, &controlledUpdateSource{candidate: candidate})
			old := syscall.Umask(0o077)
			defer syscall.Umask(old)
			got := module.Update(t.Context(), func(p Progress) {
				if action == "rollback" && p.Status == "Activating the verified release" {
					if err := os.Remove(statusPath(root, "/usr/local/bin/.sbxr-update-candidate")); err != nil {
						t.Fatal(err)
					}
				}
			})
			want := UpdateInstalled
			if action == "rollback" {
				want = UpdatePriorRestored
			} else if action == "forward-recovery" {
				want = UpdateRecoveryRequired
			}
			if got.Code != want {
				t.Fatalf("Update=%+v; want %s", got, want)
			}
			if action == "forward-recovery" {
				complete = true
				if got := module.Recover(t.Context(), nil); got.Code != RecoverCandidateRetained {
					t.Fatalf("Recover=%+v", got)
				}
			}
			if action == "rollback" && !activeEvidenceMatches(t, root, priorEvidence) {
				t.Fatal("prior pair not exactly restored")
			}
			if got := module.Status(t.Context()); got.State != Ready || got.Installed == nil || (action != "rollback" && *got.Installed != target) {
				t.Fatalf("Status=%+v", got)
			}
			for _, name := range transactionPaths {
				if _, err := os.Lstat(statusPath(root, name)); !os.IsNotExist(err) {
					t.Fatalf("transaction residue: %s %v", name, err)
				}
			}
		})
	}
}

func TestRecoverRollbackUnderRestrictiveUmask(t *testing.T) {
	root, prior, _, _ := preparedRecoveryFixture(t)
	module := newInstalledInterface(filesystemInspector{root: root, uid: uint32(os.Getuid())}, nil)
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	if got := module.Recover(t.Context(), nil); got.Code != RecoverPriorRestored {
		t.Fatalf("Recover=%+v", got)
	}
	if !activeEvidenceMatches(t, root, prior) || module.Status(t.Context()).State != Ready {
		t.Fatal("recovery did not restore exact prior pair")
	}
}
