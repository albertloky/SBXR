package softwarelifecycle

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestCommittedUpdateRetainsAuthorityUntilRuntimeCompletion(t *testing.T) {
	root := t.TempDir()
	prior := ReleaseIdentity{Repository: Repository, Tag: "v3.0.22", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	target := ReleaseIdentity{Repository: Repository, Tag: "v3.0.23", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
	writeInstalledEvidence(t, root, installedEvidence(t, prior, 22, AMD64))
	candidate := updateCandidateFromEvidence(t, target, 23, AMD64, installedEvidence(t, target, 23, AMD64))
	candidate.cell.release.Support = &ReleaseSupport{Scope: RecurringSubscriptionUpgrade, Sources: []ReleaseIdentity{prior}, Contract: SubscriptionUpdateContract}
	complete := false
	held := false
	runtime := &UpdateRuntime{
		Acquire: func(context.Context, []byte, ReleaseIdentity, *UpdateTarget, *MutationLockAuthority) (func(), bool) {
			held = true
			return func() { held = false }, true
		},
		Complete: func(_ context.Context, _ []byte, identity ReleaseIdentity, _ *MutationLockAuthority) bool {
			if !held || identity != target {
				t.Fatal("runtime completion lost admission or candidate")
			}
			return complete
		},
	}
	lifecycle := newInstalledInterface(filesystemInspector{root: root, uid: uint32(os.Getuid()), requireSupport: true, updateRuntime: runtime}, &controlledUpdateSource{candidate: candidate})
	got := lifecycle.Update(t.Context(), nil)
	if got.Code != UpdateRecoveryRequired || got.Installed == nil || *got.Installed != target {
		t.Fatalf("Update=%+v", got)
	}
	reviewed := lifecycle.Status(t.Context())
	if reviewed.State != RecoveryRequiredState || reviewed.RecoveryDirection != "Keep the committed release and finish forward" {
		t.Fatalf("Status=%+v", reviewed)
	}
	complete = true
	if got := lifecycle.Recover(ConfirmReview(t.Context(), reviewed), nil); got.Code != RecoverCandidateRetained {
		t.Fatalf("Recover=%+v", got)
	}
	if got := lifecycle.Status(t.Context()); got.State != Ready || *got.Installed != target {
		t.Fatalf("Status=%+v", got)
	}
}

func TestSchemaTwoUpdateRefusesAdmissionAndRestoresBeforeCommit(t *testing.T) {
	for _, failure := range []string{"admission", "candidate replacement", "prior restoration", "runtime"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			prior := ReleaseIdentity{Repository: Repository, Tag: "v3.0.22", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
			target := ReleaseIdentity{Repository: Repository, Tag: "v3.0.23", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
			evidence := installedEvidence(t, prior, 22, AMD64)
			writeInstalledEvidence(t, root, evidence)
			candidate := updateCandidateFromEvidence(t, target, 23, AMD64, installedEvidence(t, target, 23, AMD64))
			candidate.cell.release.Support = &ReleaseSupport{Scope: RecurringSubscriptionUpgrade, Sources: []ReleaseIdentity{prior}, Contract: SubscriptionUpdateContract}
			released := false
			runtime := &UpdateRuntime{Acquire: func(context.Context, []byte, ReleaseIdentity, *UpdateTarget, *MutationLockAuthority) (func(), bool) {
				return func() { released = true }, failure != "admission"
			}, Complete: func(context.Context, []byte, ReleaseIdentity, *MutationLockAuthority) bool {
				return failure != "runtime"
			}}
			lifecycle := newInstalledInterface(filesystemInspector{root: root, uid: uint32(os.Getuid()), requireSupport: true, updateRuntime: runtime}, &controlledUpdateSource{candidate: candidate})
			got := lifecycle.Update(t.Context(), func(p Progress) {
				if p.Status == "Activating the verified release" && (failure == "candidate replacement" || failure == "prior restoration") {
					if err := os.Remove(statusPath(root, "/usr/local/bin/.sbxr-update-candidate")); err != nil {
						t.Fatal(err)
					}
					if failure == "prior restoration" {
						if err := os.WriteFile(statusPath(root, "/var/lib/sbxr/.installed.json.prior"), []byte("broken"), 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			})
			switch failure {
			case "admission":
				if got.Code != UpdateReleaseRefused {
					t.Fatalf("Update=%+v", got)
				}
			case "candidate replacement":
				if got.Code != UpdatePriorRestored || lifecycle.Status(t.Context()).State != Ready {
					t.Fatalf("Update=%+v", got)
				}
			default:
				if got.Code != UpdateRecoveryRequired || lifecycle.Status(t.Context()).State != RecoveryRequiredState {
					t.Fatalf("Update=%+v", got)
				}
			}
			if failure != "admission" && !released {
				t.Fatal("runtime exclusion leaked")
			}
			if failure == "prior restoration" {
				mustWriteStatusFile(t, statusPath(root, "/var/lib/sbxr/.installed.json.prior"), evidence.installedRecord, 0600)
				if got := lifecycle.Recover(t.Context(), nil); got.Code != RecoverPriorRestored {
					t.Fatalf("Recover=%+v", got)
				}
			}
		})
	}
}

func TestRecoverRefusesChangedDirectionAndCancelledOutput(t *testing.T) {
	root, _, _, candidate := preparedRecoveryFixture(t)
	lifecycle := newInstalledInterface(filesystemInspector{root: root, uid: uint32(os.Getuid())}, nil)
	reviewed := lifecycle.Status(t.Context())
	activateRecoveryFixture(t, root, candidate, true)
	if got := lifecycle.Recover(ConfirmReview(t.Context(), reviewed), nil); got.Code != RecoverRefused {
		t.Fatalf("changed direction=%+v", got)
	}
	ctx, cancel := context.WithCancel(t.Context())
	if got := lifecycle.Recover(ctx, func(Progress) { cancel() }); got.Code != RecoverRefused || lifecycle.Status(t.Context()).State != RecoveryRequiredState {
		t.Fatalf("cancelled=%+v", got)
	}
}
