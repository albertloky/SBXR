package softwarelifecycle

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Relocate the production construction to a disposable filesystem without
// changing its release policy or recovery wiring.
func productionLifecycleFixture(root string, source LatestReleaseSource, runtime UpdateRuntime) installedInterface {
	lifecycle := NewInstalledWithUpdateRuntime(source, nil, runtime).(installedInterface)
	inspector := lifecycle.local.(filesystemInspector)
	inspector.root, inspector.uid = root, uint32(os.Getuid())
	lifecycle.local = inspector
	return lifecycle
}

func TestProductionCleanInstallLifecycleRefusesNewUpdateWithoutMutation(t *testing.T) {
	root := t.TempDir()
	prior := ReleaseIdentity{Repository: Repository, Tag: "v3.1.81", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	target := ReleaseIdentity{Repository: Repository, Tag: "v3.1.82", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
	evidence := installedEvidence(t, prior, 159, AMD64)
	writeInstalledEvidence(t, root, evidence)
	candidate := updateCandidateFromEvidence(t, target, 160, AMD64, installedEvidence(t, target, 160, AMD64))
	// Even a target declaring this exact incoming source cannot enable Update
	// in a release whose product policy is clean installation only.
	candidate.cell.release.Support = &ReleaseSupport{Scope: RecurringSubscriptionUpgrade, Sources: []ReleaseIdentity{prior}, Contract: SubscriptionUpdateContract}
	source := &controlledUpdateSource{candidate: candidate}
	lifecycle := productionLifecycleFixture(root, source, UpdateRuntime{})
	before := recoverySurface(t, root)
	checked := lifecycle.Check(t.Context(), nil)
	if checked.Code != CheckReleaseRefused || checked.Latest != nil || !strings.Contains(checked.Message, "supports clean installation only") {
		t.Fatalf("Check offered an update: %+v", checked)
	}
	// A caller cannot bypass refusal by manufacturing an old menu approval.
	ctx := ConfirmReview(t.Context(), Result{Code: CheckUpdateAvailable, Installed: &prior, Latest: &target})
	updated := lifecycle.Update(ctx, func(Progress) { t.Fatal("refused update reported mutation progress") })
	if updated.Code != UpdateReleaseRefused || updated.UpdateInstalled || !strings.Contains(updated.Message, "supports clean installation only") || source.calls.Load() != 0 {
		t.Fatalf("Update was not refused before candidate preparation: %+v", updated)
	}
	if !reflect.DeepEqual(before, recoverySurface(t, root)) {
		t.Fatal("refused update changed installed or transaction evidence")
	}
	if _, err := os.Lstat(statusPath(root, mutationLockPath)); !os.IsNotExist(err) {
		t.Fatalf("refused update created a mutation lock: %v", err)
	}
	// Read-only release checks retain their truthful same-release outcome.
	source.candidate = updateCandidateFromEvidence(t, prior, 159, AMD64, evidence)
	if got := lifecycle.Check(t.Context(), nil); got.Code != CheckAlreadyCurrent {
		t.Fatalf("same-release Check = %+v", got)
	}
}

func TestProductionCleanInstallLifecyclePreservesRecoveryWithoutMigration(t *testing.T) {
	for _, schema := range []int{1, 2} {
		for _, committed := range []bool{false, true} {
			name := map[int]string{1: "schema1", 2: "schema2"}[schema] + "/" + map[bool]string{false: "rollback", true: "forward"}[committed]
			t.Run(name, func(t *testing.T) {
				root, prior, target, candidate := preparedRecoveryFixture(t)
				activateRecoveryFixture(t, root, candidate, committed)
				if schema == 2 {
					updateRoot, err := os.OpenRoot(root)
					if err != nil {
						t.Fatal(err)
					}
					record, err := readUpdateRecord(updateRoot)
					updateRoot.Close()
					if err != nil {
						t.Fatal(err)
					}
					record.Schema, record.OwnershipSHA256 = 2, digestBytes(nil)
					mustWriteStatusFile(t, statusPath(root, "/var/lib/sbxr/update.json"), updateRecordBytes(record), 0600)
				}
				completions := 0
				lifecycle := productionLifecycleFixture(root, nil, UpdateRuntime{
					Acquire: func(context.Context, []byte, ReleaseIdentity, *UpdateTarget, *MutationLockAuthority) (func(), bool) {
						return func() {}, true
					},
					Complete: func(context.Context, []byte, ReleaseIdentity, *MutationLockAuthority) bool {
						completions++
						return true
					},
					AfterComplete: func(context.Context, ReleaseIdentity, *MutationLockAuthority) (string, bool) {
						t.Fatal("clean-install recovery initiated automatic migration")
						return "", false
					},
				})
				before := recoverySurface(t, root)
				if got := lifecycle.Update(t.Context(), nil); got.Code != UpdateNotReady || !reflect.DeepEqual(before, recoverySurface(t, root)) {
					t.Fatalf("Update changed pending recovery: %+v", got)
				}
				got := lifecycle.Recover(ConfirmReview(t.Context(), lifecycle.Status(t.Context())), nil)
				want, active := RecoverPriorRestored, prior
				if committed {
					want, active = RecoverCandidateRetained, target
				}
				if got.Code != want || !activeEvidenceMatches(t, root, active) {
					t.Fatalf("Recover = %+v; want %s with exact selected pair", got, want)
				}
				wantCompletions := 0
				if schema == 2 && committed {
					wantCompletions = 1
				}
				if completions != wantCompletions {
					t.Fatalf("runtime completions = %d, want %d", completions, wantCompletions)
				}
				if got := lifecycle.Recover(t.Context(), nil); got.Code != RecoverNotRequired {
					t.Fatalf("journal-free Recover = %+v", got)
				}
			})
		}
	}
}
