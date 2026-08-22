package softwarelifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

type controlledLocalInspector struct{ evidence localInspection }

func (inspector controlledLocalInspector) inspect(context.Context) localInspection {
	return inspector.evidence
}

type changingLocalInspector struct{ next func() localInspection }

func (inspector changingLocalInspector) inspect(context.Context) localInspection {
	return inspector.next()
}

type controlledLatestSource struct {
	result  LatestRelease
	outcome LatestReleaseOutcome
	check   func()
}

type controlledUpdateSource struct {
	candidate UpdateCandidate
	outcome   LatestReleaseOutcome
	prepare   func()
	calls     atomic.Int64
}

func (source *controlledUpdateSource) CheckLatest(context.Context) (LatestRelease, LatestReleaseOutcome) {
	if source.candidate.cell == nil {
		return LatestRelease{}, LatestReleaseRefused
	}
	return source.candidate.cell.release, LatestReleaseAccepted
}

func (source *controlledUpdateSource) PrepareLatest(context.Context, Architecture) (UpdateCandidate, LatestReleaseOutcome) {
	source.calls.Add(1)
	if source.prepare != nil {
		source.prepare()
	}
	if source.outcome != 0 {
		return source.candidate, source.outcome
	}
	return source.candidate, LatestReleaseAccepted
}

func (source controlledLatestSource) CheckLatest(context.Context) (LatestRelease, LatestReleaseOutcome) {
	if source.check != nil {
		source.check()
	}
	return source.result, source.outcome
}

func TestUpdateReturnsTruthfulEarlyOutcomesWithoutMutation(t *testing.T) {
	prior := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	for _, test := range []struct {
		name      string
		candidate LatestRelease
		outcome   LatestReleaseOutcome
		want      ResultCode
	}{
		{"already current", LatestRelease{Identity: prior, Sequence: 17}, LatestReleaseAccepted, UpdateAlreadyCurrent},
		{"same sequence changed identity", LatestRelease{Identity: ReleaseIdentity{Repository: Repository, Tag: "v2.0.1", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}, Sequence: 17}, LatestReleaseAccepted, UpdateReleaseRefused},
		{"release refused", LatestRelease{}, LatestReleaseRefused, UpdateReleaseRefused},
		{"release unavailable", LatestRelease{}, LatestReleaseUnavailable, UpdateReleaseUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			priorEvidence := installedEvidence(t, prior, 17, AMD64)
			writeInstalledEvidence(t, root, priorEvidence)
			source := &controlledUpdateSource{outcome: test.outcome}
			if test.candidate.Sequence != 0 {
				evidence := installedEvidence(t, test.candidate.Identity, test.candidate.Sequence, AMD64)
				source.candidate = updateCandidateFromEvidence(t, test.candidate.Identity, test.candidate.Sequence, AMD64, evidence)
			}

			result := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), source).Update(t.Context(), nil)

			if result.State != Ready || result.Code != test.want || result.UpdateInstalled || !activeEvidenceMatches(t, root, priorEvidence) {
				t.Fatalf("Update() = %#v", result)
			}
		})
	}
}

func TestUpdateRefusesConcurrentMutationWithoutFreshDiscovery(t *testing.T) {
	root := t.TempDir()
	prior := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	writeInstalledEvidence(t, root, installedEvidence(t, prior, 17, AMD64))
	lockPath := statusPath(root, mutationLockPath)
	mustWriteStatusFile(t, lockPath, nil, 0o600)
	lock, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	source := &controlledUpdateSource{}

	result := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), source).Update(t.Context(), nil)

	if result.State != UpdateInProgress || result.Code != UpdateConcurrentMutation || source.calls.Load() != 0 {
		t.Fatalf("Update() = %#v, fresh calls = %d", result, source.calls.Load())
	}
}

func TestUpdateFailureAfterPreparedRestoresVerifiedPriorPair(t *testing.T) {
	root := t.TempDir()
	prior := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	candidate := ReleaseIdentity{Repository: Repository, Tag: "v2.0.1", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
	priorEvidence := installedEvidence(t, prior, 17, AMD64)
	candidateEvidence := installedEvidence(t, candidate, 18, AMD64)
	writeInstalledEvidence(t, root, priorEvidence)
	source := &controlledUpdateSource{candidate: updateCandidateFromEvidence(t, candidate, 18, AMD64, candidateEvidence)}

	result := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), source).Update(t.Context(), func(progress Progress) {
		if progress.Status == "Activating the verified release" {
			if err := os.WriteFile(statusPath(root, "/usr/local/bin/.sbxr-update-candidate"), []byte("changed"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	})

	if result.State != Ready || result.Code != UpdatePriorRestored || result.UpdateInstalled || !activeEvidenceMatches(t, root, priorEvidence) {
		t.Fatalf("Update() = %#v", result)
	}
}

func TestUpdateRestoresPriorWhileTheRollbackLinkStillHasTwoLinks(t *testing.T) {
	root := t.TempDir()
	prior := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	candidate := ReleaseIdentity{Repository: Repository, Tag: "v2.0.1", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
	priorEvidence := installedEvidence(t, prior, 17, AMD64)
	candidateEvidence := installedEvidence(t, candidate, 18, AMD64)
	writeInstalledEvidence(t, root, priorEvidence)
	source := &controlledUpdateSource{candidate: updateCandidateFromEvidence(t, candidate, 18, AMD64, candidateEvidence)}

	result := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), source).Update(t.Context(), func(progress Progress) {
		if progress.Status == "Activating the verified release" {
			if err := os.Remove(statusPath(root, "/var/lib/sbxr/.installed.json.candidate")); err != nil {
				t.Fatal(err)
			}
		}
	})

	if result.State != Ready || result.Code != UpdatePriorRestored || !activeEvidenceMatches(t, root, priorEvidence) {
		t.Fatalf("Update() = %#v", result)
	}
}

func TestRollbackRefusesASecondPriorLinkThatIsNotTheActiveExecutable(t *testing.T) {
	rootPath := t.TempDir()
	prior := installedEvidence(t, ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}, 17, AMD64)
	candidate := installedEvidence(t, ReleaseIdentity{Repository: Repository, Tag: "v2.0.1", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}, 18, AMD64)
	writeInstalledEvidence(t, rootPath, prior)
	priorPath := statusPath(rootPath, "/usr/local/bin/.sbxr-update-prior")
	if err := os.Link(statusPath(rootPath, executablePath), priorPath); err != nil {
		t.Fatal(err)
	}
	candidatePath := statusPath(rootPath, "/usr/local/bin/candidate-replacement")
	if err := os.WriteFile(candidatePath, candidate.executable, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(candidatePath, statusPath(rootPath, executablePath)); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(priorPath, statusPath(rootPath, "/usr/local/bin/unexplained-prior-copy")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if _, err := readPriorExecutable(root, digestBytes(prior.executable)); err == nil {
		t.Fatal("unexplained second prior link accepted")
	}
}

func TestUpdateRetainsRecoveryEvidenceWhenPriorAuthorityChangesLate(t *testing.T) {
	root := t.TempDir()
	prior := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	candidate := ReleaseIdentity{Repository: Repository, Tag: "v2.0.1", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
	writeInstalledEvidence(t, root, installedEvidence(t, prior, 17, AMD64))
	candidateEvidence := installedEvidence(t, candidate, 18, AMD64)
	source := &controlledUpdateSource{candidate: updateCandidateFromEvidence(t, candidate, 18, AMD64, candidateEvidence)}

	result := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), source).Update(t.Context(), func(progress Progress) {
		if progress.Status == "Activating the verified release" {
			_ = os.WriteFile(statusPath(root, "/usr/local/bin/.sbxr-update-prior"), []byte("changed prior"), 0o755)
			_ = os.WriteFile(statusPath(root, "/usr/local/bin/.sbxr-update-candidate"), []byte("changed candidate"), 0o755)
		}
	})

	if result.State != RecoveryRequiredState || result.Code != UpdateRecoveryRequired {
		t.Fatalf("Update() = %#v", result)
	}
	if _, err := os.Lstat(statusPath(root, "/var/lib/sbxr/update.json")); err != nil {
		t.Fatalf("recovery authority removed: %v", err)
	}
}

func TestUpdateDefersCancellationAfterPreparedToVerifiedCommit(t *testing.T) {
	root := t.TempDir()
	prior := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	candidate := ReleaseIdentity{Repository: Repository, Tag: "v2.0.1", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
	writeInstalledEvidence(t, root, installedEvidence(t, prior, 17, AMD64))
	candidateEvidence := installedEvidence(t, candidate, 18, AMD64)
	source := &controlledUpdateSource{candidate: updateCandidateFromEvidence(t, candidate, 18, AMD64, candidateEvidence)}
	ctx, cancel := context.WithCancel(t.Context())

	result := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), source).Update(ctx, func(progress Progress) {
		if progress.Status == "Activating the verified release" {
			cancel()
		}
	})

	if result.State != Ready || result.Code != UpdateInstalled || !result.UpdateInstalled {
		t.Fatalf("Update() = %#v", result)
	}
}

func TestCandidateRecoverUnderstandsPreparedSchemaOneFromThePriorRelease(t *testing.T) {
	root, priorEvidence, _, candidate := preparedRecoveryFixture(t)
	activateRecoveryFixture(t, root, candidate, false)
	prior, _ := verifyInstalledRelease(priorEvidence.installedRecord, priorEvidence.executable)

	var lifecycle Interface = newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), nil)
	result := lifecycle.Recover(t.Context(), nil)

	if result.State != Ready || result.Code != RecoverPriorRestored || result.Installed == nil || *result.Installed != prior.identity || !activeEvidenceMatches(t, root, priorEvidence) {
		t.Fatalf("Recover() = %#v", result)
	}
	for _, name := range transactionPaths {
		if _, err := os.Lstat(statusPath(root, name)); !os.IsNotExist(err) {
			t.Fatalf("transaction material remains at %s: %v", name, err)
		}
	}
}

func TestRecoverRefusesChangedPreparedEvidenceWithoutMutation(t *testing.T) {
	root, priorEvidence, _, _ := preparedRecoveryFixture(t)
	changedPath := statusPath(root, "/usr/local/bin/.sbxr-update-candidate")
	if err := os.WriteFile(changedPath, []byte("changed candidate"), 0o755); err != nil {
		t.Fatal(err)
	}

	result := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), nil).Recover(t.Context(), nil)

	changed, err := os.ReadFile(changedPath)
	if result.State != RecoveryRequiredState || result.Code != RecoverRefused || err != nil || string(changed) != "changed candidate" || !activeEvidenceMatches(t, root, priorEvidence) {
		t.Fatalf("Recover() = %#v; changed evidence = %q, %v", result, changed, err)
	}
}

func TestRecoverCommittedRetainsTheExactCandidatePairThroughPublicInterface(t *testing.T) {
	root, _, candidateEvidence, candidate := preparedRecoveryFixture(t)
	activateRecoveryFixture(t, root, candidate, true)
	installed, _ := verifyInstalledRelease(candidateEvidence.installedRecord, candidateEvidence.executable)

	result := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), nil).Recover(t.Context(), nil)

	if result.State != Ready || result.Code != RecoverCandidateRetained || result.Installed == nil || *result.Installed != installed.identity || !activeEvidenceMatches(t, root, candidateEvidence) {
		t.Fatalf("Recover() = %#v", result)
	}
	for _, name := range transactionPaths {
		if _, err := os.Lstat(statusPath(root, name)); !os.IsNotExist(err) {
			t.Fatalf("transaction material remains at %s: %v", name, err)
		}
	}
}

func TestRecoverRefusesChangedCommittedCleanupEvidenceWithoutMutation(t *testing.T) {
	root, _, candidateEvidence, candidate := preparedRecoveryFixture(t)
	activateRecoveryFixture(t, root, candidate, true)
	changedPath := statusPath(root, "/var/lib/sbxr/.installed.json.prior")
	if err := os.WriteFile(changedPath, []byte("changed prior record"), 0o600); err != nil {
		t.Fatal(err)
	}

	result := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), nil).Recover(t.Context(), nil)

	changed, err := os.ReadFile(changedPath)
	if result.State != RecoveryRequiredState || result.Code != RecoverRefused || err != nil || string(changed) != "changed prior record" || !activeEvidenceMatches(t, root, candidateEvidence) {
		t.Fatalf("Recover() = %#v; changed evidence = %q, %v", result, changed, err)
	}
	if _, err := os.Lstat(statusPath(root, "/usr/local/bin/.sbxr-update-prior")); err != nil {
		t.Fatalf("prior executable changed before refusal: %v", err)
	}
}

func TestRecoverReportsNotRequiredAndConcurrentMutation(t *testing.T) {
	root := t.TempDir()
	installed := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	writeInstalledEvidence(t, root, installedEvidence(t, installed, 17, AMD64))
	lifecycle := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), nil)

	if result := lifecycle.Recover(t.Context(), nil); result.State != Ready || result.Code != RecoverNotRequired || result.Installed == nil || *result.Installed != installed {
		t.Fatalf("not-required Recover() = %#v", result)
	}
	lockPath := statusPath(root, mutationLockPath)
	lock, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if result := lifecycle.Recover(t.Context(), nil); result.State != UpdateInProgress || result.Code != RecoverConcurrentMutation {
		t.Fatalf("concurrent Recover() = %#v", result)
	}
}

func TestRecoverReportsFailureAfterAProvenDirectionCannotFinish(t *testing.T) {
	root, _, _, _ := preparedRecoveryFixture(t)
	inspector := filesystemInspector{root: root, uid: uint32(os.Getuid()), beforeRecoveryMutation: func() {
		if err := os.WriteFile(statusPath(root, "/usr/local/bin/.sbxr-update-candidate"), []byte("late I/O failure"), 0o755); err != nil {
			t.Fatal(err)
		}
	}}

	result := newInstalledInterface(inspector, nil).Recover(t.Context(), nil)

	if result.State != RecoveryRequiredState || result.Code != RecoverFailed {
		t.Fatalf("Recover() = %#v", result)
	}
	if _, err := os.Lstat(statusPath(root, "/var/lib/sbxr/update.json")); err != nil {
		t.Fatalf("durable recovery authority removed: %v", err)
	}
}

func TestRecoverRefusesAnActiveTargetChangedDuringProgress(t *testing.T) {
	root, _, _, _ := preparedRecoveryFixture(t)
	changed := []byte("concurrently changed active executable")

	result := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), nil).Recover(t.Context(), func(Progress) {
		if err := os.WriteFile(statusPath(root, executablePath), changed, 0o755); err != nil {
			t.Fatal(err)
		}
	})

	active, err := os.ReadFile(statusPath(root, executablePath))
	if result.State != RecoveryRequiredState || result.Code != RecoverRefused || err != nil || !bytes.Equal(active, changed) {
		t.Fatalf("Recover() = %#v; active executable = %q, %v", result, active, err)
	}
}

func TestRecoverSafelyRepeatsInterruptedRestorationAndCleanup(t *testing.T) {
	t.Run("Prepared before activation", func(t *testing.T) {
		root, prior, _, _ := preparedRecoveryFixture(t)

		result := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), nil).Recover(t.Context(), nil)
		if result.State != Ready || result.Code != RecoverPriorRestored || !activeEvidenceMatches(t, root, prior) {
			t.Fatalf("Recover() = %#v", result)
		}
	})

	t.Run("Prepared restoration", func(t *testing.T) {
		root, prior, _, candidate := preparedRecoveryFixture(t)
		updateRoot, err := os.OpenRoot(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := activateCandidate(updateRoot, candidate); err != nil {
			t.Fatal(err)
		}
		if err := writeUpdateFile(updateRoot, "var/lib/sbxr/.installed.json.candidate", prior.installedRecord, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := updateRoot.Rename("var/lib/sbxr/.installed.json.candidate", "var/lib/sbxr/installed.json"); err != nil {
			t.Fatal(err)
		}
		if err := updateRoot.Close(); err != nil {
			t.Fatal(err)
		}

		result := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), nil).Recover(t.Context(), nil)
		if result.State != Ready || result.Code != RecoverPriorRestored || !activeEvidenceMatches(t, root, prior) {
			t.Fatalf("Recover() = %#v", result)
		}
	})

	t.Run("Prepared cleanup", func(t *testing.T) {
		root, prior, _, candidate := preparedRecoveryFixture(t)
		updateRoot, err := os.OpenRoot(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := activateCandidate(updateRoot, candidate); err != nil {
			t.Fatal(err)
		}
		if err := writeUpdateFile(updateRoot, "var/lib/sbxr/.installed.json.candidate", prior.installedRecord, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := updateRoot.Rename("var/lib/sbxr/.installed.json.candidate", "var/lib/sbxr/installed.json"); err != nil {
			t.Fatal(err)
		}
		if err := writeUpdateFile(updateRoot, "usr/local/bin/.sbxr-update-candidate", prior.executable, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := updateRoot.Rename("usr/local/bin/.sbxr-update-candidate", "usr/local/bin/sbxr"); err != nil {
			t.Fatal(err)
		}
		if err := updateRoot.Remove("usr/local/bin/.sbxr-update-prior"); err != nil {
			t.Fatal(err)
		}
		if err := updateRoot.Close(); err != nil {
			t.Fatal(err)
		}

		result := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), nil).Recover(t.Context(), nil)
		if result.State != Ready || result.Code != RecoverPriorRestored || !activeEvidenceMatches(t, root, prior) {
			t.Fatalf("Recover() = %#v", result)
		}
	})

	t.Run("Committed cleanup", func(t *testing.T) {
		root, _, candidateEvidence, candidate := preparedRecoveryFixture(t)
		updateRoot, err := os.OpenRoot(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := activateCandidate(updateRoot, candidate); err != nil {
			t.Fatal(err)
		}
		record, err := readUpdateRecord(updateRoot)
		if err != nil {
			t.Fatal(err)
		}
		record.Checkpoint = committedCheckpoint
		if err := publishUpdateRecord(updateRoot, record, preparedCheckpoint); err != nil {
			t.Fatal(err)
		}
		if err := updateRoot.Remove("var/lib/sbxr/.installed.json.prior"); err != nil {
			t.Fatal(err)
		}
		if err := updateRoot.Close(); err != nil {
			t.Fatal(err)
		}

		result := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), nil).Recover(t.Context(), nil)
		if result.State != Ready || result.Code != RecoverCandidateRetained || !activeEvidenceMatches(t, root, candidateEvidence) {
			t.Fatalf("Recover() = %#v", result)
		}
	})
}

func TestRecoverStrictEvidenceRefusalsChangeNothing(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, string)
	}{
		{"malformed record", func(t *testing.T, root string) {
			mustWriteStatusFile(t, statusPath(root, "/var/lib/sbxr/update.json"), []byte(`{"schema":1,"checkpoint":"Unknown"}`), 0o600)
		}},
		{"oversized record", func(t *testing.T, root string) {
			mustWriteStatusFile(t, statusPath(root, "/var/lib/sbxr/update.json"), bytes.Repeat([]byte("x"), maxUpdateRecord+1), 0o600)
		}},
		{"linked candidate record", func(t *testing.T, root string) {
			if err := os.Link(statusPath(root, "/var/lib/sbxr/.installed.json.candidate"), statusPath(root, "/var/lib/sbxr/unexpected-link")); err != nil {
				t.Fatal(err)
			}
		}},
		{"linked prior record", func(t *testing.T, root string) {
			path := statusPath(root, "/var/lib/sbxr/.installed.json.prior")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("installed.json", path); err != nil {
				t.Fatal(err)
			}
		}},
		{"changed publication residue", func(t *testing.T, root string) {
			mustWriteStatusFile(t, statusPath(root, "/var/lib/sbxr/.update.json.next"), []byte("changed"), 0o600)
		}},
		{"unsafe state directory", func(t *testing.T, root string) {
			if err := os.Chmod(statusPath(root, "/var/lib/sbxr"), 0o777); err != nil {
				t.Fatal(err)
			}
		}},
		{"contradictory candidate pair", func(t *testing.T, root string) {
			identity := ReleaseIdentity{Repository: Repository, Tag: "v2.0.2", Commit: strings.Repeat("e", 40), IndexSHA256: strings.Repeat("f", 64)}
			contradiction := installedEvidence(t, identity, 19, AMD64).installedRecord
			mustWriteStatusFile(t, statusPath(root, "/var/lib/sbxr/.installed.json.candidate"), contradiction, 0o600)
			var record updateRecord
			body, err := os.ReadFile(statusPath(root, "/var/lib/sbxr/update.json"))
			if err != nil || json.Unmarshal(body, &record) != nil {
				t.Fatal(err)
			}
			record.CandidateInstalledRecordSHA256 = digestBytes(contradiction)
			mustWriteStatusFile(t, statusPath(root, "/var/lib/sbxr/update.json"), updateRecordBytes(record), 0o600)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, prior, _, _ := preparedRecoveryFixture(t)
			test.change(t, root)
			before := recoverySurface(t, root)

			result := newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), nil).Recover(t.Context(), nil)

			if result.State != RecoveryRequiredState || result.Code != RecoverRefused || !reflect.DeepEqual(recoverySurface(t, root), before) || !activeEvidenceMatches(t, root, prior) {
				t.Fatalf("Recover() = %#v", result)
			}
		})
	}
}

func recoverySurface(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	paths := append([]string{executablePath, installedRecordPath, "/var/lib/sbxr/unexpected-link"}, transactionPaths...)
	for _, name := range paths {
		path := statusPath(root, name)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			result[name] = "missing"
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		value := fmt.Sprintf("%s:%o:%d:", info.Mode().Type(), info.Mode().Perm(), stat.Nlink)
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				t.Fatal(err)
			}
			result[name] = value + target
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		result[name] = value + digestBytes(body)
	}
	return result
}

func preparedRecoveryFixture(t *testing.T) (string, localInspection, localInspection, UpdateCandidate) {
	t.Helper()
	root := t.TempDir()
	prior := installedEvidence(t, ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}, 17, AMD64)
	candidateIdentity := ReleaseIdentity{Repository: Repository, Tag: "v2.0.1", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
	candidateEvidence := installedEvidence(t, candidateIdentity, 18, AMD64)
	writeInstalledEvidence(t, root, prior)
	candidate := updateCandidateFromEvidence(t, candidateIdentity, 18, AMD64, candidateEvidence)
	updateRoot, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	record := bindUpdateRecord(prior, candidate)
	if err := prepareUpdate(updateRoot, prior, candidate); err != nil {
		t.Fatal(err)
	}
	if err := publishUpdateRecord(updateRoot, record, ""); err != nil {
		t.Fatal(err)
	}
	if err := updateRoot.Close(); err != nil {
		t.Fatal(err)
	}
	return root, prior, candidateEvidence, candidate
}

func activateRecoveryFixture(t *testing.T, root string, candidate UpdateCandidate, committed bool) {
	t.Helper()
	updateRoot, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer updateRoot.Close()
	if err := activateCandidate(updateRoot, candidate); err != nil {
		t.Fatal(err)
	}
	if !committed {
		return
	}
	record, err := readUpdateRecord(updateRoot)
	if err != nil {
		t.Fatal(err)
	}
	record.Checkpoint = committedCheckpoint
	if err := publishUpdateRecord(updateRoot, record, preparedCheckpoint); err != nil {
		t.Fatal(err)
	}
}

func TestStatusReportsReadyFromVerifiedInstalledEvidence(t *testing.T) {
	identity := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	evidence := installedEvidence(t, identity, 17, AMD64)

	var lifecycle Interface = newInstalledInterface(controlledLocalInspector{evidence}, nil)
	got := lifecycle.Status(context.Background())

	if got.State != Ready || got.Code != StatusReady || got.Message != "SBXR is ready." || got.Installed == nil || *got.Installed != identity {
		t.Fatalf("Status() = %#v", got)
	}
}

func TestStatusRequiresRecoveryForUnverifiedLocalEvidence(t *testing.T) {
	identity := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	tests := []struct {
		name   string
		change func(*localInspection)
	}{
		{"missing", func(value *localInspection) { value.installedRecord = nil }},
		{"malformed", func(value *localInspection) { value.installedRecord = []byte(`{"schema":1`) }},
		{"contradictory release identity", func(value *localInspection) {
			value.installedRecord = []byte(strings.Replace(string(value.installedRecord), `"tag":"v2.0.0"`, `"tag":"v2.0.1"`, 1))
		}},
		{"contradictory release sequence", func(value *localInspection) {
			value.installedRecord = []byte(strings.Replace(string(value.installedRecord), `"sequence":17`, `"sequence":18`, 1))
		}},
		{"contradictory architecture", func(value *localInspection) {
			value.installedRecord = []byte(strings.Replace(string(value.installedRecord), `"architecture":"amd64"`, `"architecture":"arm64"`, 1))
		}},
		{"contradictory executable digest", func(value *localInspection) {
			var record installedRecord
			if json.Unmarshal(value.installedRecord, &record) != nil {
				panic("invalid test fixture")
			}
			record.ExecutableSHA256 = strings.Repeat("c", 64)
			value.installedRecord, _ = json.Marshal(record)
		}},
		{"unsafe", func(value *localInspection) { value.inspectionValid = false }},
		{"unfinished", func(value *localInspection) { value.transactionEvidence = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := installedEvidence(t, identity, 17, AMD64)
			test.change(&evidence)

			got := newInstalledInterface(controlledLocalInspector{evidence}, nil).Status(context.Background())

			if got.State != RecoveryRequiredState || got.Code != StatusRecoveryRequired || got.Message != "SBXR needs recovery before normal operations can continue." || strings.Contains(got.Message, "installed.json") {
				t.Fatalf("Status() = %#v", got)
			}
		})
	}
}

func TestStatusReportsConcurrentUpdateWithoutExposingLockFacts(t *testing.T) {
	evidence := installedEvidence(t, ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}, 17, AMD64)
	evidence.lockHeld = true

	got := newInstalledInterface(controlledLocalInspector{evidence}, nil).Status(context.Background())

	if got.State != UpdateInProgress || got.Code != StatusUpdateInProgress || got.Message != "Another Software Lifecycle change is in progress." || strings.Contains(got.Message, "lock") {
		t.Fatalf("Status() = %#v", got)
	}
}

func TestPendingOperationsReturnVerifiedStatusWithoutInventingAnOutcome(t *testing.T) {
	evidence := installedEvidence(t, ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}, 17, AMD64)
	var lifecycle Interface = newInstalledInterface(controlledLocalInspector{evidence}, nil)

	for name, result := range map[string]Result{
		"Recover": lifecycle.Recover(context.Background(), nil),
	} {
		if result.State != Ready || result.Code != RecoverNotRequired || result.Message != "SBXR does not need recovery." {
			t.Fatalf("%s() = %#v", name, result)
		}
	}
	if result := lifecycle.Check(context.Background(), nil); result.State != Ready || result.Code != CheckReleaseRefused {
		t.Fatalf("Check() = %#v", result)
	}

	evidence.transactionEvidence = true
	lifecycle = newInstalledInterface(controlledLocalInspector{evidence}, nil)
	if result := lifecycle.Recover(context.Background(), nil); result.State != RecoveryRequiredState || result.Code != RecoverRefused {
		t.Fatalf("Recover() = %#v", result)
	}
}

func TestUpdateInstallsFreshQualifiedHigherSequenceThroughPublicInterface(t *testing.T) {
	root := t.TempDir()
	prior := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	candidate := ReleaseIdentity{Repository: Repository, Tag: "v2.0.1", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
	priorEvidence := installedEvidence(t, prior, 17, AMD64)
	candidateEvidence := installedEvidence(t, candidate, 18, AMD64)
	writeInstalledEvidence(t, root, priorEvidence)
	source := &controlledUpdateSource{candidate: updateCandidateFromEvidence(t, candidate, 18, AMD64, candidateEvidence)}
	var lifecycle Interface = newInstalledInterface(newLocalInspector(root, uint32(os.Getuid())), source)
	var preparedRecord []byte

	result := lifecycle.Update(t.Context(), func(progress Progress) {
		if progress.Status == "Activating the verified release" {
			preparedRecord, _ = os.ReadFile(statusPath(root, "/var/lib/sbxr/update.json"))
		}
	})

	if result.State != Ready || result.Code != UpdateInstalled || !result.UpdateInstalled || result.Installed == nil || *result.Installed != candidate || source.calls.Load() != 1 {
		t.Fatalf("Update() = %#v, fresh calls = %d", result, source.calls.Load())
	}
	if status := lifecycle.Status(t.Context()); status.State != Ready || status.Installed == nil || *status.Installed != candidate {
		t.Fatalf("Status() = %#v", status)
	}
	wantPrepared := fmt.Sprintf("{\"schema\":1,\"checkpoint\":\"Prepared\",\"prior_executable_sha256\":%q,\"prior_installed_record_sha256\":%q,\"candidate_executable_sha256\":%q,\"candidate_installed_record_sha256\":%q}\n", digestBytes(priorEvidence.executable), digestBytes(priorEvidence.installedRecord), digestBytes(candidateEvidence.executable), digestBytes(source.candidate.cell.record))
	if string(preparedRecord) != wantPrepared {
		t.Fatalf("Prepared record = %q", preparedRecord)
	}
	for _, name := range transactionPaths {
		if _, err := os.Lstat(statusPath(root, name)); !os.IsNotExist(err) {
			t.Fatalf("transaction material remains at %s: %v", name, err)
		}
	}
}

func TestCheckReportsQualifiedLatestReleaseBySequence(t *testing.T) {
	installed := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	latest := ReleaseIdentity{Repository: Repository, Tag: "v2.0.1", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
	evidence := installedEvidence(t, installed, 17, AMD64)

	for _, test := range []struct {
		name     string
		release  LatestRelease
		wantCode ResultCode
		wantLast *ReleaseIdentity
	}{
		{"higher sequence", LatestRelease{Identity: latest, Sequence: 18}, CheckUpdateAvailable, &latest},
		{"same identity and sequence", LatestRelease{Identity: installed, Sequence: 17}, CheckAlreadyCurrent, &installed},
		{"same sequence different identity", LatestRelease{Identity: latest, Sequence: 17}, CheckReleaseRefused, nil},
		{"lower sequence", LatestRelease{Identity: latest, Sequence: 16}, CheckReleaseRefused, nil},
		{"same identity different sequence", LatestRelease{Identity: installed, Sequence: 18}, CheckReleaseRefused, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := newInstalledInterface(controlledLocalInspector{evidence: evidence}, controlledLatestSource{result: test.release, outcome: LatestReleaseAccepted}).Check(t.Context(), nil)
			if result.State != Ready || result.Code != test.wantCode || result.Installed == nil || *result.Installed != installed || !reflect.DeepEqual(result.Latest, test.wantLast) {
				t.Fatalf("Check() = %#v", result)
			}
		})
	}
}

func TestCheckReportsOnlyItsVerifiedRemoteWork(t *testing.T) {
	installed := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	evidence := installedEvidence(t, installed, 17, AMD64)
	var reports []Progress

	newInstalledInterface(controlledLocalInspector{evidence: evidence}, controlledLatestSource{outcome: LatestReleaseUnavailable}).Check(t.Context(), func(progress Progress) {
		reports = append(reports, progress)
	})

	want := []Progress{{Operation: CheckOperation, Status: "Checking the qualified latest release", Mode: Spinner}}
	if !reflect.DeepEqual(reports, want) {
		t.Fatalf("Check progress = %+v, want %+v", reports, want)
	}
}

func TestCheckDistinguishesSafeReleaseAndLocalOutcomes(t *testing.T) {
	installed := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	evidence := installedEvidence(t, installed, 17, AMD64)
	for _, test := range []struct {
		name    string
		outcome LatestReleaseOutcome
		want    ResultCode
	}{
		{"release refused", LatestReleaseRefused, CheckReleaseRefused},
		{"release unavailable", LatestReleaseUnavailable, CheckReleaseUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := newInstalledInterface(controlledLocalInspector{evidence: evidence}, controlledLatestSource{outcome: test.outcome}).Check(t.Context(), nil)
			if result.State != Ready || result.Code != test.want || result.Latest != nil || strings.Contains(result.Message, "PRIVATE-MARKER") {
				t.Fatalf("Check() = %#v", result)
			}
		})
	}

	called := false
	notReady := evidence
	notReady.transactionEvidence = true
	result := newInstalledInterface(controlledLocalInspector{evidence: notReady}, controlledLatestSource{check: func() { called = true }}).Check(t.Context(), nil)
	if called || result.State != RecoveryRequiredState || result.Code != CheckNotReady {
		t.Fatalf("Check() = %#v, remote called = %t", result, called)
	}
}

func TestCheckRefusesResultAfterAnyConcurrentLocalChange(t *testing.T) {
	installed := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	latest := ReleaseIdentity{Repository: Repository, Tag: "v2.0.1", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
	before := installedEvidence(t, installed, 17, AMD64)
	after := before
	after.lockHeld = true
	reads := 0
	local := changingLocalInspector{next: func() localInspection {
		reads++
		if reads == 1 {
			return before
		}
		return after
	}}

	result := newInstalledInterface(local, controlledLatestSource{result: LatestRelease{Identity: latest, Sequence: 18}, outcome: LatestReleaseAccepted}).Check(t.Context(), nil)

	if result.State != UpdateInProgress || result.Code != CheckConcurrentChange || result.Latest != nil || reads != 2 {
		t.Fatalf("Check() = %#v, reads = %d", result, reads)
	}
}

func installedEvidence(t *testing.T, identity ReleaseIdentity, sequence uint64, architecture Architecture) localInspection {
	t.Helper()
	payload := []byte("test executable")
	executable := installedExecutableFixture(t, payload, embeddedIdentity{Schema: 1, Repository: identity.Repository, Tag: identity.Tag, Commit: identity.Commit, Sequence: sequence, Architecture: architecture})
	executableDigest := sha256.Sum256(executable)
	record := installedRecord{Schema: 1, Repository: identity.Repository, Tag: identity.Tag, Commit: identity.Commit, ReleaseIndexSHA256: identity.IndexSHA256, Sequence: sequence, Architecture: architecture, ExecutableSHA256: hex.EncodeToString(executableDigest[:])}
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return localInspection{inspectionValid: true, installedRecord: append(body, '\n'), executable: executable}
}

func installedExecutableFixture(t *testing.T, payload []byte, identity embeddedIdentity) []byte {
	t.Helper()
	payloadDigest := sha256.Sum256(payload)
	identity.PayloadSHA256 = hex.EncodeToString(payloadDigest[:])
	document, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	documentDigest := sha256.Sum256(document)
	result := append([]byte(nil), payload...)
	result = append(result, document...)
	result = append(result, documentDigest[:]...)
	result = binary.LittleEndian.AppendUint64(result, uint64(len(document)))
	return append(result, identityMagic...)
}

func writeInstalledEvidence(t *testing.T, root string, evidence localInspection) {
	t.Helper()
	for _, directory := range []string{"usr/local/bin", "var/lib/sbxr", "run/lock"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	mustWriteStatusFile(t, statusPath(root, executablePath), evidence.executable, 0o755)
	mustWriteStatusFile(t, statusPath(root, installedRecordPath), evidence.installedRecord, 0o600)
	if err := os.Chmod(statusPath(root, "/var/lib/sbxr"), 0o700); err != nil {
		t.Fatal(err)
	}
}

func updateCandidateFromEvidence(t *testing.T, identity ReleaseIdentity, sequence uint64, architecture Architecture, evidence localInspection) UpdateCandidate {
	t.Helper()
	candidate, ok := newUpdateCandidate(LatestRelease{Identity: identity, Sequence: sequence}, architecture, evidence.executable)
	if !ok {
		t.Fatal("candidate fixture refused")
	}
	return candidate
}

func activeEvidenceMatches(t *testing.T, root string, evidence localInspection) bool {
	t.Helper()
	record, recordErr := os.ReadFile(statusPath(root, installedRecordPath))
	executable, executableErr := os.ReadFile(statusPath(root, executablePath))
	return recordErr == nil && executableErr == nil && bytes.Equal(record, evidence.installedRecord) && bytes.Equal(executable, evidence.executable)
}
