package ubuntu

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestRecoveryStartingStatusComesFromTheProtectedTransaction(t *testing.T) {
	for _, status := range []systemchanges.InstallationStatus{systemchanges.NotInstalled, systemchanges.Managed} {
		t.Run(string(status), func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, transactionDirectory, "client-access-recovery")
			if err := os.MkdirAll(filepath.Join(directory, "snapshot"), 0o700); err != nil || os.MkdirAll(filepath.Join(directory, "prepared"), 0o700) != nil {
				t.Fatal("create transaction")
			}
			files := map[string][]byte{"prepared/state.json": []byte("state"), "prepared/manifests.json": []byte("manifests")}
			if status == systemchanges.Managed {
				files["snapshot/prior-state.json"] = []byte("prior")
			}
			checksums := map[string]string{}
			for name, body := range files {
				path := filepath.Join(directory, name)
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
				checksums[name] = testDigest(body)
			}
			release := systemchanges.ReleaseBinding{Repository: "albertloky/SBXR", Tag: "v1.0.0", Commit: "0123456789abcdef0123456789abcdef01234567", ReleaseIndexSHA256: testDigest([]byte("release"))}
			mutation, owner := systemchanges.SettingChangeMutation, systemchanges.StateModule
			starting := systemchanges.StateLineage{Status: status}
			binding := systemchanges.StateTransactionBinding{ChangeSet: "client-access-recovery", CandidateRevision: 1, CandidateSHA256: testDigest([]byte("candidate")), CandidateRelease: release, PreparedStateSHA256: checksums["prepared/state.json"], PreparedManifestSHA256: checksums["prepared/manifests.json"]}
			if status == systemchanges.Managed {
				starting.Revision, starting.SHA256 = 7, testDigest([]byte("starting"))
				binding.StartingRevision, binding.CandidateRevision, binding.StartingSHA256, binding.StartingRelease = 7, 8, starting.SHA256, release
			} else {
				mutation, owner = systemchanges.InstallationMutation, systemchanges.SoftwareModule
			}
			entry := journalEntry{Checkpoint: systemchanges.Prepared, ChangeSet: "client-access-recovery", Mutation: mutation, Starting: starting, OutcomeOwner: owner, PlanSHA256: testDigest([]byte("plan")), State: &binding,
				Steps:  []journalStep{{Owner: systemchanges.ConnectionProfilesModule, Forward: systemchanges.ActivatePreparedConfiguration, Rollback: systemchanges.RestorePriorConfiguration, Cancellation: systemchanges.SafeCheckpointCancellation, Inspection: systemchanges.InspectBeforeIdempotentReverse}},
				Checks: []systemchanges.Check{{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-ACTIVE"}}, Timeouts: systemchanges.Timeouts{Step: time.Minute, Check: time.Minute}}
			journal, _ := json.Marshal(entry)
			if err := os.WriteFile(filepath.Join(directory, "journal.jsonl"), append(journal, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			manifest, _ := json.Marshal(snapshotManifest{SchemaVersion: 1, Release: release, Reason: mutation, Files: checksums})
			if err := os.WriteFile(filepath.Join(directory, "manifest.json"), manifest, 0o600); err != nil {
				t.Fatal(err)
			}
			pending, found, err := NewAt(root, nil, nil).PendingChangeSet()
			gotRelease := pending.StartingRelease
			if gotRelease == (systemchanges.ReleaseBinding{}) {
				gotRelease = pending.CandidateRelease
			}
			if err != nil || !found || pending.StartingStatus != status || gotRelease != release || pending.ForwardOnly || pending.Checkpoint != systemchanges.Prepared {
				t.Fatalf("starting recovery = %+v, found=%t, %v; want %s, %+v", pending, found, err, status, release)
			}
			base := systemchanges.Observation{Status: status, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
			if status == systemchanges.Managed {
				base.StateRevision, base.StateSHA256, base.LastChangeSet = 7, starting.SHA256, "change-0007"
			}
			observed, err := RecoveryHealthObservation(root, func() (systemchanges.Observation, error) { return base, nil })
			if err != nil || observed.Status != systemchanges.ChangeInProgress || observed.CurrentChangeSet != "client-access-recovery" || observed.Checkpoint != systemchanges.PreparedCheckpoint || observed.TotalSteps != 1 || !observed.RollbackAvailable {
				t.Fatalf("health recovery observation = %+v, %v", observed, err)
			}
			if err := os.WriteFile(filepath.Join(directory, "journal.jsonl"), []byte("{\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			observed, err = RecoveryHealthObservation(root, func() (systemchanges.Observation, error) { return base, nil })
			if err != nil || observed.Status != systemchanges.RecoveryRequired || observed.RecoveryCause != systemchanges.JournalUnprovable {
				t.Fatalf("invalid health recovery observation = %+v, %v", observed, err)
			}
		})
	}
}

func TestRecoveryStartingReleaseReportsEveryForwardRunTokenCheckpoint(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, transactionDirectory, "run-token-recovery")
	if err := os.MkdirAll(filepath.Join(directory, "snapshot"), 0o700); err != nil || os.MkdirAll(filepath.Join(directory, "prepared"), 0o700) != nil {
		t.Fatal("create transaction")
	}
	files := map[string][]byte{"prepared/state.json": []byte("state"), "prepared/manifests.json": []byte("manifests"), "snapshot/prior-state.json": []byte("prior")}
	checksums := map[string]string{}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(directory, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
		checksums[name] = testDigest(body)
	}
	release := systemchanges.ReleaseBinding{Repository: "albertloky/SBXR", Tag: "v1.0.0", Commit: "0123456789abcdef0123456789abcdef01234567", ReleaseIndexSHA256: testDigest([]byte("release"))}
	starting := systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: testDigest([]byte("starting"))}
	binding := systemchanges.StateTransactionBinding{ChangeSet: "run-token-recovery", StartingRevision: 7, CandidateRevision: 8, StartingSHA256: starting.SHA256, CandidateSHA256: testDigest([]byte("candidate")), StartingRelease: release, CandidateRelease: release, PreparedStateSHA256: checksums["prepared/state.json"], PreparedManifestSHA256: checksums["prepared/manifests.json"]}
	evidence := &systemchanges.StepEvidence{Code: "RUN-TOKEN-EVIDENCE", SHA256: testDigest([]byte("token"))}
	entries := []journalEntry{
		{Checkpoint: systemchanges.Prepared, ChangeSet: "run-token-recovery", Mutation: systemchanges.RotationMutation, Starting: starting, OutcomeOwner: systemchanges.CloudflareModule, PlanSHA256: testDigest([]byte("plan")), State: &binding, Steps: []journalStep{{Owner: systemchanges.CloudflareModule, Forward: systemchanges.RotateCloudflaredRunToken, Rollback: systemchanges.RestoreCloudflaredService, Cancellation: systemchanges.SafeCheckpointCancellation, Inspection: systemchanges.InspectBeforeIdempotentReverse}}, Checks: []systemchanges.Check{{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CLOUDFLARE-WHOLE-TUNNEL"}}, Timeouts: systemchanges.Timeouts{Step: time.Minute, Check: time.Minute}},
		{Checkpoint: systemchanges.IrreversibleRunTokenRotationStarted, Evidence: evidence},
		{Checkpoint: systemchanges.StateFinalized, State: &binding},
		{Checkpoint: systemchanges.StepStarted, Step: 1},
		{Checkpoint: systemchanges.StepCompleted, Step: 1, Evidence: evidence},
		{Checkpoint: systemchanges.PrePublicationHealthPassed},
		{Checkpoint: systemchanges.StatePublicationStarted},
		{Checkpoint: systemchanges.StatePublished},
		{Checkpoint: systemchanges.PostPublicationHealthPassed},
		{Checkpoint: systemchanges.Complete},
	}
	manifest, _ := json.Marshal(snapshotManifest{SchemaVersion: 1, Release: release, Reason: systemchanges.RotationMutation, Files: checksums})
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	for length := 2; length <= len(entries); length++ {
		file, err := os.OpenFile(filepath.Join(directory, "journal.jsonl"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries[:length] {
			encoded, _ := json.Marshal(entry)
			_, _ = file.Write(append(encoded, '\n'))
		}
		_ = file.Close()
		pending, found, err := NewAt(root, nil, nil).PendingChangeSet()
		if err != nil || !found || !pending.ForwardOnly || pending.Checkpoint != entries[length-1].Checkpoint {
			t.Fatalf("checkpoint %s = pending=%+v found=%t err=%v", entries[length-1].Checkpoint, pending, found, err)
		}
		base := systemchanges.Observation{Status: systemchanges.Managed, LastChangeSet: "change-0007", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, StateRevision: starting.Revision, StateSHA256: starting.SHA256, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
		observed, err := RecoveryHealthObservation(root, func() (systemchanges.Observation, error) { return base, nil })
		if err != nil || observed.Status != systemchanges.ChangeInProgress || observed.CurrentChangeSet != "run-token-recovery" || observed.RollbackAvailable {
			t.Fatalf("checkpoint %s health observation = %+v, %v", entries[length-1].Checkpoint, observed, err)
		}
	}
}

func testDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}
