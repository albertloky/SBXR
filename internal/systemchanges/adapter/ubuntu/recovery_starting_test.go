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
			starting := systemchanges.StateLineage{Status: status}
			binding := systemchanges.StateTransactionBinding{ChangeSet: "client-access-recovery", CandidateRevision: 1, CandidateSHA256: testDigest([]byte("candidate")), CandidateRelease: release, PreparedStateSHA256: checksums["prepared/state.json"], PreparedManifestSHA256: checksums["prepared/manifests.json"]}
			if status == systemchanges.Managed {
				starting.Revision, starting.SHA256 = 7, testDigest([]byte("starting"))
				binding.StartingRevision, binding.CandidateRevision, binding.StartingSHA256, binding.StartingRelease = 7, 8, starting.SHA256, release
			}
			entry := journalEntry{Checkpoint: systemchanges.Prepared, ChangeSet: "client-access-recovery", Mutation: systemchanges.SettingChangeMutation, Starting: starting, OutcomeOwner: systemchanges.StateModule, PlanSHA256: testDigest([]byte("plan")), State: &binding,
				Steps:  []journalStep{{Owner: systemchanges.ConnectionProfilesModule, Forward: systemchanges.ActivatePreparedConfiguration, Rollback: systemchanges.RestorePriorConfiguration, Cancellation: systemchanges.SafeCheckpointCancellation, Inspection: systemchanges.InspectBeforeIdempotentReverse}},
				Checks: []systemchanges.Check{{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-ACTIVE"}}, Timeouts: systemchanges.Timeouts{Step: time.Minute, Check: time.Minute}}
			journal, _ := json.Marshal(entry)
			if err := os.WriteFile(filepath.Join(directory, "journal.jsonl"), append(journal, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			manifest, _ := json.Marshal(snapshotManifest{SchemaVersion: 1, Release: release, Reason: systemchanges.SettingChangeMutation, Files: checksums})
			if err := os.WriteFile(filepath.Join(directory, "manifest.json"), manifest, 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := RecoveryStartingStatus(root)
			if err != nil || got != status {
				t.Fatalf("starting status = %s, %v; want %s", got, err, status)
			}
		})
	}
}

func testDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}
