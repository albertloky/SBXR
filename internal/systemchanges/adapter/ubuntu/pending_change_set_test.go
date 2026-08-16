package ubuntu

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestPendingChangeSetReportsEverySupportedMutationKind(t *testing.T) {
	tests := []struct {
		kind  systemchanges.MutationClass
		owner systemchanges.Module
	}{
		{systemchanges.InstallationMutation, systemchanges.SoftwareModule},
		{systemchanges.RepairMutation, systemchanges.SoftwareModule},
		{systemchanges.SettingChangeMutation, systemchanges.StateModule},
		{systemchanges.RotationMutation, systemchanges.CloudflareModule},
		{systemchanges.CertificateChangeMutation, systemchanges.CertificateModule},
		{systemchanges.UpdateMutation, systemchanges.SoftwareModule},
		{systemchanges.CertificateRenewalMutation, systemchanges.CertificateModule},
		{systemchanges.CloudflareProfileSetupMutation, systemchanges.CloudflareModule},
		{systemchanges.CompleteRemovalMutation, systemchanges.SoftwareModule},
	}
	for _, test := range tests {
		t.Run(string(test.kind), func(t *testing.T) {
			root := t.TempDir()
			writePendingChangeSet(t, root, test.kind, test.owner)
			pending, found, err := NewAt(root, nil, nil).PendingChangeSet()
			if err != nil || !found || pending.Identity != "change-0008" || pending.Kind != test.kind || pending.TotalSteps != 1 || pending.Checkpoint != systemchanges.Prepared {
				t.Fatalf("pending Change Set = %+v, found=%t, err=%v", pending, found, err)
			}
		})
	}
}

func TestPendingChangeSetReportsNoPendingTransaction(t *testing.T) {
	for _, createDirectory := range []bool{false, true} {
		root := t.TempDir()
		if createDirectory {
			if err := os.MkdirAll(filepath.Join(root, transactionDirectory), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		pending, found, err := NewAt(root, nil, nil).PendingChangeSet()
		if err != nil || found || pending != (systemchanges.PendingChangeSet{}) {
			t.Fatalf("no pending Change Set = %+v, found=%t, err=%v", pending, found, err)
		}
	}
}

func TestPendingChangeSetReportsFinalizingCompleteRemoval(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, transactionDirectory, finalizingRemovalDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	pending, found, err := NewAt(root, nil, nil).PendingChangeSet()
	if err != nil || !found || pending.Identity != finalizingRemovalDirectory || pending.Kind != systemchanges.CompleteRemovalMutation || !pending.ForwardOnly || pending.Checkpoint != systemchanges.FinalRemovalAbsenceVerified {
		t.Fatalf("finalizing Complete removal = %+v, found=%t, err=%v", pending, found, err)
	}
	if err := os.WriteFile(filepath.Join(root, transactionDirectory, finalizingRemovalDirectory, "unexpected"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if pending, found, err := NewAt(root, nil, nil).PendingChangeSet(); err == nil || found || pending != (systemchanges.PendingChangeSet{}) {
		t.Fatalf("invalid finalizing Complete removal = %+v, found=%t, err=%v", pending, found, err)
	}
}

func TestPendingChangeSetFailsClosedForUnprovedDurableMaterial(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"invalid ownership", func(t *testing.T, root string) {
			rewritePreparedJournal(t, root, func(entry *journalEntry) { entry.OutcomeOwner = "Owner Console" })
		}},
		{"contradictory mutation and baseline", func(t *testing.T, root string) {
			rewritePreparedJournal(t, root, func(entry *journalEntry) { entry.Mutation = systemchanges.InstallationMutation })
			rewriteManifestReason(t, root, systemchanges.InstallationMutation)
		}},
		{"unsupported mutation", func(t *testing.T, root string) {
			rewritePreparedJournal(t, root, func(entry *journalEntry) { entry.Mutation = "Unknown" })
		}},
		{"invalid lineage", func(t *testing.T, root string) {
			name := filepath.Join(root, transactionDirectory, "change-0008", "manifest.json")
			if err := os.WriteFile(name, []byte(`{"schema_version":1}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"conflicting material", func(t *testing.T, root string) {
			if err := os.Mkdir(filepath.Join(root, transactionDirectory, "change-0009"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory identity mismatch", func(t *testing.T, root string) {
			if err := os.Rename(filepath.Join(root, transactionDirectory, "change-0008"), filepath.Join(root, transactionDirectory, "change-0009")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writePendingChangeSet(t, root, systemchanges.SettingChangeMutation, systemchanges.StateModule)
			test.mutate(t, root)
			if pending, found, err := NewAt(root, nil, nil).PendingChangeSet(); err == nil || found || pending != (systemchanges.PendingChangeSet{}) {
				t.Fatalf("unproved pending Change Set = %+v, found=%t, err=%v", pending, found, err)
			}
		})
	}

	t.Run("read failure", func(t *testing.T) {
		root := t.TempDir()
		name := filepath.Join(root, transactionDirectory)
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil || os.WriteFile(name, nil, 0o600) != nil {
			t.Fatal("create unreadable transaction seam")
		}
		if pending, found, err := NewAt(root, nil, nil).PendingChangeSet(); err == nil || found || pending != (systemchanges.PendingChangeSet{}) {
			t.Fatalf("unreadable pending Change Set = %+v, found=%t, err=%v", pending, found, err)
		}
	})
}

func writePendingChangeSet(t *testing.T, root string, kind systemchanges.MutationClass, owner systemchanges.Module) {
	t.Helper()
	directory := filepath.Join(root, transactionDirectory, "change-0008")
	if err := os.MkdirAll(filepath.Join(directory, "snapshot"), 0o700); err != nil || os.MkdirAll(filepath.Join(directory, "prepared"), 0o700) != nil {
		t.Fatal("create transaction")
	}
	files := map[string][]byte{"prepared/state.json": []byte("state"), "prepared/manifests.json": []byte("manifests")}
	release := systemchanges.ReleaseBinding{Repository: "albertloky/SBXR", Tag: "v1.0.0", Commit: "0123456789abcdef0123456789abcdef01234567", ReleaseIndexSHA256: testDigest([]byte("release"))}
	starting := systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: testDigest([]byte("starting"))}
	binding := systemchanges.StateTransactionBinding{ChangeSet: "change-0008", StartingRevision: 7, CandidateRevision: 8, StartingSHA256: starting.SHA256, CandidateSHA256: testDigest([]byte("candidate")), StartingRelease: release, CandidateRelease: release}
	if kind == systemchanges.InstallationMutation {
		starting = systemchanges.StateLineage{Status: systemchanges.NotInstalled}
		binding.StartingRevision, binding.CandidateRevision, binding.StartingSHA256, binding.StartingRelease = 0, 1, "", systemchanges.ReleaseBinding{}
	} else {
		files["snapshot/prior-state.json"] = []byte("prior")
	}
	checksums := map[string]string{}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(directory, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
		checksums[name] = testDigest(body)
	}
	binding.PreparedStateSHA256, binding.PreparedManifestSHA256 = checksums["prepared/state.json"], checksums["prepared/manifests.json"]
	entry := journalEntry{Checkpoint: systemchanges.Prepared, ChangeSet: "change-0008", Mutation: kind, Starting: starting, OutcomeOwner: owner, PlanSHA256: testDigest([]byte("plan")), State: &binding,
		Steps:  []journalStep{{Owner: systemchanges.ConnectionProfilesModule, Forward: systemchanges.ActivatePreparedConfiguration, Rollback: systemchanges.RestorePriorConfiguration, Cancellation: systemchanges.SafeCheckpointCancellation, Inspection: systemchanges.InspectBeforeIdempotentReverse}},
		Checks: []systemchanges.Check{{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-ACTIVE"}}, Timeouts: systemchanges.Timeouts{Step: time.Minute, Check: time.Minute}}
	writePreparedJournal(t, directory, entry)
	manifest, _ := json.Marshal(snapshotManifest{SchemaVersion: 1, Release: recoveryRelease(binding), Reason: kind, Files: checksums})
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
}

func rewritePreparedJournal(t *testing.T, root string, mutate func(*journalEntry)) {
	t.Helper()
	directory := filepath.Join(root, transactionDirectory, "change-0008")
	body, err := os.ReadFile(filepath.Join(directory, "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var entry journalEntry
	if json.Unmarshal(body, &entry) != nil {
		t.Fatal("decode journal")
	}
	mutate(&entry)
	writePreparedJournal(t, directory, entry)
}

func rewriteManifestReason(t *testing.T, root string, reason systemchanges.MutationClass) {
	t.Helper()
	name := filepath.Join(root, transactionDirectory, "change-0008", "manifest.json")
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var manifest snapshotManifest
	if json.Unmarshal(body, &manifest) != nil {
		t.Fatal("decode manifest")
	}
	manifest.Reason = reason
	body, _ = json.Marshal(manifest)
	if err := os.WriteFile(name, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writePreparedJournal(t *testing.T, directory string, entry journalEntry) {
	t.Helper()
	body, _ := json.Marshal(entry)
	if err := os.WriteFile(filepath.Join(directory, "journal.jsonl"), append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
