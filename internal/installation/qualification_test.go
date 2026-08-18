package installation

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/state"
	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

func TestControlledInstallationRunsThroughRevisionOneAndCleansItsRoot(t *testing.T) {
	parent := t.TempDir()
	root, err := os.MkdirTemp(parent, "sbxr-controlled-install-")
	if err != nil {
		t.Fatal(err)
	}
	load, err := RunControlledInstallationAt(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := statefilesystem.NewAt(root).Load(load)
	if err != nil || loaded.Snapshot == nil || !controlledRevisionOne(loaded.Snapshot.DesiredState) {
		t.Fatalf("revision 1 = %+v, %v", loaded, err)
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("controlled root cleanup = %v, %v", entries, err)
	}
}

func TestControlledInstallationDeathRestartsAfterStatePublication(t *testing.T) {
	if os.Getenv("SBXR_CONTROLLED_INSTALL_DEATH_CHILD") != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestControlledInstallationDeathRestartsAfterStatePublication$")
		command.Env = append(os.Environ(), "SBXR_CONTROLLED_INSTALL_DEATH_CHILD=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("controlled Installation death subprocess: %v\n%s", err, output)
		}
		return
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	request, err := controlledInstallRequest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applyControlledInstallationWithDeath(t.Context(), root, request, systemchanges.StatePublished); err == nil || err.Error() != "controlled Installation worker death" {
		t.Fatalf("controlled worker death = %v", err)
	}
	identity := request.Candidate.Verified.Identity
	release := state.ReleaseIdentity{Repository: identity.Repository, Tag: identity.Tag, Commit: identity.Commit, ReleaseIndexSHA256: identity.IndexSHA256}
	load := state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: 1, LastCompletedChangeSet: requestChangeSet(request), ReleaseIdentity: release}}
	stateModule := statefilesystem.NewAt(root)
	loaded, err := stateModule.Load(load)
	if err != nil || loaded.Snapshot == nil {
		t.Fatalf("published revision 1 = (%+v, %v)", loaded, err)
	}
	_, sha, _, _, valid := stateModule.SystemChangesLineageInspection(loaded).SystemChangesStateLineageFacts()
	if !valid {
		t.Fatal("published revision 1 lineage unavailable")
	}
	observation := systemchanges.Observation{Status: systemchanges.Managed, StateRevision: 1, StateSHA256: sha, LastChangeSet: string(requestChangeSet(request)), Lock: systemchanges.LockReleased, VolatileSHA256: strings.Repeat("9", 64), WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
	adapter, err := systemubuntu.NewControlledInstallRecoveryAdapter(root, observation, stateModule)
	if err != nil {
		t.Fatal(err)
	}
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.Completed && result.Outcome != systemchanges.RecoveryRequiredOutcome {
		t.Fatalf("fresh Installation recovery = %+v", result)
	}
	journal := filepath.Join(root, "var/lib/sbxr/transactions", string(requestChangeSet(request)), "journal.jsonl")
	if _, err := os.Stat(journal); result.Outcome == systemchanges.Completed && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed recovery journal error = %v", err)
	}
}

func TestControlledInstallationCleansItsRootAfterRefusal(t *testing.T) {
	parent := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := RunControlledInstallation(ctx, parent); err == nil {
		t.Fatal("cancelled controlled Installation passed")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("refused controlled root cleanup = %v, %v", entries, err)
	}
}
