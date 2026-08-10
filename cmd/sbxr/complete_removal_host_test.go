package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

func TestCompleteRemovalLocalDeletionDoesNotFollowSymlinksAndDeletesRunnerLast(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "keep")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "var/lib/sbxr/state")
	if err := os.MkdirAll(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(statePath, "outside")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"etc/systemd/system/sbxr-recovery.service", "usr/local/bin/sbxr"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("owned"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	host := completeRemovalHost{root: root, run: func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "is-active" {
			return []byte("inactive\n"), errors.New("inactive")
		}
		if len(args) > 0 && args[0] == "is-enabled" {
			return []byte("disabled\n"), errors.New("disabled")
		}
		return nil, nil
	}}
	if _, err := host.DeleteIrreversibleRemovalPhase(systemchanges.LocalStatePhase, time.Second); err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(outside); err != nil || string(body) != "keep" {
		t.Fatalf("symlink target changed: %q %v", body, err)
	}
	if _, err := os.Stat(filepath.Join(root, "usr/local/bin/sbxr")); err != nil {
		t.Fatalf("recovery runner was removed before finalization: %v", err)
	}
	if err := host.PrepareRemovalFinalization(time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "usr/local/bin/sbxr")); err != nil {
		t.Fatalf("recovery runner disappeared before final unlink: %v", err)
	}
	if err := host.FinalizeRemoval(time.Second); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"etc/systemd/system/sbxr-recovery.service", "usr/local/bin/sbxr"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("final runner material remains: %s %v", name, err)
		}
	}
}

func TestCompleteRemovalDisablesEveryManagedTimerBeforeDeletingUnits(t *testing.T) {
	root := t.TempDir()
	for _, unit := range removalManagedUnits() {
		path := filepath.Join(root, "etc/systemd/system", unit)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("owned"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var disabled []string
	host := completeRemovalHost{root: root, run: func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, error) {
		if len(args) > 2 && args[0] == "disable" {
			disabled = append(disabled, args[2:]...)
			return nil, nil
		}
		if len(args) > 0 && (args[0] == "is-active" || args[0] == "is-enabled") {
			if args[0] == "is-active" {
				return []byte("inactive\n"), errors.New("inactive")
			}
			return []byte("disabled\n"), errors.New("disabled")
		}
		return nil, nil
	}}
	if _, err := host.DeleteIrreversibleRemovalPhase(systemchanges.UnitsPhase, time.Second); err != nil {
		t.Fatal(err)
	}
	for _, timer := range []string{"sbxr-cert-renew.timer", "sbxr-health-check.timer", "sbxr-update-check.timer"} {
		if !slices.Contains(disabled, timer) {
			t.Fatalf("managed timer was not disabled: %s", timer)
		}
	}
}

func TestCompleteRemovalRefusesUnprovedManagedUnitAbsence(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(context.Context, []byte, string, ...string) ([]byte, error)
	}{
		{name: "still active", run: func(context.Context, []byte, string, ...string) ([]byte, error) { return []byte("active\n"), nil }},
		{name: "inspection unavailable", run: func(context.Context, []byte, string, ...string) ([]byte, error) {
			return nil, errors.New("systemctl unavailable")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			host := completeRemovalHost{run: test.run}
			if err := host.proveUnitsStoppedAndDisabled(t.Context(), []string{"sbxr-health-check.timer"}); err == nil {
				t.Fatal("unproved managed timer absence was accepted")
			}
		})
	}
}

func TestCompleteRemovalKeepsExecutableWhenRecoveryServiceFinalizationFails(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"etc/systemd/system/sbxr-recovery.service", "usr/local/bin/sbxr"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("owned"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	host := completeRemovalHost{root: root, run: func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "is-enabled" {
			return []byte("disabled\n"), errors.New("disabled")
		}
		if len(args) > 0 && args[0] == "daemon-reload" {
			return nil, errors.New("controlled daemon reload failure")
		}
		if slices.Contains(args, "--now") {
			t.Fatal("recovery service attempted to stop its own process")
		}
		return nil, nil
	}}
	if err := host.PrepareRemovalFinalization(time.Second); err == nil {
		t.Fatal("daemon reload failure was accepted")
	}
	if _, err := os.Stat(filepath.Join(root, "usr/local/bin/sbxr")); err != nil {
		t.Fatalf("callable recovery executable was removed after failure: %v", err)
	}
}

func TestCompleteRemovalBootDetectorAcceptsEnabledRunnerAfterJournalDeletion(t *testing.T) {
	if !validOrphanedCompleteRemoval(systemchanges.NotInstalled, true, false, nil) {
		t.Fatal("authenticated no-journal recovery runner was not recognized")
	}
	if validOrphanedCompleteRemoval(systemchanges.Managed, true, false, nil) || validOrphanedCompleteRemoval(systemchanges.NotInstalled, false, false, nil) {
		t.Fatal("unproved orphaned Complete removal was accepted")
	}
}

func TestCompleteRemovalPresentationCrossesToForwardOnlyAndEndsNotInstalled(t *testing.T) {
	outcome := &clientAccessOutcome{
		loaded: true, request: clientAccessHandoffRequest{Mode: "removal-apply"},
		presentation: clientAccessPresentation{Installation: ownerconsole.InstallationManaged, StateRevision: 7},
		change:       ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRecoveryRequired, OperationID: "complete-removal-0001", TotalSteps: completeRemovalTotalSteps, Checkpoint: "Provider deletion in progress"},
	}
	forward := outcome.ViewCompleteRemoval(t.Context())
	if forward.Kind != ownerconsole.CompleteRemovalForwardOnly || forward.Checkpoint != ownerconsole.RemovalIrreversibleStarted || forward.TokenPhase != ownerconsole.RemovalProviderDeletionInProgress || forward.Progress.CompletedSteps != 4 {
		t.Fatalf("forward-only presentation = %+v", forward)
	}
	outcome.change = ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetSucceeded, OperationID: "complete-removal-0001", TotalSteps: completeRemovalTotalSteps}
	complete := outcome.ViewCompleteRemoval(t.Context())
	if complete.Kind != ownerconsole.CompleteRemovalSucceeded || complete.FinalStatus != ownerconsole.InstallationNotInstalled || complete.Progress.CompletedSteps != completeRemovalTotalSteps || !complete.NoRecoveryMaterial {
		t.Fatalf("completed presentation = %+v", complete)
	}
	progress := completeRemovalCompletedSteps(systemubuntu.RecoveryTransactionIdentity{Checkpoint: systemchanges.SecretsDeleted, CompletedSteps: 4})
	if progress != 10 {
		t.Fatalf("restart progress = %d, want 10", progress)
	}
}

func TestCompleteRemovalWatcherAdvancesFromProviderDeletionToOwnerRevocation(t *testing.T) {
	outcome := &clientAccessOutcome{
		loaded: true, request: clientAccessHandoffRequest{Mode: "removal-apply"}, removalPoll: time.Millisecond,
		presentation:  clientAccessPresentation{Installation: ownerconsole.InstallationManaged, StateRevision: 7},
		change:        ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRecoveryRequired, OperationID: "complete-removal-0001", TotalSteps: completeRemovalTotalSteps, Checkpoint: "Provider deletion in progress"},
		recoveryRetry: func(context.Context, string) (systemchanges.InstallationStatus, error) { return "", nil },
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	updates := outcome.WatchCompleteRemoval(ctx)
	if first := <-updates; first.TokenPhase != ownerconsole.RemovalProviderDeletionInProgress {
		t.Fatalf("first token phase = %v", first.TokenPhase)
	}
	if second := <-updates; second.TokenPhase != ownerconsole.RemovalTokenAwaitingOwnerRevocation || second.Progress.CompletedSteps != 7 {
		t.Fatalf("second presentation = %+v", second)
	}
}

func TestCompleteRemovalWatcherReportsAutomaticPreCheckpointRollback(t *testing.T) {
	outcome := &clientAccessOutcome{
		loaded: true, request: clientAccessHandoffRequest{Mode: "removal-apply"},
		presentation: clientAccessPresentation{Installation: ownerconsole.InstallationManaged, StateRevision: 7},
		change:       ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRecoveryRequired, OperationID: "complete-removal-0001", TotalSteps: completeRemovalTotalSteps, Checkpoint: "Recovery Required"},
		recoveryRetry: func(context.Context, string) (systemchanges.InstallationStatus, error) {
			return systemchanges.Managed, nil
		},
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	updates := outcome.WatchCompleteRemoval(ctx)
	if first := <-updates; first.Kind != ownerconsole.CompleteRemovalRollbackCapable {
		t.Fatalf("first presentation = %+v", first)
	}
	if second := <-updates; second.Kind != ownerconsole.CompleteRemovalCancelled || second.RestoredStatus != ownerconsole.InstallationManaged {
		t.Fatalf("rollback presentation = %+v", second)
	}
}
