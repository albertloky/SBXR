package proxyinstallation

import (
	"slices"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
)

func TestFailedActivationPublicationThenInterruptedCleanupRecoversFresh(t *testing.T) {
	host := acceptedHost()
	host.failPublish = activationCommitted
	host.fails = map[hostadapter.Operation]bool{}
	module := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	review := module.Review(t.Context(), StartSetupAction)
	if review.Prepared == nil {
		t.Fatalf("setup review: %#v", review)
	}
	result := module.Execute(t.Context(), *review.Prepared, Approved, func(p Progress) {
		if p.Phase == string(hostadapter.StopDisableService) {
			host.fails[hostadapter.UnmaskService] = true
		}
	})
	if result.Code != SetupNeedsCleanup || result.FailedCheck != string(hostadapter.UnmaskService) {
		t.Fatalf("interrupted cleanup: %#v", result)
	}
	record, valid := decodeOwnership(host.ownership)
	if !valid || record.Direction != cleanupRequired || record.CleanupCheckpoint != 1 {
		t.Fatalf("unrecoverable authority: %s", host.ownership)
	}
	fresh := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	status := fresh.Review(t.Context(), StatusAction)
	finish := fresh.Review(t.Context(), FinishCleanupAction)
	if !slices.Contains(status.LegalActions, FinishCleanupAction) || finish.Prepared == nil {
		t.Fatalf("fresh recovery unavailable: %#v / %#v", status, finish)
	}
	host.fails = nil
	if result := fresh.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != SetupCleanedUp || len(host.ownership) != 0 {
		t.Fatalf("fresh cleanup: %#v", result)
	}
}

func TestLateActivationPublicationRequiresSyncBeforeStarting(t *testing.T) {
	host := acceptedHost()
	host.failPublish, host.latePublish, host.failOwnershipSync = activationCommitted, true, true
	module := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	review := module.Review(t.Context(), StartSetupAction)
	result := module.Execute(t.Context(), *review.Prepared, Approved, nil)
	if result.Code != SetupNeedsCompletion || slices.Contains(host.operations, hostadapter.EnableService) || slices.Contains(host.operations, hostadapter.RemovePackage) {
		t.Fatalf("unsynchronized authority allowed effects: %#v, %v", result, host.operations)
	}
	host.failOwnershipSync = false
	fresh := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	finish := fresh.Review(t.Context(), FinishSetupAction)
	if finish.Prepared == nil {
		t.Fatalf("fresh forward recovery unavailable: %#v", finish)
	}
	if result := fresh.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != SetupComplete {
		t.Fatalf("fresh setup: %#v", result)
	}
}
