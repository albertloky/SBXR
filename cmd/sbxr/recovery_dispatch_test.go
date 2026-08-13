package main

import (
	"testing"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestStartupRecoveryDispatchesEverySupportedMutationKind(t *testing.T) {
	kinds := []systemchanges.MutationClass{
		systemchanges.InstallationMutation,
		systemchanges.RepairMutation,
		systemchanges.SettingChangeMutation,
		systemchanges.RotationMutation,
		systemchanges.CertificateChangeMutation,
		systemchanges.UpdateMutation,
		systemchanges.CertificateRenewalMutation,
		systemchanges.CompleteRemovalMutation,
	}
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			called := false
			routes := recoveryRoutes(func(systemchanges.PendingChangeSet) error { called = true; return nil })
			if err := dispatchPendingChangeSet(systemchanges.PendingChangeSet{Kind: kind}, routes); err != nil || !called {
				t.Fatalf("dispatch %s: called=%t err=%v", kind, called, err)
			}
		})
	}
}

func TestStartupRecoveryFailsClosedForUnsupportedMutationKind(t *testing.T) {
	if err := dispatchPendingChangeSet(systemchanges.PendingChangeSet{Kind: "Unknown"}, recoveryRoutes(func(systemchanges.PendingChangeSet) error { return nil })); err == nil {
		t.Fatal("unsupported pending Change Set was dispatched")
	}
}

type pendingChangeSetReaderStub struct {
	pending systemchanges.PendingChangeSet
	found   bool
	err     error
}

func (stub pendingChangeSetReaderStub) PendingChangeSet() (systemchanges.PendingChangeSet, bool, error) {
	return stub.pending, stub.found, stub.err
}
