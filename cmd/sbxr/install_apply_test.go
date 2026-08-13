package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestInstallApplyObservationFailsClosedAndKeepsProvenStateLineage(t *testing.T) {
	changeSet := "install-aaaaaaaaaaaaaaaa"
	managed := systemchanges.Observation{Status: systemchanges.Managed, StateRevision: 7, StateSHA256: strings.Repeat("a", 64), LastChangeSet: "change-0007", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
	got, err := observeInstallApply(func() (systemchanges.Observation, error) { return managed, nil }, pendingChangeSetReaderStub{}, changeSet, 19, "volatile")
	if err != nil || got.StateRevision != 7 || got.StateSHA256 != managed.StateSHA256 || got.LastChangeSet != managed.LastChangeSet {
		t.Fatalf("observeInstallApply() = (%+v, %v)", got, err)
	}

	for _, test := range []struct {
		name        string
		state       systemubuntuObservation
		readErr     error
		transaction string
	}{
		{name: "State", state: systemubuntuObservation{err: errors.New("corrupt State")}},
		{name: "transaction directory", state: systemubuntuObservation{observation: systemchanges.Observation{Status: systemchanges.NotInstalled}}, readErr: errors.New("permission denied")},
		{name: "unexpected transaction", state: systemubuntuObservation{observation: systemchanges.Observation{Status: systemchanges.NotInstalled}}, transaction: "other-change"},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := pendingChangeSetReaderStub{err: test.readErr}
			if test.transaction != "" {
				reader.pending, reader.found = systemchanges.PendingChangeSet{Identity: test.transaction}, true
			}
			if _, err := observeInstallApply(test.state.load, reader, changeSet, 19, "volatile"); err == nil {
				t.Fatal("unprovable install lineage accepted")
			}
		})
	}
}

type systemubuntuObservation struct {
	observation systemchanges.Observation
	err         error
}

func (source systemubuntuObservation) load() (systemchanges.Observation, error) {
	return source.observation, source.err
}
