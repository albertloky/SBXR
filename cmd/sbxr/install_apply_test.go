package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestInstallApplyObservationFailsClosedAndKeepsProvenStateLineage(t *testing.T) {
	changeSet := "install-aaaaaaaaaaaaaaaa"
	empty := func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist }
	managed := systemchanges.Observation{Status: systemchanges.Managed, StateRevision: 7, StateSHA256: strings.Repeat("a", 64), LastChangeSet: "change-0007", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
	got, err := observeInstallApply(func() (systemchanges.Observation, error) { return managed, nil }, empty, changeSet, 19, "volatile")
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
			readDir := func(string) ([]os.DirEntry, error) {
				if test.readErr != nil {
					return nil, test.readErr
				}
				if test.transaction == "" {
					return nil, os.ErrNotExist
				}
				directory := t.TempDir()
				if err := os.Mkdir(directory+"/"+test.transaction, 0o700); err != nil {
					t.Fatal(err)
				}
				return os.ReadDir(directory)
			}
			if _, err := observeInstallApply(test.state.load, readDir, changeSet, 19, "volatile"); err == nil {
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
