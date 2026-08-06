package state

import (
	"io/fs"
	"sync/atomic"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

type systemChangesAdapter struct {
	observation systemchanges.Observation
	closes      atomic.Int32
}

func (a *systemChangesAdapter) Observe() (systemchanges.Observation, error) {
	return a.observation, nil
}

func (a *systemChangesAdapter) TryLock() (systemchanges.Lock, bool, error) {
	return systemChangesLock{closes: &a.closes}, true, nil
}

type systemChangesLock struct{ closes *atomic.Int32 }

func (lock systemChangesLock) Close() error { lock.closes.Add(1); return nil }

func TestPreparedCommitIsTheOneUseSystemChangesAuthorityForEveryMutationClass(t *testing.T) {
	for _, mutation := range []systemchanges.MutationClass{
		systemchanges.InstallationMutation,
		systemchanges.RepairMutation,
		systemchanges.SettingChangeMutation,
		systemchanges.RotationMutation,
		systemchanges.UpdateMutation,
		systemchanges.CertificateRenewalMutation,
		systemchanges.CompleteRemovalMutation,
	} {
		t.Run(string(mutation), func(t *testing.T) {
			candidate := completeDesiredState()
			var module Interface
			var request PrepareRequest
			if mutation == systemchanges.InstallationMutation {
				module = New(&mutableStateStorage{err: fs.ErrNotExist})
				loaded, err := module.Load(LoadRequest{Baseline: CleanVPS})
				if err != nil {
					t.Fatal(err)
				}
				request = preparedRequest(t, loaded, candidate, "change-0001")
			} else {
				module, request, _ = managedPrepareRequest(t, candidate)
			}
			prepared, err := module.PrepareCommit(request)
			if err != nil {
				t.Fatal(err)
			}
			identity, revision, target, planIdentity, planSHA256, valid := prepared.SystemChangesPreparedState()
			if !valid {
				t.Fatal("State returned an invalid prepared binding")
			}
			starting := systemchanges.StateLineage{Status: systemchanges.Managed, Revision: revision - 1, SHA256: testSHA('1')}
			observed := systemchanges.Observation{
				Status: systemchanges.Managed, LastChangeSet: "change-0007", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased,
				StateRevision: revision - 1, StateSHA256: testSHA('1'), VolatileSHA256: testSHA('2'),
				FilesystemBytes: 20 << 30, AvailableBytes: 5 << 30, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service",
			}
			if mutation == systemchanges.InstallationMutation {
				starting = systemchanges.StateLineage{Status: systemchanges.NotInstalled}
				observed.Status, observed.LastChangeSet, observed.StateRevision, observed.StateSHA256 = systemchanges.NotInstalled, "", 0, ""
			}
			step, err := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
			if err != nil {
				t.Fatal(err)
			}
			spec := systemchanges.ChangeSetSpec{
				Identity: identity, Mutation: mutation, OutcomeOwner: systemchanges.ConnectionProfilesModule,
				StartingState: starting, TargetStateSHA256: target,
				Plan:          systemchanges.PlanBinding{Identity: planIdentity, SHA256: planSHA256, VolatileSHA256: testSHA('2')},
				PreparedState: prepared, Steps: []systemchanges.Step{step},
				Checks:   []systemchanges.Check{{Owner: systemchanges.NetworkPolicyModule, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-PREFLIGHT"}},
				Timeouts: systemchanges.Timeouts{Step: 30 * time.Second, Check: 60 * time.Second},
				Disk: systemchanges.DiskRequirement{
					PreparationBytes: 100, TemporaryBytes: 100, SnapshotBytes: 100,
					JournalBytes: 100, RollbackBytes: 100, OverheadBytes: 100,
				},
			}
			changeSet, err := systemchanges.NewChangeSet(spec)
			if err != nil {
				t.Fatal(err)
			}
			duplicate, err := systemchanges.NewChangeSet(spec)
			if err != nil {
				t.Fatal(err)
			}
			adapter := &systemChangesAdapter{observation: observed}
			boundary := systemchanges.New(adapter)
			result := boundary.Apply(changeSet)
			if result.Outcome != systemchanges.Admitted || !result.NothingChanged || !result.PlanConsumed || adapter.closes.Load() != 1 {
				t.Fatalf("Apply() = %+v; lock closes = %d", result, adapter.closes.Load())
			}
			if replayed := boundary.Apply(duplicate); replayed.Finding == nil || replayed.Finding.Code != "SYSTEM-CHANGES-PLAN-USED" {
				t.Fatalf("duplicate wrapper replayed prepared authority: %+v", replayed)
			}
			if reused := boundary.Apply(changeSet); reused.Finding == nil || reused.Finding.Code != "SYSTEM-CHANGES-PLAN-USED" {
				t.Fatalf("prepared authority was reusable: %+v", reused)
			}
		})
	}
}
