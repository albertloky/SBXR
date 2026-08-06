package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
	"github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

type systemChangesAdapter struct {
	observation  systemchanges.Observation
	closes       atomic.Int32
	events       []string
	artifacts    map[string][]byte
	statuses     map[systemchanges.GatePhase]systemchanges.HealthStatus
	beforeStep   func() error
	prepareErr   error
	closeErr     error
	stepEvidence *systemchanges.StepEvidence
	lease        systemchanges.ExecutionLease
}

func (a *systemChangesAdapter) Observe() (systemchanges.Observation, error) {
	return a.observation, nil
}

func (a *systemChangesAdapter) TryLock() (systemchanges.Lock, bool, error) {
	return systemChangesLock{closes: &a.closes, err: a.closeErr}, true, nil
}

type systemChangesLock struct {
	closes *atomic.Int32
	err    error
}

func (lock systemChangesLock) Close() error { lock.closes.Add(1); return lock.err }

func (a *systemChangesAdapter) Prepare(lease systemchanges.ExecutionLease, preparation systemchanges.Preparation) error {
	a.lease = lease
	if a.prepareErr != nil {
		return a.prepareErr
	}
	a.artifacts = map[string][]byte{}
	if err := preparation.WriteStateArtifacts(func(name string, _ uint32, source io.Reader) error {
		content, err := io.ReadAll(source)
		if err == nil {
			a.artifacts[name] = content
		}
		return err
	}); err != nil {
		return err
	}
	a.events = append(a.events, string(systemchanges.Prepared))
	return nil
}

func (a *systemChangesAdapter) Record(_ systemchanges.ExecutionLease, record systemchanges.CheckpointRecord) error {
	a.events = append(a.events, record.String())
	return nil
}

func (a *systemChangesAdapter) Execute(_ systemchanges.ExecutionLease, step systemchanges.Step, _ time.Duration) (systemchanges.StepEvidence, error) {
	a.events = append(a.events, "execute "+string(step.Forward()))
	if a.beforeStep != nil {
		if err := a.beforeStep(); err != nil {
			return systemchanges.StepEvidence{}, err
		}
	}
	if a.stepEvidence != nil {
		return *a.stepEvidence, nil
	}
	return systemchanges.StepEvidence{Code: "step-ok", SHA256: testSHA('a')}, nil
}

func (a *systemChangesAdapter) Check(_ systemchanges.ExecutionLease, check systemchanges.Check, phase systemchanges.GatePhase, _ time.Duration) (systemchanges.HealthStatus, error) {
	a.events = append(a.events, "check "+string(phase)+" "+check.Code)
	if status := a.statuses[phase]; status != "" && check.Code == "NETWORK-GATE" {
		return status, nil
	}
	return check.Status, nil
}

func (a *systemChangesAdapter) VerifyAgreement(systemchanges.ExecutionLease, systemchanges.Agreement) error {
	a.events = append(a.events, "agreement verified")
	return nil
}

func (a *systemChangesAdapter) Cleanup(systemchanges.ExecutionLease, string) error {
	a.events = append(a.events, "cleanup")
	return nil
}

func TestPreparedCommitDurablyCompletesOneSystemChangesChangeSet(t *testing.T) {
	stateModule, changeSet, duplicate, observed := preparedSystemChange(t)
	adapter := &systemChangesAdapter{observation: observed, beforeStep: func() error {
		loaded, err := stateModule.Load(intentManagedRequest())
		if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 7 || loaded.Snapshot.LastCompletedChangeSet != "change-0007" {
			return errors.New("old Desired State was not current during forward work")
		}
		return nil
	}}
	boundary := systemchanges.New(adapter)
	result := boundary.Apply(changeSet)
	if result.Outcome != systemchanges.Completed || result.NothingChanged || !result.PlanConsumed || adapter.closes.Load() != 1 || adapter.lease.Authorized() {
		t.Fatalf("Apply() = %+v; lock closes = %d", result, adapter.closes.Load())
	}
	wantEvents := "Prepared,Step started 1,execute Activate prepared configuration,Step completed 1,check Pre-publication NETWORK-PREFLIGHT,Pre-publication health passed,Desired State publication started,Desired State published,check Post-publication NETWORK-PREFLIGHT,agreement verified,Post-publication health passed,Complete,cleanup"
	if got := strings.Join(adapter.events, ","); got != wantEvents {
		t.Fatalf("durable success checkpoints = %s, want %s", got, wantEvents)
	}
	if len(adapter.artifacts) == 0 || strings.Contains(fmt.Sprintf("%+v", result), "SECRET-MARKER") {
		t.Fatal("opaque transaction artifacts were missing or exposed as evidence")
	}
	loaded, err := stateModule.Load(LoadRequest{Baseline: ManagedEvidence, SupportedRelease: testRelease, Lineage: &LineageProof{Revision: 8, LastCompletedChangeSet: "change-0008", ReleaseIdentity: testRelease}})
	if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 8 || loaded.Snapshot.LastCompletedChangeSet != "change-0008" {
		t.Fatalf("published State readback = (%+v, %v)", loaded, err)
	}
	if replayed := boundary.Apply(duplicate); replayed.Finding == nil || replayed.Finding.Code != "SYSTEM-CHANGES-PLAN-USED" {
		t.Fatalf("duplicate wrapper replayed prepared authority: %+v", replayed)
	}
	if reused := boundary.Apply(changeSet); reused.Finding == nil || reused.Finding.Code != "SYSTEM-CHANGES-PLAN-USED" {
		t.Fatalf("prepared authority was reusable: %+v", reused)
	}
}

func preparedSystemChange(t *testing.T) (Interface, *systemchanges.ChangeSet, *systemchanges.ChangeSet, systemchanges.Observation) {
	return preparedSystemChangeWithCheck(t, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-PREFLIGHT"})
}

func preparedSystemChangeWithCheck(t *testing.T, check systemchanges.Check) (Interface, *systemchanges.ChangeSet, *systemchanges.ChangeSet, systemchanges.Observation) {
	return preparedSystemChangeForMutation(t, systemchanges.SettingChangeMutation, check)
}

func preparedSystemChangeForMutation(t *testing.T, mutation systemchanges.MutationClass, check systemchanges.Check) (Interface, *systemchanges.ChangeSet, *systemchanges.ChangeSet, systemchanges.Observation) {
	t.Helper()
	candidate := completeDesiredState()
	candidate.Subscription.Token = NewClientAccessValue(testSHA('e'))
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
	identity, revision, startingSHA256, target, planIdentity, planSHA256, valid := prepared.SystemChangesPreparedState()
	if !valid {
		t.Fatal("State returned an invalid prepared binding")
	}
	starting := systemchanges.StateLineage{Status: systemchanges.Managed, Revision: revision - 1, SHA256: startingSHA256}
	observed := systemchanges.Observation{
		Status: systemchanges.Managed, LastChangeSet: "change-0007", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased,
		StateRevision: revision - 1, StateSHA256: startingSHA256, VolatileSHA256: testSHA('2'),
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
		Checks: func() []systemchanges.Check {
			pre, post := check, check
			pre.Phase, post.Phase = systemchanges.PrePublication, systemchanges.PostPublication
			checks := []systemchanges.Check{pre, post}
			if check.Classification == systemchanges.Advisory {
				checks = append(checks,
					systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-REQUIRED-PRE"},
					systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-REQUIRED-POST"},
				)
			}
			return checks
		}(),
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
	return module, changeSet, duplicate, observed
}

func TestEveryMutationClassUsesOneSystemChangesLockBeforeLiveWork(t *testing.T) {
	check := systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-GATE"}
	for _, mutation := range []systemchanges.MutationClass{
		systemchanges.InstallationMutation, systemchanges.RepairMutation, systemchanges.SettingChangeMutation,
		systemchanges.RotationMutation, systemchanges.UpdateMutation, systemchanges.CertificateRenewalMutation, systemchanges.CompleteRemovalMutation,
	} {
		t.Run(string(mutation), func(t *testing.T) {
			_, changeSet, _, observed := preparedSystemChangeForMutation(t, mutation, check)
			adapter := &systemChangesAdapter{observation: observed, prepareErr: errors.New("controlled preparation stop")}
			result := systemchanges.New(adapter).Apply(changeSet)
			if result.Outcome != systemchanges.Incomplete || !result.NothingChanged || adapter.closes.Load() != 1 {
				t.Fatalf("%s lock boundary = %+v; closes=%d", mutation, result, adapter.closes.Load())
			}
		})
	}
}

func TestSuccessfulChangeSetEnforcesFreshRequiredAndAdvisoryGates(t *testing.T) {
	for _, test := range []struct {
		name          string
		check         systemchanges.Check
		fresh         systemchanges.HealthStatus
		wantCompleted bool
	}{
		{name: "Required Healthy", check: systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-GATE"}, fresh: systemchanges.Healthy, wantCompleted: true},
		{name: "Required Needs attention", check: systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-GATE"}, fresh: systemchanges.NeedsAttention},
		{name: "Required Failed", check: systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-GATE"}, fresh: systemchanges.Failed},
		{name: "Required Unknown", check: systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-GATE"}, fresh: systemchanges.Unknown},
		{name: "reviewed Advisory Needs attention", check: systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Advisory, Status: systemchanges.NeedsAttention, Code: "NETWORK-GATE", Disclosed: true}, fresh: systemchanges.NeedsAttention, wantCompleted: true},
		{name: "Advisory Failed", check: systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Advisory, Status: systemchanges.Healthy, Code: "NETWORK-GATE"}, fresh: systemchanges.Failed},
		{name: "Advisory Unknown", check: systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Advisory, Status: systemchanges.Healthy, Code: "NETWORK-GATE"}, fresh: systemchanges.Unknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, changeSet, _, observed := preparedSystemChangeWithCheck(t, test.check)
			adapter := &systemChangesAdapter{observation: observed, statuses: map[systemchanges.GatePhase]systemchanges.HealthStatus{systemchanges.PrePublication: test.fresh, systemchanges.PostPublication: test.fresh}}
			result := systemchanges.New(adapter).Apply(changeSet)
			if test.wantCompleted && result.Outcome != systemchanges.Completed || !test.wantCompleted && (result.Outcome != systemchanges.Incomplete || result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-HEALTH") {
				t.Fatalf("fresh gate result = %+v", result)
			}
		})
	}
}

func TestChangedWorkIsNeverReportedAsNothingChangedWhenLockReleaseIsUncertain(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChange(t)
	adapter := &systemChangesAdapter{observation: observed, closeErr: errors.New("unlock failed")}
	result := systemchanges.New(adapter).Apply(changeSet)
	if result.Outcome != systemchanges.Incomplete || result.NothingChanged || result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-LOCK-RELEASE" {
		t.Fatalf("post-change lock release = %+v", result)
	}
}

func TestStateTransactionBridgeRejectsCallerMadeLease(t *testing.T) {
	candidate := completeDesiredState()
	candidate.Subscription.Token = NewClientAccessValue(testSHA('e'))
	module, request, _ := managedPrepareRequest(t, candidate)
	prepared, err := module.PrepareCommit(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, planIdentity, planSHA256, valid := prepared.SystemChangesPreparedState()
	if !valid {
		t.Fatal("prepared State binding is invalid")
	}
	if _, err := prepared.SystemChangesConsume(systemchanges.ExecutionLease{}, planIdentity, planSHA256); err == nil {
		t.Fatal("caller-made lease consumed State transaction authority")
	}
}

func TestStepCompletionRequiresDurableTypedEvidence(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChange(t)
	adapter := &systemChangesAdapter{observation: observed, stepEvidence: &systemchanges.StepEvidence{Code: "step-ok", SHA256: "not-a-checksum"}}
	result := systemchanges.New(adapter).Apply(changeSet)
	if result.Outcome != systemchanges.Incomplete || result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-STEP" || strings.Contains(strings.Join(adapter.events, ","), string(systemchanges.StepCompleted)) {
		t.Fatalf("invalid step evidence = %+v; events=%v", result, adapter.events)
	}
}

type controlledUbuntuHost struct {
	root       string
	executed   int
	checks     int
	agreements int
}

func (host *controlledUbuntuHost) CaptureRollback(_ systemchanges.Step, write func(io.Reader) error) error {
	return write(strings.NewReader(`{"credential":"SECRET-MARKER-rollback"}`))
}

func (host *controlledUbuntuHost) Execute(systemchanges.Step, time.Duration) (systemchanges.StepEvidence, error) {
	host.executed++
	transaction := filepath.Join(host.root, "var/lib/sbxr/transactions/change-0008")
	if err := filepath.WalkDir(transaction, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symbolic link in transaction material")
		}
		if entry.IsDir() && info.Mode().Perm() != 0o700 || !entry.IsDir() && info.Mode().Perm() != 0o600 {
			return fmt.Errorf("unsafe transaction mode %s on %s", info.Mode(), name)
		}
		return nil
	}); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	manifestBytes, err := os.ReadFile(filepath.Join(transaction, "manifest.json"))
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	var manifest struct {
		SchemaVersion int                          `json:"schema_version"`
		Release       systemchanges.ReleaseBinding `json:"release_identity"`
		Reason        systemchanges.MutationClass  `json:"reason"`
		Files         map[string]string            `json:"sha256"`
	}
	wantRelease := systemchanges.ReleaseBinding{Repository: testRelease.Repository, Tag: testRelease.Tag, Commit: testRelease.Commit, ReleaseIndexSHA256: testRelease.ReleaseIndexSHA256}
	if json.Unmarshal(manifestBytes, &manifest) != nil || manifest.SchemaVersion != 1 || manifest.Release != wantRelease || manifest.Reason != systemchanges.SettingChangeMutation || len(manifest.Files) < 3 {
		return systemchanges.StepEvidence{}, errors.New("snapshot manifest binding is incomplete")
	}
	journalBytes, err := os.ReadFile(filepath.Join(transaction, "journal.jsonl"))
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	var preparedEntry struct {
		Checkpoint string                                `json:"checkpoint"`
		ChangeSet  string                                `json:"change_set"`
		PlanSHA256 string                                `json:"plan_sha256"`
		State      systemchanges.StateTransactionBinding `json:"state"`
		Steps      []map[string]any                      `json:"steps"`
		Checks     []systemchanges.Check                 `json:"health_gates"`
	}
	first, _, _ := bytes.Cut(journalBytes, []byte{'\n'})
	if json.Unmarshal(first, &preparedEntry) != nil || preparedEntry.Checkpoint != "Prepared" || preparedEntry.ChangeSet != "change-0008" || len(preparedEntry.PlanSHA256) != 64 || preparedEntry.State.StartingRevision != 7 || preparedEntry.State.CandidateRevision != 8 || len(preparedEntry.Steps) != 1 || len(preparedEntry.Checks) != 2 || bytes.Contains(journalBytes, []byte("SECRET-MARKER")) || bytes.Contains(manifestBytes, []byte("SECRET-MARKER")) {
		return systemchanges.StepEvidence{}, errors.New("Prepared journal binding is incomplete or unsafe")
	}
	preparedConfig, err := os.ReadFile(filepath.Join(transaction, "prepared/subscription.json"))
	if err != nil || !json.Valid(preparedConfig) {
		return systemchanges.StepEvidence{}, errors.New("prepared native configuration is invalid")
	}
	active := filepath.Join(host.root, "run/sbxr/active-subscription.json")
	if err := os.WriteFile(active, preparedConfig, 0o600); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	digest := sha256.Sum256(preparedConfig)
	return systemchanges.StepEvidence{Code: "native-valid", SHA256: fmt.Sprintf("%x", digest)}, nil
}

func (host *controlledUbuntuHost) Check(_ systemchanges.Check, _ systemchanges.GatePhase, _ time.Duration) (systemchanges.HealthStatus, error) {
	host.checks++
	return systemchanges.Healthy, nil
}

func (host *controlledUbuntuHost) VerifyAgreement(agreement systemchanges.Agreement) error {
	host.agreements++
	if agreement.Revision != 8 || agreement.ChangeSet != "change-0008" || agreement.CandidateSHA256 == "" || agreement.PublishedStateSHA256 == "" || agreement.PreparedManifestSHA256 == "" {
		return errors.New("incomplete active agreement")
	}
	if active, err := os.ReadFile(filepath.Join(host.root, "run/sbxr/active-subscription.json")); err != nil || !json.Valid(active) {
		return errors.New("active configuration agreement failed")
	}
	return nil
}

func TestUbuntuAdapterDurablyProtectsAndCleansSuccessfulTransaction(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChange(t)
	root := t.TempDir()
	lockPath := filepath.Join(root, "run/sbxr/system-changes.lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	host := &controlledUbuntuHost{root: root}
	adapter := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host)
	unauthorizedStep, err := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Execute(systemchanges.ExecutionLease{}, unauthorizedStep, time.Second); err == nil || host.executed != 0 {
		t.Fatal("Ubuntu Adapter exposed a second mutation path outside Apply")
	}
	result := systemchanges.New(adapter).Apply(changeSet)
	if result.Outcome != systemchanges.Completed || host.executed != 1 || host.checks != 2 || host.agreements != 1 {
		t.Fatalf("controlled Ubuntu success = (%+v, executed=%d checks=%d agreements=%d)", result, host.executed, host.checks, host.agreements)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/sbxr/transactions/change-0008")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed transaction material still exists: %v", err)
	}
}

func TestUbuntuAdapterRefusesUnsafeTransactionPathsBeforeLiveWork(t *testing.T) {
	for _, test := range []struct {
		name  string
		plant func(string) error
	}{
		{name: "broad transaction directory", plant: func(base string) error { return os.MkdirAll(base, 0o755) }},
		{name: "symbolic link preparing path", plant: func(base string) error {
			if err := os.MkdirAll(base, 0o700); err != nil {
				return err
			}
			return os.Symlink("elsewhere", filepath.Join(base, "change-0008.preparing"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, changeSet, _, observed := preparedSystemChange(t)
			root := t.TempDir()
			lockPath := filepath.Join(root, "run/sbxr/system-changes.lock")
			if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			base := filepath.Join(root, "var/lib/sbxr/transactions")
			if err := test.plant(base); err != nil {
				t.Fatal(err)
			}
			host := &controlledUbuntuHost{root: root}
			adapter := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host)
			result := systemchanges.New(adapter).Apply(changeSet)
			if result.Outcome != systemchanges.Incomplete || !result.NothingChanged || host.executed != 0 || result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-PREPARATION" {
				t.Fatalf("unsafe path result = %+v; executed=%d", result, host.executed)
			}
		})
	}
}
