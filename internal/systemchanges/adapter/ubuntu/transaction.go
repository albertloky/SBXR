package ubuntu

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

const transactionDirectory = "var/lib/sbxr/transactions"

// Host owns the typed native effects and observations; Adapter owns their durability.
type Host interface {
	CaptureRollback(systemchanges.Step, func(source io.Reader) error) error
	Execute(systemchanges.Step, time.Duration, *systemchanges.Cancellation) (systemchanges.StepEvidence, error)
	Reverse(systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEvidence, error)
	// HoldServices is the systemd-ordering seam before public services and timers.
	HoldServices() error
	// AllowProvenServices may release only services matching the resolved State.
	AllowProvenServices(systemchanges.RecoveryTransaction, time.Duration) error
	InspectStep(systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEffect, error)
	VerifyStartingServices(systemchanges.RecoveryTransaction, time.Duration) error
	Check(systemchanges.Check, systemchanges.GatePhase, time.Duration) (systemchanges.HealthStatus, error)
	VerifyAgreement(systemchanges.Agreement, time.Duration) error
	VerifyRollback(systemchanges.RollbackAgreement, time.Duration) error
}

type IrreversibleRemovalHost interface {
	VerifyCloudflareTokenRevoked(time.Duration) (bool, error)
	DeleteIrreversibleRemovalPhase(systemchanges.IrreversibleRemovalPhase, time.Duration) (systemchanges.StepEvidence, error)
	VerifyFinalRemovalAbsence(time.Duration) (bool, error)
	FinalizeRemoval(time.Duration) error
}

// FirewallExecutor is the narrow native seam for approved inet sbxr changes.
type FirewallExecutor interface {
	CaptureRollback(systemchanges.Step, func(source io.Reader) error) error
	Execute(systemchanges.Step, string, time.Duration, *systemchanges.Cancellation) (systemchanges.StepEvidence, error)
	Commit(systemchanges.Step, systemchanges.StepEvidence) error
	Reverse(systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEvidence, error)
	Inspect(systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEffect, error)
}

type CloudflareExecutor interface {
	CaptureRollback(systemchanges.Step, func(io.Reader) error) error
	Execute(systemchanges.Step, string, time.Duration) (systemchanges.StepEvidence, error)
	Reverse(systemchanges.Step, systemchanges.StepEvidence, io.Reader, time.Duration) (systemchanges.StepEvidence, error)
	CheckWholeTunnel([]systemchanges.StepEvidence, time.Duration) (systemchanges.HealthStatus, error)
	ValidateInstalledService(string) error
	ValidateNativeConfiguration(time.Duration) error
}

type snapshotManifest struct {
	SchemaVersion int                          `json:"schema_version"`
	Release       systemchanges.ReleaseBinding `json:"release_identity"`
	Reason        systemchanges.MutationClass  `json:"reason"`
	Files         map[string]string            `json:"sha256"`
}

type journalStep struct {
	Owner        systemchanges.Module               `json:"owner"`
	Forward      systemchanges.OperationKind        `json:"forward"`
	Rollback     systemchanges.OperationKind        `json:"rollback"`
	Cancellation systemchanges.CancellationContract `json:"cancellation"`
	Inspection   systemchanges.InspectionContract   `json:"inspection"`
	Firewall     *systemchanges.FirewallChange      `json:"firewall,omitempty"`
	Removal      *systemchanges.RemovalChange       `json:"removal,omitempty"`
	Cloudflare   *systemchanges.CloudflareChange    `json:"cloudflare,omitempty"`
}

type journalEntry struct {
	Checkpoint   systemchanges.DurableCheckpoint        `json:"checkpoint"`
	Step         int                                    `json:"step,omitempty"`
	ChangeSet    string                                 `json:"change_set,omitempty"`
	Mutation     systemchanges.MutationClass            `json:"mutation,omitempty"`
	Starting     systemchanges.StateLineage             `json:"starting_state,omitempty"`
	OutcomeOwner systemchanges.Module                   `json:"outcome_owner,omitempty"`
	PlanSHA256   string                                 `json:"plan_sha256,omitempty"`
	State        *systemchanges.StateTransactionBinding `json:"state,omitempty"`
	Steps        []journalStep                          `json:"steps,omitempty"`
	Checks       []systemchanges.Check                  `json:"health_gates,omitempty"`
	Timeouts     systemchanges.Timeouts                 `json:"timeouts,omitempty"`
	Evidence     *systemchanges.StepEvidence            `json:"evidence,omitempty"`
}

func (a Adapter) Prepare(lease systemchanges.ExecutionLease, preparation systemchanges.Preparation) error {
	if !lease.Authorized() || a.host == nil || !safeName(preparation.ChangeSet) {
		return errors.New("typed Ubuntu transaction host unavailable")
	}
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.MkdirAll(transactionDirectory, 0o700); err != nil {
		return err
	}
	if err := verifyDirectory(root, transactionDirectory, a.uid); err != nil {
		return err
	}
	target := path.Join(transactionDirectory, preparation.ChangeSet)
	temporary := target + ".preparing"
	if _, err := root.Lstat(target); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return errors.New("active transaction material already exists")
	}
	if _, err := root.Lstat(temporary); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return errors.New("unresolved temporary transaction material exists")
	}
	for _, directory := range []string{temporary, path.Join(temporary, "snapshot"), path.Join(temporary, "prepared")} {
		if err := root.Mkdir(directory, 0o700); err != nil {
			return err
		}
	}
	checksums := map[string]string{}
	write := func(name string, mode uint32, source io.Reader) error {
		if mode != 0o600 || !safeArtifact(name) || checksums[name] != "" {
			return errors.New("unsafe or duplicate transaction artifact")
		}
		checksum, err := writeProtected(root, path.Join(temporary, name), source, a.uid)
		if err == nil {
			checksums[name] = checksum
		}
		return err
	}
	if err := preparation.WriteStateArtifacts(write); err != nil {
		return err
	}
	for index, step := range preparation.Steps {
		called := false
		captureRollback := func(source io.Reader) error {
			if called || source == nil {
				return errors.New("rollback capture must provide one exact artifact")
			}
			called = true
			return write(fmt.Sprintf("snapshot/step-%03d.rollback", index+1), 0o600, source)
		}
		var captureErr error
		if _, ok := step.FirewallChange(); ok {
			if a.firewall == nil {
				return errors.New("native firewall Adapter unavailable")
			}
			captureErr = a.firewall.CaptureRollback(step, captureRollback)
		} else if _, ok := step.CloudflareChange(); ok {
			if a.cloudflare == nil {
				return errors.New("Cloudflare transaction executor unavailable")
			}
			captureErr = a.cloudflare.CaptureRollback(step, captureRollback)
		} else {
			captureErr = a.host.CaptureRollback(step, captureRollback)
		}
		if captureErr != nil || !called {
			return errors.New("rollback capture is incomplete")
		}
	}
	release := preparation.State.StartingRelease
	if release == (systemchanges.ReleaseBinding{}) {
		release = preparation.State.CandidateRelease
	}
	manifest := snapshotManifest{SchemaVersion: 1, Release: release, Reason: preparation.Mutation, Files: checksums}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if _, err := writeProtected(root, path.Join(temporary, "manifest.json"), strings.NewReader(string(manifestBytes)), a.uid); err != nil {
		return err
	}
	steps := make([]journalStep, len(preparation.Steps))
	for index, step := range preparation.Steps {
		steps[index] = journalStep{Owner: step.Owner(), Forward: step.Forward(), Rollback: step.Rollback(), Cancellation: step.CancellationContract(), Inspection: step.InspectionContract()}
		if firewall, ok := step.FirewallChange(); ok {
			steps[index].Firewall = &firewall
		}
		if removal, ok := step.RemovalChange(); ok {
			steps[index].Removal = &removal
		}
		if cloudflare, ok := step.CloudflareChange(); ok {
			steps[index].Cloudflare = &cloudflare
		}
	}
	entry := journalEntry{Checkpoint: systemchanges.Prepared, ChangeSet: preparation.ChangeSet, Mutation: preparation.Mutation, Starting: preparation.Starting, OutcomeOwner: preparation.OutcomeOwner, PlanSHA256: preparation.PlanSHA256, State: &preparation.State, Steps: steps, Checks: preparation.Checks, Timeouts: preparation.Timeouts}
	if _, err := writeProtected(root, path.Join(temporary, "journal.jsonl"), strings.NewReader(""), a.uid); err != nil {
		return err
	}
	for _, directory := range []string{path.Join(temporary, "snapshot"), path.Join(temporary, "prepared"), temporary} {
		if err := syncDirectory(root, directory); err != nil {
			return err
		}
	}
	if err := verifyTransaction(root, temporary, a.uid); err != nil {
		return err
	}
	if err := root.Rename(temporary, target); err != nil {
		return err
	}
	if err := syncDirectory(root, transactionDirectory); err != nil {
		return err
	}
	if err := verifyTransaction(root, target, a.uid); err != nil {
		return err
	}
	if err := appendJournal(root, path.Join(target, "journal.jsonl"), entry, a.uid); err != nil {
		return err
	}
	return verifyTransaction(root, target, a.uid)
}

func (a Adapter) Record(lease systemchanges.ExecutionLease, record systemchanges.CheckpointRecord) error {
	if !lease.Authorized() || !safeName(record.ChangeSet) || record.Checkpoint == "" {
		return errors.New("invalid journal checkpoint")
	}
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return err
	}
	defer root.Close()
	target := path.Join(transactionDirectory, record.ChangeSet)
	verify := verifyTransaction
	if record.Checkpoint == systemchanges.TransactionMaterialDeleted || record.Checkpoint == systemchanges.FinalRemovalAbsenceVerified {
		verify = verifyFinalizingTransaction
	}
	if record.Checkpoint == systemchanges.StateFinalized && record.State != nil {
		if err := verifyDeferredStateGeneration(root, target, *record.State, a.uid); err != nil {
			return err
		}
	} else if err := verify(root, target, a.uid); err != nil {
		return err
	}
	if err := appendJournal(root, path.Join(target, "journal.jsonl"), journalEntry{Checkpoint: record.Checkpoint, Step: record.Step, Evidence: record.Evidence, State: record.State}, a.uid); err != nil {
		return err
	}
	if record.Checkpoint == systemchanges.StateFinalized {
		return discardDeferredPrevious(root, target)
	}
	if record.Checkpoint == systemchanges.StepCompleted && record.CompletedStep != nil {
		if _, ok := record.CompletedStep.FirewallChange(); ok && a.firewall != nil {
			if record.Evidence == nil {
				return errors.New("durable firewall evidence unavailable")
			}
			return a.firewall.Commit(*record.CompletedStep, *record.Evidence)
		}
	}
	return nil
}

func (a Adapter) ReplaceStateArtifacts(lease systemchanges.ExecutionLease, changeSet string, binding systemchanges.StateTransactionBinding, stream func(func(name string, mode uint32, source io.Reader) error) error) error {
	if !lease.Authorized() || !safeName(changeSet) || binding.ChangeSet != changeSet || stream == nil {
		return errors.New("invalid deferred State finalization")
	}
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return err
	}
	defer root.Close()
	target := path.Join(transactionDirectory, changeSet)
	manifest, err := verifyTransactionManifest(root, target, a.uid)
	if err != nil {
		return err
	}
	temporary := path.Join(target, "prepared.finalizing")
	previous := path.Join(target, "prepared.previous")
	if err := root.Mkdir(temporary, 0o700); err != nil {
		return err
	}
	checksums := map[string]string{}
	write := func(name string, mode uint32, source io.Reader) error {
		if mode != 0o600 || !strings.HasPrefix(name, "prepared/") || !safeArtifact(name) || checksums[name] != "" {
			return errors.New("unsafe deferred State artifact")
		}
		checksum, err := writeProtected(root, path.Join(temporary, path.Base(name)), source, a.uid)
		if err == nil {
			checksums[name] = checksum
		}
		return err
	}
	if err := stream(write); err != nil || checksums["prepared/state.json"] != binding.PreparedStateSHA256 || checksums["prepared/manifests.json"] != binding.PreparedManifestSHA256 {
		return errors.New("final State artifacts disagree with their binding")
	}
	for name := range manifest.Files {
		if strings.HasPrefix(name, "prepared/") {
			delete(manifest.Files, name)
		}
	}
	for name, checksum := range checksums {
		manifest.Files[name] = checksum
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	nextManifest := path.Join(target, "manifest.finalizing")
	oldManifest := path.Join(target, "manifest.previous")
	if _, err := writeProtected(root, nextManifest, bytes.NewReader(manifestBytes), a.uid); err != nil {
		return err
	}
	if err := syncDirectory(root, temporary); err != nil || root.Rename(path.Join(target, "prepared"), previous) != nil || root.Rename(temporary, path.Join(target, "prepared")) != nil || root.Rename(path.Join(target, "manifest.json"), oldManifest) != nil || root.Rename(nextManifest, path.Join(target, "manifest.json")) != nil {
		return errors.New("deferred State artifact replacement was interrupted")
	}
	if err := syncDirectory(root, target); err != nil {
		return err
	}
	return verifyDeferredStateGeneration(root, target, binding, a.uid)
}

func (a Adapter) Execute(lease systemchanges.ExecutionLease, changeSet string, number int, step systemchanges.Step, timeout time.Duration, cancellation *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	if !lease.Authorized() || a.host == nil {
		return systemchanges.StepEvidence{}, errors.New("typed Ubuntu transaction host unavailable")
	}
	if _, ok := step.FirewallChange(); ok {
		if a.firewall == nil {
			return systemchanges.StepEvidence{}, errors.New("native firewall Adapter unavailable")
		}
		if !safeName(changeSet) || number < 1 {
			return systemchanges.StepEvidence{}, errors.New("invalid firewall transaction identity")
		}
		name := fmt.Sprintf("snapshot/step-%03d.rollback", number)
		if _, err := a.recoveryArtifact(lease, changeSet, name); err != nil {
			return systemchanges.StepEvidence{}, err
		}
		return a.firewall.Execute(step, path.Join(a.root, transactionDirectory, changeSet, name), timeout, cancellation)
	}
	if change, ok := step.CloudflareChange(); ok {
		if a.cloudflare == nil || !safeName(changeSet) || number < 1 {
			return systemchanges.StepEvidence{}, errors.New("Cloudflare transaction executor unavailable")
		}
		resolved := change.TunnelID
		if change.TunnelIDFromStep > 0 {
			prior, err := a.completedStepEvidence(changeSet, change.TunnelIDFromStep)
			if err != nil || prior.ResourceType != string(systemchanges.CloudflareTunnelResource) {
				return systemchanges.StepEvidence{}, errors.New("journaled Tunnel identifier unavailable")
			}
			resolved = prior.ResourceID
		}
		return a.cloudflare.Execute(step, resolved, timeout)
	}
	evidence, err := a.host.Execute(step, timeout, cancellation)
	if err == nil && step.Owner() == systemchanges.CloudflareModule && step.Forward() == systemchanges.ActivatePreparedConfiguration {
		if a.cloudflare == nil || a.cloudflare.ValidateInstalledService(a.root) != nil || a.cloudflare.ValidateNativeConfiguration(timeout) != nil {
			return systemchanges.StepEvidence{}, errors.New("installed cloudflared service is unproved")
		}
	}
	return evidence, err
}

func (a Adapter) Reverse(lease systemchanges.ExecutionLease, changeSet string, number int, step systemchanges.Step, timeout time.Duration) (systemchanges.StepEvidence, error) {
	if !lease.Authorized() || a.host == nil || !safeName(changeSet) || number < 1 {
		return systemchanges.StepEvidence{}, errors.New("typed Ubuntu transaction host unavailable")
	}
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	defer root.Close()
	directory := path.Join(transactionDirectory, changeSet)
	manifest, err := verifyTransactionManifest(root, directory, a.uid)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	name := fmt.Sprintf("snapshot/step-%03d.rollback", number)
	content, err := root.ReadFile(path.Join(directory, name))
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != manifest.Files[name] {
		return systemchanges.StepEvidence{}, errors.New("rollback snapshot checksum mismatch")
	}
	if _, ok := step.FirewallChange(); ok {
		if a.firewall == nil {
			return systemchanges.StepEvidence{}, errors.New("native firewall Adapter unavailable")
		}
		return a.firewall.Reverse(step, bytes.NewReader(content), timeout)
	}
	if _, ok := step.CloudflareChange(); ok {
		if a.cloudflare == nil {
			return systemchanges.StepEvidence{}, errors.New("Cloudflare rollback executor unavailable")
		}
		evidence, err := a.completedStepEvidence(changeSet, number)
		if err != nil {
			evidence = systemchanges.StepEvidence{}
		}
		return a.cloudflare.Reverse(step, evidence, bytes.NewReader(content), timeout)
	}
	return a.host.Reverse(step, bytes.NewReader(content), timeout)
}

func (a Adapter) completedStepEvidence(changeSet string, number int) (systemchanges.StepEvidence, error) {
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	defer root.Close()
	entries, err := readJournal(root, path.Join(transactionDirectory, changeSet, "journal.jsonl"))
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	for index := len(entries) - 1; index >= 0; index-- {
		entry := entries[index]
		if entry.Checkpoint == systemchanges.StepCompleted && entry.Step == number && entry.Evidence != nil {
			return *entry.Evidence, nil
		}
	}
	return systemchanges.StepEvidence{}, errors.New("completed step evidence unavailable")
}

func (a Adapter) LoadRecovery(lease systemchanges.ExecutionLease) (systemchanges.RecoveryTransaction, error) {
	if !lease.Authorized() || a.host == nil || a.source == nil {
		return systemchanges.RecoveryTransaction{}, errors.New("typed Ubuntu recovery host unavailable")
	}
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return systemchanges.RecoveryTransaction{}, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), transactionDirectory)
	if errors.Is(err, fs.ErrNotExist) || err == nil && len(entries) == 0 {
		return systemchanges.RecoveryTransaction{}, systemchanges.ErrNoRecoveryTransaction
	}
	if err != nil || len(entries) != 1 || !entries[0].IsDir() || !safeName(entries[0].Name()) {
		return systemchanges.RecoveryTransaction{}, errors.New("one unfinished transaction was not proven")
	}
	changeSet := entries[0].Name()
	directory := path.Join(transactionDirectory, changeSet)
	if err := verifyDirectory(root, directory, a.uid); err != nil {
		return systemchanges.RecoveryTransaction{}, err
	}
	if err := verifyFile(root, path.Join(directory, "journal.jsonl"), a.uid); err != nil {
		return systemchanges.RecoveryTransaction{}, err
	}
	journal, err := readJournal(root, path.Join(directory, "journal.jsonl"))
	if err != nil || !validJournal(journal) {
		return systemchanges.RecoveryTransaction{}, errors.New("recovery journal is invalid")
	}
	if err := reconcileDeferredReplacement(root, directory, journal); err != nil {
		return systemchanges.RecoveryTransaction{}, errors.New("deferred State replacement is unprovable")
	}
	prepared, last := journal[0], journal[len(journal)-1]
	for _, entry := range journal[1:] {
		if entry.Checkpoint == systemchanges.StateFinalized && entry.State != nil {
			prepared.State = entry.State
		}
	}
	irreversible := prepared.Mutation == systemchanges.CompleteRemovalMutation && systemchanges.IsIrreversibleRemovalCheckpoint(last.Checkpoint)
	if prepared.State == nil || prepared.ChangeSet != changeSet || !validRecoveryJournalBinding(prepared) {
		return systemchanges.RecoveryTransaction{}, errors.New("recovery transaction lineage is invalid")
	}
	if !irreversible {
		manifest, err := verifyTransactionManifest(root, directory, a.uid)
		if err != nil || manifest.Reason != prepared.Mutation || !validRecoveryBinding(prepared, manifest) {
			return systemchanges.RecoveryTransaction{}, errors.New("recovery transaction lineage is invalid")
		}
	}
	steps := make([]systemchanges.Step, len(prepared.Steps))
	for index, persisted := range prepared.Steps {
		var step systemchanges.Step
		var err error
		if persisted.Firewall == nil && persisted.Removal == nil && persisted.Cloudflare == nil {
			step, err = systemchanges.NewStep(persisted.Owner, persisted.Forward, persisted.Rollback)
		} else if persisted.Firewall != nil && persisted.Removal == nil && persisted.Cloudflare == nil {
			if a.firewall == nil {
				return systemchanges.RecoveryTransaction{}, errors.New("native firewall Adapter unavailable")
			}
			switch persisted.Firewall.Action {
			case systemchanges.FirewallPolicyAction:
				step, err = systemchanges.NewFirewallPolicyStep(persisted.Firewall.Candidate, persisted.Firewall.SSHPort)
			case systemchanges.HTTP01OpenAction:
				step, err = systemchanges.NewHTTP01OpenStep(persisted.Firewall.Candidate, persisted.Firewall.SSHPort)
			case systemchanges.HTTP01CloseAction:
				step, err = systemchanges.NewHTTP01CloseStep()
			default:
				err = errors.New("unknown firewall action")
			}
		} else if persisted.Firewall == nil && persisted.Removal != nil && persisted.Cloudflare == nil {
			step, err = systemchanges.RestoreRemovalStep(lease, *persisted.Removal)
		} else if persisted.Firewall == nil && persisted.Removal == nil && persisted.Cloudflare != nil {
			step, err = systemchanges.NewCloudflareStep(*persisted.Cloudflare)
		} else {
			err = errors.New("ambiguous typed step")
		}
		if err != nil || step.Owner() != persisted.Owner || step.Forward() != persisted.Forward || step.Rollback() != persisted.Rollback || persisted.Cancellation != systemchanges.SafeCheckpointCancellation || persisted.Inspection != systemchanges.InspectBeforeIdempotentReverse {
			return systemchanges.RecoveryTransaction{}, errors.New("recovery step contract is invalid")
		}
		steps[index] = step
	}
	observed, err := a.source()
	startingState := observed.StateRevision == prepared.State.StartingRevision && observed.StateSHA256 == prepared.State.StartingSHA256
	candidateState := observed.StateRevision == prepared.State.CandidateRevision && observed.StateSHA256 == prepared.State.CandidateSHA256
	complete := last.Checkpoint == systemchanges.Complete && observed.Status == systemchanges.Managed && observed.LastChangeSet == changeSet && candidateState
	unfinished := observed.Status == systemchanges.ChangeInProgress && observed.CurrentChangeSet == changeSet && (startingState || candidateState) && (last.Checkpoint != systemchanges.RolledBack || startingState)
	irreversibleRemoval := irreversible && (observed.Status == systemchanges.ChangeInProgress && observed.CurrentChangeSet == changeSet || observed.Status == systemchanges.NotInstalled)
	if err != nil || !complete && !unfinished && !irreversibleRemoval {
		return systemchanges.RecoveryTransaction{}, errors.New("current State does not match the recovery transaction")
	}
	return systemchanges.RecoveryTransaction{
		ChangeSet: changeSet, Mutation: prepared.Mutation, Starting: prepared.Starting, StartingRelease: prepared.State.StartingRelease,
		Candidate: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: prepared.State.CandidateRevision, SHA256: prepared.State.CandidateSHA256}, CandidateRelease: prepared.State.CandidateRelease,
		OutcomeOwner: prepared.OutcomeOwner, Steps: steps, AttemptedSteps: highestStartedStep(journal), RollbackStep: rollbackResumeStep(journal), LastCheckpoint: last.Checkpoint, Timeouts: prepared.Timeouts,
	}, nil
}

func rollbackResumeStep(entries []journalEntry) int {
	last := entries[len(entries)-1]
	switch last.Checkpoint {
	case systemchanges.RollbackStarted:
		return highestStartedStep(entries)
	case systemchanges.RollbackStepStarted:
		return last.Step
	case systemchanges.RollbackStepCompleted:
		return last.Step - 1
	}
	return 0
}

func (a Adapter) HoldServices(lease systemchanges.ExecutionLease) error {
	if !lease.Authorized() || a.host == nil {
		return errors.New("typed Ubuntu recovery host unavailable")
	}
	return a.host.HoldServices()
}

func (a Adapter) AllowProvenServices(lease systemchanges.ExecutionLease, recovery systemchanges.RecoveryTransaction, timeout time.Duration) error {
	if !lease.Authorized() || a.host == nil {
		return errors.New("typed Ubuntu recovery host unavailable")
	}
	return a.host.AllowProvenServices(recovery, timeout)
}

func (a Adapter) InspectStep(lease systemchanges.ExecutionLease, recovery systemchanges.RecoveryTransaction, number int, step systemchanges.Step, timeout time.Duration) (systemchanges.StepEffect, error) {
	content, err := a.recoveryArtifact(lease, recovery.ChangeSet, fmt.Sprintf("snapshot/step-%03d.rollback", number))
	if err != nil {
		return "", err
	}
	if _, ok := step.FirewallChange(); ok {
		if a.firewall == nil {
			return "", errors.New("native firewall Adapter unavailable")
		}
		return a.firewall.Inspect(step, bytes.NewReader(content), timeout)
	}
	return a.host.InspectStep(step, bytes.NewReader(content), timeout)
}

func (a Adapter) RestoreRecoveryState(lease systemchanges.ExecutionLease, recovery systemchanges.RecoveryTransaction) (systemchanges.RollbackAgreement, error) {
	if !lease.Authorized() || a.state == nil {
		return systemchanges.RollbackAgreement{}, errors.New("State recovery boundary unavailable")
	}
	candidate, err := a.recoveryArtifact(lease, recovery.ChangeSet, "prepared/state.json")
	if err != nil {
		return systemchanges.RollbackAgreement{}, err
	}
	var prior []byte
	if recovery.Starting.Status == systemchanges.Managed || recovery.Starting.Status == systemchanges.RecoveryRequired && recovery.Starting.Revision > 0 {
		prior, err = a.recoveryArtifact(lease, recovery.ChangeSet, "snapshot/prior-state.json")
		if err != nil {
			return systemchanges.RollbackAgreement{}, err
		}
	}
	binding, err := a.recoveryBinding(lease, recovery.ChangeSet)
	if err != nil {
		return systemchanges.RollbackAgreement{}, err
	}
	bindingJSON, err := json.Marshal(binding)
	if err != nil {
		return systemchanges.RollbackAgreement{}, err
	}
	agreementJSON, err := a.state.SystemChangesRestoreDurable(lease, bindingJSON, bytes.NewReader(prior), bytes.NewReader(candidate))
	var agreement systemchanges.RollbackAgreement
	if err != nil || json.Unmarshal(agreementJSON, &agreement) != nil {
		return systemchanges.RollbackAgreement{}, errors.New("State recovery agreement unavailable")
	}
	return agreement, nil
}

func (a Adapter) VerifyStartingServices(lease systemchanges.ExecutionLease, recovery systemchanges.RecoveryTransaction, timeout time.Duration) error {
	if !lease.Authorized() || a.host == nil {
		return errors.New("typed Ubuntu recovery host unavailable")
	}
	return a.host.VerifyStartingServices(recovery, timeout)
}

func (a Adapter) VerifyCloudflareTokenRevoked(lease systemchanges.ExecutionLease, _ systemchanges.RecoveryTransaction, timeout time.Duration) (bool, error) {
	host, ok := a.host.(IrreversibleRemovalHost)
	if !lease.Authorized() || !ok {
		return false, errors.New("irreversible removal host unavailable")
	}
	return host.VerifyCloudflareTokenRevoked(timeout)
}

func (a Adapter) DeleteIrreversibleRemovalPhase(lease systemchanges.ExecutionLease, _ systemchanges.RecoveryTransaction, phase systemchanges.IrreversibleRemovalPhase, timeout time.Duration) (systemchanges.StepEvidence, error) {
	if phase == systemchanges.TransactionMaterialPhase {
		return a.deleteTransactionMaterial(lease)
	}
	host, ok := a.host.(IrreversibleRemovalHost)
	if !lease.Authorized() || !ok {
		return systemchanges.StepEvidence{}, errors.New("irreversible removal host unavailable")
	}
	return host.DeleteIrreversibleRemovalPhase(phase, timeout)
}

func (a Adapter) VerifyFinalRemovalAbsence(lease systemchanges.ExecutionLease, _ systemchanges.RecoveryTransaction, timeout time.Duration) (systemchanges.Observation, error) {
	host, ok := a.host.(IrreversibleRemovalHost)
	if !lease.Authorized() || !ok || a.source == nil {
		return systemchanges.Observation{}, errors.New("irreversible removal host unavailable")
	}
	absent, err := host.VerifyFinalRemovalAbsence(timeout)
	if err != nil || !absent {
		return systemchanges.Observation{}, errors.New("SBXR-owned resources remain")
	}
	return a.source()
}

func (a Adapter) FinalizeRemoval(lease systemchanges.ExecutionLease, recovery systemchanges.RecoveryTransaction, timeout time.Duration) error {
	host, ok := a.host.(IrreversibleRemovalHost)
	if !lease.Authorized() || !ok {
		return errors.New("irreversible removal host unavailable")
	}
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return err
	}
	defer root.Close()
	target := path.Join(transactionDirectory, recovery.ChangeSet)
	journal := path.Join(target, "journal.jsonl")
	entries, err := readJournal(root, journal)
	if err != nil || !validJournal(entries) || entries[len(entries)-1].Checkpoint != systemchanges.FinalRemovalAbsenceVerified {
		return errors.New("final removal journal is unresolved")
	}
	if err := root.Remove(journal); err != nil {
		return err
	}
	if err := root.Remove(target); err != nil {
		return err
	}
	if err := syncDirectory(root, transactionDirectory); err != nil {
		return err
	}
	return host.FinalizeRemoval(timeout)
}

func (a Adapter) FinalizeOrphanedRemoval(lease systemchanges.ExecutionLease, observed systemchanges.Observation, timeout time.Duration) error {
	host, ok := a.host.(IrreversibleRemovalHost)
	if !lease.Authorized() || !ok || observed.Status != systemchanges.NotInstalled || observed.CurrentChangeSet != "" || observed.StateRevision != 0 || observed.StateSHA256 != "" || observed.RollbackAvailable {
		return errors.New("orphaned removal runner cannot prove Not installed")
	}
	absent, err := host.VerifyFinalRemovalAbsence(timeout)
	if err != nil || !absent {
		return errors.New("orphaned removal runner found owned resources")
	}
	return host.FinalizeRemoval(timeout)
}

func (a Adapter) deleteTransactionMaterial(lease systemchanges.ExecutionLease) (systemchanges.StepEvidence, error) {
	if !lease.Authorized() {
		return systemchanges.StepEvidence{}, errors.New("invalid transaction authority")
	}
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), transactionDirectory)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() || !safeName(entries[0].Name()) {
		return systemchanges.StepEvidence{}, errors.New("one finalizing transaction was not proven")
	}
	target := path.Join(transactionDirectory, entries[0].Name())
	journal, err := readJournal(root, path.Join(target, "journal.jsonl"))
	if err != nil || !validJournal(journal) || journal[len(journal)-1].Checkpoint != systemchanges.ReleasesDeleted {
		return systemchanges.StepEvidence{}, errors.New("transaction material deletion is out of order")
	}
	manifest, manifestErr := readSnapshotManifest(root, target, a.uid)
	if manifestErr == nil {
		names := make([]string, 0, len(manifest.Files))
		for name := range manifest.Files {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if err := root.Remove(path.Join(target, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return systemchanges.StepEvidence{}, err
			}
		}
		for _, name := range []string{"snapshot", "prepared"} {
			if err := root.Remove(path.Join(target, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return systemchanges.StepEvidence{}, err
			}
		}
		if err := root.Remove(path.Join(target, "manifest.json")); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return systemchanges.StepEvidence{}, err
		}
	} else if err := verifyFinalizingTransaction(root, target, a.uid); err != nil {
		return systemchanges.StepEvidence{}, manifestErr
	}
	if err := syncDirectory(root, target); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	digest := sha256.Sum256([]byte(systemchanges.TransactionMaterialPhase))
	return systemchanges.StepEvidence{Code: "transaction-material-absent", SHA256: hex.EncodeToString(digest[:])}, nil
}

func (a Adapter) recoveryArtifact(lease systemchanges.ExecutionLease, changeSet, name string) ([]byte, error) {
	if !lease.Authorized() || !safeName(changeSet) || !safeArtifact(name) {
		return nil, errors.New("invalid recovery artifact request")
	}
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	directory := path.Join(transactionDirectory, changeSet)
	manifest, err := verifyTransactionManifest(root, directory, a.uid)
	if err != nil || manifest.Files[name] == "" {
		return nil, errors.New("recovery artifact is not transaction-bound")
	}
	content, err := root.ReadFile(path.Join(directory, name))
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != manifest.Files[name] {
		return nil, errors.New("recovery artifact checksum mismatch")
	}
	return content, nil
}

func (a Adapter) recoveryBinding(lease systemchanges.ExecutionLease, changeSet string) (systemchanges.StateTransactionBinding, error) {
	if !lease.Authorized() || !safeName(changeSet) {
		return systemchanges.StateTransactionBinding{}, errors.New("invalid recovery binding request")
	}
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return systemchanges.StateTransactionBinding{}, err
	}
	defer root.Close()
	journal, err := readJournal(root, path.Join(transactionDirectory, changeSet, "journal.jsonl"))
	if err != nil || !validJournal(journal) || journal[0].State == nil {
		return systemchanges.StateTransactionBinding{}, errors.New("recovery State binding is invalid")
	}
	return *journal[0].State, nil
}

func recoveryRelease(binding systemchanges.StateTransactionBinding) systemchanges.ReleaseBinding {
	if binding.StartingRelease != (systemchanges.ReleaseBinding{}) {
		return binding.StartingRelease
	}
	return binding.CandidateRelease
}

func validRecoveryBinding(prepared journalEntry, manifest snapshotManifest) bool {
	binding := *prepared.State
	if !validRecoveryJournalBinding(prepared) || manifest.Release != recoveryRelease(binding) || manifest.Files["prepared/state.json"] != binding.PreparedStateSHA256 || manifest.Files["prepared/manifests.json"] != binding.PreparedManifestSHA256 {
		return false
	}
	if prepared.Starting.Status == systemchanges.Managed || prepared.Starting.Status == systemchanges.RecoveryRequired && binding.StartingRevision > 0 {
		return binding.StartingRelease != (systemchanges.ReleaseBinding{}) && manifest.Files["snapshot/prior-state.json"] != ""
	}
	return prepared.Starting.Status == systemchanges.NotInstalled && binding.StartingRevision == 0 && binding.StartingSHA256 == "" && binding.StartingRelease == (systemchanges.ReleaseBinding{}) && manifest.Files["snapshot/prior-state.json"] == ""
}

func validRecoveryJournalBinding(prepared journalEntry) bool {
	if prepared.State == nil || prepared.Mutation == "" {
		return false
	}
	binding := *prepared.State
	return binding.ChangeSet == prepared.ChangeSet && binding.StartingRevision == prepared.Starting.Revision && binding.StartingSHA256 == prepared.Starting.SHA256 && binding.CandidateRevision == binding.StartingRevision+1 && binding.CandidateRelease != (systemchanges.ReleaseBinding{}) && validDigest(prepared.PlanSHA256) && validDigest(binding.CandidateSHA256) && validDigest(binding.PreparedStateSHA256) && validDigest(binding.PreparedManifestSHA256)
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (a Adapter) Check(lease systemchanges.ExecutionLease, check systemchanges.Check, phase systemchanges.GatePhase, timeout time.Duration) (systemchanges.HealthStatus, error) {
	if !lease.Authorized() || a.host == nil {
		return systemchanges.Unknown, errors.New("typed Ubuntu transaction host unavailable")
	}
	if check.Owner == systemchanges.CloudflareModule && check.Code == "CLOUDFLARE-WHOLE-TUNNEL" {
		if a.cloudflare == nil {
			return systemchanges.Unknown, errors.New("Cloudflare health executor unavailable")
		}
		evidence, err := a.activeStepEvidence()
		if err != nil {
			return systemchanges.Unknown, err
		}
		return a.cloudflare.CheckWholeTunnel(evidence, timeout)
	}
	return a.host.Check(check, phase, timeout)
}

func (a Adapter) activeStepEvidence() ([]systemchanges.StepEvidence, error) {
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), transactionDirectory)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		return nil, errors.New("active Cloudflare transaction unavailable")
	}
	journal, err := readJournal(root, path.Join(transactionDirectory, entries[0].Name(), "journal.jsonl"))
	if err != nil || !validJournal(journal) || len(journal) == 0 {
		return nil, errors.New("Cloudflare health journal unavailable")
	}
	evidence := make([]systemchanges.StepEvidence, len(journal[0].Steps))
	for _, entry := range journal {
		if entry.Checkpoint == systemchanges.StepCompleted && entry.Step > 0 && entry.Step <= len(evidence) && entry.Evidence != nil {
			evidence[entry.Step-1] = *entry.Evidence
		}
	}
	return evidence, nil
}

func (a Adapter) VerifyAgreement(lease systemchanges.ExecutionLease, agreement systemchanges.Agreement, timeout time.Duration) error {
	if !lease.Authorized() || a.host == nil {
		return errors.New("typed Ubuntu transaction host unavailable")
	}
	return a.host.VerifyAgreement(agreement, timeout)
}

func (a Adapter) VerifyRollback(lease systemchanges.ExecutionLease, agreement systemchanges.RollbackAgreement, timeout time.Duration) error {
	if !lease.Authorized() || a.host == nil {
		return errors.New("typed Ubuntu transaction host unavailable")
	}
	return a.host.VerifyRollback(agreement, timeout)
}

func (a Adapter) Cleanup(lease systemchanges.ExecutionLease, changeSet string) error {
	if !lease.Authorized() || !safeName(changeSet) {
		return errors.New("invalid transaction identity")
	}
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return err
	}
	defer root.Close()
	target := path.Join(transactionDirectory, changeSet)
	manifest, err := verifyTransactionManifest(root, target, a.uid)
	if err != nil {
		return err
	}
	entries, err := readJournal(root, path.Join(target, "journal.jsonl"))
	if err != nil || len(entries) == 0 || entries[len(entries)-1].Checkpoint != systemchanges.Complete && entries[len(entries)-1].Checkpoint != systemchanges.RolledBack && entries[len(entries)-1].Checkpoint != systemchanges.FinalRemovalAbsenceVerified {
		return errors.New("transaction is not durably resolved")
	}
	names := make([]string, 0, len(manifest.Files))
	for name := range manifest.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := root.Remove(path.Join(target, name)); err != nil {
			return err
		}
	}
	for _, name := range []string{"manifest.json", "journal.jsonl"} {
		if err := root.Remove(path.Join(target, name)); err != nil {
			return err
		}
	}
	for _, directory := range []string{"snapshot", "prepared", "."} {
		name := target
		if directory != "." {
			name = path.Join(target, directory)
		}
		if err := root.Remove(name); err != nil {
			return err
		}
	}
	return syncDirectory(root, transactionDirectory)
}

func writeProtected(root *os.Root, name string, source io.Reader, uid int) (string, error) {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(file, digest), source)
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if syncErr != nil {
		return "", syncErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err := verifyFile(root, name, uid); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func appendJournal(root *os.Root, name string, entry journalEntry, uid int) error {
	if err := verifyFile(root, name, uid); err != nil {
		return err
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	entries, err := readJournal(root, name)
	if err != nil || !validNextCheckpoint(entries, entry) {
		return errors.New("journal checkpoint order is invalid")
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	if _, err = file.Write(append(data, '\n')); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return verifyLastJournalEntry(root, name, entry)
}

func verifyLastJournalEntry(root *os.Root, name string, want journalEntry) error {
	entries, err := readJournal(root, name)
	if err != nil || len(entries) == 0 {
		return errors.New("journal readback unavailable")
	}
	got, _ := json.Marshal(entries[len(entries)-1])
	expected, _ := json.Marshal(want)
	if string(got) != string(expected) {
		return errors.New("journal readback mismatch")
	}
	return nil
}

func readJournal(root *os.Root, name string) ([]journalEntry, error) {
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var entries []journalEntry
	for scanner.Scan() {
		var current journalEntry
		if err := json.Unmarshal(scanner.Bytes(), &current); err != nil {
			return nil, err
		}
		entries = append(entries, current)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func validJournal(entries []journalEntry) bool {
	for index, entry := range entries {
		if !validNextCheckpoint(entries[:index], entry) {
			return false
		}
	}
	return len(entries) > 0
}

func validNextCheckpoint(entries []journalEntry, next journalEntry) bool {
	if len(entries) == 0 {
		return next.Checkpoint == systemchanges.Prepared && next.ChangeSet != "" && next.Mutation != "" && next.OutcomeOwner != "" && next.PlanSHA256 != "" && next.State != nil && len(next.Steps) > 0 && len(next.Checks) > 0 && next.Timeouts.Step > 0 && next.Timeouts.Check > 0
	}
	if entries[0].Checkpoint != systemchanges.Prepared || len(entries[0].Steps) == 0 {
		return false
	}
	last, total := entries[len(entries)-1], len(entries[0].Steps)
	switch last.Checkpoint {
	case systemchanges.Prepared:
		return next.Checkpoint == systemchanges.StepStarted && next.Step == 1 || next.Checkpoint == systemchanges.CancellationRequested && next.Step == 0 || next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0
	case systemchanges.StepStarted:
		return next.Checkpoint == systemchanges.StepCompleted && next.Step == last.Step && validEvidence(next.Evidence) || next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0 || next.Checkpoint == systemchanges.CancellationRequested && next.Step == last.Step
	case systemchanges.StepCompleted:
		if last.Step < total {
			return next.Checkpoint == systemchanges.StateFinalized && next.Step == last.Step && next.State != nil || next.Checkpoint == systemchanges.StepStarted && next.Step == last.Step+1 || next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0 || next.Checkpoint == systemchanges.CancellationRequested && next.Step == last.Step
		}
		return next.Checkpoint == systemchanges.StateFinalized && next.Step == 0 && next.State != nil || next.Checkpoint == systemchanges.PrePublicationHealthPassed && next.Step == 0 || next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0 || next.Checkpoint == systemchanges.CancellationRequested && next.Step == last.Step
	case systemchanges.StateFinalized:
		return next.Checkpoint == systemchanges.StepStarted && next.Step == last.Step+1 || next.Checkpoint == systemchanges.PrePublicationHealthPassed && next.Step == 0 || next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0 || next.Checkpoint == systemchanges.CancellationRequested && next.Step == last.Step
	case systemchanges.PrePublicationHealthPassed:
		return next.Checkpoint == systemchanges.OwnedExternalDeletionVerified && next.Step == 0 || next.Checkpoint == systemchanges.StatePublicationStarted && next.Step == 0 || next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0 || next.Checkpoint == systemchanges.CancellationRequested && next.Step == total
	case systemchanges.OwnedExternalDeletionVerified:
		return next.Checkpoint == systemchanges.IrreversibleRemovalStarted && next.Step == 0 || next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0 || next.Checkpoint == systemchanges.CancellationRequested && next.Step == total
	case systemchanges.StatePublicationStarted:
		return next.Checkpoint == systemchanges.StatePublished && next.Step == 0 || next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0 || next.Checkpoint == systemchanges.CancellationRequested && next.Step == total
	case systemchanges.StatePublished:
		return next.Checkpoint == systemchanges.PostPublicationHealthPassed && next.Step == 0 || next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0 || next.Checkpoint == systemchanges.CancellationRequested && next.Step == total
	case systemchanges.PostPublicationHealthPassed:
		return next.Checkpoint == systemchanges.Complete && next.Step == 0 || next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0 || next.Checkpoint == systemchanges.CancellationRequested && next.Step == total
	case systemchanges.CancellationRequested:
		return next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0
	case systemchanges.RollbackStarted:
		attempted := highestStartedStep(entries)
		return attempted == 0 && next.Checkpoint == systemchanges.RollbackVerified && next.Step == 0 || attempted > 0 && next.Checkpoint == systemchanges.RollbackStepStarted && next.Step == attempted
	case systemchanges.RollbackStepStarted:
		return next.Checkpoint == systemchanges.RollbackStepCompleted && next.Step == last.Step && validEvidence(next.Evidence)
	case systemchanges.RollbackStepCompleted:
		if last.Step > 1 {
			return next.Checkpoint == systemchanges.RollbackStepStarted && next.Step == last.Step-1
		}
		return next.Checkpoint == systemchanges.RollbackVerified && next.Step == 0
	case systemchanges.RollbackVerified:
		return next.Checkpoint == systemchanges.RolledBack && next.Step == 0
	}
	expected, irreversible := systemchanges.NextIrreversibleRemovalCheckpoint(last.Checkpoint)
	if !irreversible || expected == "" || next.Checkpoint != expected || next.Step != 0 {
		return false
	}
	if expected == systemchanges.TokenRevocationVerified || expected == systemchanges.FinalRemovalAbsenceVerified {
		return next.Evidence == nil
	}
	return validEvidence(next.Evidence)
}

func highestStartedStep(entries []journalEntry) int {
	highest := 0
	for _, entry := range entries {
		if entry.Checkpoint == systemchanges.StepStarted && entry.Step > highest {
			highest = entry.Step
		}
	}
	return highest
}

func validEvidence(evidence *systemchanges.StepEvidence) bool {
	if evidence == nil || evidence.Code == "" || len(evidence.Code) > 128 || len(evidence.SHA256) != 64 {
		return false
	}
	if (evidence.ResourceType == "") != (evidence.ResourceID == "") || evidence.ResourceType != "" && (!safeName(evidence.ResourceType) || !safeName(evidence.ResourceID)) {
		return false
	}
	for _, character := range evidence.Code {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	_, err := hex.DecodeString(evidence.SHA256)
	return err == nil
}

func verifyTransaction(root *os.Root, directory string, uid int) error {
	_, err := verifyTransactionManifest(root, directory, uid)
	return err
}

func verifyDeferredStateGeneration(root *os.Root, directory string, binding systemchanges.StateTransactionBinding, uid int) error {
	manifest, err := readSnapshotManifest(root, directory, uid)
	if err != nil || manifest.Files["prepared/state.json"] != binding.PreparedStateSHA256 || manifest.Files["prepared/manifests.json"] != binding.PreparedManifestSHA256 {
		return errors.New("finalized State generation is unbound")
	}
	for name, checksum := range manifest.Files {
		if !safeArtifact(name) || verifyFile(root, path.Join(directory, name), uid) != nil {
			return errors.New("finalized State artifact is unsafe")
		}
		content, readErr := root.ReadFile(path.Join(directory, name))
		digest := sha256.Sum256(content)
		if readErr != nil || hex.EncodeToString(digest[:]) != checksum {
			return errors.New("finalized State artifact checksum mismatch")
		}
	}
	return nil
}

func reconcileDeferredReplacement(root *os.Root, directory string, journal []journalEntry) error {
	previous := path.Join(directory, "prepared.previous")
	oldManifest := path.Join(directory, "manifest.previous")
	hasPrevious := pathExists(root, previous) || pathExists(root, oldManifest)
	if !hasPrevious && !pathExists(root, path.Join(directory, "prepared.finalizing")) && !pathExists(root, path.Join(directory, "manifest.finalizing")) {
		return nil
	}
	finalized := false
	for _, entry := range journal {
		if entry.Checkpoint == systemchanges.StateFinalized && entry.State != nil {
			finalized = true
		}
	}
	if finalized {
		return discardDeferredPrevious(root, directory)
	}
	if pathExists(root, previous) {
		if pathExists(root, path.Join(directory, "prepared")) {
			if err := removeFlatDirectory(root, path.Join(directory, "prepared")); err != nil {
				return err
			}
		}
		if err := root.Rename(previous, path.Join(directory, "prepared")); err != nil {
			return err
		}
	}
	if pathExists(root, oldManifest) {
		_ = root.Remove(path.Join(directory, "manifest.json"))
		if err := root.Rename(oldManifest, path.Join(directory, "manifest.json")); err != nil {
			return err
		}
	}
	for _, name := range []string{"prepared.finalizing", "manifest.finalizing"} {
		candidate := path.Join(directory, name)
		if pathExists(root, candidate) {
			if strings.HasPrefix(name, "prepared") {
				if err := removeFlatDirectory(root, candidate); err != nil {
					return err
				}
			} else if err := root.Remove(candidate); err != nil {
				return err
			}
		}
	}
	return syncDirectory(root, directory)
}

func discardDeferredPrevious(root *os.Root, directory string) error {
	previous := path.Join(directory, "prepared.previous")
	if pathExists(root, previous) {
		if err := removeFlatDirectory(root, previous); err != nil {
			return err
		}
	}
	for _, name := range []string{"manifest.previous", "prepared.finalizing", "manifest.finalizing"} {
		candidate := path.Join(directory, name)
		if !pathExists(root, candidate) {
			continue
		}
		if strings.HasPrefix(name, "prepared") {
			if err := removeFlatDirectory(root, candidate); err != nil {
				return err
			}
		} else if err := root.Remove(candidate); err != nil {
			return err
		}
	}
	return syncDirectory(root, directory)
}

func removeFlatDirectory(root *os.Root, directory string) error {
	entries, err := fs.ReadDir(root.FS(), directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !safeName(entry.Name()) || root.Remove(path.Join(directory, entry.Name())) != nil {
			return errors.New("deferred State generation could not be removed")
		}
	}
	return root.Remove(directory)
}

func pathExists(root *os.Root, name string) bool {
	_, err := root.Lstat(name)
	return err == nil
}

func verifyTransactionManifest(root *os.Root, directory string, uid int) (snapshotManifest, error) {
	for _, name := range []string{directory, path.Join(directory, "snapshot"), path.Join(directory, "prepared")} {
		if err := verifyDirectory(root, name, uid); err != nil {
			return snapshotManifest{}, err
		}
	}
	for _, name := range []string{"manifest.json", "journal.jsonl"} {
		if err := verifyFile(root, path.Join(directory, name), uid); err != nil {
			return snapshotManifest{}, err
		}
	}
	data, err := root.ReadFile(path.Join(directory, "manifest.json"))
	if err != nil {
		return snapshotManifest{}, err
	}
	var manifest snapshotManifest
	if err := json.Unmarshal(data, &manifest); err != nil || manifest.SchemaVersion != 1 || manifest.Release == (systemchanges.ReleaseBinding{}) || manifest.Reason == "" {
		return snapshotManifest{}, errors.New("invalid snapshot manifest")
	}
	want := map[string]bool{"manifest.json": true, "journal.jsonl": true, "snapshot": true, "prepared": true}
	for name, checksum := range manifest.Files {
		if !safeArtifact(name) || len(checksum) != 64 {
			return snapshotManifest{}, errors.New("invalid snapshot artifact binding")
		}
		artifact := path.Join(directory, name)
		if err := verifyFile(root, artifact, uid); err != nil {
			return snapshotManifest{}, err
		}
		content, err := root.ReadFile(artifact)
		if err != nil {
			return snapshotManifest{}, err
		}
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != checksum {
			return snapshotManifest{}, errors.New("snapshot checksum mismatch")
		}
		want[name] = true
	}
	err = fs.WalkDir(root.FS(), directory, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == directory {
			return nil
		}
		relative := strings.TrimPrefix(name, directory+"/")
		if !want[relative] {
			return fmt.Errorf("unexpected transaction artifact %s", relative)
		}
		return nil
	})
	return manifest, err
}

func readSnapshotManifest(root *os.Root, directory string, uid int) (snapshotManifest, error) {
	if err := verifyFile(root, path.Join(directory, "manifest.json"), uid); err != nil {
		return snapshotManifest{}, err
	}
	data, err := root.ReadFile(path.Join(directory, "manifest.json"))
	var manifest snapshotManifest
	if err != nil || json.Unmarshal(data, &manifest) != nil || manifest.SchemaVersion != 1 || manifest.Release == (systemchanges.ReleaseBinding{}) || manifest.Reason == "" {
		return snapshotManifest{}, errors.New("invalid snapshot manifest")
	}
	for name, checksum := range manifest.Files {
		if !safeArtifact(name) || !validDigest(checksum) {
			return snapshotManifest{}, errors.New("invalid snapshot artifact binding")
		}
	}
	return manifest, nil
}

func verifyFinalizingTransaction(root *os.Root, directory string, uid int) error {
	if err := verifyDirectory(root, directory, uid); err != nil {
		return err
	}
	if err := verifyFile(root, path.Join(directory, "journal.jsonl"), uid); err != nil {
		return err
	}
	entries, err := fs.ReadDir(root.FS(), directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != "journal.jsonl" || !entries[0].Type().IsRegular() {
		return errors.New("finalizing transaction retained recovery material")
	}
	return nil
}

func verifyDirectory(root *os.Root, name string, uid int) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !exactMode(info.Mode(), 0o700) || info.Sys().(*syscall.Stat_t).Uid != uint32(uid) {
		return fs.ErrPermission
	}
	return nil
}

func verifyFile(root *os.Root, name string, uid int) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !exactMode(info.Mode(), 0o600) || info.Sys().(*syscall.Stat_t).Uid != uint32(uid) || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return fs.ErrPermission
	}
	return nil
}

func syncDirectory(root *os.Root, name string) error {
	directory, err := root.Open(name)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func safeArtifact(name string) bool {
	parts := strings.Split(name, "/")
	return len(parts) == 2 && (parts[0] == "snapshot" || parts[0] == "prepared") && safeName(parts[1])
}

func safeName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, character := range name {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}
