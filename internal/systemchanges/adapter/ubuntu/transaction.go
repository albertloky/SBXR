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

const (
	transactionDirectory       = "var/lib/sbxr/transactions"
	finalizingRemovalDirectory = "removal-finalizing"
	FinalizingRemovalChangeSet = finalizingRemovalDirectory
)

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
	VerifyIrreversibleRemovalReady(time.Duration) error
	VerifyCloudflareTokenRevoked(time.Duration) (bool, error)
	DeleteIrreversibleRemovalPhase(systemchanges.IrreversibleRemovalPhase, time.Duration) (systemchanges.StepEvidence, error)
	VerifyFinalRemovalAbsence(time.Duration) (bool, error)
	PrepareRemovalFinalization(time.Duration) error
	FinalizeRemoval(time.Duration) error
}

type removalRecoveryHost interface {
	LoadRemovalRecovery(io.Reader) error
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
	CaptureServiceRollback(string, func(io.Reader) error) error
	Execute(systemchanges.Step, string, time.Duration) (systemchanges.StepEvidence, error)
	ActivateService(string, io.Reader, time.Duration) (systemchanges.StepEvidence, error)
	Reverse(systemchanges.Step, systemchanges.StepEvidence, io.Reader, time.Duration) (systemchanges.StepEvidence, error)
	InspectRepair(systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEffect, error)
	ReverseService(string, io.Reader, time.Duration) (systemchanges.StepEvidence, error)
	InspectService(string, io.Reader) (systemchanges.StepEffect, error)
	CheckWholeTunnel([]systemchanges.StepEvidence, time.Duration) (systemchanges.HealthStatus, error)
	ValidateInstalledService(string) error
	RunTokenFingerprint(string) (string, error)
	RemoveRunToken(string) error
	RetrieveRunToken(systemchanges.CloudflareChange, string, time.Duration) (any, bool, error)
	RotateService(string, io.Reader, time.Duration) (systemchanges.StepEvidence, error)
	CheckRunTokenRotation(systemchanges.CloudflareChange, time.Duration) (systemchanges.HealthStatus, error)
}

type CertificateExecutor interface {
	CaptureRollback(string, systemchanges.Step, func(io.Reader) error) error
	Execute(string, systemchanges.Step, time.Duration, *systemchanges.Cancellation) (systemchanges.StepEvidence, error)
	Reverse(string, systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEvidence, error)
	Inspect(string, systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEffect, error)
	Check(string, string, systemchanges.GatePhase, time.Duration) (systemchanges.HealthStatus, error)
	Cleanup(string, systemchanges.CertificateAction) error
}

type ConnectionProfilesExecutor interface {
	ValidateConfiguration(root, destination, hostname string, timeout time.Duration) error
	Activate(root, destination, hostname string, timeout time.Duration) error
	Restore(root, destination, hostname string, timeout time.Duration) error
	Check(root, destination, hostname, code string, timeout time.Duration) (bool, error)
}

type SubscriptionPublicationExecutor interface {
	CaptureRollback(string, func(io.Reader) error) error
	Activate(string, string, systemchanges.StateTransactionBinding, string, time.Duration) (systemchanges.StepEvidence, error)
	Reverse(string, io.Reader, time.Duration) (systemchanges.StepEvidence, error)
	Inspect(string, io.Reader, time.Duration) (systemchanges.StepEffect, error)
	Check(string, string, systemchanges.StateTransactionBinding, string, time.Duration) (systemchanges.HealthStatus, error)
	Cleanup(string) error
}

type SoftwareLifecycleExecutor interface {
	CaptureRollback(string, systemchanges.Step, func(io.Reader) error) error
	Activate(string, systemchanges.Step, time.Duration) (systemchanges.StepEvidence, error)
	Reverse(string, systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEvidence, error)
	Inspect(string, systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEffect, error)
	Check(string, systemchanges.Check, systemchanges.GatePhase, time.Duration) (systemchanges.HealthStatus, error)
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
	Certificate  *systemchanges.CertificateChange   `json:"certificate,omitempty"`
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
	for _, step := range preparation.Steps {
		if !subscriptionActivation(step) {
			continue
		}
		if checksums["prepared/subscriptions.bundle"] == "" {
			return errors.New("complete Subscription Publication artifact set unavailable")
		}
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
		} else if managementTokenStateChange(step) {
			captureErr = captureRollback(strings.NewReader(`{"management_token_state_only":true}`))
		} else if preparation.Mutation == systemchanges.RotationMutation && runTokenActivation(step) {
			captureErr = captureRollback(strings.NewReader(`{"rotation_forward_only":true}`))
		} else if irreversibleRemoteRemoval(step) {
			captureErr = captureRollback(strings.NewReader(`{"irreversible_after_checkpoint":true}`))
		} else if softwareInstallation(step) {
			if a.software == nil {
				return errors.New("Software Lifecycle executor unavailable")
			}
			captureErr = a.software.CaptureRollback(a.root, step, captureRollback)
		} else if subscriptionActivation(step) {
			if a.subscription == nil {
				return errors.New("Subscription Publication executor unavailable")
			}
			captureErr = a.subscription.CaptureRollback(a.root, captureRollback)
		} else if cloudflaredActivation(step) {
			if a.cloudflare == nil {
				return errors.New("Cloudflare service executor unavailable")
			}
			captureErr = a.cloudflare.CaptureServiceRollback(a.root, captureRollback)
		} else if _, ok := step.CloudflareChange(); ok {
			if a.cloudflare == nil {
				return errors.New("Cloudflare transaction executor unavailable")
			}
			captureErr = a.cloudflare.CaptureRollback(step, captureRollback)
		} else if _, ok := step.CertificateChange(); ok {
			if a.certificate == nil {
				return errors.New("Certificate Lifecycle executor unavailable")
			}
			captureErr = a.certificate.CaptureRollback(a.root, step, captureRollback)
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
		if certificate, ok := step.CertificateChange(); ok {
			steps[index].Certificate = &certificate
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
	if finalizingRemovalCheckpoint(record.Checkpoint) {
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

func (a Adapter) StartRunTokenRotation(lease systemchanges.ExecutionLease, changeSet string) (bool, error) {
	if !lease.Authorized() || a.cloudflare == nil || !safeName(changeSet) {
		return false, errors.New("run-token rotation checkpoint unavailable")
	}
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return false, err
	}
	defer root.Close()
	target := path.Join(transactionDirectory, changeSet)
	journalName := path.Join(target, "journal.jsonl")
	journal, err := readJournal(root, journalName)
	if err != nil || !validJournal(journal) || len(journal) != 1 || journal[0].Checkpoint != systemchanges.Prepared || journal[0].Mutation != systemchanges.RotationMutation || len(journal[0].Steps) != 1 || journal[0].Steps[0].Cloudflare == nil || journal[0].Steps[0].Cloudflare.Action != systemchanges.CloudflareRunTokenActivate {
		return false, errors.New("run-token rotation preparation is unproved")
	}
	fingerprint, err := a.cloudflare.RunTokenFingerprint(a.root)
	if err != nil || !validDigest(fingerprint) {
		return false, errors.New("current run token is unproved")
	}
	evidence := &systemchanges.StepEvidence{Code: "old-run-token-fingerprint", SHA256: fingerprint}
	if err := appendJournal(root, journalName, journalEntry{Checkpoint: systemchanges.IrreversibleRunTokenRotationStarted, Evidence: evidence}, a.uid); err != nil {
		return false, err
	}
	if err := a.discardRunTokenRollback(root, target); err != nil {
		return true, err
	}
	return true, verifyTransaction(root, target, a.uid)
}

func (a Adapter) discardRunTokenRollback(root *os.Root, target string) error {
	if a.cloudflare == nil {
		return errors.New("Cloudflare run-token cleanup unavailable")
	}
	if err := a.cloudflare.RemoveRunToken(a.root); err != nil {
		return err
	}
	manifest, err := readSnapshotManifest(root, target, a.uid)
	if err != nil {
		return err
	}
	for name := range manifest.Files {
		if !strings.HasPrefix(name, "snapshot/") {
			continue
		}
		if err := root.Remove(path.Join(target, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		delete(manifest.Files, name)
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	temporary := path.Join(target, "manifest.rotation")
	_ = root.Remove(temporary)
	if _, err := writeProtected(root, temporary, bytes.NewReader(data), a.uid); err != nil {
		return err
	}
	if err := root.Rename(temporary, path.Join(target, "manifest.json")); err != nil {
		return err
	}
	return syncDirectory(root, target)
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

type runTokenStateMaterial interface {
	SystemChangesBindings(any) ([]byte, error)
	SystemChangesWriteArtifacts(any, func(string, uint32, io.Reader) error) error
}

func (a Adapter) FinalizeRunTokenRotation(lease systemchanges.ExecutionLease, recovery systemchanges.RecoveryTransaction, timeout time.Duration) (any, systemchanges.StateTransactionBinding, bool, error) {
	if !lease.RecoveryAuthorized() || a.cloudflare == nil || a.state == nil || recovery.LastCheckpoint != systemchanges.IrreversibleRunTokenRotationStarted || len(recovery.Steps) != 1 || !validDigest(recovery.PriorRunTokenSHA256) {
		return nil, systemchanges.StateTransactionBinding{}, false, errors.New("run-token State finalization unavailable")
	}
	change, ok := recovery.Steps[0].CloudflareChange()
	if !ok || change.Action != systemchanges.CloudflareRunTokenActivate {
		return nil, systemchanges.StateTransactionBinding{}, false, errors.New("run-token provider binding unavailable")
	}
	source, changed, err := a.cloudflare.RetrieveRunToken(change, recovery.PriorRunTokenSHA256, timeout)
	if err != nil || !changed {
		return nil, systemchanges.StateTransactionBinding{}, changed, err
	}
	candidate, err := a.recoveryArtifact(lease, recovery.ChangeSet, "prepared/state.json")
	if err != nil {
		return nil, systemchanges.StateTransactionBinding{}, false, err
	}
	bindingJSON, err := json.Marshal(recovery.State)
	if err != nil {
		return nil, systemchanges.StateTransactionBinding{}, false, err
	}
	material, err := a.state.SystemChangesFinalizeRunTokenRotation(lease, bindingJSON, bytes.NewReader(candidate), source)
	stateMaterial, ok := material.(runTokenStateMaterial)
	if err != nil || !ok {
		return nil, systemchanges.StateTransactionBinding{}, false, errors.New("State refused the rotated run token")
	}
	finalBindingJSON, err := stateMaterial.SystemChangesBindings(lease)
	var finalBinding systemchanges.StateTransactionBinding
	if err != nil || json.Unmarshal(finalBindingJSON, &finalBinding) != nil {
		return nil, systemchanges.StateTransactionBinding{}, false, errors.New("final run-token State binding unavailable")
	}
	if err := a.ReplaceStateArtifacts(lease, recovery.ChangeSet, finalBinding, func(write func(string, uint32, io.Reader) error) error {
		return stateMaterial.SystemChangesWriteArtifacts(lease, write)
	}); err != nil {
		return nil, systemchanges.StateTransactionBinding{}, false, err
	}
	return material, finalBinding, true, nil
}

func (a Adapter) LoadRunTokenRotationState(lease systemchanges.ExecutionLease, recovery systemchanges.RecoveryTransaction) (any, error) {
	if !lease.RecoveryAuthorized() || a.state == nil || recovery.LastCheckpoint == systemchanges.IrreversibleRunTokenRotationStarted {
		return nil, errors.New("finalized run-token State unavailable")
	}
	candidate, err := a.recoveryArtifact(lease, recovery.ChangeSet, "prepared/state.json")
	if err != nil {
		return nil, err
	}
	manifests, err := a.recoveryArtifact(lease, recovery.ChangeSet, "prepared/manifests.json")
	if err != nil {
		return nil, err
	}
	bindingJSON, err := json.Marshal(recovery.State)
	if err != nil {
		return nil, err
	}
	return a.state.SystemChangesLoadRunTokenRotation(lease, bindingJSON, bytes.NewReader(candidate), bytes.NewReader(manifests))
}

func (a Adapter) Execute(lease systemchanges.ExecutionLease, changeSet string, number int, step systemchanges.Step, timeout time.Duration, cancellation *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	if !lease.Authorized() || a.host == nil {
		return systemchanges.StepEvidence{}, errors.New("typed Ubuntu transaction host unavailable")
	}
	if managementTokenStateChange(step) {
		return managementTokenStateEvidence(), nil
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
	if softwareInstallation(step) {
		if a.software == nil {
			return systemchanges.StepEvidence{}, errors.New("Software Lifecycle executor unavailable")
		}
		return a.software.Activate(a.root, step, timeout)
	}
	if runTokenActivation(step) {
		if a.cloudflare == nil || !safeName(changeSet) || number != 1 {
			return systemchanges.StepEvidence{}, errors.New("Cloudflare run-token service executor unavailable")
		}
		material, err := a.recoveryArtifact(lease, changeSet, "prepared/cloudflared.json")
		if err != nil {
			return systemchanges.StepEvidence{}, err
		}
		return a.cloudflare.RotateService(a.root, bytes.NewReader(material), timeout)
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
	if _, ok := step.CertificateChange(); ok {
		if a.certificate == nil {
			return systemchanges.StepEvidence{}, errors.New("Certificate Lifecycle executor unavailable")
		}
		change, _ := step.CertificateChange()
		if change.Action == systemchanges.CertificateDomainActivate {
			return executeDomainCertificateActivation(a.root, a.certificate, a.profiles, step, timeout, cancellation)
		}
		return a.certificate.Execute(a.root, step, timeout, cancellation)
	}
	if subscriptionActivation(step) {
		if a.subscription == nil || !safeName(changeSet) || number < 1 {
			return systemchanges.StepEvidence{}, errors.New("Subscription Publication executor unavailable")
		}
		binding, planSHA256, err := a.recoveryPublicationBinding(lease, changeSet)
		if err != nil {
			return systemchanges.StepEvidence{}, err
		}
		return a.subscription.Activate(a.root, path.Join(a.root, transactionDirectory, changeSet, "prepared"), binding, planSHA256, timeout)
	}
	if cloudflaredActivation(step) {
		if a.cloudflare == nil || !safeName(changeSet) || number < 1 {
			return systemchanges.StepEvidence{}, errors.New("Cloudflare service executor unavailable")
		}
		material, err := a.recoveryArtifact(lease, changeSet, "prepared/cloudflared.json")
		if err != nil {
			return systemchanges.StepEvidence{}, err
		}
		evidence, err := a.cloudflare.ActivateService(a.root, bytes.NewReader(material), timeout)
		if err != nil || a.cloudflare.ValidateInstalledService(a.root) != nil {
			return systemchanges.StepEvidence{}, errors.New("installed cloudflared service is unproved")
		}
		return evidence, nil
	}
	evidence, err := a.host.Execute(step, timeout, cancellation)
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
	if managementTokenStateChange(step) {
		return managementTokenStateEvidence(), nil
	}
	if _, ok := step.FirewallChange(); ok {
		if a.firewall == nil {
			return systemchanges.StepEvidence{}, errors.New("native firewall Adapter unavailable")
		}
		return a.firewall.Reverse(step, bytes.NewReader(content), timeout)
	}
	if softwareInstallation(step) {
		if a.software == nil {
			return systemchanges.StepEvidence{}, errors.New("Software Lifecycle rollback executor unavailable")
		}
		return a.software.Reverse(a.root, step, bytes.NewReader(content), timeout)
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
	if _, ok := step.CertificateChange(); ok {
		if a.certificate == nil {
			return systemchanges.StepEvidence{}, errors.New("Certificate Lifecycle rollback executor unavailable")
		}
		change, _ := step.CertificateChange()
		if change.Action == systemchanges.CertificateDomainActivate {
			return reverseDomainCertificateActivation(a.root, a.certificate, a.profiles, step, bytes.NewReader(content), timeout)
		}
		return a.certificate.Reverse(a.root, step, bytes.NewReader(content), timeout)
	}
	if subscriptionActivation(step) {
		if a.subscription == nil {
			return systemchanges.StepEvidence{}, errors.New("Subscription Publication rollback executor unavailable")
		}
		return a.subscription.Reverse(a.root, bytes.NewReader(content), timeout)
	}
	if cloudflaredActivation(step) {
		if a.cloudflare == nil {
			return systemchanges.StepEvidence{}, errors.New("Cloudflare service executor unavailable")
		}
		return a.cloudflare.ReverseService(a.root, bytes.NewReader(content), timeout)
	}
	return a.host.Reverse(step, bytes.NewReader(content), timeout)
}

func executeDomainCertificateActivation(root string, certificate CertificateExecutor, profiles ConnectionProfilesExecutor, step systemchanges.Step, timeout time.Duration, cancellation *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	change, ok := step.CertificateChange()
	if !ok || change.Action != systemchanges.CertificateDomainActivate || certificate == nil || profiles == nil || profiles.ValidateConfiguration(root, change.DestinationIP, change.Identity, timeout) != nil {
		return systemchanges.StepEvidence{}, errors.New("Connection Profiles configuration is unproved")
	}
	evidence, err := certificate.Execute(root, step, timeout, cancellation)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if profiles.Activate(root, change.DestinationIP, change.Identity, timeout) != nil {
		return systemchanges.StepEvidence{}, errors.New("Direct TLS consumers are unproved")
	}
	return evidence, nil
}

func reverseDomainCertificateActivation(root string, certificate CertificateExecutor, profiles ConnectionProfilesExecutor, step systemchanges.Step, snapshot io.Reader, timeout time.Duration) (systemchanges.StepEvidence, error) {
	change, ok := step.CertificateChange()
	if !ok || change.Action != systemchanges.CertificateDomainActivate || certificate == nil || profiles == nil {
		return systemchanges.StepEvidence{}, errors.New("Direct TLS rollback is unavailable")
	}
	evidence, err := certificate.Reverse(root, step, snapshot, timeout)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if profiles.Restore(root, change.DestinationIP, change.Identity, timeout) != nil {
		return systemchanges.StepEvidence{}, errors.New("prior Direct TLS consumers are unproved")
	}
	return evidence, nil
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
	if err == nil && len(entries) == 1 && entries[0].IsDir() && entries[0].Name() == finalizingRemovalDirectory {
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
	if journal[len(journal)-1].Checkpoint == systemchanges.IrreversibleRunTokenRotationStarted {
		if err := a.discardRunTokenRollback(root, directory); err != nil {
			return systemchanges.RecoveryTransaction{}, errors.New("run-token rollback cleanup is unprovable")
		}
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
	irreversible := prepared.Mutation == systemchanges.CompleteRemovalMutation && journalHasCheckpoint(journal, systemchanges.IrreversibleRemovalStarted)
	removalSnapshotDeleted := prepared.Mutation == systemchanges.CompleteRemovalMutation && journalHasCheckpoint(journal, systemchanges.TransactionMaterialDeletionAuthorized)
	irreversibleRotation := prepared.Mutation == systemchanges.RotationMutation && runTokenFingerprint(journal) != ""
	if prepared.State == nil || prepared.ChangeSet != changeSet || !validRecoveryJournalBinding(prepared) {
		return systemchanges.RecoveryTransaction{}, errors.New("recovery transaction lineage is invalid")
	}
	if !removalSnapshotDeleted {
		manifest, err := verifyTransactionManifest(root, directory, a.uid)
		if err != nil || manifest.Reason != prepared.Mutation || !validRecoveryBinding(prepared, manifest, irreversibleRotation) {
			return systemchanges.RecoveryTransaction{}, errors.New("recovery transaction lineage is invalid")
		}
	}
	steps := make([]systemchanges.Step, len(prepared.Steps))
	for index, persisted := range prepared.Steps {
		var step systemchanges.Step
		var err error
		if persisted.Firewall == nil && persisted.Removal == nil && persisted.Cloudflare == nil && persisted.Certificate == nil {
			step, err = systemchanges.NewStep(persisted.Owner, persisted.Forward, persisted.Rollback)
		} else if persisted.Firewall != nil && persisted.Removal == nil && persisted.Cloudflare == nil && persisted.Certificate == nil {
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
		} else if persisted.Firewall == nil && persisted.Removal != nil && persisted.Cloudflare == nil && persisted.Certificate == nil {
			step, err = systemchanges.RestoreRemovalStep(lease, *persisted.Removal)
		} else if persisted.Firewall == nil && persisted.Removal == nil && persisted.Cloudflare != nil && persisted.Certificate == nil {
			step, err = systemchanges.NewCloudflareStep(*persisted.Cloudflare)
		} else if persisted.Firewall == nil && persisted.Removal == nil && persisted.Cloudflare == nil && persisted.Certificate != nil {
			step, err = systemchanges.NewCertificateStep(*persisted.Certificate)
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
		OutcomeOwner: prepared.OutcomeOwner, State: *prepared.State, Steps: steps, Checks: append([]systemchanges.Check(nil), prepared.Checks...), AttemptedSteps: highestStartedStep(journal), RollbackStep: rollbackResumeStep(journal), LastCheckpoint: last.Checkpoint, Timeouts: prepared.Timeouts, PriorRunTokenSHA256: runTokenFingerprint(journal), IrreversibleRemovalStarted: irreversible,
	}, nil
}

func runTokenFingerprint(entries []journalEntry) string {
	for _, entry := range entries {
		if entry.Checkpoint == systemchanges.IrreversibleRunTokenRotationStarted && entry.Evidence != nil {
			return entry.Evidence.SHA256
		}
	}
	return ""
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
	if managementTokenStateChange(step) {
		return systemchanges.StepEffectPresent, nil
	}
	if _, ok := step.FirewallChange(); ok {
		if a.firewall == nil {
			return "", errors.New("native firewall Adapter unavailable")
		}
		return a.firewall.Inspect(step, bytes.NewReader(content), timeout)
	}
	if softwareInstallation(step) {
		if a.software == nil {
			return "", errors.New("Software Lifecycle recovery executor unavailable")
		}
		return a.software.Inspect(a.root, step, bytes.NewReader(content), timeout)
	}
	if cloudflaredActivation(step) {
		if a.cloudflare == nil {
			return "", errors.New("Cloudflare service executor unavailable")
		}
		return a.cloudflare.InspectService(a.root, bytes.NewReader(content))
	}
	if cloudflareRepair(step) {
		if a.cloudflare == nil {
			return "", errors.New("Cloudflare repair executor unavailable")
		}
		return a.cloudflare.InspectRepair(step, bytes.NewReader(content), timeout)
	}
	if _, ok := step.CertificateChange(); ok {
		if a.certificate == nil {
			return "", errors.New("Certificate Lifecycle recovery executor unavailable")
		}
		return a.certificate.Inspect(a.root, step, bytes.NewReader(content), timeout)
	}
	if subscriptionActivation(step) {
		if a.subscription == nil {
			return "", errors.New("Subscription Publication recovery executor unavailable")
		}
		return a.subscription.Inspect(a.root, bytes.NewReader(content), timeout)
	}
	return a.host.InspectStep(step, bytes.NewReader(content), timeout)
}

func cloudflaredActivation(step systemchanges.Step) bool {
	return step.Owner() == systemchanges.CloudflareModule && step.Forward() == systemchanges.ActivatePreparedConfiguration && step.Rollback() == systemchanges.RestorePriorConfiguration
}

func managementTokenStateChange(step systemchanges.Step) bool {
	return step.Owner() == systemchanges.CloudflareModule && step.Forward() == systemchanges.RecordManagementTokenChange && step.Rollback() == systemchanges.RestoreManagementTokenRecord
}

func managementTokenStateEvidence() systemchanges.StepEvidence {
	digest := sha256.Sum256([]byte("management-token-state-only"))
	return systemchanges.StepEvidence{Code: "CLOUDFLARE-MANAGEMENT-TOKEN-STATE", SHA256: hex.EncodeToString(digest[:])}
}

func subscriptionActivation(step systemchanges.Step) bool {
	return step.Owner() == systemchanges.SubscriptionModule && step.Forward() == systemchanges.ActivatePreparedConfiguration && step.Rollback() == systemchanges.RestorePriorConfiguration
}

func softwareInstallation(step systemchanges.Step) bool {
	return step.Owner() == systemchanges.SoftwareModule && step.Forward() == systemchanges.ActivatePreparedConfiguration && step.Rollback() == systemchanges.RestorePriorConfiguration
}

func runTokenActivation(step systemchanges.Step) bool {
	change, ok := step.CloudflareChange()
	return ok && change.Action == systemchanges.CloudflareRunTokenActivate && step.Forward() == systemchanges.RotateCloudflaredRunToken
}

func cloudflareRepair(step systemchanges.Step) bool {
	change, ok := step.CloudflareChange()
	return ok && (change.Action == systemchanges.CloudflareRoutesPut && change.TunnelID != "" || change.Action == systemchanges.CloudflareDNSRepair)
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

func (a Adapter) VerifyIrreversibleRemovalReady(lease systemchanges.ExecutionLease, _ string, timeout time.Duration) error {
	host, ok := a.host.(IrreversibleRemovalHost)
	if !lease.Authorized() || !ok {
		return errors.New("irreversible removal host unavailable")
	}
	return host.VerifyIrreversibleRemovalReady(timeout)
}

func (a Adapter) VerifyCloudflareTokenRevoked(lease systemchanges.ExecutionLease, recovery systemchanges.RecoveryTransaction, timeout time.Duration) (bool, error) {
	host, ok := a.host.(IrreversibleRemovalHost)
	if !lease.Authorized() || !ok {
		return false, errors.New("irreversible removal host unavailable")
	}
	if err := a.loadRemovalRecovery(lease, recovery); err != nil {
		return false, err
	}
	return host.VerifyCloudflareTokenRevoked(timeout)
}

func (a Adapter) DeleteIrreversibleRemovalPhase(lease systemchanges.ExecutionLease, recovery systemchanges.RecoveryTransaction, phase systemchanges.IrreversibleRemovalPhase, timeout time.Duration) (systemchanges.StepEvidence, error) {
	if phase == systemchanges.TransactionMaterialPhase {
		return a.deleteTransactionMaterial(lease)
	}
	if phase == systemchanges.CloudflareDNSRecordsPhase || phase == systemchanges.CloudflareTunnelPhase {
		if !lease.Authorized() || a.host == nil {
			return systemchanges.StepEvidence{}, errors.New("irreversible removal host unavailable")
		}
		if err := a.loadRemovalRecovery(lease, recovery); err != nil {
			return systemchanges.StepEvidence{}, err
		}
		digest := sha256.New()
		removed := 0
		for _, step := range recovery.Steps {
			change, ok := step.RemovalChange()
			if !ok || change.Action != systemchanges.CloudflareRemoval || phase == systemchanges.CloudflareDNSRecordsPhase && change.Resource != systemchanges.CloudflareDNSRecordResource || phase == systemchanges.CloudflareTunnelPhase && change.Resource != systemchanges.CloudflareTunnelResource {
				continue
			}
			evidence, err := a.host.Execute(step, timeout, systemchanges.NewCancellation())
			if err != nil || !validDigest(evidence.SHA256) {
				return systemchanges.StepEvidence{}, errors.New("owned Cloudflare resource deletion failed")
			}
			_, _ = digest.Write([]byte(evidence.Code + evidence.SHA256))
			removed++
		}
		if removed == 0 {
			return systemchanges.StepEvidence{}, errors.New("owned Cloudflare removal inventory unavailable")
		}
		return systemchanges.StepEvidence{Code: "owned-cloudflare-removal-verified", SHA256: hex.EncodeToString(digest.Sum(nil))}, nil
	}
	host, ok := a.host.(IrreversibleRemovalHost)
	if !lease.Authorized() || !ok {
		return systemchanges.StepEvidence{}, errors.New("irreversible removal host unavailable")
	}
	return host.DeleteIrreversibleRemovalPhase(phase, timeout)
}

func (a Adapter) loadRemovalRecovery(lease systemchanges.ExecutionLease, recovery systemchanges.RecoveryTransaction) error {
	host, ok := a.host.(removalRecoveryHost)
	if !lease.Authorized() || !ok {
		return errors.New("Complete removal recovery authority unavailable")
	}
	for index, step := range recovery.Steps {
		change, valid := step.RemovalChange()
		if !valid || change.Resource != systemchanges.CloudflareRouteResource {
			continue
		}
		content, err := a.recoveryArtifact(lease, recovery.ChangeSet, fmt.Sprintf("snapshot/step-%03d.rollback", index+1))
		if err != nil {
			return err
		}
		return host.LoadRemovalRecovery(bytes.NewReader(content))
	}
	return errors.New("Complete removal recovery authority unavailable")
}

func irreversibleRemoteRemoval(step systemchanges.Step) bool {
	change, ok := step.RemovalChange()
	return ok && change.Action == systemchanges.CloudflareRemoval && (change.Resource == systemchanges.CloudflareDNSRecordResource || change.Resource == systemchanges.CloudflareTunnelResource)
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
	finalizing := path.Join(transactionDirectory, finalizingRemovalDirectory)
	journal := path.Join(target, "journal.jsonl")
	entries, err := readJournal(root, journal)
	if err != nil || !validJournal(entries) || entries[len(entries)-1].Checkpoint != systemchanges.FinalRemovalAbsenceVerified {
		return errors.New("final removal journal is unresolved")
	}
	if _, err := root.Lstat(finalizing); !errors.Is(err, fs.ErrNotExist) {
		return errors.New("final removal directory already exists")
	}
	if err := root.Rename(target, finalizing); err != nil {
		return err
	}
	if err := syncDirectory(root, transactionDirectory); err != nil {
		return err
	}
	if err := discardFinalizingRemoval(root, a.uid); err != nil {
		return err
	}
	if err := host.PrepareRemovalFinalization(timeout); err != nil {
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
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return err
	}
	defer root.Close()
	if pathExists(root, path.Join(transactionDirectory, finalizingRemovalDirectory)) {
		if err := discardFinalizingRemoval(root, a.uid); err != nil {
			return err
		}
	}
	if err := host.PrepareRemovalFinalization(timeout); err != nil {
		return err
	}
	return host.FinalizeRemoval(timeout)
}

func discardFinalizingRemoval(root *os.Root, uid int) error {
	directory := path.Join(transactionDirectory, finalizingRemovalDirectory)
	if err := verifyDirectory(root, directory, uid); err != nil {
		return err
	}
	entries, err := fs.ReadDir(root.FS(), directory)
	if err != nil || len(entries) > 1 || len(entries) == 1 && (entries[0].Name() != "journal.jsonl" || !entries[0].Type().IsRegular()) {
		return errors.New("final removal directory is unproved")
	}
	if len(entries) == 1 {
		journal := path.Join(directory, "journal.jsonl")
		records, err := readJournal(root, journal)
		if err != nil || !validJournal(records) || records[len(records)-1].Checkpoint != systemchanges.FinalRemovalAbsenceVerified {
			return errors.New("final removal journal is unresolved")
		}
		if err := root.Remove(journal); err != nil {
			return err
		}
	}
	if err := root.Remove(directory); err != nil {
		return err
	}
	return syncDirectory(root, transactionDirectory)
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
	if err != nil || !validJournal(journal) || journal[len(journal)-1].Checkpoint != systemchanges.TransactionMaterialDeletionAuthorized {
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

func finalizingRemovalCheckpoint(checkpoint systemchanges.DurableCheckpoint) bool {
	switch checkpoint {
	case systemchanges.TransactionMaterialDeleted, systemchanges.ReleasesDeleted, systemchanges.UnitsDeleted,
		systemchanges.IdentitiesDeleted, systemchanges.ListenersDeleted, systemchanges.PreparedArtifactsDeleted,
		systemchanges.OwnedFirewallStateDeleted, systemchanges.FinalRemovalAbsenceVerified:
		return true
	}
	return false
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
	binding, _, err := a.recoveryPublicationBinding(lease, changeSet)
	return binding, err
}

func (a Adapter) recoveryPublicationBinding(lease systemchanges.ExecutionLease, changeSet string) (systemchanges.StateTransactionBinding, string, error) {
	if !lease.Authorized() || !safeName(changeSet) {
		return systemchanges.StateTransactionBinding{}, "", errors.New("invalid recovery binding request")
	}
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return systemchanges.StateTransactionBinding{}, "", err
	}
	defer root.Close()
	journal, err := readJournal(root, path.Join(transactionDirectory, changeSet, "journal.jsonl"))
	if err != nil || !validJournal(journal) || journal[0].State == nil {
		return systemchanges.StateTransactionBinding{}, "", errors.New("recovery State binding is invalid")
	}
	return *journal[0].State, journal[0].PlanSHA256, nil
}

func recoveryRelease(binding systemchanges.StateTransactionBinding) systemchanges.ReleaseBinding {
	if binding.StartingRelease != (systemchanges.ReleaseBinding{}) {
		return binding.StartingRelease
	}
	return binding.CandidateRelease
}

func validRecoveryBinding(prepared journalEntry, manifest snapshotManifest, forwardRotation ...bool) bool {
	binding := *prepared.State
	if !validRecoveryJournalBinding(prepared) || manifest.Release != recoveryRelease(binding) || manifest.Files["prepared/state.json"] != binding.PreparedStateSHA256 || manifest.Files["prepared/manifests.json"] != binding.PreparedManifestSHA256 {
		return false
	}
	if binding.LineageUnavailable {
		prior := manifest.Files["snapshot/prior-state.json"]
		return prior == "" || prior == binding.PreparedStateSHA256
	}
	if prepared.Starting.Status == systemchanges.Managed || prepared.Starting.Status == systemchanges.RecoveryRequired && binding.StartingRevision > 0 {
		return binding.StartingRelease != (systemchanges.ReleaseBinding{}) && (len(forwardRotation) == 1 && forwardRotation[0] && manifest.Files["snapshot/prior-state.json"] == "" || manifest.Files["snapshot/prior-state.json"] != "")
	}
	return prepared.Starting.Status == systemchanges.NotInstalled && binding.StartingRevision == 0 && binding.StartingSHA256 == "" && binding.StartingRelease == (systemchanges.ReleaseBinding{}) && manifest.Files["snapshot/prior-state.json"] == ""
}

// RecoveryStartingStatus reads the protected journal and manifest without
// mutating them so startup can construct executors for the transaction's true
// starting baseline rather than whichever State file is currently published.
func RecoveryStartingStatus(rootPath string) (systemchanges.InstallationStatus, error) {
	status, _, _, _, err := RecoveryStartingRelease(rootPath)
	return status, err
}

type RecoveryTransactionIdentity struct {
	ChangeSet                         string
	StartingStatus                    systemchanges.InstallationStatus
	StartingRevision                  uint64
	Mutation                          systemchanges.MutationClass
	StartingRelease, CandidateRelease systemchanges.ReleaseBinding
	ForwardOnly                       bool
	Checkpoint                        systemchanges.DurableCheckpoint
	CompletedSteps, TotalSteps        int
}

// RecoveryStartingRelease returns only the release already authenticated by
// the protected journal and manifest so recovery can reconstruct fixed tools.
func RecoveryStartingRelease(rootPath string) (systemchanges.InstallationStatus, systemchanges.ReleaseBinding, bool, systemchanges.DurableCheckpoint, error) {
	identity, err := RecoveryTransaction(rootPath)
	if err != nil {
		return "", systemchanges.ReleaseBinding{}, false, "", err
	}
	release := identity.StartingRelease
	if release == (systemchanges.ReleaseBinding{}) {
		release = identity.CandidateRelease
	}
	return identity.StartingStatus, release, identity.ForwardOnly, identity.Checkpoint, nil
}

func RecoveryTransaction(rootPath string) (RecoveryTransactionIdentity, error) {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return RecoveryTransactionIdentity{}, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), transactionDirectory)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() || !safeName(entries[0].Name()) {
		return RecoveryTransactionIdentity{}, errors.New("one unfinished transaction was not proven")
	}
	directory := path.Join(transactionDirectory, entries[0].Name())
	uid := os.Geteuid()
	if verifyDirectory(root, directory, uid) != nil || verifyFile(root, path.Join(directory, "journal.jsonl"), uid) != nil {
		return RecoveryTransactionIdentity{}, errors.New("recovery transaction identity is invalid")
	}
	journal, err := readJournal(root, path.Join(directory, "journal.jsonl"))
	if err != nil || !validJournal(journal) || len(journal) == 0 || journal[0].State == nil {
		return RecoveryTransactionIdentity{}, errors.New("recovery transaction lineage is invalid")
	}
	irreversibleRemoval := journal[0].Mutation == systemchanges.CompleteRemovalMutation && journalHasCheckpoint(journal, systemchanges.IrreversibleRemovalStarted)
	removalSnapshotDeleted := journal[0].Mutation == systemchanges.CompleteRemovalMutation && journalHasCheckpoint(journal, systemchanges.TransactionMaterialDeletionAuthorized)
	if !removalSnapshotDeleted {
		manifest, manifestErr := verifyTransactionManifest(root, directory, uid)
		if manifestErr != nil || manifest.Reason != journal[0].Mutation || !validRecoveryBinding(journal[0], manifest, journal[0].Mutation == systemchanges.RotationMutation && runTokenFingerprint(journal) != "") {
			return RecoveryTransactionIdentity{}, errors.New("recovery transaction lineage is invalid")
		}
	}
	if journal[0].Starting.Status != systemchanges.Managed && journal[0].Starting.Status != systemchanges.NotInstalled && (journal[0].Starting.Status != systemchanges.RecoveryRequired || journal[0].Mutation != systemchanges.CompleteRemovalMutation) {
		return RecoveryTransactionIdentity{}, errors.New("recovery starting baseline is unsupported")
	}
	forwardOnly := journal[0].Mutation == systemchanges.RotationMutation && runTokenFingerprint(journal) != "" || irreversibleRemoval
	return RecoveryTransactionIdentity{ChangeSet: journal[0].ChangeSet, StartingStatus: journal[0].Starting.Status, StartingRevision: journal[0].Starting.Revision, Mutation: journal[0].Mutation, StartingRelease: journal[0].State.StartingRelease, CandidateRelease: journal[0].State.CandidateRelease, ForwardOnly: forwardOnly, Checkpoint: journal[len(journal)-1].Checkpoint, CompletedSteps: highestCompletedStep(journal), TotalSteps: len(journal[0].Steps)}, nil
}

// RecoveryHealthObservation overlays one validated unfinished transaction on
// the current State observation without acquiring the mutation lock or changing
// journal, snapshot, or rollback material.
func RecoveryHealthObservation(rootPath string, source ObservationSource) (systemchanges.Observation, error) {
	if source == nil {
		return systemchanges.Observation{}, errors.New("health observation source unavailable")
	}
	base, err := source()
	if err != nil {
		return systemchanges.Observation{}, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return systemchanges.Observation{}, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), transactionDirectory)
	if errors.Is(err, fs.ErrNotExist) {
		return base, nil
	}
	uid := os.Geteuid()
	if err == nil && verifyDirectory(root, transactionDirectory, uid) != nil {
		return healthRecoveryRequired(systemchanges.JournalUnprovable), nil
	}
	if err != nil || len(entries) > 1 || len(entries) == 1 && (!entries[0].IsDir() || !safeName(entries[0].Name())) {
		return healthRecoveryRequired(systemchanges.JournalUnprovable), nil
	}
	if len(entries) == 0 {
		return base, nil
	}
	changeSet := entries[0].Name()
	directory := path.Join(transactionDirectory, changeSet)
	if verifyDirectory(root, directory, uid) != nil || verifyFile(root, path.Join(directory, "journal.jsonl"), uid) != nil {
		return healthRecoveryRequired(systemchanges.JournalUnprovable), nil
	}
	journal, journalErr := readJournal(root, path.Join(directory, "journal.jsonl"))
	if journalErr != nil || !validJournal(journal) || len(journal) == 0 || journal[0].State == nil {
		return healthRecoveryRequired(systemchanges.JournalUnprovable), nil
	}
	prepared := journal[0]
	for _, entry := range journal[1:] {
		if entry.Checkpoint == systemchanges.StateFinalized && entry.State != nil {
			prepared.State = entry.State
		}
	}
	irreversibleRemoval := prepared.Mutation == systemchanges.CompleteRemovalMutation && journalHasCheckpoint(journal, systemchanges.IrreversibleRemovalStarted)
	removalSnapshotDeleted := prepared.Mutation == systemchanges.CompleteRemovalMutation && journalHasCheckpoint(journal, systemchanges.TransactionMaterialDeletionAuthorized)
	irreversibleRotation := prepared.Mutation == systemchanges.RotationMutation && runTokenFingerprint(journal) != ""
	if prepared.ChangeSet != changeSet || !validRecoveryJournalBinding(prepared) {
		return healthRecoveryRequired(systemchanges.JournalUnprovable), nil
	}
	if !removalSnapshotDeleted {
		manifest, manifestErr := verifyTransactionManifest(root, directory, uid)
		if manifestErr != nil || manifest.Reason != prepared.Mutation || !validRecoveryBinding(prepared, manifest, irreversibleRotation) {
			return healthRecoveryRequired(systemchanges.SnapshotUnprovable), nil
		}
	}
	total := len(prepared.Steps)
	last := journal[len(journal)-1].Checkpoint
	starting := base.Status == prepared.Starting.Status && base.StateRevision == prepared.Starting.Revision && base.StateSHA256 == prepared.Starting.SHA256
	candidate := base.Status == systemchanges.Managed && base.StateRevision == prepared.State.CandidateRevision && base.StateSHA256 == prepared.State.CandidateSHA256
	removed := irreversibleRemoval && base.Status == systemchanges.NotInstalled
	rollback := !irreversibleRemoval && !irreversibleRotation && last != systemchanges.Complete && last != systemchanges.RolledBack
	completed := highestCompletedStep(journal)
	if last == systemchanges.Complete {
		completed = total
	}
	if !starting && !candidate && !removed {
		return systemchanges.Observation{Status: systemchanges.RecoveryRequired, CurrentChangeSet: changeSet, LastChangeSet: base.LastChangeSet, Checkpoint: systemchanges.PreparedCheckpoint, CompletedSteps: completed, TotalSteps: total, RollbackAvailable: rollback, RecoveryCause: systemchanges.PriorAgreementUnprovable, StateRevision: base.StateRevision, StateSHA256: base.StateSHA256, WallTimeSynchronized: base.WallTimeSynchronized, MonotonicClock: base.MonotonicClock, TimeOwner: base.TimeOwner}, nil
	}
	base.Status, base.CurrentChangeSet = systemchanges.ChangeInProgress, changeSet
	base.Checkpoint, base.CompletedSteps, base.TotalSteps, base.RollbackAvailable = systemchanges.PreparedCheckpoint, completed, total, rollback
	return base, nil
}

func healthRecoveryRequired(cause systemchanges.RecoveryCause) systemchanges.Observation {
	return systemchanges.Observation{Status: systemchanges.RecoveryRequired, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, RecoveryCause: cause, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
}

func highestCompletedStep(entries []journalEntry) int {
	highest := 0
	for _, entry := range entries {
		if entry.Checkpoint == systemchanges.StepCompleted && entry.Step > highest {
			highest = entry.Step
		}
	}
	return highest
}

func validRecoveryJournalBinding(prepared journalEntry) bool {
	if prepared.State == nil || prepared.Mutation == "" {
		return false
	}
	binding := *prepared.State
	if binding.LineageUnavailable {
		return prepared.Mutation == systemchanges.CompleteRemovalMutation && prepared.Starting.Status == systemchanges.RecoveryRequired && prepared.Starting.Revision == 0 && prepared.Starting.SHA256 == "" && binding.ChangeSet == prepared.ChangeSet && binding.StartingRevision == 0 && binding.CandidateRevision == 0 && binding.StartingSHA256 == "" && binding.CandidateSHA256 == "" && binding.StartingRelease == (systemchanges.ReleaseBinding{}) && binding.CandidateRelease == (systemchanges.ReleaseBinding{}) && validDigest(prepared.PlanSHA256) && validDigest(binding.PreparedStateSHA256) && validDigest(binding.PreparedManifestSHA256)
	}
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
	if softwareLifecycleCheck(check) {
		if a.software == nil {
			return systemchanges.Unknown, errors.New("Software Lifecycle health executor unavailable")
		}
		return a.software.Check(a.root, check, phase, timeout)
	}
	if check.Owner == systemchanges.CloudflareModule && (check.Code == "CLOUDFLARE-MANAGEMENT-TOKEN-REPLACED" || check.Code == "CLOUDFLARE-MANAGEMENT-TOKEN-REMOVED") {
		if err := a.activeManagementTokenStateChange(); err != nil {
			return systemchanges.Unknown, err
		}
		return systemchanges.Healthy, nil
	}
	if check.Owner == systemchanges.CloudflareModule && check.Code == "CLOUDFLARE-WHOLE-TUNNEL" {
		if a.cloudflare == nil {
			return systemchanges.Unknown, errors.New("Cloudflare health executor unavailable")
		}
		change, rotation, err := a.activeRunTokenRotation()
		if err == nil && rotation {
			return a.cloudflare.CheckRunTokenRotation(change, timeout)
		}
		evidence, err := a.activeStepEvidence()
		if err != nil {
			return systemchanges.Unknown, err
		}
		return a.cloudflare.CheckWholeTunnel(evidence, timeout)
	}
	if check.Owner == systemchanges.CertificateModule && (check.Code == "CERTIFICATE-IP-CANDIDATE" || check.Code == "CERTIFICATE-IP-HTTPS" || check.Code == "CERTIFICATE-DOMAIN-CANDIDATE") {
		if a.certificate == nil {
			return systemchanges.Unknown, errors.New("Certificate Lifecycle health executor unavailable")
		}
		return a.certificate.Check(a.root, check.Code, phase, timeout)
	}
	if check.Owner == systemchanges.SubscriptionModule && strings.HasPrefix(check.Code, "SUBSCRIPTION-PUBLICATION-") {
		if a.subscription == nil {
			return systemchanges.Unknown, errors.New("Subscription Publication health executor unavailable")
		}
		binding, planSHA256, err := a.activeTransactionBinding()
		if err != nil {
			return systemchanges.Unknown, err
		}
		return a.subscription.Check(a.root, check.Code, binding, planSHA256, timeout)
	}
	if check.Owner == systemchanges.NetworkPolicyModule && (check.Code == "NETWORK-CLIENT-ACCESS-CANDIDATE" || check.Code == "NETWORK-CLIENT-ACCESS-ACTIVE") {
		if a.firewall == nil {
			return systemchanges.Unknown, errors.New("Network Policy health executor unavailable")
		}
		checker, ok := a.firewall.(interface {
			CheckCandidate(systemchanges.Step, time.Duration) (systemchanges.HealthStatus, error)
		})
		if !ok {
			return systemchanges.Unknown, errors.New("Network Policy candidate health unavailable")
		}
		step, err := a.activeFirewallPolicyStep()
		if err != nil {
			return systemchanges.Unknown, err
		}
		return checker.CheckCandidate(step, timeout)
	}
	if check.Owner == systemchanges.ConnectionProfilesModule && strings.HasPrefix(check.Code, "CONNECTION-PROFILES-") && strings.HasSuffix(check.Code, "-DIRECT-TLS") {
		if a.profiles == nil {
			return systemchanges.Unknown, errors.New("Connection Profiles health executor unavailable")
		}
		change, err := a.activeDomainCertificateChange()
		if err != nil {
			return systemchanges.Unknown, err
		}
		healthy, checkErr := a.profiles.Check(a.root, change.DestinationIP, change.Identity, check.Code, timeout)
		if checkErr != nil || !healthy {
			return systemchanges.Failed, checkErr
		}
		return systemchanges.Healthy, nil
	}
	return a.host.Check(check, phase, timeout)
}

func (a Adapter) activeFirewallPolicyStep() (systemchanges.Step, error) {
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return systemchanges.Step{}, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), transactionDirectory)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		return systemchanges.Step{}, errors.New("active firewall transaction unavailable")
	}
	journal, err := readJournal(root, path.Join(transactionDirectory, entries[0].Name(), "journal.jsonl"))
	if err != nil || !validJournal(journal) {
		return systemchanges.Step{}, errors.New("active firewall journal unavailable")
	}
	for _, persisted := range journal[0].Steps {
		if persisted.Firewall != nil && persisted.Firewall.Action == systemchanges.FirewallPolicyAction {
			return systemchanges.NewFirewallPolicyStep(persisted.Firewall.Candidate, persisted.Firewall.SSHPort)
		}
	}
	return systemchanges.Step{}, errors.New("active firewall candidate unavailable")
}

func (a Adapter) activeManagementTokenStateChange() error {
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), transactionDirectory)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		return errors.New("active management-token transaction unavailable")
	}
	journal, err := readJournal(root, path.Join(transactionDirectory, entries[0].Name(), "journal.jsonl"))
	if err != nil || !validJournal(journal) || len(journal[0].Steps) != 1 {
		return errors.New("active management-token journal unavailable")
	}
	step := journal[0].Steps[0]
	if step.Owner != systemchanges.CloudflareModule || step.Forward != systemchanges.RecordManagementTokenChange || step.Rollback != systemchanges.RestoreManagementTokenRecord {
		return errors.New("active management-token change unavailable")
	}
	return nil
}

func softwareLifecycleCheck(check systemchanges.Check) bool {
	return check.Owner == systemchanges.SoftwareModule && (strings.HasPrefix(check.Code, "SOFTWARE-LIFECYCLE-INSTALL-") || strings.HasPrefix(check.Code, "SOFTWARE-LIFECYCLE-UPDATE-"))
}

func (a Adapter) activeTransactionBinding() (systemchanges.StateTransactionBinding, string, error) {
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return systemchanges.StateTransactionBinding{}, "", err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), transactionDirectory)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		return systemchanges.StateTransactionBinding{}, "", errors.New("active State transaction unavailable")
	}
	journal, err := readJournal(root, path.Join(transactionDirectory, entries[0].Name(), "journal.jsonl"))
	if err != nil || !validJournal(journal) || journal[0].State == nil {
		return systemchanges.StateTransactionBinding{}, "", errors.New("active State transaction binding is invalid")
	}
	return *journal[0].State, journal[0].PlanSHA256, nil
}

func (a Adapter) activeDomainCertificateChange() (systemchanges.CertificateChange, error) {
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return systemchanges.CertificateChange{}, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), transactionDirectory)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		return systemchanges.CertificateChange{}, errors.New("active certificate transaction unavailable")
	}
	journal, err := readJournal(root, path.Join(transactionDirectory, entries[0].Name(), "journal.jsonl"))
	if err != nil || len(journal) == 0 {
		return systemchanges.CertificateChange{}, errors.New("active certificate journal unavailable")
	}
	for _, step := range journal[0].Steps {
		if step.Certificate != nil && step.Certificate.Action == systemchanges.CertificateDomainActivate {
			return *step.Certificate, nil
		}
	}
	return systemchanges.CertificateChange{}, errors.New("active domain certificate activation unavailable")
}

func (a Adapter) activeRunTokenRotation() (systemchanges.CloudflareChange, bool, error) {
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return systemchanges.CloudflareChange{}, false, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), transactionDirectory)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		return systemchanges.CloudflareChange{}, false, errors.New("active transaction unavailable")
	}
	journal, err := readJournal(root, path.Join(transactionDirectory, entries[0].Name(), "journal.jsonl"))
	if err != nil || len(journal) == 0 || len(journal[0].Steps) != 1 || journal[0].Steps[0].Cloudflare == nil {
		return systemchanges.CloudflareChange{}, false, err
	}
	change := *journal[0].Steps[0].Cloudflare
	return change, change.Action == systemchanges.CloudflareRunTokenActivate, nil
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
	if entries[len(entries)-1].Checkpoint == systemchanges.Complete && journalHasCertificate(entries[0].Steps) {
		action, ok := certificateActivationAction(entries[0].Steps)
		if a.certificate == nil || !ok || a.certificate.Cleanup(a.root, action) != nil {
			return errors.New("completed certificate rollback material cleanup failed")
		}
	}
	if entries[len(entries)-1].Checkpoint == systemchanges.Complete && journalHasSubscription(entries[0].Steps) {
		if a.subscription == nil || a.subscription.Cleanup(a.root) != nil {
			return errors.New("completed subscription artifact cleanup failed")
		}
	}
	if entries[len(entries)-1].Checkpoint == systemchanges.Complete && entries[0].Mutation == systemchanges.UpdateMutation {
		cleaner, ok := a.software.(interface{ CleanupComplete(string) error })
		if !ok || cleaner.CleanupComplete(a.root) != nil {
			return errors.New("completed update candidate cleanup failed")
		}
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

func certificateActivationAction(steps []journalStep) (systemchanges.CertificateAction, bool) {
	for _, step := range steps {
		if step.Certificate != nil && (step.Certificate.Action == systemchanges.CertificateIPActivate || step.Certificate.Action == systemchanges.CertificateDomainActivate) {
			return step.Certificate.Action, true
		}
	}
	return "", false
}

func journalHasCertificate(steps []journalStep) bool {
	for _, step := range steps {
		if step.Certificate != nil {
			return true
		}
	}
	return false
}

func journalHasSubscription(steps []journalStep) bool {
	for _, step := range steps {
		if step.Owner == systemchanges.SubscriptionModule && step.Forward == systemchanges.ActivatePreparedConfiguration && step.Rollback == systemchanges.RestorePriorConfiguration {
			return true
		}
	}
	return false
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
	rollbackCapable := total
	if entries[0].Mutation == systemchanges.CompleteRemovalMutation {
		rollbackCapable = firstIrreversibleJournalStep(entries[0].Steps)
		if rollbackCapable < 1 {
			return false
		}
	}
	irreversibleRemoval := entries[0].Mutation == systemchanges.CompleteRemovalMutation && journalHasCheckpoint(entries, systemchanges.IrreversibleRemovalStarted)
	switch last.Checkpoint {
	case systemchanges.Prepared:
		return next.Checkpoint == systemchanges.StepStarted && next.Step == 1 || next.Checkpoint == systemchanges.IrreversibleRunTokenRotationStarted && next.Step == 0 && entries[0].Mutation == systemchanges.RotationMutation && validEvidence(next.Evidence) || next.Checkpoint == systemchanges.CancellationRequested && next.Step == 0 || next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0
	case systemchanges.IrreversibleRunTokenRotationStarted:
		return next.Checkpoint == systemchanges.StateFinalized && next.Step == 0 && next.State != nil
	case systemchanges.StepStarted:
		if irreversibleRemoval {
			return next.Checkpoint == systemchanges.StepCompleted && next.Step == last.Step && validEvidence(next.Evidence)
		}
		return next.Checkpoint == systemchanges.StepCompleted && next.Step == last.Step && validEvidence(next.Evidence) || next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0 || next.Checkpoint == systemchanges.CancellationRequested && next.Step == last.Step
	case systemchanges.StepCompleted:
		if last.Step < rollbackCapable {
			if irreversibleRemoval {
				return next.Checkpoint == systemchanges.StepStarted && next.Step == last.Step+1
			}
			return next.Checkpoint == systemchanges.StateFinalized && next.Step == last.Step && next.State != nil || next.Checkpoint == systemchanges.StepStarted && next.Step == last.Step+1 || next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0 || next.Checkpoint == systemchanges.CancellationRequested && next.Step == last.Step
		}
		if irreversibleRemoval {
			return next.Checkpoint == systemchanges.PrePublicationHealthPassed && next.Step == 0
		}
		return next.Checkpoint == systemchanges.StateFinalized && next.Step == 0 && next.State != nil || next.Checkpoint == systemchanges.PrePublicationHealthPassed && next.Step == 0 || next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0 || next.Checkpoint == systemchanges.CancellationRequested && next.Step == last.Step
	case systemchanges.StateFinalized:
		return next.Checkpoint == systemchanges.StepStarted && next.Step == last.Step+1 || next.Checkpoint == systemchanges.PrePublicationHealthPassed && next.Step == 0 || next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0 || next.Checkpoint == systemchanges.CancellationRequested && next.Step == last.Step
	case systemchanges.PrePublicationHealthPassed:
		if entries[0].Mutation == systemchanges.CompleteRemovalMutation {
			return next.Checkpoint == systemchanges.IrreversibleRemovalStarted && next.Step == 0 || next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0 || next.Checkpoint == systemchanges.CancellationRequested && next.Step == rollbackCapable
		}
		return next.Checkpoint == systemchanges.StatePublicationStarted && next.Step == 0 || next.Checkpoint == systemchanges.RollbackStarted && next.Step == 0 || next.Checkpoint == systemchanges.CancellationRequested && next.Step == total
	case systemchanges.OwnedExternalDeletionVerified:
		return next.Checkpoint == systemchanges.TokenRevocationVerified && next.Step == 0 && next.Evidence == nil
	case systemchanges.IrreversibleRemovalStarted:
		return next.Checkpoint == systemchanges.OwnedDNSRecordsDeleted && next.Step == 0 && validEvidence(next.Evidence)
	case systemchanges.OwnedDNSRecordsDeleted:
		return next.Checkpoint == systemchanges.OwnedTunnelDeleted && next.Step == 0 && validEvidence(next.Evidence)
	case systemchanges.OwnedTunnelDeleted:
		return next.Checkpoint == systemchanges.OwnedExternalDeletionVerified && next.Step == 0 && next.Evidence == nil
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

func firstIrreversibleJournalStep(steps []journalStep) int {
	for index, step := range steps {
		if step.Removal != nil && step.Removal.Action == systemchanges.CloudflareRemoval && (step.Removal.Resource == systemchanges.CloudflareDNSRecordResource || step.Removal.Resource == systemchanges.CloudflareTunnelResource) {
			return index
		}
	}
	return -1
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

func journalHasCheckpoint(entries []journalEntry, checkpoint systemchanges.DurableCheckpoint) bool {
	for _, entry := range entries {
		if entry.Checkpoint == checkpoint {
			return true
		}
	}
	return false
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
	if err := json.Unmarshal(data, &manifest); err != nil || manifest.SchemaVersion != 1 || manifest.Release == (systemchanges.ReleaseBinding{}) && manifest.Reason != systemchanges.CompleteRemovalMutation || manifest.Reason == "" {
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
	if err != nil || json.Unmarshal(data, &manifest) != nil || manifest.SchemaVersion != 1 || manifest.Release == (systemchanges.ReleaseBinding{}) && manifest.Reason != systemchanges.CompleteRemovalMutation || manifest.Reason == "" {
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
