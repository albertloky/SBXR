package ubuntu

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

// ControlledInstallationAdapter keeps controlled Installation effects away
// from the live Ubuntu host while using the real System Changes transaction.
type ControlledInstallationAdapter struct {
	observation systemchanges.Observation
	artifacts   map[string][]byte
	checked     map[systemchanges.Module]map[systemchanges.GatePhase]bool
	failPost    bool
	failReverse bool
	reversed    int
	executed    []string
}

func NewControlledInstallationAdapter(observation systemchanges.Observation) *ControlledInstallationAdapter {
	return &ControlledInstallationAdapter{observation: observation}
}

func NewRefusingControlledInstallationAdapter(observation systemchanges.Observation, failPost, failReverse bool) *ControlledInstallationAdapter {
	return &ControlledInstallationAdapter{observation: observation, failPost: failPost, failReverse: failReverse}
}

func (adapter *ControlledInstallationAdapter) RequiredGatePassed(owner systemchanges.Module, phase systemchanges.GatePhase) bool {
	return adapter != nil && adapter.checked[owner][phase]
}

func (adapter *ControlledInstallationAdapter) ReversedSteps() int { return adapter.reversed }

func (adapter *ControlledInstallationAdapter) ExecutedSteps() []string {
	return append([]string(nil), adapter.executed...)
}

func (adapter *ControlledInstallationAdapter) Observe() (systemchanges.Observation, error) {
	return adapter.observation, nil
}
func (*ControlledInstallationAdapter) TryLock() (systemchanges.Lock, bool, error) {
	return controlledInstallationLock{}, true, nil
}
func (adapter *ControlledInstallationAdapter) Prepare(_ systemchanges.ExecutionLease, preparation systemchanges.Preparation) error {
	adapter.artifacts = map[string][]byte{}
	if err := preparation.WriteStateArtifacts(func(name string, _ uint32, source io.Reader) error {
		body, err := io.ReadAll(source)
		adapter.artifacts[name] = body
		return err
	}); err != nil {
		return err
	}
	if preparation.SSHAgreementSHA256 != "" {
		if err := preparation.WriteSSHPreservation(func(source io.Reader) error {
			body, err := io.ReadAll(source)
			adapter.artifacts["ssh-preservation"] = body
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}
func (adapter *ControlledInstallationAdapter) ReplaceStateArtifacts(_ systemchanges.ExecutionLease, changeSet string, binding systemchanges.StateTransactionBinding, stream func(func(string, uint32, io.Reader) error) error) error {
	if binding.ChangeSet != changeSet {
		return errors.New("final State binding mismatch")
	}
	for name := range adapter.artifacts {
		if strings.HasPrefix(name, "prepared/") {
			delete(adapter.artifacts, name)
		}
	}
	err := stream(func(name string, _ uint32, source io.Reader) error {
		body, err := io.ReadAll(source)
		adapter.artifacts[name] = body
		return err
	})
	return err
}
func (*ControlledInstallationAdapter) Record(systemchanges.ExecutionLease, systemchanges.CheckpointRecord) error {
	return nil
}
func (adapter *ControlledInstallationAdapter) Execute(_ systemchanges.ExecutionLease, _ string, number int, step systemchanges.Step, _ time.Duration, _ *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	_, cloudflare := step.CloudflareChange()
	if cloudflare {
		return systemchanges.StepEvidence{}, errors.New("controlled Installation refuses every Cloudflare effect")
	}
	if certificate, ok := step.CertificateChange(); ok {
		ip := certificate.CertName == "sbxr-ip" && (certificate.Action == systemchanges.CertificateIPStage || certificate.Action == systemchanges.CertificateIPOrder || certificate.Action == systemchanges.CertificateIPActivate)
		if !ip {
			return systemchanges.StepEvidence{}, errors.New("controlled Installation permits only sbxr-ip certificate effects")
		}
	}
	adapter.executed = append(adapter.executed, fmt.Sprintf("%d:%s:%s", number, step.Owner(), step.Forward()))
	adapter.artifacts["active/xray.json"] = append([]byte(nil), adapter.artifacts["prepared/xray.json"]...)
	adapter.artifacts["active/sing-box.json"] = append([]byte(nil), adapter.artifacts["prepared/sing-box.json"]...)
	adapter.artifacts["active/cloudflared.json"] = append([]byte(nil), adapter.artifacts["prepared/cloudflared.json"]...)
	adapter.artifacts["active/subscription.json"] = append([]byte(nil), adapter.artifacts["prepared/subscription.json"]...)
	evidence := systemchanges.StepEvidence{Code: "controlled-applied", SHA256: strings.Repeat("a", 64)}
	return evidence, nil
}
func (adapter *ControlledInstallationAdapter) Reverse(systemchanges.ExecutionLease, string, int, systemchanges.Step, time.Duration) (systemchanges.StepEvidence, error) {
	adapter.reversed++
	if adapter.failReverse {
		return systemchanges.StepEvidence{}, errors.New("controlled rollback failure")
	}
	return systemchanges.StepEvidence{Code: "controlled-restored", SHA256: strings.Repeat("b", 64)}, nil
}
func (adapter *ControlledInstallationAdapter) Check(_ systemchanges.ExecutionLease, check systemchanges.Check, phase systemchanges.GatePhase, _ time.Duration) (systemchanges.HealthStatus, error) {
	if adapter.checked == nil {
		adapter.checked = map[systemchanges.Module]map[systemchanges.GatePhase]bool{}
	}
	if adapter.checked[check.Owner] == nil {
		adapter.checked[check.Owner] = map[systemchanges.GatePhase]bool{}
	}
	if check.Classification == systemchanges.Required {
		adapter.checked[check.Owner][phase] = true
	}
	if adapter.failPost && phase == systemchanges.PostPublication {
		adapter.artifacts["active/subscription.json"] = []byte(`{"profiles":[]}`)
	}
	var manifests struct {
		Xray         *controlledServiceManifest `json:"xray"`
		SingBox      *controlledServiceManifest `json:"sing_box"`
		Cloudflared  *controlledServiceManifest `json:"cloudflared"`
		Subscription *controlledServiceManifest `json:"subscription"`
	}
	if err := json.Unmarshal(adapter.artifacts["prepared/manifests.json"], &manifests); err != nil || manifests.Xray == nil || manifests.Subscription == nil || manifests.SingBox != nil || manifests.Cloudflared != nil {
		return systemchanges.Unknown, err
	}
	expected := map[string]string{"active/xray.json": manifests.Xray.SHA256, "active/subscription.json": manifests.Subscription.SHA256}
	for name, expected := range expected {
		digest := sha256.Sum256(adapter.artifacts[name])
		if hex.EncodeToString(digest[:]) != expected {
			return systemchanges.Failed, nil
		}
	}
	return systemchanges.Healthy, nil
}
func (*ControlledInstallationAdapter) VerifyAgreement(systemchanges.ExecutionLease, systemchanges.Agreement, time.Duration) error {
	return nil
}
func (*ControlledInstallationAdapter) VerifyRollback(systemchanges.ExecutionLease, systemchanges.RollbackAgreement, time.Duration) error {
	return nil
}
func (adapter *ControlledInstallationAdapter) VerifySSHPreservation(_ systemchanges.ExecutionLease, _ string, agreement string, _ systemchanges.SSHPreservationPhase, _ time.Duration) error {
	digest := sha256.Sum256(adapter.artifacts["ssh-preservation"])
	if hex.EncodeToString(digest[:]) != agreement {
		return errors.New("SSH agreement changed")
	}
	return nil
}
func (*ControlledInstallationAdapter) Cleanup(systemchanges.ExecutionLease, string) error { return nil }

type controlledInstallationLock struct{}

func (controlledInstallationLock) Close() error { return nil }

type controlledServiceManifest struct {
	SHA256 string `json:"sha256"`
}

// NewControlledManagedProviderAdapter uses the production durable transaction
// below root while replacing every native and provider effect with a fixed
// controlled effect.
func NewControlledManagedProviderAdapter(root string, observation systemchanges.Observation, stateRecovery systemchanges.StateRecovery, cloudflare func(systemchanges.Step, string, time.Duration) (systemchanges.StepEvidence, error)) (Adapter, error) {
	if err := prepareControlledLock(root); err != nil {
		return Adapter{}, err
	}
	effects := &controlledManagedProviderEffects{cloudflare: cloudflare}
	return NewAtForManagedProvider(root, func() (systemchanges.Observation, error) { return observation, nil }, controlledHost{}, controlledFirewall{}, effects, controlledCertificate{}, controlledProfiles{}, controlledSubscription{}, stateRecovery), nil
}

// NewControlledInstallAdapter uses the production durable fresh-install transaction.
func NewControlledInstallAdapter(root string, observation systemchanges.Observation, authority systemchanges.FreshInstallationAuthority, stateRecovery systemchanges.StateRecovery) (Adapter, error) {
	if err := prepareControlledLock(root); err != nil {
		return Adapter{}, err
	}
	effects := &controlledManagedProviderEffects{}
	return NewAtForInstall(root, func() (systemchanges.Observation, error) { return observation, nil }, controlledHost{}, authority, controlledFirewall{}, effects, controlledCertificate{}, controlledProfiles{}, controlledSubscription{}, controlledSoftware{}, stateRecovery), nil
}

// NewControlledInstallRecoveryAdapter starts a fresh production recovery instance.
func NewControlledInstallRecoveryAdapter(root string, observation systemchanges.Observation, stateRecovery systemchanges.StateRecovery) (Adapter, error) {
	if err := prepareControlledLock(root); err != nil {
		return Adapter{}, err
	}
	effects := &controlledManagedProviderEffects{}
	return NewAtForInstallRecovery(root, func() (systemchanges.Observation, error) { return observation, nil }, controlledHost{}, controlledFirewall{}, effects, controlledCertificate{}, controlledProfiles{}, controlledSubscription{}, controlledSoftware{}, stateRecovery), nil
}

func prepareControlledLock(root string) error {
	directory := filepath.Join(root, "run/sbxr")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(directory, "system-changes.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	return file.Close()
}

type controlledManagedProviderEffects struct {
	cloudflare func(systemchanges.Step, string, time.Duration) (systemchanges.StepEvidence, error)
}

func controlledEffect(code string) systemchanges.StepEvidence {
	return systemchanges.StepEvidence{Code: code, SHA256: strings.Repeat("a", 64)}
}

type controlledHost struct{}
type controlledFirewall struct{}
type controlledCertificate struct{}
type controlledProfiles struct{}
type controlledSubscription struct{}
type controlledSoftware struct{}

func (controlledHost) CaptureRollback(_ systemchanges.Step, write func(io.Reader) error) error {
	return write(strings.NewReader("controlled rollback"))
}
func (controlledHost) Execute(_ systemchanges.Step, _ time.Duration, _ *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	return controlledEffect("controlled-host-applied"), nil
}
func (controlledHost) Reverse(_ systemchanges.Step, _ io.Reader, _ time.Duration) (systemchanges.StepEvidence, error) {
	return controlledEffect("controlled-host-restored"), nil
}
func (controlledHost) HoldServices() error { return nil }
func (controlledHost) AllowProvenServices(systemchanges.RecoveryTransaction, time.Duration) error {
	return nil
}
func (controlledHost) InspectStep(systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEffect, error) {
	return systemchanges.StepEffectAbsent, nil
}
func (controlledHost) VerifyStartingServices(systemchanges.RecoveryTransaction, time.Duration) error {
	return nil
}
func (controlledHost) Check(systemchanges.Check, systemchanges.GatePhase, time.Duration) (systemchanges.HealthStatus, error) {
	return systemchanges.Healthy, nil
}
func (controlledHost) VerifyAgreement(systemchanges.Agreement, time.Duration) error { return nil }
func (controlledHost) VerifyRollback(systemchanges.RollbackAgreement, time.Duration) error {
	return nil
}
func (controlledHost) activatePostCertificateUnits(time.Duration) error { return nil }
func (controlledHost) reversePostCertificateUnits(time.Duration) error  { return nil }
func (controlledHost) inspectPostCertificateUnits(time.Duration) error  { return nil }

func (controlledFirewall) CaptureRollback(_ systemchanges.Step, write func(io.Reader) error) error {
	return write(strings.NewReader("controlled firewall rollback"))
}
func (controlledFirewall) Execute(systemchanges.Step, string, time.Duration, *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	return controlledEffect("controlled-firewall-applied"), nil
}
func (controlledFirewall) ExecuteForwardOnly(systemchanges.Step, time.Duration, *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	return controlledEffect("controlled-firewall-applied"), nil
}
func (controlledFirewall) ExecuteProtected(step systemchanges.Step, path string, timeout time.Duration, cancellation *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	return controlledEffect("controlled-firewall-applied"), nil
}
func (controlledFirewall) Commit(systemchanges.Step, systemchanges.StepEvidence) error { return nil }
func (controlledFirewall) Reverse(systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEvidence, error) {
	return controlledEffect("controlled-firewall-restored"), nil
}
func (controlledFirewall) Inspect(systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEffect, error) {
	return systemchanges.StepEffectAbsent, nil
}
func (controlledFirewall) VerifySSHSession(string, time.Duration) error  { return nil }
func (controlledFirewall) VerifySSHIdentity(string, time.Duration) error { return nil }

func (*controlledManagedProviderEffects) CaptureRollback(_ systemchanges.Step, write func(io.Reader) error) error {
	return write(strings.NewReader("controlled Cloudflare rollback"))
}
func (*controlledManagedProviderEffects) CaptureServiceRollback(_ string, write func(io.Reader) error) error {
	return write(strings.NewReader("controlled cloudflared rollback"))
}
func (effects *controlledManagedProviderEffects) Execute(step systemchanges.Step, tunnelID string, timeout time.Duration) (systemchanges.StepEvidence, error) {
	if effects.cloudflare == nil {
		return systemchanges.StepEvidence{}, errors.New("controlled Cloudflare effect unavailable")
	}
	return effects.cloudflare(step, tunnelID, timeout)
}
func (*controlledManagedProviderEffects) ActivateService(string, io.Reader, time.Duration) (systemchanges.StepEvidence, error) {
	return controlledEffect("controlled-cloudflared-active"), nil
}
func (*controlledManagedProviderEffects) Reverse(systemchanges.Step, systemchanges.StepEvidence, io.Reader, time.Duration) (systemchanges.StepEvidence, error) {
	return controlledEffect("controlled-cloudflare-restored"), nil
}
func (*controlledManagedProviderEffects) InspectRepair(systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEffect, error) {
	return systemchanges.StepEffectAbsent, nil
}
func (*controlledManagedProviderEffects) InspectReclamation(systemchanges.Step, time.Duration) (systemchanges.StepEffect, error) {
	return systemchanges.StepEffectAbsent, nil
}
func (*controlledManagedProviderEffects) VerifyReclamation([]systemchanges.Step, time.Duration) error {
	return nil
}
func (*controlledManagedProviderEffects) ReverseService(string, io.Reader, time.Duration) (systemchanges.StepEvidence, error) {
	return controlledEffect("controlled-cloudflared-restored"), nil
}
func (*controlledManagedProviderEffects) InspectService(string, io.Reader) (systemchanges.StepEffect, error) {
	return systemchanges.StepEffectAbsent, nil
}
func (*controlledManagedProviderEffects) CheckRuntime(string, []systemchanges.StepEvidence, *systemchanges.CloudflareChange, time.Duration) (systemchanges.HealthStatus, error) {
	return systemchanges.Healthy, nil
}
func (*controlledManagedProviderEffects) ValidateInstalledService(string) error { return nil }
func (*controlledManagedProviderEffects) RunTokenFingerprint(string) (string, error) {
	return strings.Repeat("a", 64), nil
}
func (*controlledManagedProviderEffects) RemoveRunToken(string) error { return nil }
func (*controlledManagedProviderEffects) RetrieveRunToken(systemchanges.CloudflareChange, string, time.Duration) (any, bool, error) {
	return nil, false, nil
}
func (*controlledManagedProviderEffects) RotateService(string, io.Reader, time.Duration) (systemchanges.StepEvidence, error) {
	return controlledEffect("controlled-cloudflared-rotated"), nil
}
func (*controlledManagedProviderEffects) PrepareManagementTokenRotation(io.Reader, time.Duration, func([]byte) error) ([]byte, string, error) {
	return nil, "", nil
}
func (*controlledManagedProviderEffects) CleanupManagementTokenCandidate(io.Reader, time.Duration) error {
	return nil
}
func (*controlledManagedProviderEffects) CompleteManagementTokenRotation(io.Reader, time.Duration) (any, error) {
	return nil, nil
}

func (controlledCertificate) CaptureRollback(_ string, _ systemchanges.Step, write func(io.Reader) error) error {
	return write(strings.NewReader("controlled certificate rollback"))
}
func (controlledCertificate) Execute(string, systemchanges.Step, time.Duration, *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	return controlledEffect("controlled-certificate-applied"), nil
}
func (controlledCertificate) Reverse(string, systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEvidence, error) {
	return controlledEffect("controlled-certificate-restored"), nil
}
func (controlledCertificate) Inspect(string, systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEffect, error) {
	return systemchanges.StepEffectAbsent, nil
}
func (controlledCertificate) Check(string, string, systemchanges.GatePhase, time.Duration) (systemchanges.HealthStatus, error) {
	return systemchanges.Healthy, nil
}
func (controlledCertificate) Cleanup(string, systemchanges.CertificateAction) error { return nil }

func (controlledProfiles) ValidateConfiguration(string, string, string, systemchanges.ConnectionProfilesRuntimeBinding, time.Duration) error {
	return nil
}
func (controlledProfiles) Activate(string, string, string, systemchanges.ConnectionProfilesRuntimeBinding, time.Duration) error {
	return nil
}
func (controlledProfiles) Restore(string, string, string, systemchanges.ConnectionProfilesRuntimeBinding, time.Duration) error {
	return nil
}
func (controlledProfiles) Check(string, string, string, string, systemchanges.ConnectionProfilesRuntimeBinding, time.Duration) (bool, error) {
	return true, nil
}

func (controlledSubscription) CaptureRollback(_ string, write func(io.Reader) error) error {
	return write(strings.NewReader("controlled subscription rollback"))
}
func (controlledSubscription) Activate(string, string, systemchanges.StateTransactionBinding, string, time.Duration) (systemchanges.StepEvidence, error) {
	return controlledEffect("controlled-subscription-active"), nil
}
func (controlledSubscription) Reverse(string, io.Reader, time.Duration) (systemchanges.StepEvidence, error) {
	return controlledEffect("controlled-subscription-restored"), nil
}
func (controlledSubscription) Inspect(string, io.Reader, time.Duration) (systemchanges.StepEffect, error) {
	return systemchanges.StepEffectAbsent, nil
}
func (controlledSubscription) Check(string, string, systemchanges.StateTransactionBinding, string, time.Duration) (systemchanges.HealthStatus, error) {
	return systemchanges.Healthy, nil
}
func (controlledSubscription) Cleanup(string) error { return nil }

func (controlledSoftware) CaptureRollback(_ string, _ systemchanges.Step, write func(io.Reader) error) error {
	return write(strings.NewReader("controlled software rollback"))
}
func (controlledSoftware) Activate(string, systemchanges.Step, time.Duration) (systemchanges.StepEvidence, error) {
	return controlledEffect("controlled-software-active"), nil
}
func (controlledSoftware) Reverse(string, systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEvidence, error) {
	return controlledEffect("controlled-software-restored"), nil
}
func (controlledSoftware) Inspect(string, systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEffect, error) {
	return systemchanges.StepEffectAbsent, nil
}
func (controlledSoftware) Check(string, systemchanges.Check, systemchanges.GatePhase, time.Duration) (systemchanges.HealthStatus, error) {
	return systemchanges.Healthy, nil
}
