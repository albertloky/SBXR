package ubuntu

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		return preparation.WriteSSHPreservation(func(source io.Reader) error {
			body, err := io.ReadAll(source)
			adapter.artifacts["ssh-preservation"] = body
			return err
		})
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
	return stream(func(name string, _ uint32, source io.Reader) error {
		body, err := io.ReadAll(source)
		adapter.artifacts[name] = body
		return err
	})
}
func (*ControlledInstallationAdapter) Record(systemchanges.ExecutionLease, systemchanges.CheckpointRecord) error {
	return nil
}
func (adapter *ControlledInstallationAdapter) Execute(_ systemchanges.ExecutionLease, _ string, number int, step systemchanges.Step, _ time.Duration, _ *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	if _, cloudflare := step.CloudflareChange(); cloudflare {
		return systemchanges.StepEvidence{}, errors.New("controlled Installation refuses every Cloudflare effect")
	}
	if certificate, ok := step.CertificateChange(); ok && (certificate.CertName != "sbxr-ip" || certificate.Action != systemchanges.CertificateIPStage && certificate.Action != systemchanges.CertificateIPOrder && certificate.Action != systemchanges.CertificateIPActivate) {
		return systemchanges.StepEvidence{}, errors.New("controlled Installation permits only sbxr-ip certificate effects")
	}
	adapter.executed = append(adapter.executed, fmt.Sprintf("%d:%s:%s", number, step.Owner(), step.Forward()))
	adapter.artifacts["active/xray.json"] = append([]byte(nil), adapter.artifacts["prepared/xray.json"]...)
	adapter.artifacts["active/subscription.json"] = append([]byte(nil), adapter.artifacts["prepared/subscription.json"]...)
	return systemchanges.StepEvidence{Code: "controlled-applied", SHA256: strings.Repeat("a", 64)}, nil
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
	if err := json.Unmarshal(adapter.artifacts["prepared/manifests.json"], &manifests); err != nil || manifests.Xray == nil || manifests.SingBox != nil || manifests.Cloudflared != nil || manifests.Subscription == nil {
		return systemchanges.Unknown, err
	}
	for name, expected := range map[string]string{"active/xray.json": manifests.Xray.SHA256, "active/subscription.json": manifests.Subscription.SHA256} {
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
