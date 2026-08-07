package ubuntu

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

type recordingCertificateExecutor struct{ events *[]string }

func (executor recordingCertificateExecutor) CaptureRollback(string, systemchanges.Step, func(io.Reader) error) error {
	return nil
}
func (executor recordingCertificateExecutor) Execute(string, systemchanges.Step, time.Duration, *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	*executor.events = append(*executor.events, "certificate-switch")
	return systemchanges.StepEvidence{Code: "certificate-domain-activated", SHA256: strings.Repeat("a", 64)}, nil
}
func (executor recordingCertificateExecutor) Reverse(string, systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEvidence, error) {
	*executor.events = append(*executor.events, "certificate-restore")
	return systemchanges.StepEvidence{Code: "certificate-domain-rollback", SHA256: strings.Repeat("b", 64)}, nil
}
func (recordingCertificateExecutor) Inspect(string, systemchanges.Step, io.Reader, time.Duration) (systemchanges.StepEffect, error) {
	return systemchanges.StepEffectPresent, nil
}
func (recordingCertificateExecutor) Check(string, string, systemchanges.GatePhase, time.Duration) (systemchanges.HealthStatus, error) {
	return systemchanges.Healthy, nil
}
func (recordingCertificateExecutor) Cleanup(string, systemchanges.CertificateAction) error {
	return nil
}

type recordingProfilesExecutor struct {
	events                 *[]string
	validation, activation error
}

func (executor recordingProfilesExecutor) ValidateConfiguration(string, string, string, time.Duration) error {
	*executor.events = append(*executor.events, "configuration-validate")
	return executor.validation
}
func (executor recordingProfilesExecutor) Activate(string, string, string, time.Duration) error {
	*executor.events = append(*executor.events, "restart-and-prove-three")
	return executor.activation
}
func (executor recordingProfilesExecutor) Restore(string, string, string, time.Duration) error {
	*executor.events = append(*executor.events, "restart-and-reprove-prior-three")
	return nil
}
func (recordingProfilesExecutor) Check(string, string, string, string, time.Duration) (bool, error) {
	return true, nil
}

func TestDomainActivationOrchestrationRefusesBeforeSwitchAndRestoresAfterConsumerFailure(t *testing.T) {
	change := systemchanges.CertificateChange{Action: systemchanges.CertificateDomainActivate, Identity: "direct.example.com", DestinationIP: "192.0.2.10", RequiredProfile: "tlsserver", CertName: "sbxr-domain", DirectTLSRevision: 7, DirectTLSSHA256: strings.Repeat("c", 64)}
	step, err := systemchanges.NewCertificateStep(change)
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	certificate := recordingCertificateExecutor{events: &events}
	profiles := recordingProfilesExecutor{events: &events, validation: errors.New("configuration refused")}
	if _, err := executeDomainCertificateActivation("/", certificate, profiles, step, time.Minute, systemchanges.NewCancellation()); err == nil || strings.Join(events, ",") != "configuration-validate" {
		t.Fatalf("configuration refusal events=%#v err=%v", events, err)
	}

	events = nil
	profiles.validation, profiles.activation = nil, errors.New("one consumer refused")
	if _, err := executeDomainCertificateActivation("/", certificate, profiles, step, time.Minute, systemchanges.NewCancellation()); err == nil || strings.Join(events, ",") != "configuration-validate,certificate-switch,restart-and-prove-three" {
		t.Fatalf("consumer refusal events=%#v err=%v", events, err)
	}
	if _, err := reverseDomainCertificateActivation("/", certificate, profiles, step, strings.NewReader(`{}`), time.Minute); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(events, ","); got != "configuration-validate,certificate-switch,restart-and-prove-three,certificate-restore,restart-and-reprove-prior-three" || strings.Contains(got, "order") {
		t.Fatalf("rollback events=%s", got)
	}
}
