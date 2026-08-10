package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/ownerconsole"
)

var _ ownerconsole.CloudflareModule = (*clientAccessOutcome)(nil)
var _ ownerconsole.CertificatesModule = (*clientAccessOutcome)(nil)
var _ ownerconsole.DiagnosticsModule = (*clientAccessOutcome)(nil)
var _ ownerconsole.DiagnosticsModule = (*installOutcome)(nil)

func TestDefaultRunRefusesRedirectedTerminal(t *testing.T) {
	input, writeInput, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writeInput.Close()
	readOutput, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readOutput.Close()
	if err := runOwnerConsole(context.Background(), input, output, []string{"TERM=xterm-256color", "LANG=C.UTF-8"}); err == nil {
		t.Fatal("redirected default Run was admitted")
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	refusal, err := io.ReadAll(readOutput)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(refusal); !strings.Contains(got, "interactive input") || strings.Contains(got, "CLIENT-ACCESS-MARKER") {
		t.Fatalf("refusal = %q", got)
	}
}

func TestPreinstallOutcomeProvidesRestrictedFailSafeDiagnostics(t *testing.T) {
	presentation := newInstallOutcome().ViewDiagnostics(t.Context())
	if presentation.Installation != ownerconsole.InstallationRecoveryRequired || len(presentation.Modules) != 11 || len(presentation.Services) != 10 || len(presentation.Bundles) != 0 {
		t.Fatalf("preinstall diagnostics = %+v", presentation)
	}
}

func TestSystemAuthenticationReportsEveryOutcome(t *testing.T) {
	if got := systemAuthenticationResult(nil, nil); got != ownerconsole.AuthenticationSucceeded {
		t.Fatalf("successful authentication = %v", got)
	}
	denied := exec.Command("/usr/bin/false").Run()
	if got := systemAuthenticationResult(denied, nil); got != ownerconsole.AuthenticationDenied {
		t.Fatalf("denied authentication = %v", got)
	}
	cancelled := exec.Command("/bin/sh", "-c", "kill -INT $$").Run()
	if got := systemAuthenticationResult(cancelled, nil); got != ownerconsole.AuthenticationCancelled {
		t.Fatalf("cancelled authentication = %v", got)
	}
	if got := systemAuthenticationResult(errors.New("command unavailable"), nil); got != ownerconsole.AuthenticationFailed {
		t.Fatalf("failed authentication = %v", got)
	}
	if got := systemAuthenticationResult(context.DeadlineExceeded, context.DeadlineExceeded); got != ownerconsole.AuthenticationExpired {
		t.Fatalf("expired authentication = %v", got)
	}
}

func TestOwnerRecoveryPresentsRunTokenRotationAsForwardOnly(t *testing.T) {
	view := (ownerRecovery{changeSet: "provider-run-token", forwardOnly: true, needsRunTokenRotation: true}).ViewRecovery(t.Context())
	if view.Kind != ownerconsole.RecoveryForwardOnly || view.Proof != ownerconsole.ProvenForwardOnlyRecovery || !strings.Contains(view.Guidance, "Rotate token") || strings.Contains(view.Guidance, "rollback") {
		t.Fatalf("forward-only recovery = %+v", view)
	}
}

func TestOwnerRecoveryDoesNotAskForASecondRunTokenRotation(t *testing.T) {
	view := (ownerRecovery{changeSet: "provider-run-token", forwardOnly: true}).ViewRecovery(t.Context())
	if strings.Contains(view.Guidance, "Select Rotate token") || !strings.Contains(view.Guidance, "do not rotate") {
		t.Fatalf("post-rotation recovery guidance = %+v", view)
	}
}
