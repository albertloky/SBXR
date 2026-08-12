package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
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

func TestInstalledReentryRefusesAnExecutableChangedBeforeLaunch(t *testing.T) {
	if err := runOwnerConsole(context.Background(), os.Stdin, os.Stdout, []string{"TERM=xterm-256color", "SBXR_INSTALLED_REENTRY=1"}); err == nil || err.Error() != "installed Client Access executable changed before re-entry" {
		t.Fatalf("changed installed re-entry = %v", err)
	}
}

func TestPreactivationRecoveryReceiptBindsTheAuthenticatedExecutable(t *testing.T) {
	name := filepath.Join(t.TempDir(), "recovery.json")
	receipt := recoveryReceipt{Schema: 1, ChangeSet: "install-session-0001", Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: strings.Repeat("a", 40), ReleaseIndexSHA256: strings.Repeat("b", 64), PayloadSHA256: strings.Repeat("d", 64)}
	body, _ := json.Marshal(receipt)
	if err := os.WriteFile(name, append(body, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	uid := info.Sys().(*syscall.Stat_t).Uid
	report := versionReport{Build: softwarelifecycle.EmbeddedBuildIdentity{Repository: receipt.Repository, Tag: receipt.Tag, Commit: receipt.Commit, PayloadSHA256: receipt.PayloadSHA256}}
	if !validClientAccessRecoveryMarker(name, report, uid) {
		t.Fatal("exact recovery receipt was refused")
	}
	receipt.Commit = strings.Repeat("c", 40)
	body, _ = json.Marshal(receipt)
	if err := os.WriteFile(name, append(body, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if validClientAccessRecoveryMarker(name, report, uid) {
		t.Fatal("changed recovery receipt was accepted")
	}
}

func TestPreinstallOutcomeProvidesRestrictedFailSafeDiagnostics(t *testing.T) {
	presentation := newInstallOutcome().ViewDiagnostics(t.Context())
	if presentation.Installation != ownerconsole.InstallationRecoveryRequired || len(presentation.Modules) != 11 || len(presentation.Services) != 10 || len(presentation.Bundles) != 0 {
		t.Fatalf("preinstall diagnostics = %+v", presentation)
	}
}

func TestReclaimableVPSUsesTheInstallationReviewWithoutStartingApply(t *testing.T) {
	plan := &networkpolicy.ReclamationPlan{Digest: strings.Repeat("a", 64), Targets: []string{"executable /usr/local/bin/xray sha256 " + strings.Repeat("b", 64)}, Preservation: []string{"preserve Docker volumes"}, PermanentWarnings: []string{"Future reclamation is permanent"}, Interruption: "No work starts; interruption changes nothing", Cancellation: "Back or Cancel changes nothing", Rollback: "no rollback exists after future permanent reclamation starts"}
	review := reclamationReview(plan, false)
	if review.Plan == nil || review.Plan.ReclamationDigest != plan.Digest || review.Plan.ReclamationConfirmed || !review.Plan.LineageUnavailable || !strings.Contains(strings.Join(review.Plan.Effects, " "), "/usr/local/bin/xray") {
		t.Fatalf("reclamation installation review = %+v", review)
	}
	outcome := &installOutcome{values: map[string]string{}, reclamation: plan}
	if result := outcome.Apply(t.Context(), review.Plan.Identity); result.Kind != ownerconsole.ChangePlanRejected || outcome.change.Kind != ownerconsole.NoChangeSet {
		t.Fatalf("review-only reclamation started work: result=%+v change=%+v", result, outcome.change)
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

func TestOwnerRecoveryDoesNotReportManagedWhileRemovalAwaitsTokenRevocation(t *testing.T) {
	result := ownerRecoveryResult(ownerRecovery{changeSet: "complete-removal-0001", forwardOnly: true, completeRemoval: true}, "", nil)
	if result.Kind != ownerconsole.ChangeSetRecoveryRequired || result.Checkpoint != "Awaiting Owner token revocation" {
		t.Fatalf("nonterminal removal recovery = %+v", result)
	}
}
