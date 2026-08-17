package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflareprofilesetup"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/installation"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

var _ ownerconsole.CloudflareModule = (*clientAccessOutcome)(nil)

func TestProductionConstructsOneCloudflareProfileSetupInterface(t *testing.T) {
	changes := systemchanges.Interface{}
	module, err := newCloudflareProfileSetupModule(networkpolicy.Interface{}, cloudflaretunnel.Interface{}, certificatelifecycle.Interface{}, connectionprofiles.Interface{}, subscriptionpublication.Interface{}, state.Interface{}, changes.Inspect, func(*systemchanges.ChangeSet, cloudflareprofilesetup.Execution) systemchanges.ApplyResult {
		return systemchanges.ApplyResult{}
	})
	if err != nil || module == nil {
		t.Fatalf("Cloudflare Profile Setup construction = %v, %v", module, err)
	}
}

func TestManagedProductionConstructsCloudflareProfileSetup(t *testing.T) {
	module, err := newProductionCloudflareProfileSetupModule()
	if err != nil || module == nil {
		t.Fatalf("production Cloudflare Profile Setup = %v, %v", module, err)
	}
}

func TestProductionConsequentialConfirmationHelpCrossesTypedBoundaries(t *testing.T) {
	reclamation := ownerPlan(&installation.Plan{ReclamationDigest: strings.Repeat("a", 64), ConfirmationHelp: installation.ReclamationConfirmationGuidance()})
	if reclamation.ConfirmationHelp.Title == "" || !strings.Contains(strings.Join(reclamation.ConfirmationHelp.Lines, " "), "Reclamation Boundary") || !strings.Contains(strings.Join(reclamation.ConfirmationHelp.Lines, " "), "Protected Host Foundation") {
		t.Fatalf("reclamation Help did not cross the production presentation boundary: %+v", reclamation.ConfirmationHelp)
	}

	outcome := &clientAccessOutcome{loaded: true, presentation: clientAccessPresentation{Installation: ownerconsole.InstallationManaged, StateRevision: 42}}
	removal := outcome.ViewCompleteRemoval(t.Context())
	if removal.Kind != ownerconsole.CompleteRemovalReviewAvailable || removal.ConfirmationHelp.Title == "" || !strings.Contains(strings.Join(removal.ConfirmationHelp.Lines, " "), "COMPLETE REMOVAL") || !strings.Contains(strings.Join(removal.ConfirmationHelp.Lines, " "), "Irreversible removal started") {
		t.Fatalf("Complete removal Help did not cross the production presentation boundary: %+v", removal)
	}
}

var _ ownerconsole.CertificatesModule = (*clientAccessOutcome)(nil)
var _ ownerconsole.DiagnosticsModule = (*clientAccessOutcome)(nil)
var _ ownerconsole.DiagnosticsModule = (*installOutcome)(nil)

func TestProductionProfileActionSeamRefusesHiddenPortAndRepairValues(t *testing.T) {
	outcome := &clientAccessOutcome{}
	for _, test := range []struct {
		name   string
		change ownerconsole.ProfileChange
	}{{"Change port", 2}, {"Repair", 3}} {
		review := outcome.ReviewProfileChange(t.Context(), ownerconsole.ProfileChangeRequest{Profile: ownerconsole.RealityVisionProfile, Change: test.change})
		if review.Correction == nil || review.Plan != nil || review.Editing != nil || review.Correction.Evidence != "CLIENT-ACCESS-PLAN-REFUSED" {
			t.Fatalf("hidden production profile action %s (%d) = %+v", test.name, test.change, review)
		}
	}
}

func TestManagedClientAccessSSHFailureSelectsOnlyLegalCorrectionActions(t *testing.T) {
	for _, test := range []struct {
		cause networkpolicy.SSHPreservationFailureCause
		hide  bool
	}{
		{cause: networkpolicy.SSHLaunchIdentityInvalid, hide: true},
		{cause: networkpolicy.SSHOriginalSessionLost, hide: true},
		{cause: networkpolicy.SSHObservationUnavailable},
	} {
		outcome := &clientAccessOutcome{sshPreflight: func(clientAccessAction) *networkpolicy.SSHPreservationFailure {
			return &networkpolicy.SSHPreservationFailure{Cause: test.cause}
		}}
		review := outcome.ReviewProfileChange(t.Context(), ownerconsole.ProfileChangeRequest{Profile: ownerconsole.RealityVisionProfile, Change: ownerconsole.EnableProfile})
		if review.Correction == nil || review.Plan != nil || review.Correction.Evidence != "CLIENT-ACCESS-PLAN-REFUSED" || review.Correction.HideCheckAgain != test.hide || review.Correction.FixWithSBXR {
			t.Fatalf("Managed Client Access SSH Correction for %q = %+v", test.cause, review)
		}
		if test.cause == networkpolicy.SSHObservationUnavailable {
			outcome.sshPreflight = func(clientAccessAction) *networkpolicy.SSHPreservationFailure { return nil }
			outcome.clientAccessLaunch = func(context.Context, clientAccessHandoffRequest) (*clientAccessHandoffSession, error) {
				return &clientAccessHandoffSession{review: clientAccessHandoffReview{Identity: "client-access-plan", SHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64), VolatileSHA256: strings.Repeat("c", 64), StartingRevision: 7, CandidateRevision: 8, TotalSteps: 2}}, nil
			}
			if retried := outcome.CheckAgain(t.Context()); retried.Plan == nil || retried.Correction != nil {
				t.Fatalf("Managed Client Access Check again = %+v", retried)
			}
		}
		if backed := outcome.Back(t.Context()); backed != (ownerconsole.ChangeReview{}) {
			t.Fatalf("Managed Client Access Back = %+v", backed)
		}
	}
}

func TestManagedClientAccessNonFirewallChangeDoesNotRequireDirectSSH(t *testing.T) {
	preflights, launches := 0, 0
	outcome := &clientAccessOutcome{
		sshPreflight: func(clientAccessAction) *networkpolicy.SSHPreservationFailure {
			preflights++
			return &networkpolicy.SSHPreservationFailure{Cause: networkpolicy.SSHLaunchIdentityInvalid}
		},
		clientAccessLaunch: func(context.Context, clientAccessHandoffRequest) (*clientAccessHandoffSession, error) {
			launches++
			return &clientAccessHandoffSession{review: clientAccessHandoffReview{Identity: "client-access-plan", SHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64), VolatileSHA256: strings.Repeat("c", 64), StartingRevision: 7, CandidateRevision: 8, TotalSteps: 2}}, nil
		},
	}
	review := outcome.ReviewProfileChange(t.Context(), ownerconsole.ProfileChangeRequest{Profile: ownerconsole.RealityVisionProfile, Change: ownerconsole.RotateProfileCredential})
	if review.Plan == nil || review.Correction != nil || preflights != 0 || launches != 1 {
		t.Fatalf("non-firewall Managed Client Access review = %+v preflights=%d launches=%d", review, preflights, launches)
	}
}

func TestManagedClientAccessPrivilegedRecheckPreservesSSHFailureCause(t *testing.T) {
	for _, test := range []struct {
		cause networkpolicy.SSHPreservationFailureCause
		hide  bool
	}{
		{cause: networkpolicy.SSHOriginalSessionLost, hide: true},
		{cause: networkpolicy.SSHObservationUnavailable},
	} {
		outcome := &clientAccessOutcome{
			sshPreflight: func(clientAccessAction) *networkpolicy.SSHPreservationFailure { return nil },
			clientAccessLaunch: func(context.Context, clientAccessHandoffRequest) (*clientAccessHandoffSession, error) {
				return nil, &sshPreservationFailureError{Cause: test.cause}
			},
		}
		review := outcome.ReviewProfileChange(t.Context(), ownerconsole.ProfileChangeRequest{Profile: ownerconsole.RealityVisionProfile, Change: ownerconsole.EnableProfile})
		if review.Correction == nil || review.Correction.Evidence != "CLIENT-ACCESS-PLAN-REFUSED" || review.Correction.HideCheckAgain != test.hide || review.Correction.FixWithSBXR {
			t.Fatalf("privileged Managed Client Access SSH Correction for %q = %+v", test.cause, review)
		}
	}
}

func TestProductionCompleteRemovalCheckAgainUsesOnlyTheAwaitingOperation(t *testing.T) {
	const operation = ownerconsole.OperationIdentity("complete-removal-operation")
	newOutcome := func() (*clientAccessOutcome, *int) {
		calls := 0
		outcome := &clientAccessOutcome{
			loaded: true,
			presentation: clientAccessPresentation{Installation: ownerconsole.InstallationRecoveryRequired, Removal: ownerconsole.CompleteRemovalPresentation{
				Kind: ownerconsole.CompleteRemovalForwardOnly, StartingStatus: ownerconsole.InstallationManaged, StartingRevision: 42,
				Progress: ownerconsole.CompleteRemovalProgress{OperationID: operation, CompletedSteps: 7, TotalSteps: 10}, Checkpoint: ownerconsole.RemovalIrreversibleStarted, TokenPhase: ownerconsole.RemovalTokenAwaitingOwnerRevocation,
			}},
			request: clientAccessHandoffRequest{Schema: 1, Mode: "removal-apply"},
			change:  ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRecoveryRequired, OperationID: operation, CompletedSteps: 7, TotalSteps: 10, Checkpoint: "Awaiting Owner token revocation"},
			recoveryRetry: func(_ context.Context, got string) (systemchanges.InstallationStatus, error) {
				calls++
				if got != string(operation) {
					t.Fatalf("Complete removal retry operation = %q", got)
				}
				return systemchanges.NotInstalled, nil
			},
		}
		return outcome, &calls
	}

	outcome, calls := newOutcome()
	view := outcome.CheckCompleteRemoval(t.Context(), operation)
	if *calls != 1 || view.Kind != ownerconsole.CompleteRemovalSucceeded || view.FinalStatus != ownerconsole.InstallationNotInstalled || !view.NoRecoveryMaterial {
		t.Fatalf("CheckCompleteRemoval() calls=%d view=%+v", *calls, view)
	}

	outcome, calls = newOutcome()
	if view := outcome.CheckCompleteRemoval(t.Context(), "different-operation"); *calls != 0 || !reflect.DeepEqual(view, ownerconsole.CompleteRemovalPresentation{}) {
		t.Fatalf("wrong-operation CheckCompleteRemoval() calls=%d view=%+v", *calls, view)
	}
}

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
	if presentation.Installation != ownerconsole.InstallationRecoveryRequired || len(presentation.Modules) != 13 || len(presentation.Services) != 10 || len(presentation.Bundles) != 0 {
		t.Fatalf("preinstall diagnostics = %+v", presentation)
	}
}

func TestInstallationPresentationCannotApplyWithoutModuleApproval(t *testing.T) {
	outcome := &installOutcome{}
	if result := outcome.Apply(t.Context(), "reclaim-vps-aaaaaaaaaaaaaaaa"); result.Kind != ownerconsole.ChangePlanRejected {
		t.Fatalf("presentation forged Installation authority: %+v", result)
	}
}

func TestInstallationPresentationClearsReviewedHealthWhenReviewIsInvalidated(t *testing.T) {
	outcome := &installOutcome{reviewedHealth: &installation.ReviewedHealth{Network: healthdiagnostics.Healthy}}
	outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "release-tag", Text: "changed"})
	if outcome.reviewedHealth != nil {
		t.Fatal("edited Installation retained stale reviewed health")
	}
}

func TestOwnerRecoveryPresentsRunTokenRotationAsForwardOnly(t *testing.T) {
	view := (ownerRecovery{changeSet: "provider-run-token", forwardOnly: true, needsRunTokenRotation: true}).ViewRecovery(t.Context())
	if view.Kind != ownerconsole.RecoveryForwardOnly || view.Proof != ownerconsole.ProvenForwardOnlyRecovery || view.ExternalGuidance.HelpURL != "https://developers.cloudflare.com/tunnel/advanced/tunnel-tokens/" || !strings.Contains(strings.Join(view.ExternalGuidance.Instructions[:], " "), "Networking > Tunnels") || strings.Contains(view.Guidance, "rollback") {
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

func TestOwnerRecoveryMapsSSHFailureCauseToExactCorrection(t *testing.T) {
	for _, test := range []struct {
		cause networkpolicy.SSHPreservationFailureCause
		hide  bool
	}{
		{cause: networkpolicy.SSHLaunchIdentityInvalid, hide: true},
		{cause: networkpolicy.SSHOriginalSessionLost, hide: true},
		{cause: networkpolicy.SSHObservationUnavailable},
	} {
		failure := &networkpolicy.SSHPreservationFailure{Cause: test.cause}
		view := (ownerRecovery{changeSet: "install-recovery-0001", forwardOnly: true, sshFailure: failure}).ViewRecovery(t.Context())
		if !view.SSHBlocked || !view.InstallationForward || view.CauseCode != "SYSTEM-CHANGES-UNFINISHED" || view.HideCheckAgain != test.hide {
			t.Fatalf("SSH recovery correction for %s = %+v", test.cause, view)
		}
	}
}

func TestOwnerRecoveryNamesForwardInstallationWithoutRunTokenGuidance(t *testing.T) {
	view := (ownerRecovery{changeSet: "install-recovery-0001", forwardOnly: true, installationForward: true}).ViewRecovery(t.Context())
	if view.CauseCode != "SYSTEM-CHANGES-UNFINISHED" || !view.InstallationForward || !strings.Contains(view.Explanation, "Irreversible Reclamation Started") || strings.Contains(view.Guidance, "token") {
		t.Fatalf("forward Installation recovery = %+v", view)
	}
}

func TestOwnerRecoveryRetryPreservesTypedSSHCorrection(t *testing.T) {
	for _, test := range []struct {
		cause networkpolicy.SSHPreservationFailureCause
		hide  bool
	}{
		{cause: networkpolicy.SSHLaunchIdentityInvalid, hide: true},
		{cause: networkpolicy.SSHOriginalSessionLost, hide: true},
		{cause: networkpolicy.SSHObservationUnavailable},
	} {
		recovery := ownerRecovery{changeSet: "install-recovery-0001", forwardOnly: true, installationForward: true, retry: func(context.Context, string) (systemchanges.InstallationStatus, error) {
			return "", &sshPreservationFailureError{Cause: test.cause}
		}}
		result := recovery.RetryAutomaticRollback(t.Context())
		if result.Change != (ownerconsole.DurableChangeSet{}) || !result.Correction.SSHBlocked || !result.Correction.InstallationForward || result.Correction.CauseCode != "SYSTEM-CHANGES-UNFINISHED" || result.Correction.HideCheckAgain != test.hide {
			t.Fatalf("retry SSH correction for %s = %+v", test.cause, result)
		}
	}
}

func TestOwnerRecoveryReportsSuccessfulForwardInstallation(t *testing.T) {
	result := ownerRecoveryResult(ownerRecovery{forwardOnly: true, installationForward: true}, systemchanges.Managed, nil)
	if result.Kind != ownerconsole.ChangeSetSucceeded || result.Checkpoint != "Complete" || result.Explanation != "Forward-only Installation recovery proved Managed State." || strings.Contains(result.Explanation, "token") {
		t.Fatalf("successful forward Installation = %+v", result)
	}
}
