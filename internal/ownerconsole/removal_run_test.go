package ownerconsole

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type completeRemovalStub struct {
	view          CompleteRemovalPresentation
	review        ChangeReview
	updates       <-chan CompleteRemovalPresentation
	cancelResult  *CompleteRemovalPresentation
	delay         time.Duration
	reviews       int
	cancellations []OperationIdentity
	checks        []OperationIdentity
	checkResult   *CompleteRemovalPresentation
}

func TestRunCompleteRemovalAwaitingRevocationShowsExactUserTokenHelpBeforeCheckAgain(t *testing.T) {
	view := CompleteRemovalPresentation{
		Kind: CompleteRemovalForwardOnly, StartingStatus: InstallationManaged, StartingRevision: 42,
		Progress: CompleteRemovalProgress{OperationID: "complete-removal-operation", CompletedSteps: 7, TotalSteps: 10}, Checkpoint: RemovalIrreversibleStarted, TokenPhase: RemovalTokenAwaitingOwnerRevocation,
		ManagementTokenRevocation: CloudflareExternalGuidance{
			Instructions: [3]string{"Open My Profile > API Tokens.", "Find the exact Dedicated Broad Cloudflare User API Token ID recorded by SBXR and revoke only that token.", "Do not revoke a Global API Key, Account API Token, Tunnel run token, or any unrelated user token. Return to SBXR and select Check again."},
			HelpURL:      "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
		},
	}
	checked := view
	checked.Progress.CompletedSteps = 8
	checked.TokenPhase = RemovalTokenRevocationVerified
	checked.ManagementTokenRevocation = CloudflareExternalGuidance{}
	stub := &completeRemovalStub{view: view, updates: make(chan CompleteRemovalPresentation), checkResult: &checked}
	steps := append(sectionTraversalSteps(providerPageCount(completeRemovalLines(view, true, "", 0), 1, 80, 24)), "\r", "", "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: ForwardOnlyRemoval, CompleteRemoval: stub}, 80, 24, steps...)
	for _, want := range []string{"My Profile > API Tokens", "Dedicated Broad Cloudflare User API Token", "ID recorded by SBXR", "revoke only that token", "Global API Key", "Account API Token", "Tunnel", "developers.cloudflare.com/fundamentals/api/get-sta", "Check again", "Cloudflare token revocation - verified"} {
		if !strings.Contains(got, want) {
			t.Fatalf("awaiting-revocation Help omitted %q\n%s", want, got)
		}
	}
	if len(stub.checks) != 1 || stub.checks[0] != "complete-removal-operation" || stub.reviews != 0 {
		t.Fatalf("awaiting-revocation Help bypassed or misrouted the typed check: checks=%#v reviews=%d\n%s", stub.checks, stub.reviews, got)
	}
}

func (stub *completeRemovalStub) ViewCompleteRemoval(context.Context) CompleteRemovalPresentation {
	return stub.view
}

func (stub *completeRemovalStub) WatchCompleteRemoval(context.Context) <-chan CompleteRemovalPresentation {
	return stub.updates
}

func (stub *completeRemovalStub) CheckCompleteRemoval(_ context.Context, operation OperationIdentity) CompleteRemovalPresentation {
	stub.checks = append(stub.checks, operation)
	if stub.checkResult != nil {
		stub.view = *stub.checkResult
		return stub.view
	}
	return stub.view
}

func (stub *completeRemovalStub) ReviewCompleteRemoval(context.Context, CompleteRemovalApproval) ChangeReview {
	time.Sleep(stub.delay)
	stub.reviews++
	return stub.review
}

func (stub *completeRemovalStub) CancelCompleteRemoval(_ context.Context, operation OperationIdentity) CompleteRemovalPresentation {
	time.Sleep(stub.delay)
	stub.cancellations = append(stub.cancellations, operation)
	if stub.cancelResult != nil {
		return *stub.cancelResult
	}
	return CompleteRemovalPresentation{Kind: CompleteRemovalCancelled, StartingStatus: stub.view.StartingStatus, StartingRevision: stub.view.StartingRevision, RestoredStatus: stub.view.StartingStatus, RestoredRevision: stub.view.StartingRevision, CancellationProof: RemovalRestoredExactStart, Checkpoint: RemovalBeforeIrreversibleCheckpoint, TokenPhase: RemovalTokenAvailable}
}

func TestRunCompleteRemovalRequiresTwoDistinctExactOwnerActs(t *testing.T) {
	for _, hostile := range []string{
		"complete removal",
		" COMPLETE REMOVAL",
		"COMPLETE REMOVAL ",
		"COMPLETE",
		"\x1b[200~COMPLETE REMOVAL\nPermanently remove SBXR\x1b[201~",
	} {
		stub := &completeRemovalStub{view: managedRemovalReview(), review: completeRemovalPlan()}
		lines := completeRemovalLines(stub.view, true, "", 1)
		steps := sectionTraversalSteps(providerPageCount(lines, 2, 80, 24))
		steps = append(steps, "\t", hostile, "\t\r", "\x03\r")
		got := runTranscriptSteps(t, Session{Scenario: CompleteRemovalConfirmation, CompleteRemoval: stub, CompleteRemovalOutcomes: &outcomeStub{}}, 80, 24, steps...)
		if stub.reviews != 0 || strings.Contains(got, "complete-removal-plan") {
			t.Fatalf("hostile confirmation %q started review\n%s", hostile, got)
		}
	}

	stub := &completeRemovalStub{view: managedRemovalReview(), review: completeRemovalPlan()}
	lines := completeRemovalLines(stub.view, true, "", 1)
	steps := sectionTraversalSteps(providerPageCount(lines, 2, 80, 24))
	steps = append(steps, "\t", "COMPLETE REMOVAL", "\t", "\x1b[A", "\r", "", "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: CompleteRemovalConfirmation, CompleteRemoval: stub, CompleteRemovalOutcomes: &outcomeStub{}}, 80, 24, steps...)
	if stub.reviews != 1 || !strings.Contains(got, "complete-removal-plan") || !strings.Contains(got, "REVIEW COMPLETE REMOVAL PLAN") {
		t.Fatalf("two exact Owner acts did not open one Plan review: reviews=%d\n%s", stub.reviews, got)
	}
}

func TestRunCompleteRemovalHelpAtBothSizesCannotConfirmOrSelect(t *testing.T) {
	for _, size := range []struct{ width, height int }{{120, 36}, {80, 24}} {
		view := managedRemovalReview()
		help := softwarelifecycle.CompleteRemovalConfirmationGuidance()
		view.ConfirmationHelp = ConfirmationHelp{Title: help.Title, Lines: help.Lines}
		stub := &completeRemovalStub{view: view, review: completeRemovalPlan()}
		steps := []string{""}
		if size.width == 80 {
			steps = append(steps, "h", "", "\x1b")
		}
		steps = append(steps, "", "\x1b[200~COMPLETE REMOVAL\nPermanently remove SBXR\x1b[201~", "", "\x03\r")
		got := runPseudoTerminalTranscriptSteps(t, Session{Scenario: CompleteRemovalConfirmation, CompleteRemoval: stub, CompleteRemovalOutcomes: &outcomeStub{}}, size.width, size.height, steps...)
		for _, want := range []string{"COMPLETE REMOVAL HELP", "owned local", "Cloudflare resources", "Irreversible removal started", "forward-only", "Certificate Transparency", "does not type", "Permanently", "remove SBXR", "Esc Return without confirming"} {
			if !strings.Contains(got, want) {
				t.Fatalf("%dx%d Complete removal Help omitted %q\n%s", size.width, size.height, want, got)
			}
		}
		if stub.reviews != 0 {
			t.Fatalf("%dx%d Help or hostile paste submitted Complete removal", size.width, size.height)
		}
	}
}

func TestRunCompleteRemovalPresentsAllSafetyFactsAtApprovedSizes(t *testing.T) {
	for _, size := range []struct{ width, height int }{{80, 24}, {120, 36}} {
		stub := &completeRemovalStub{view: managedRemovalReview()}
		lines := completeRemovalLines(stub.view, true, "", 1)
		steps := append(sectionTraversalSteps(providerPageCount(lines, 2, size.width, size.height)), "\x03\r")
		got := runTranscriptSteps(t, Session{Scenario: CompleteRemovalConfirmation, CompleteRemoval: stub, CompleteRemovalOutcomes: &outcomeStub{}}, size.width, size.height, steps...)
		for _, want := range []string{
			"Desired State", "Client Access Values", "Infrastructure Secrets", "certificates and ACME material",
			"transaction journal", "Rollback Snapshot", "installed release", "verified update candidate",
			"services and timers", "service identities", "prepared artifacts", "Subscription Publication artifacts",
			"SBXR-owned firewall table", "public listeners", "public services", "removal journal", "recovery runner", "deleted last", "DNS records", "Tunnel routes", "Tunnel",
			"Transparency entries", "DNS caches cannot be erased",
			"Copied client configurations may remain", "physical secure",
			"Albert revokes the scoped Cloudflare token", "Irreversible removal started", "Permanently remove SBXR", "Back",
			"restoration becomes impossible",
		} {
			if !strings.Contains(got, want) {
				t.Fatalf("%dx%d removal review omitted %q\n%s", size.width, size.height, want, got)
			}
		}
		for _, forbidden := range []string{"Uninstall and keep recovery", "Recovery Point", "backup option", "post-Complete restore"} {
			if strings.Contains(got, forbidden) {
				t.Fatalf("%dx%d removal review exposed forbidden %q\n%s", size.width, size.height, forbidden, got)
			}
		}
	}
}

func TestRunCompleteRemovalCancellationPreservesStartingStatus(t *testing.T) {
	for _, status := range []InstallationStatus{InstallationManaged, InstallationRecoveryRequired} {
		stub := &completeRemovalStub{view: CompleteRemovalPresentation{Kind: CompleteRemovalRollbackCapable, StartingStatus: status, StartingRevision: 42, Progress: CompleteRemovalProgress{OperationID: "complete-removal-operation", CompletedSteps: 2, TotalSteps: 8}, Checkpoint: RemovalBeforeIrreversibleCheckpoint, TokenPhase: RemovalTokenAvailable}}
		got := runTranscriptSteps(t, Session{Scenario: CompleteRemovalConfirmation, CompleteRemoval: stub}, 80, 24, "\r", "", "\x03\r")
		if len(stub.cancellations) != 1 || stub.cancellations[0] != "complete-removal-operation" || !strings.Contains(got, status.String()) || !strings.Contains(got, "Cancellation completed") {
			t.Fatalf("%s cancellation was not preserved: %#v\n%s", status, stub.cancellations, got)
		}
	}
	restored := CompleteRemovalPresentation{Kind: CompleteRemovalCancelled, StartingStatus: InstallationRecoveryRequired, StartingRevision: 0, RestoredStatus: InstallationManaged, RestoredRevision: 41, CancellationProof: RemovalRestoredProvenManagedBaseline, Checkpoint: RemovalBeforeIrreversibleCheckpoint, TokenPhase: RemovalTokenAvailable}
	stub := &completeRemovalStub{view: CompleteRemovalPresentation{Kind: CompleteRemovalRollbackCapable, StartingStatus: InstallationRecoveryRequired, Progress: CompleteRemovalProgress{OperationID: "recovery-removal-operation", CompletedSteps: 2, TotalSteps: 8}, Checkpoint: RemovalBeforeIrreversibleCheckpoint, TokenPhase: RemovalTokenAvailable}, cancelResult: &restored, delay: 120 * time.Millisecond}
	got := runTranscriptSteps(t, Session{Scenario: CompleteRemovalConfirmation, CompleteRemoval: stub}, 80, 24, "\r", "", "", "\x03\r")
	if !strings.Contains(got, "Requesting safe Complete removal cancellation") || !strings.Contains(got, "Proven restored status - Managed") {
		t.Fatalf("proven Managed baseline or truthful cancellation wait was omitted\n%s", got)
	}
}

func TestRunCompleteRemovalForwardOnlyRestartAndSuccessAreTruthful(t *testing.T) {
	for _, size := range []struct{ width, height int }{{80, 24}, {120, 36}} {
		forward := CompleteRemovalPresentation{Kind: CompleteRemovalForwardOnly, StartingStatus: InstallationManaged, StartingRevision: 42, Progress: CompleteRemovalProgress{OperationID: "complete-removal-operation", CompletedSteps: 4, TotalSteps: 10}, Checkpoint: RemovalIrreversibleStarted, TokenPhase: RemovalProviderDeletionInProgress}
		updates := make(chan CompleteRemovalPresentation)
		go func() {
			for _, update := range []CompleteRemovalPresentation{
				{Kind: CompleteRemovalForwardOnly, StartingStatus: InstallationManaged, StartingRevision: 42, Progress: CompleteRemovalProgress{OperationID: "complete-removal-operation", CompletedSteps: 6, TotalSteps: 10}, Checkpoint: RemovalIrreversibleStarted, TokenPhase: RemovalTokenRevocationVerified},
				{Kind: CompleteRemovalForwardOnly, StartingStatus: InstallationManaged, StartingRevision: 42, Progress: CompleteRemovalProgress{OperationID: "complete-removal-operation", CompletedSteps: 8, TotalSteps: 10}, Checkpoint: RemovalIrreversibleStarted, TokenPhase: RemovalLocalTokenDeleted},
				{Kind: CompleteRemovalSucceeded, StartingStatus: InstallationManaged, FinalStatus: InstallationNotInstalled, StartingRevision: 42, Progress: CompleteRemovalProgress{OperationID: "complete-removal-operation", CompletedSteps: 10, TotalSteps: 10}, Checkpoint: RemovalProvenComplete, TokenPhase: RemovalLocalTokenDeleted, NoRecoveryMaterial: true},
			} {
				time.Sleep(80 * time.Millisecond)
				updates <- update
			}
			close(updates)
		}()
		got := runTranscriptSteps(t, Session{Scenario: ForwardOnlyRemoval, CompleteRemoval: &completeRemovalStub{view: forward, updates: updates}}, size.width, size.height, "", "\x1b[27u", "", "", "", "", "\x03\r")
		for _, want := range []string{"FORWARD-ONLY", "Irreversible removal started", "Durable progress - 4 of 10 steps", "Do not revoke the scoped Cloudflare token yet", "Cloudflare token revocation - verified", "Local token deletion", "Restart continues", "PROVEN NOT INSTALLED", "no SBXR recovery material"} {
			if !strings.Contains(got, want) {
				t.Fatalf("%dx%d forward-only removal omitted %q\n%s", size.width, size.height, want, got)
			}
		}
		if strings.Contains(got, "> Back") || strings.Contains(got, "> Cancel") || strings.Contains(got, "Restore from") {
			t.Fatalf("%dx%d forward-only removal exposed a reverse action\n%s", size.width, size.height, got)
		}
	}

	completed := CompleteRemovalPresentation{Kind: CompleteRemovalSucceeded, StartingStatus: InstallationManaged, FinalStatus: InstallationNotInstalled, StartingRevision: 42, Progress: CompleteRemovalProgress{OperationID: "complete-removal-operation", CompletedSteps: 10, TotalSteps: 10}, Checkpoint: RemovalProvenComplete, TokenPhase: RemovalLocalTokenDeleted, NoRecoveryMaterial: true}
	got := runTranscriptSteps(t, Session{Scenario: ForwardOnlyRemoval, CompleteRemoval: &completeRemovalStub{view: completed}}, 80, 24, "\x03\r")
	for _, want := range []string{"PROVEN NOT INSTALLED", "no SBXR recovery material", "Certificate Transparency entries cannot be erased", "DNS caches cannot be erased"} {
		if !strings.Contains(got, want) {
			t.Fatalf("successful removal omitted %q\n%s", want, got)
		}
	}
}

func TestRunCompleteRemovalRefusesUnsafeTypedFacts(t *testing.T) {
	stub := &completeRemovalStub{view: CompleteRemovalPresentation{Kind: CompleteRemovalForwardOnly, StartingStatus: InstallationManaged, Progress: CompleteRemovalProgress{OperationID: "INFRASTRUCTURE-SECRET-MARKER-COMPLETE-TOKEN", TotalSteps: 2}, Checkpoint: RemovalIrreversibleStarted, TokenPhase: RemovalTokenAwaitingOwnerRevocation}}
	got := runTranscriptSteps(t, Session{Scenario: ForwardOnlyRemoval, CompleteRemoval: stub}, 80, 24, "\x03\r")
	if strings.Contains(got, "INFRASTRUCTURE-SECRET-MARKER") || !strings.Contains(got, "progress facts are unavailable") || strings.Contains(got, "> Back") {
		t.Fatalf("unsafe removal facts rendered\n%s", got)
	}
}

func TestRunCompleteRemovalForwardOnlyStreamFailureNeverRestoresBack(t *testing.T) {
	forward := CompleteRemovalPresentation{Kind: CompleteRemovalForwardOnly, StartingStatus: InstallationManaged, StartingRevision: 42, Progress: CompleteRemovalProgress{OperationID: "complete-removal-operation", CompletedSteps: 4, TotalSteps: 10}, Checkpoint: RemovalIrreversibleStarted, TokenPhase: RemovalProviderDeletionInProgress}
	closed := make(chan CompleteRemovalPresentation)
	close(closed)
	invalid := make(chan CompleteRemovalPresentation, 1)
	invalid <- CompleteRemovalPresentation{Kind: CompleteRemovalForwardOnly, StartingStatus: InstallationManaged, StartingRevision: 42, Progress: CompleteRemovalProgress{OperationID: "complete-removal-operation", CompletedSteps: 3, TotalSteps: 10}, Checkpoint: RemovalIrreversibleStarted, TokenPhase: RemovalProviderDeletionInProgress}
	for name, updates := range map[string]<-chan CompleteRemovalPresentation{"nil": nil, "closed": closed, "non-monotonic": invalid} {
		t.Run(name, func(t *testing.T) {
			got := runTranscriptSteps(t, Session{Scenario: ForwardOnlyRemoval, CompleteRemoval: &completeRemovalStub{view: forward, updates: updates}}, 80, 24, "", "\x1b[27u", "", "\x03\r")
			if !strings.Contains(got, "FORWARD-ONLY COMPLETE REMOVAL") || !strings.Contains(got, "Back and Cancel remain unavailable") || strings.Contains(got, "> Back") || strings.Contains(got, "All six Connection Profiles are Healthy") {
				t.Fatalf("%s stream failure escaped the forward-only boundary\n%s", name, got)
			}
		})
	}
	got := runTranscriptSteps(t, Session{Scenario: ForwardOnlyRemoval, CompleteRemoval: &completeRemovalStub{view: managedRemovalReview()}, CompleteRemovalOutcomes: &outcomeStub{}}, 80, 24, "", "\x1b[27u", "\x03\r")
	if !strings.Contains(got, "Back and Cancel remain unavailable") || strings.Contains(got, "Permanently remove SBXR") || strings.Contains(got, "> Back") {
		t.Fatalf("a stale pre-checkpoint view cleared the forward-only latch\n%s", got)
	}
}

func TestRunCompleteRemovalUpdateWaitsBehindExitConfirmation(t *testing.T) {
	forward := CompleteRemovalPresentation{Kind: CompleteRemovalForwardOnly, StartingStatus: InstallationManaged, StartingRevision: 42, Progress: CompleteRemovalProgress{OperationID: "complete-removal-operation", CompletedSteps: 4, TotalSteps: 10}, Checkpoint: RemovalIrreversibleStarted, TokenPhase: RemovalProviderDeletionInProgress}
	updates := make(chan CompleteRemovalPresentation)
	go func() {
		time.Sleep(120 * time.Millisecond)
		updates <- CompleteRemovalPresentation{Kind: CompleteRemovalForwardOnly, StartingStatus: InstallationManaged, StartingRevision: 42, Progress: CompleteRemovalProgress{OperationID: "complete-removal-operation", CompletedSteps: 6, TotalSteps: 10}, Checkpoint: RemovalIrreversibleStarted, TokenPhase: RemovalTokenRevocationVerified}
	}()
	got := runTranscriptSteps(t, Session{Scenario: ForwardOnlyRemoval, CompleteRemoval: &completeRemovalStub{view: forward, updates: updates}}, 80, 24, "", "\x03", "", "\x1b[27u", "", "\x03\r")
	exit := strings.Index(got, "Exit SBXR?")
	verified := strings.Index(got, "Cloudflare token revocation - verified")
	if exit < 0 || verified < exit {
		t.Fatalf("forward-only update stole or disappeared behind Exit confirmation\n%s", got)
	}
}

func managedRemovalReview() CompleteRemovalPresentation {
	return CompleteRemovalPresentation{Kind: CompleteRemovalReviewAvailable, StartingStatus: InstallationManaged, StartingRevision: 42, Checkpoint: RemovalBeforeIrreversibleCheckpoint, TokenPhase: RemovalTokenAvailable, ConfirmationHelp: ConfirmationHelp{Title: "COMPLETE REMOVAL HELP", Lines: []string{"Review exact owned deletion without confirming."}}}
}

func completeRemovalPlan() ChangeReview {
	review := completePlan("complete-removal-plan")
	review.Plan.ObservedState = "Managed revision 42 and complete owned-resource inventory freshly observed"
	review.Plan.VerifiedExternalInputs = []string{"Cloudflare DNS records, Tunnel routes, and Tunnel inventory verified", "Scoped Cloudflare token active and available through rollback-capable cleanup"}
	review.Plan.Effects = []string{"Delete every reviewed owned local category", "Delete and verify owned Cloudflare DNS records, Tunnel routes, and Tunnel", "Record Irreversible removal started only after owned external deletion is verified", "Verify token revocation, delete the local token copy, then continue fixed durable deletion", "Prove Not installed with no SBXR recovery material"}
	review.Plan.RequiredChecks = []string{"Owned external deletion verified", "Cloudflare token revocation verified", "Not installed and no recovery material"}
	review.Plan.AdvisoryChecks = []string{"Certificate Transparency entries and DNS caches remain outside SBXR deletion control"}
	review.Plan.Interruption = "Public exposure and every SBXR service are removed."
	review.Plan.Cancellation = "Back or Cancel restores the exact Managed revision 42 start until Irreversible removal started is durable."
	review.Plan.Rollback = "Before the checkpoint, restore every removed exposure and owned Cloudflare resource from the one transaction Rollback Snapshot."
	return review
}
