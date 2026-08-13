package ownerconsole

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
)

type outcomeStub struct {
	mu               sync.Mutex
	reviews          []ChangeReview
	applyResults     []ChangeResult
	currentChangeSet DurableChangeSet
	reviewCalls      int
	fixes            []CorrectionInput
	checkCalls       int
	backCalls        int
	backReview       ChangeReview
	edits            []EditingInput
	editReview       ChangeReview
	applyPlans       []PlanIdentity
	applyContexts    []context.Context
	cancelled        []OperationIdentity
	reclamationCalls int
	reclamationOK    bool
}

func (stub *outcomeStub) ConfirmReclamation(_ context.Context, identity PlanIdentity, approval ReclamationApproval) ChangeReview {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.reclamationCalls++
	plan := stub.reviews[0].Plan
	stub.reclamationOK = plan != nil && approval.NetworkPolicyReclamationApproval(identity, plan.ReclamationDigest) && !approval.NetworkPolicyReclamationApproval(identity, plan.ReclamationDigest)
	if plan == nil || !stub.reclamationOK {
		return ChangeReview{}
	}
	confirmed := *plan
	confirmed.ReclamationConfirmed = true
	return ChangeReview{Plan: &confirmed}
}

func (stub *outcomeStub) Review(context.Context) ChangeReview {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.nextReview()
}

func (stub *outcomeStub) Fix(_ context.Context, input CorrectionInput) ChangeReview {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.fixes = append(stub.fixes, input)
	return stub.nextReview()
}

func (stub *outcomeStub) CheckAgain(context.Context) ChangeReview {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.checkCalls++
	return stub.nextReview()
}

func (stub *outcomeStub) Back(context.Context) ChangeReview {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.backCalls++
	return stub.backReview
}

func (stub *outcomeStub) Edit(_ context.Context, input EditingInput) ChangeReview {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.edits = append(stub.edits, input)
	return stub.editReview
}

func (stub *outcomeStub) nextReview() ChangeReview {
	index := stub.reviewCalls
	stub.reviewCalls++
	if index >= len(stub.reviews) {
		return ChangeReview{}
	}
	return stub.reviews[index]
}

func (stub *outcomeStub) Apply(ctx context.Context, plan PlanIdentity) ChangeResult {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.applyPlans = append(stub.applyPlans, plan)
	stub.applyContexts = append(stub.applyContexts, ctx)
	if len(stub.applyResults) == 0 {
		return ChangeResult{}
	}
	result := stub.applyResults[0]
	stub.applyResults = stub.applyResults[1:]
	return result
}

func TestOwnershipRefusalWithBackSelectionRemainsNavigable(t *testing.T) {
	review := validatedChangeReview(ChangeReview{Correction: &CorrectionPresentation{
		Problem: "Complete removal cannot prove owned Cloudflare resources", Found: "Desired State lineage is unavailable",
		Required: "Exact immutable IDs and active scoped authority", WhyStopped: "Raw State is not ownership proof",
		OwnerSteps: []string{"Use Diagnostics", "Clean up only independently verified resources", "Rebuild on a clean VPS"},
		Selections: []CorrectionSelection{{Identity: "back", Label: "Back"}}, Evidence: "SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-OWNERSHIP-UNPROVED",
	}})
	if review.Correction == nil || review.Correction.Evidence != "SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-OWNERSHIP-UNPROVED" {
		t.Fatalf("ownership refusal was replaced: %+v", review)
	}
}

func (stub *outcomeStub) Inspect(context.Context) DurableChangeSet { return stub.currentChangeSet }

func (stub *outcomeStub) RequestCancellation(_ context.Context, operation OperationIdentity) ChangeResult {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.cancelled = append(stub.cancelled, operation)
	return ChangeResult{Kind: ChangeCancellationRequested, OperationID: operation}
}

func completePlan(identity PlanIdentity) ChangeReview {
	return ChangeReview{Plan: &PlanPresentation{
		Identity: identity, DesiredStateRevision: 0, DesiredStateSHA256: strings.Repeat("a", 64),
		RelevantChecksums: []string{"release-index " + strings.Repeat("b", 64)},
		ObservedState:     "fresh Clean VPS inspection", VerifiedExternalInputs: []string{"Release Identity verified", "Cloudflare account and zone verified"},
		Effects:        []string{"Install all six Connection Profiles", "Publish seven subscription representations"},
		RequiredChecks: []string{"Network Policy preflight", "post-publication agreement"}, AdvisoryChecks: []string{"RAM recommendation disclosed"},
		Interruption: "No managed service exists before Apply.", Cancellation: "After start, wait for a safe checkpoint and roll back.", Rollback: "Remove only additions recorded by this Change Set and prove Not installed.",
	}}
}

func planTraversalSteps(plan *PlanPresentation, width, height int) []string {
	var steps []string
	for range minimumPlanPages(plan, width, height)[1:] {
		steps = append(steps, "\r")
	}
	return steps
}

func fillFinalPlanPage(plan *PlanPresentation, width, height int) {
	contentWidth := width - navigationWidth - 1
	if width >= 120 {
		contentWidth = 48
	}
	capacity := max(1, height-13)
	for index := 0; len(wrapLines(planFactLines(plan), contentWidth))%capacity != 0; index++ {
		plan.Effects = append(plan.Effects, fmt.Sprintf("Additional exact effect %02d", index))
	}
}

func TestRunReviewsCompleteTypedPlanWithoutStartingWork(t *testing.T) {
	stub := &outcomeStub{reviews: []ChangeReview{completePlan("install-plan-1")}}
	steps := append([]string{""}, planTraversalSteps(stub.reviews[0].Plan, 120, 36)...)
	steps = append(steps, "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 120, 36, steps...)
	for _, want := range []string{"install-plan-1", "Desired State revision 0", "fresh Clean VPS inspection", "Release Identity verified", "Install all six Connection Profiles", "Required - Network Policy preflight", "Advisory - RAM recommendation disclosed", "No managed service exists before", "wait for a safe", "prove Not installed"} {
		if !strings.Contains(got, want) {
			t.Fatalf("review omitted %q\n%s", want, got)
		}
	}
	if len(stub.applyPlans) != 0 {
		t.Fatal("review or disconnect before approval started work")
	}
}

func TestRunReviewsEveryPlanSectionAtMinimumSizeBeforeApply(t *testing.T) {
	stub := &outcomeStub{reviews: []ChangeReview{completePlan("install-plan-minimum")}}
	steps := append([]string{""}, planTraversalSteps(stub.reviews[0].Plan, 80, 24)...)
	steps = append(steps, "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 80, 24, steps...)
	for _, want := range []string{"PLAN 1 OF", strings.Repeat("a", 50), "release-index", strings.Repeat("b", 50), "Release Identity verified", "Install all six", "quired - Network Policy preflight", "Advisory - RAM recommendation disclosed", "Interruption:", "Cancellation:", "Rollback:", "Apply exact one-use Plan"} {
		if !strings.Contains(got, want) {
			t.Fatalf("minimum Plan review omitted %q\n%s", want, got)
		}
	}
	if len(stub.applyPlans) != 0 {
		t.Fatal("reviewing minimum-size Plan sections applied work")
	}
}

func TestRunPresentsCompleteCorrectionFlowWithoutBypass(t *testing.T) {
	stub := &outcomeStub{reviews: []ChangeReview{{Correction: &CorrectionPresentation{
		Problem: "TCP port 443 is occupied", Found: "unowned listener on 0.0.0.0:443", Required: "one available reviewed profile port", WhyStopped: "SBXR never adopts an unowned listener", FixWithSBXR: true,
		OwnerSteps: []string{"Open the provider firewall", "Allow the newly reviewed port"}, InputLabel: "Replacement port", Selections: []CorrectionSelection{{Identity: "another-port", Label: "Choose another available port"}}, Evidence: "NETWORK-PORT-CONFLICT listener=redacted",
	}}}}
	got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 80, 24, "", "\t", "\r", "", "\x03\r")
	for _, want := range []string{"CORRECTION FLOW", "Problem", "TCP port 443 is occupied", "Found", "Required", "Why SBXR stopped", "Fix with SBXR", "Open the provider firewall", "Replacement port", "Choose another available port", "Check again", "Back", "NETWORK-PORT-CONFLICT listener=redacted"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Correction Flow omitted %q\n%s", want, got)
		}
	}
	for _, forbidden := range []string{"Continue anyway", "force unlock", "reveal secret"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("Correction Flow exposed bypass %q", forbidden)
		}
	}
}

func TestRunRejectsStaleApprovalAndRebuildsAPlan(t *testing.T) {
	for _, size := range []struct{ width, height int }{{80, 24}, {120, 36}} {
		t.Run(fmt.Sprintf("%dx%d", size.width, size.height), func(t *testing.T) {
			first, second := completePlan("install-plan-1"), completePlan("install-plan-2")
			fillFinalPlanPage(second.Plan, size.width, size.height)
			stub := &outcomeStub{reviews: []ChangeReview{first, second}, applyResults: []ChangeResult{{Kind: ChangePlanRejected, Explanation: "The approved Plan became stale; a fresh Plan is required."}}}
			steps := append(planTraversalSteps(first.Plan, size.width, size.height), "\r", "", "")
			steps = append(steps, planTraversalSteps(second.Plan, size.width, size.height)...)
			steps = append(steps, "", "\x03\r")
			got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub, Authenticator: &authenticationStub{result: AuthenticationSucceeded}}, size.width, size.height, steps...)
			if len(stub.applyPlans) != 1 || stub.applyPlans[0] != "install-plan-1" || stub.reviewCalls != 2 {
				t.Fatalf("stale approval calls = plans %#v reviews %d", stub.applyPlans, stub.reviewCalls)
			}
			if !strings.Contains(got, "became stale") || !strings.Contains(got, "install-plan-2") || !strings.Contains(got, "Apply exact one-use Plan") {
				t.Fatalf("stale approval did not keep feedback and rebuilt-Plan actions visible\n%s", got)
			}
		})
	}
}

func TestRunShowsChangeSetProgressAndRequestsSafeCancellation(t *testing.T) {
	stub := &outcomeStub{currentChangeSet: DurableChangeSet{Kind: ChangeSetActive, OperationID: "change-set-42", CompletedSteps: 3, TotalSteps: 8, Checkpoint: "Step completed"}}
	got := runTranscriptSteps(t, Session{Scenario: AuthenticatedOverview, Outcome: stub}, 120, 36, "", "c", "", "\x03\r")
	if len(stub.cancelled) != 1 || stub.cancelled[0] != "change-set-42" {
		t.Fatalf("cancellation requests = %#v", stub.cancelled)
	}
	for _, want := range []string{"CHANGE IN PROGRESS", "change-set-42", "Change Set progress 3 of 8 steps", "Step completed", "ancellation requested", "rollback checkpoint", "approved work continues"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Change Set progress omitted %q\n%s", want, got)
		}
	}
}

func TestRunRelaunchShowsOnlyTypedChangeSetResult(t *testing.T) {
	for _, test := range []struct {
		name string
		kind ChangeSetStatus
		want string
	}{
		{name: "active", kind: ChangeSetActive, want: "CHANGE IN PROGRESS"},
		{name: "success", kind: ChangeSetSucceeded, want: "PROVEN SUCCESS"},
		{name: "rollback", kind: ChangeSetRolledBack, want: "PROVEN ROLLBACK"},
		{name: "recovery", kind: ChangeSetRecoveryRequired, want: "RECOVERY REQUIRED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := &outcomeStub{currentChangeSet: DurableChangeSet{Kind: test.kind, OperationID: "change-set-relaunch", Checkpoint: "typed Change Set checkpoint"}}
			got := runTranscriptSteps(t, Session{Scenario: AuthenticatedOverview, Outcome: stub}, 120, 36, "", "\x03\r")
			if !strings.Contains(got, test.want) || !strings.Contains(got, "Change Set checkpoint:") || !strings.Contains(got, "No result is inferred") {
				t.Fatalf("relaunch did not show %s from typed Change Set facts\n%s", test.want, got)
			}
		})
	}
}

func TestRunRefusesUnsafeTypedPlanEvidence(t *testing.T) {
	review := completePlan("install-plan-secret")
	review.Plan.Effects = []string{"INFRASTRUCTURE-SECRET-MARKER-COMPLETE-TOKEN"}
	stub := &outcomeStub{reviews: []ChangeReview{review}}
	got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 120, 36, "", "\x03\r")
	if strings.Contains(got, "INFRASTRUCTURE-SECRET-MARKER") || !strings.Contains(got, "OWNER-CONSOLE-TYPED-OUTCOME-REFUSED") {
		t.Fatalf("unsafe typed Plan was rendered instead of refused\n%s", got)
	}
}

func TestRunConfirmsExactReclamationReviewBeforeSeparateApply(t *testing.T) {
	review := completePlan("reclaim-vps-review")
	review.Plan.LineageUnavailable, review.Plan.DesiredStateRevision, review.Plan.DesiredStateSHA256 = true, 0, ""
	review.Plan.ReclamationDigest = strings.Repeat("c", 64)
	review.Plan.Effects = []string{"Review exact executable, service, package, firewall, Docker, and Cloudflare conflict targets; change nothing"}
	review.Plan.Interruption = "No work starts; interruption changes nothing."
	review.Plan.Cancellation = "Back or Cancel changes nothing."
	review.Plan.Rollback = "No rollback exists because this review makes no change."
	stub := &outcomeStub{reviews: []ChangeReview{review}}
	steps := append([]string{""}, planTraversalSteps(review.Plan, 120, 36)...)
	steps = append(steps, "\t", ReclamationPhrase, "\t", "\r", "", "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 120, 36, steps...)
	if stub.reclamationCalls != 1 || !stub.reclamationOK || len(stub.applyPlans) != 0 || !strings.Contains(got, "Reclamation review confirmed") || !strings.Contains(got, "Apply has not") {
		t.Fatalf("reclamation confirmation crossed the review-only boundary: calls=%d ok=%t apply=%v\n%s", stub.reclamationCalls, stub.reclamationOK, stub.applyPlans, got)
	}
}

func TestReclamationApprovalIsOpaqueExactAndOneUse(t *testing.T) {
	digest := strings.Repeat("d", 64)
	approval := ReclamationApproval{cell: &reclamationApprovalCell{identity: "reclaim-vps-review", digest: digest}}
	if (ReclamationApproval{}).NetworkPolicyReclamationApproval("reclaim-vps-review", digest) || approval.NetworkPolicyReclamationApproval("other-plan", digest) || approval.NetworkPolicyReclamationApproval("reclaim-vps-review", strings.Repeat("e", 64)) || !approval.NetworkPolicyReclamationApproval("reclaim-vps-review", digest) || approval.NetworkPolicyReclamationApproval("reclaim-vps-review", digest) {
		t.Fatal("reclamation approval was forgeable, mismatched, or reusable")
	}
	if _, err := approval.MarshalJSON(); err == nil || strings.Contains(fmt.Sprintf("%v %#v", approval, approval), digest) {
		t.Fatal("reclamation approval was renderable")
	}
}

func TestRunRefusesIncompletePlanFacts(t *testing.T) {
	tests := map[string]func(*PlanPresentation){
		"relevant checksums":       func(plan *PlanPresentation) { plan.RelevantChecksums = nil },
		"verified external inputs": func(plan *PlanPresentation) { plan.VerifiedExternalInputs = nil },
		"exact effects":            func(plan *PlanPresentation) { plan.Effects = nil },
		"required checks":          func(plan *PlanPresentation) { plan.RequiredChecks = nil },
		"advisory checks":          func(plan *PlanPresentation) { plan.AdvisoryChecks = nil },
	}
	for name, remove := range tests {
		t.Run(name, func(t *testing.T) {
			review := completePlan("install-plan-incomplete")
			remove(review.Plan)
			stub := &outcomeStub{reviews: []ChangeReview{review}}
			got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 120, 36, "", "\x03\r")
			if !strings.Contains(got, "OWNER-CONSOLE-TYPED-OUTCOME-REFUSED") || len(stub.applyPlans) != 0 {
				t.Fatalf("Plan without %s remained Apply-able\n%s", name, got)
			}
		})
	}
}

func TestRunSubmitsCorrectionInputAndSelectionOnlyToASeparateFixPlan(t *testing.T) {
	correction := ChangeReview{Correction: &CorrectionPresentation{
		Problem: "Port correction is required", Found: "443 occupied", Required: "one available port", WhyStopped: "the listener is unowned", FixWithSBXR: true,
		OwnerSteps: []string{"Allow the reviewed port externally"}, InputLabel: "Replacement port", Selections: []CorrectionSelection{{Identity: "tcp-8443", Label: "TCP 8443"}, {Identity: "tcp-9443", Label: "TCP 9443"}}, Evidence: "NETWORK-PORT-CORRECTION redacted",
	}}
	stub := &outcomeStub{reviews: []ChangeReview{correction, completePlan("correction-plan-1")}}
	steps := []string{"", "8443", "\t", "\x1b[C", "\r", ""}
	steps = append(steps, planTraversalSteps(stub.reviews[1].Plan, 120, 36)...)
	steps = append(steps, "", "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 120, 36, steps...)
	if len(stub.fixes) != 1 || stub.fixes[0].Text != "8443" || stub.fixes[0].Selection != "tcp-9443" {
		t.Fatalf("correction requests = %#v", stub.fixes)
	}
	if !strings.Contains(got, "correction-plan-1") || !strings.Contains(got, "Apply exact one-use Plan") {
		t.Fatalf("Fix with SBXR bypassed separate Plan review\n%s", got)
	}
}

func TestRunRequiredCorrectionInputCannotBeSubmittedEmpty(t *testing.T) {
	correction := ChangeReview{Correction: &CorrectionPresentation{Problem: "Port correction is required", Found: "443 occupied", Required: "one available port", WhyStopped: "the listener is unowned", FixWithSBXR: true, OwnerSteps: []string{"Allow the reviewed port"}, InputLabel: "Replacement port", Selections: []CorrectionSelection{{Identity: "tcp-8443", Label: "TCP 8443"}}, Evidence: "NETWORK-PORT redacted"}}
	stub := &outcomeStub{reviews: []ChangeReview{correction}}
	steps := []string{"", "\t"}
	for range minimumCorrectionPages(correction.Correction, 80, 24)[1:] {
		steps = append(steps, "\r")
	}
	steps = append(steps, "\r", "", "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 80, 24, steps...)
	if len(stub.fixes) != 0 || !strings.Contains(got, "Required correction input is empty") || !strings.Contains(got, "Fix with SBXR") || !strings.Contains(got, "Check again") {
		t.Fatalf("empty required correction input was submitted\n%s", got)
	}
}

func TestRunFixPlanBackRestoresCorrectionEditingState(t *testing.T) {
	correction := ChangeReview{Correction: &CorrectionPresentation{Problem: "Port correction is required", Found: "443 occupied", Required: "one available port", WhyStopped: "the listener is unowned", FixWithSBXR: true, OwnerSteps: []string{"Allow the reviewed port"}, InputLabel: "Replacement port", Selections: []CorrectionSelection{{Identity: "tcp-8443", Label: "TCP 8443"}}, Evidence: "NETWORK-PORT redacted"}}
	stub := &outcomeStub{reviews: []ChangeReview{correction, completePlan("fix-plan-back")}, backReview: correction}
	got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 120, 36, "", "8443", "\t", "\r", "", "\x1b[27u", "", "\x03\r")
	if stub.backCalls != 1 || len(stub.fixes) != 1 || stub.fixes[0].Text != "8443" || !strings.Contains(got, `"8443"`) || !strings.Contains(got, "CORRECTION FLOW") {
		t.Fatalf("Fix Plan Back did not restore Correction editing state\n%s", got)
	}
}

func TestRunApprovedWorkUsesAnOperationContextIndependentOfTheConsole(t *testing.T) {
	stub := &outcomeStub{reviews: []ChangeReview{completePlan("install-plan-continues")}, applyResults: []ChangeResult{{Kind: ChangeStarted, OperationID: "change-set-continues", Explanation: "Approved work is durably owned by the outcome Module."}}}
	steps := append(planTraversalSteps(stub.reviews[0].Plan, 120, 36), "\r", "", "", "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub, Authenticator: &authenticationStub{result: AuthenticationSucceeded}}, 120, 36, steps...)
	if len(stub.applyContexts) != 1 || stub.applyContexts[0].Err() != nil {
		t.Fatal("closing the Console cancelled the approved operation request")
	}
	if !strings.Contains(got, "Approved work is durably owned") || !strings.Contains(got, "Close TUI - approved work continues") {
		t.Fatalf("post-approval disconnect behavior was not explicit\n%s", got)
	}
}

func TestRootOwnerConsoleAppliesWithoutASecondAuthentication(t *testing.T) {
	stub := &outcomeStub{reviews: []ChangeReview{completePlan("root-console-plan")}, applyResults: []ChangeResult{{Kind: ChangeStarted, OperationID: "root-console-change"}}}
	steps := append(planTraversalSteps(stub.reviews[0].Plan, 120, 36), "\r", "", "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 120, 36, steps...)
	if len(stub.applyPlans) != 1 || stub.applyPlans[0] != "root-console-plan" || strings.Contains(got, "authentication") || strings.Contains(got, "LIMITED DASHBOARD") {
		t.Fatalf("root Owner Console approval = plans %#v\n%s", stub.applyPlans, got)
	}
}

func TestRunReadOnlyChoiceCreatesNothingAndFreshInstallReviewsWithoutSudo(t *testing.T) {
	stub := &outcomeStub{reviews: []ChangeReview{completePlan("install-plan-privacy")}}
	limited := runTranscriptSteps(t, Session{Outcome: stub, AuthenticationPolicy: DeferAuthenticationUntilApply}, 80, 24, "\x1b[B\r", "\x03\r")
	if stub.reviewCalls != 0 || len(stub.applyPlans) != 0 || !strings.Contains(limited, "LIMITED DASHBOARD") {
		t.Fatalf("read-only choice created work or sudo\n%s", limited)
	}

	got := runTranscriptSteps(t, Session{Outcome: stub, AuthenticationPolicy: DeferAuthenticationUntilApply}, 120, 36, "\r", "", "\x03\r")
	if stub.reviewCalls != 1 || len(stub.applyPlans) != 0 || !strings.Contains(got, "install-plan-privacy") || strings.Contains(got, "Normal system sudo authentication") {
		t.Fatalf("fresh-install review was not unprivileged and mutation-free\n%s", got)
	}
}

func TestRunCheckAgainReturnsToTheOwningModule(t *testing.T) {
	correction := ChangeReview{Correction: &CorrectionPresentation{Problem: "External correction required", Found: "DNS is pending", Required: "active DNS", WhyStopped: "the provider has not published the record", OwnerSteps: []string{"Publish the required DNS record"}, Selections: []CorrectionSelection{{Identity: "record-published", Label: "I published the record"}}, Evidence: "DNS-PENDING redacted"}}
	stub := &outcomeStub{reviews: []ChangeReview{correction, correction}}
	steps := []string{""}
	for range minimumCorrectionPages(correction.Correction, 80, 24)[1:] {
		steps = append(steps, "\r")
	}
	steps = append(steps, "\r", "", "\x03\r")
	_ = runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 80, 24, steps...)
	if stub.checkCalls != 1 {
		t.Fatalf("Check again calls = %d", stub.checkCalls)
	}
}

func TestRunPlanBackReturnsToSafeEditing(t *testing.T) {
	stub := &outcomeStub{
		reviews:    []ChangeReview{completePlan("install-plan-back")},
		backReview: ChangeReview{Editing: &EditingPresentation{Title: "Installation choices", Field: EditingField{Identity: "port", Label: "Port", Value: "443", Required: true}}},
		editReview: completePlan("install-plan-edited"),
	}
	got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 80, 24, "", "\x1b[27u", "", "\x7f\x7f\x7f8443", "\t", "\r", "", "\x03\r")
	if stub.backCalls != 1 || len(stub.edits) != 1 || stub.edits[0] != (EditingInput{Field: "port", Text: "8443"}) || !strings.Contains(got, "install-plan-edited") || len(stub.applyPlans) != 0 {
		t.Fatalf("Plan Back did not return to safe editing\n%s", got)
	}
}

func TestRunPagesLongValidReviewsAtLargeSize(t *testing.T) {
	t.Run("Plan", func(t *testing.T) {
		review := completePlan("long-plan")
		for index := range 32 {
			review.Plan.Effects = append(review.Plan.Effects, fmt.Sprintf("Exact effect %02d with safely wrapped detail", index))
		}
		stub := &outcomeStub{reviews: []ChangeReview{review}}
		steps := []string{""}
		for range minimumPlanPages(review.Plan, 120, 36)[1:] {
			steps = append(steps, "\r")
		}
		steps = append(steps, "", "\x03\r")
		got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 120, 36, steps...)
		pages := minimumPlanPages(review.Plan, 120, 36)
		allPages := fmt.Sprint(pages)
		if !strings.Contains(got, "PLAN 1 OF") || !strings.Contains(allPages, "Exact effect 31") || !strings.Contains(got, "Apply exact one-use Plan") || len(stub.applyPlans) != 0 {
			t.Fatalf("large Plan hid facts or actions\n%s", got)
		}
		for _, page := range pages {
			if len(page) > 23 {
				t.Fatalf("120x36 Plan page has %d facts; maximum is 23", len(page))
			}
		}
	})

	t.Run("Correction", func(t *testing.T) {
		correction := ChangeReview{Correction: &CorrectionPresentation{Problem: "External correction required", Found: "provider facts disagree", Required: "all exact external steps", WhyStopped: "SBXR has no provider authority", Selections: []CorrectionSelection{{Identity: "steps-done", Label: "I completed every exact step"}}, Evidence: "PROVIDER-CORRECTION redacted"}}
		for index := range 32 {
			correction.Correction.OwnerSteps = append(correction.Correction.OwnerSteps, fmt.Sprintf("Complete exact provider step %02d", index))
		}
		stub := &outcomeStub{reviews: []ChangeReview{correction}}
		steps := []string{""}
		for range minimumCorrectionPages(correction.Correction, 120, 36)[1:] {
			steps = append(steps, "\r")
		}
		steps = append(steps, "", "\x03\r")
		got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 120, 36, steps...)
		allPages := fmt.Sprint(minimumCorrectionPages(correction.Correction, 120, 36))
		if !strings.Contains(got, "CORRECTION FLOW 1 OF") || !strings.Contains(allPages, "Complete exact provider step 31") || !strings.Contains(got, "Check again") || !strings.Contains(got, "Copy redacted evidence") {
			t.Fatalf("large Correction Flow hid facts or actions\n%s", got)
		}
	})

	t.Run("120x24 Plan", func(t *testing.T) {
		review := completePlan("wide-short-plan")
		stub := &outcomeStub{reviews: []ChangeReview{review}}
		steps := []string{""}
		for range minimumPlanPages(review.Plan, 120, 24)[1:] {
			steps = append(steps, "\r")
		}
		steps = append(steps, "", "\x03\r")
		got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 120, 24, steps...)
		if !strings.Contains(got, "PLAN 1 OF") || !strings.Contains(got, "Apply exact one-use Plan") || len(stub.applyPlans) != 0 {
			t.Fatalf("120x24 Plan hid its review action\n%s", got)
		}
	})
}

func TestRunCopiesCorrectionEvidenceThroughAnExplicitAction(t *testing.T) {
	evidence := "NETWORK-CORRECTION evidence=redacted"
	correction := ChangeReview{Correction: &CorrectionPresentation{Problem: "External correction required", Found: "provider rule absent", Required: "one provider rule", WhyStopped: "SBXR has no provider authority", OwnerSteps: []string{"Create the named provider rule"}, Selections: []CorrectionSelection{{Identity: "rule-created", Label: "I created the rule"}}, Evidence: evidence}}
	stub := &outcomeStub{reviews: []ChangeReview{correction}}
	clipboard := &clipboardStub{result: CopyConfirmed}
	steps := []string{""}
	for range minimumCorrectionPages(correction.Correction, 80, 24)[1:] {
		steps = append(steps, "\r")
	}
	steps = append(steps, "\x1b[B", "\r", "", "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub, Clipboard: clipboard}, 80, 24, steps...)
	if !strings.Contains(got, "Copied redacted evidence.") || len(clipboard.copied()) != 1 || clipboard.copied()[0] != evidence {
		t.Fatalf("Correction evidence copy was not explicit and exact\n%s", got)
	}
}

type cancellingAuthentication struct{ prompted chan struct{} }

func (authentication *cancellingAuthentication) Authenticate(ctx context.Context, _ io.Reader, _ io.Writer) AuthenticationResult {
	close(authentication.prompted)
	<-ctx.Done()
	return AuthenticationCancelled
}

func TestRunDisconnectCancelsPendingAuthenticationBeforeApply(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	if err := pty.Setsize(slave, &pty.Winsize{Cols: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.Copy(io.Discard, master) }()
	stub := &outcomeStub{reviews: []ChangeReview{completePlan("install-plan-pending-sudo")}}
	authentication := &cancellingAuthentication{prompted: make(chan struct{})}
	capabilities := capableTerminal(80, 24)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Session{Input: slave, Output: slave, Capabilities: &capabilities, Scenario: InstallationReview, Outcome: stub, Authenticator: authentication})
	}()
	time.Sleep(300 * time.Millisecond)
	for range minimumPlanPages(stub.reviews[0].Plan, 80, 24) {
		if _, err := master.Write([]byte("\r")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case <-authentication.prompted:
	case <-time.After(2 * time.Second):
		t.Fatal("Apply did not reach pending ordinary authentication")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("disconnect did not cancel pending authentication")
	}
	if len(stub.applyPlans) != 0 {
		t.Fatal("pending authentication reached Apply after disconnect")
	}
}

func TestRunMalformedOutcomeFactsNeverInventADomainResult(t *testing.T) {
	t.Run("currentChangeSet facts", func(t *testing.T) {
		stub := &outcomeStub{currentChangeSet: DurableChangeSet{Kind: ChangeSetSucceeded, OperationID: "bad\x1b-operation"}}
		got := runTranscriptSteps(t, Session{Scenario: AuthenticatedOverview, Outcome: stub}, 80, 24, "", "\x03\r")
		if !strings.Contains(got, "DURABLE FACTS UNAVAILABLE") || strings.Contains(got, "PROVEN SUCCESS") || strings.Contains(got, "RECOVERY REQUIRED") || stub.reviewCalls != 0 {
			t.Fatalf("malformed currentChangeSet facts invented a domain result\n%s", got)
		}
	})

	t.Run("apply facts", func(t *testing.T) {
		stub := &outcomeStub{reviews: []ChangeReview{completePlan("install-plan-invalid-result")}, applyResults: []ChangeResult{{Kind: ChangeStarted, OperationID: "bad\x1b-operation"}}}
		steps := append(planTraversalSteps(stub.reviews[0].Plan, 120, 36), "\r", "", "", "\r", "\x03\r")
		got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub, Authenticator: &authenticationStub{result: AuthenticationSucceeded}}, 120, 36, steps...)
		if !strings.Contains(got, "No result was inferred") || strings.Contains(got, "CHANGE IN PROGRESS") || strings.Contains(got, "RECOVERY REQUIRED") || stub.reviewCalls != 1 || len(stub.applyPlans) != 1 {
			t.Fatalf("malformed Apply facts invented a rejection or currentChangeSet result\n%s", got)
		}
	})
}

func TestRunRefusesIncompleteCorrectionFlow(t *testing.T) {
	stub := &outcomeStub{reviews: []ChangeReview{{Correction: &CorrectionPresentation{Problem: "Blocked", Found: "unknown", Required: "known", WhyStopped: "facts are absent", Evidence: "SAFE-EVIDENCE"}}}}
	got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 120, 36, "", "\x03\r")
	if !strings.Contains(got, "OWNER-CONSOLE-TYPED-OUTCOME-REFUSED") || strings.Contains(got, "SAFE-EVIDENCE") {
		t.Fatalf("incomplete Correction Flow was accepted\n%s", got)
	}
}
