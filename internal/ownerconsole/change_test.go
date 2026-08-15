package ownerconsole

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/albertloky/SBXR/internal/installation"
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
	confirmed.ConfirmationHelp = ConfirmationHelp{}
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

func TestCorrectionFlowCanRequireExitAndRestartWithoutCheckAgain(t *testing.T) {
	correction := &CorrectionPresentation{Problem: "The direct SSH session could not be proved", Found: "the original session is closed", Required: "one fresh direct SSH launch", WhyStopped: "Installation cannot preserve a different session", OwnerSteps: []string{"Exit and restart from direct SSH."}, Evidence: "NETWORK-INSTALLATION-SSH-UNPROVED", HideCheckAgain: true}
	actions := (model{}).correctionActions(correction)
	labels := make([]string, len(actions))
	for index := range actions {
		labels[index] = actions[index].label
	}
	if slices.Contains(labels, "Check again") || !slices.Contains(labels, "Copy redacted evidence") || !slices.Contains(labels, "Back") {
		t.Fatalf("restart-only Correction Flow actions = %v", labels)
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
			got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, size.width, size.height, steps...)
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
	review.Plan.ConfirmationHelp = ConfirmationHelp{Title: "RECLAIM THIS VPS HELP", Lines: []string{"Review the exact boundary without confirming."}}
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

func TestRunShowsReclamationHelpAtBothSizesWithoutConfirming(t *testing.T) {
	for _, size := range []struct{ width, height int }{{120, 36}, {80, 24}} {
		review := completePlan("reclaim-vps-help")
		review.Plan.LineageUnavailable, review.Plan.DesiredStateRevision, review.Plan.DesiredStateSHA256 = true, 0, ""
		review.Plan.ReclamationDigest = strings.Repeat("c", 64)
		help := installation.ReclamationConfirmationGuidance()
		review.Plan.ConfirmationHelp = ConfirmationHelp{Title: help.Title, Lines: help.Lines}
		stub := &outcomeStub{reviews: []ChangeReview{review}}
		steps := []string{""}
		if size.width == 80 {
			steps = append(steps, "h", "", "\x1b")
		}
		steps = append(steps, "", "\x1b[200~RECLAIM THIS VPS\n\x1b[201~", "", "\x03\r")
		got := runPseudoTerminalTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, size.width, size.height, steps...)
		for _, want := range []string{"RECLAIM THIS VPS HELP", "clamation Boundary", "Protected Host Foundation", "Irreversible Reclamation Started", "to Managed", "Help does not confirm", "Esc Return without confirming"} {
			if !strings.Contains(got, want) {
				t.Fatalf("%dx%d reclamation Help omitted %q\n%s", size.width, size.height, want, got)
			}
		}
		if stub.reclamationCalls != 0 || len(stub.applyPlans) != 0 {
			t.Fatalf("%dx%d Help or hostile paste confirmed reclamation: calls=%d apply=%v", size.width, size.height, stub.reclamationCalls, stub.applyPlans)
		}
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
	got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 120, 36, steps...)
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

func TestRunCorrectionInputReachesOwnerAndFreshCorrectionClearsStaleState(t *testing.T) {
	first := ChangeReview{Correction: &CorrectionPresentation{Problem: "External correction required", Found: "provider value missing", Required: "one exact external value", WhyStopped: "the owning Module needs fresh provider facts", FixWithSBXR: true, OwnerSteps: []string{"Enter the provider value"}, InputLabel: "Provider value", Selections: []CorrectionSelection{{Identity: "account", Label: "Selected account"}}, Evidence: "PROVIDER-VALUE-MISSING"}}
	second := ChangeReview{Correction: &CorrectionPresentation{Problem: "External correction changed", Found: "provider facts changed", Required: "fresh provider evidence", WhyStopped: "the owning Module rechecked the provider", FixWithSBXR: true, OwnerSteps: []string{"Enter the current value"}, InputLabel: "Current provider value", Selections: []CorrectionSelection{{Identity: "zone", Label: "Selected zone"}}, Evidence: "PROVIDER-FACTS-CHANGED"}}
	third := ChangeReview{Correction: &CorrectionPresentation{Problem: "Fresh external correction", Found: "fresh provider facts", Required: "provider publication", WhyStopped: "publication is pending", OwnerSteps: []string{"Publish the value"}, Selections: []CorrectionSelection{{Identity: "published", Label: "Value published"}}, Evidence: "PROVIDER-FRESH-CHECK"}}
	stub := &outcomeStub{reviews: []ChangeReview{first, second, third}}
	got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 120, 36, "", "stale-value", "\t", "\r", "", "\t", "r", "", "\x03\r")
	if len(stub.fixes) != 1 || stub.fixes[0] != (CorrectionInput{Text: "stale-value", Selection: "account"}) || stub.checkCalls != 1 {
		t.Fatalf("correction calls = fixes=%+v checks=%d", stub.fixes, stub.checkCalls)
	}
	fresh := strings.LastIndex(got, "Fresh external correction")
	if fresh < 0 || strings.Contains(got[fresh:], "stale-value") || !strings.Contains(got[fresh:], "fresh provider facts") {
		t.Fatalf("fresh correction retained stale input or omitted fresh facts\n%s", got)
	}
}

func TestRunCorrectionInputCannotConfirmAReclamationPlan(t *testing.T) {
	correction := ChangeReview{Correction: &CorrectionPresentation{Problem: "External correction required", Found: "provider value missing", Required: "one external value", WhyStopped: "the owning Module needs that value", FixWithSBXR: true, OwnerSteps: []string{"Enter the provider value"}, InputLabel: "Provider value", Evidence: "PROVIDER-VALUE-MISSING"}}
	reclamation := completePlan("reclaim-after-correction")
	reclamation.Plan.LineageUnavailable, reclamation.Plan.DesiredStateRevision, reclamation.Plan.DesiredStateSHA256 = true, 0, ""
	reclamation.Plan.ReclamationDigest = strings.Repeat("d", 64)
	help := installation.ReclamationConfirmationGuidance()
	reclamation.Plan.ConfirmationHelp = ConfirmationHelp{Title: help.Title, Lines: help.Lines}
	stub := &outcomeStub{reviews: []ChangeReview{correction, reclamation}}
	steps := []string{"", ReclamationPhrase, "\t", "\r", ""}
	steps = append(steps, planTraversalSteps(reclamation.Plan, 120, 36)...)
	steps = append(steps, "\r", "", "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 120, 36, steps...)
	if len(stub.fixes) != 1 || stub.reclamationCalls != 0 || !strings.Contains(got, "Type exactly: "+ReclamationPhrase) {
		t.Fatalf("stale correction input confirmed reclamation: fixes=%+v confirmations=%d\n%s", stub.fixes, stub.reclamationCalls, got)
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

func TestRunShowsReadOnlyInstallationFactsAndDetectedPublicIPv4(t *testing.T) {
	review := ChangeReview{Editing: &EditingPresentation{
		Title: "Clean VPS installation",
		Facts: []EditingFact{{Label: "Running release tag", Value: "v1.0.7"}, {Label: "Active SSH port", Value: "2222"}},
		Field: EditingField{Identity: "public-ipv4", Label: "Public IPv4 (detected)", Value: "8.8.8.8", Required: true},
	}}
	got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: &outcomeStub{reviews: []ChangeReview{review}}}, 120, 36, "", "\x03\r")
	for _, want := range []string{"Running release tag: v1.0.7", "Active SSH port: 2222", `Public IPv4 (detected): "8.8.8.8"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("Installation editing omitted %q\n%s", want, got)
		}
	}
}

func TestRunShowsTheSameCompleteDomainHelpAtExactTerminalSizes(t *testing.T) {
	help := EditingHelp{
		Purpose:        "Choose SBXR's public domain.",
		Instructions:   []string{"Enter your Cloudflare domain."},
		AcceptedFormat: "Lowercase DNS name only.",
		CommonMistakes: []string{"No URL, port, or final dot."},
		Recovery:       "Correct it; prior values remain.",
		Example:        "vpn.example",
		URL:            "https://developers.cloudflare.com/fundamentals/manage-domains/add-site/",
		Sensitivity:    PublicInformation,
	}
	editing := ChangeReview{Editing: &EditingPresentation{Title: "Clean VPS installation", Field: EditingField{Identity: "domain", Label: "Domain", Value: "owner.example.test", Required: true}, Help: help}}

	wide := runPseudoTerminalTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: &outcomeStub{reviews: []ChangeReview{editing}}}, 120, 36, "", "\x03\r")
	for _, want := range []string{"DOMAIN HELP", "Purpose", "Choose SBXR's public domain", "Accepted format", "Lowercase DNS name", "Common mistakes", "No URL, port, or final dot", "Recovery", "EXAMPLE ONLY — DO NOT COPY", help.Example, "Sensitivity", "Public Information", "developers.cloudflare.com/fundamentals/", "manage-domains/add-site/", "Esc Return to field", "\x1b]8;;" + help.URL} {
		if !strings.Contains(wide, want) {
			t.Fatalf("wide Domain Help omitted %q\n%s", want, wide)
		}
	}
	if strings.Contains(wide, "PLAN BINDING") {
		t.Fatalf("wide Domain Help retained stale Plan details\n%s", wide)
	}
	requireClosedHelpHyperlinks(t, wide, help.URL)

	stub := &outcomeStub{reviews: []ChangeReview{editing}, editReview: editing}
	narrow := runPseudoTerminalTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 80, 24, "", "\t", "\x1b[B", "\r", "", "\x1b", "", "\r", "", "\x03\r")
	for _, want := range []string{"Help for this field", "> Help for this field", "DOMAIN HELP", "Choose SBXR's public domain", "Lowercase DNS name", "EXAMPLE ONLY — DO NOT COPY", help.Example, "developers.cloudflare.com/fundamentals/", "manage-domains/add-site/", "Esc Return to field"} {
		if !strings.Contains(narrow, want) {
			t.Fatalf("narrow Domain Help omitted %q\n%s", want, narrow)
		}
	}
	if len(stub.edits) != 1 || stub.edits[0] != (EditingInput{Field: "domain", Text: "owner.example.test"}) || stub.backCalls != 0 {
		t.Fatalf("Help changed input or activated the wrong action: edits=%+v back=%d", stub.edits, stub.backCalls)
	}
	requireClosedHelpHyperlinks(t, narrow, help.URL)

	for _, width := range []int{49, 58} {
		visible := ""
		for index, line := range terminalHyperlinkLines(help.URL, width) {
			open := "\x1b]8;;" + help.URL + "\a"
			close := "\x1b]8;;\a"
			if index == 0 {
				start, end := strings.Index(line, open), strings.Index(line, close)
				if start < 0 || end < start || strings.Count(line, open) != 1 || strings.Count(line, close) != 1 || !strings.Contains(line[start+len(open):end], "Open official Help") {
					t.Fatalf("width %d Help link was not closed on its row: %q", width, line)
				}
				continue
			}
			if strings.Contains(line, "\x1b]") {
				t.Fatalf("width %d plain Help URL contained terminal controls: %q", width, line)
			}
			visible += line
		}
		if visible != help.URL {
			t.Fatalf("width %d Help link text = %q, want %q", width, visible, help.URL)
		}
	}
}

func requireClosedHelpHyperlinks(t *testing.T, transcript, url string) {
	t.Helper()
	open := "\x1b]8;;" + url + "\a"
	close := "\x1b]8;;\a"
	count := 0
	for rest := transcript; ; {
		start := strings.Index(rest, open)
		if start < 0 {
			break
		}
		rest = rest[start+len(open):]
		end := strings.Index(rest, close)
		boundary := strings.IndexAny(rest, "\r\n")
		if end < 0 || boundary >= 0 && boundary < end {
			t.Fatalf("Help hyperlink crossed a frame row")
		}
		count++
		rest = rest[end+len(close):]
	}
	if count < 1 {
		t.Fatalf("wrapped Help URL emitted %d closed hyperlink fragments\n%s", count, transcript)
	}
}

func TestEditingHelpRefusesANonAllowlistedLink(t *testing.T) {
	review := validatedChangeReview(ChangeReview{Editing: &EditingPresentation{Title: "Clean VPS installation", Field: EditingField{Identity: "domain", Label: "Domain", Required: true}, Help: EditingHelp{Purpose: "Purpose", Instructions: []string{"Instructions"}, AcceptedFormat: "Format", CommonMistakes: []string{"Mistake"}, Recovery: "Correct the field.", Example: "vpn.example", URL: "https://owner.example.test/help", Sensitivity: PublicInformation}}})
	if review.Correction == nil || review.Editing != nil {
		t.Fatalf("non-allowlisted Help URL was accepted: %+v", review)
	}
}

func TestRunShowsEveryInstallationHelpSourceAtExactTerminalSizes(t *testing.T) {
	tests := []struct {
		name, label, urlTail string
		help                 EditingHelp
	}{
		{"Owner email", "Owner email", "certbot-command-line-options", EditingHelp{Purpose: "Register and recover the ACME account.", Instructions: []string{"Enter one address you monitor."}, AcceptedFormat: "local-part@domain; no spaces.", CommonMistakes: []string{"No name or multiple addresses."}, Recovery: "Correct it; prior values remain.", Example: "owner@sbxr.example", URL: "https://eff-certbot.readthedocs.io/en/stable/using.html#certbot-command-line-options", Sensitivity: PersonalInformation}},
		{"Public IPv4", "Public IPv4", "iana-ipv4-special-registry.xhtml", EditingHelp{Purpose: "Select the direct-service public IPv4.", Instructions: []string{"Use the VPS network details."}, AcceptedFormat: "Public dotted-decimal IPv4.", CommonMistakes: []string{"No private or special-use IP."}, Recovery: "Use the VPS provider's usable IPv4.", Example: "192.0.2.10", URL: "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml", Sensitivity: PublicInformation}},
		{"Port", "REALITY port", "service-names-port-numbers.xhtml", EditingHelp{Purpose: "Choose the REALITY TCP port.", Instructions: []string{"Keep the default if available."}, AcceptedFormat: "Decimal integer from 1 to 65535.", CommonMistakes: []string{"No text, sign, space, or zero."}, Recovery: "Use a valid REALITY port.", Example: "10444", URL: "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml", Sensitivity: PublicInformation}},
		{"Longest port", "Subscription HTTPS port", "service-names-port-numbers.xhtml", EditingHelp{Purpose: "Choose the Subscription HTTPS TCP port.", Instructions: []string{"Keep the default if available."}, AcceptedFormat: "Decimal integer from 1 to 65535.", CommonMistakes: []string{"No text, sign, space, or zero."}, Recovery: "Use a valid Subscription HTTPS port.", Example: "10448", URL: "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml", Sensitivity: PublicInformation}},
		{"REALITY target", "REALITY target hostname", "transport.html#realityobject", EditingHelp{Purpose: "Choose the REALITY Vision HTTPS target.", Instructions: []string{"Enter an ordinary external host."}, AcceptedFormat: "Lowercase DNS hostname only.", CommonMistakes: []string{"No URL, port, or blocked host."}, Recovery: "Replace it; SBXR probes again.", Example: "target.example", URL: "https://xtls.github.io/en/config/transport.html#realityobject", Sensitivity: PublicInformation}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			review := ChangeReview{Editing: &EditingPresentation{Title: "Clean VPS installation", Field: EditingField{Identity: "guided-field", Label: test.label, Required: true}, Help: test.help}}
			for _, size := range []struct{ width, height int }{{120, 36}, {80, 24}} {
				steps := []string{"", "\x03\r"}
				if size.width == 80 {
					steps = []string{"", "\t", "\x1b[B", "\r", "", "\x03\r"}
				}
				got := runPseudoTerminalTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: &outcomeStub{reviews: []ChangeReview{review}}}, size.width, size.height, steps...)
				for _, want := range []string{strings.ToUpper(test.label) + " HELP", test.help.Purpose, test.help.Recovery, "EXAMPLE ONLY — DO NOT COPY: " + test.help.Example, test.help.Sensitivity.String(), test.urlTail, "Esc Return to field", "\x1b]8;;" + test.help.URL} {
					if !strings.Contains(got, want) {
						t.Fatalf("%dx%d Help omitted %q\n%s", size.width, size.height, want, got)
					}
				}
				requireClosedHelpHyperlinks(t, got, test.help.URL)
			}
		})
	}
}

func TestRunShowsCompleteDowngradeAndCertificateGuidanceAtExactTerminalSizes(t *testing.T) {
	tests := []struct {
		name   string
		review ChangeReview
		wants  []string
	}{
		{
			name: "downgrade",
			review: ChangeReview{Editing: &EditingPresentation{Title: "Select compatible downgrade", Field: EditingField{Identity: "release-tag", Label: "Exact immutable release tag", Required: true}, Feedback: "Enter one exact immutable release tag in vX.Y.Z form.", Help: EditingHelp{
				Purpose: "Select one older compatible SBXR release.", Instructions: []string{"Open official SBXR Releases and copy one immutable tag; SBXR refuses unproved compatibility."}, AcceptedFormat: "One exact immutable vX.Y.Z tag with no spaces or suffix.", CommonMistakes: []string{"vX.Y.Z is tutorial only; malformed, current, newer, incompatible, branch, commit, URL, or prerelease values are refused."}, Recovery: "Choose another official tag; no Plan or host change exists until compatibility passes.", Example: "vX.Y.Z", URL: "https://github.com/albertloky/SBXR/releases", Sensitivity: PublicInformation,
			}}},
			wants: []string{"older compatible SBXR", "release.", "vX.Y.Z", "compatibility", "Field correction: Enter one exact immutable", "https://github.com/albertloky/SBXR/releases"},
		},
		{
			name: "email",
			review: ChangeReview{Editing: &EditingPresentation{Title: "Certificate issuance or renewal", Field: EditingField{Identity: "owner-email", Label: "Owner email", Required: true}, Help: EditingHelp{
				Purpose: "Supply one email to Certbot for ACME account registration.", Instructions: []string{"SBXR keeps this Personal Information in protected Desired State; Let's Encrypt ended expiration emails on June 4, 2025."}, AcceptedFormat: "One exact local-part@domain email address with no display name, spaces, or control data.", CommonMistakes: []string{"Display names, two addresses, whitespace, and typing mistakes are refused."}, Recovery: "Correct it and submit again; no certificate request or Plan exists yet.", Example: "owner@sbxr.example", URL: "https://letsencrypt.org/docs/expiration-emails/", Sensitivity: PersonalInformation,
			}}},
			wants: []string{"Personal Information", "protected Desired", "State", "ended expiration", "emails on June 4, 2025", "local-part@domain", "typing mistakes", "request or Plan exists", "https://letsencrypt.org/docs/expiration-emails/"},
		},
		{
			name: "agreement",
			review: ChangeReview{Editing: &EditingPresentation{Title: "Certificate issuance or renewal", Facts: []EditingFact{{Label: "Let's Encrypt Policy and Legal Repository", Value: "https://letsencrypt.org/repository/"}}, Field: EditingField{Identity: "subscriber-agreement", Label: "Type AGREE after reviewing the subscriber agreement", Required: true}, Help: EditingHelp{
				Purpose: "Review the current Let's Encrypt Subscriber Agreement before certificate issuance.", Instructions: []string{"Open the current Policy and Legal Repository and read the current Subscriber Agreement.", "Opening Help does not accept the agreement, authorize issuance, or approve a Plan."}, AcceptedFormat: "Exact uppercase AGREE after review.", CommonMistakes: []string{"Lowercase, added spaces, and any other text are refused."}, Recovery: "Review the current agreement, then type AGREE; use Back if you do not agree.", Example: "AGREE only after review", URL: "https://letsencrypt.org/repository/", Sensitivity: PublicInformation,
			}}},
			wants: []string{"Policy and Legal Repository", "Opening Help does not accept", "authorize issuance", "approve a Plan.", "Exact uppercase AGREE", "https://letsencrypt.org/repository/"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, size := range []struct{ width, height int }{{120, 36}, {80, 24}} {
				steps := []string{"", "\x03\r"}
				if size.width == 80 {
					steps = []string{"", "\t", "\x1b[B", "\r", "", "\x03\r"}
				}
				got := runPseudoTerminalTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: &outcomeStub{reviews: []ChangeReview{test.review}}}, size.width, size.height, steps...)
				for _, want := range test.wants {
					if !strings.Contains(got, want) {
						t.Fatalf("%dx%d guidance omitted %q\n%s", size.width, size.height, want, got)
					}
				}
				requireClosedHelpHyperlinks(t, got, test.review.Editing.Help.URL)
			}
		})
	}
}

func TestRunFieldChangeClearsEditingStateThroughThePublicOutcome(t *testing.T) {
	domain := ChangeReview{Editing: &EditingPresentation{Title: "Clean VPS installation", Field: EditingField{Identity: "domain", Label: "Domain", Required: true}, Help: EditingHelp{Purpose: "Choose the public domain.", Instructions: []string{"Enter the domain."}, AcceptedFormat: "One lowercase DNS domain.", CommonMistakes: []string{"Do not enter a URL."}, Recovery: "Correct the domain and submit it again.", Example: "vpn.example", URL: "https://developers.cloudflare.com/fundamentals/manage-domains/add-site/", Sensitivity: PublicInformation}}}
	email := ChangeReview{Editing: &EditingPresentation{Title: "Clean VPS installation", Field: EditingField{Identity: "owner-email", Label: "Owner email", Required: true}, Help: EditingHelp{Purpose: "Register the ACME account.", Instructions: []string{"Enter one email."}, AcceptedFormat: "One local-part@domain address.", CommonMistakes: []string{"Do not enter a display name."}, Recovery: "Correct the email and submit it again.", Example: "owner@sbxr.example", URL: "https://eff-certbot.readthedocs.io/en/stable/using.html#certbot-command-line-options", Sensitivity: PersonalInformation}}}
	stub := &outcomeStub{reviews: []ChangeReview{domain}, editReview: email}
	got := runPseudoTerminalTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 80, 24,
		"", "\r", "", "owner.com", "\t", "\x1b[B", "\r", "", "\x1b", "", "\r", "", "\x03", "", "\x1b", "", "owner@example.com", "\t", "\r", "", "\x03\r")
	if len(stub.edits) != 2 || stub.edits[0] != (EditingInput{Field: "domain", Text: "owner.com"}) || stub.edits[1] != (EditingInput{Field: "owner-email", Text: "owner@example.com"}) || stub.backCalls != 0 {
		t.Fatalf("field change retained input, Help selection, or correction action: edits=%+v back=%d", stub.edits, stub.backCalls)
	}
	const stale = "Required editing input is empty. Nothing was submitted."
	firstDismissal := strings.Index(got, "Stay in SBXR")
	if firstDismissal < 0 {
		t.Fatalf("first Exit confirmation was not shown\n%s", got)
	}
	redraw := got[firstDismissal+len("Stay in SBXR"):]
	if secondConfirmation := strings.LastIndex(redraw, "Exit SBXR?"); secondConfirmation >= 0 {
		redraw = redraw[:secondConfirmation]
	}
	if strings.Contains(redraw, stale) {
		t.Fatalf("field change retained stale feedback after a full public redraw\n%s", got)
	}
}

func TestRunMasksAndRevealsOnlyTheFocusedInstallationInfrastructureSecret(t *testing.T) {
	const secret = "cfat_INITIAL-SECRET-MARKER-012345678901234567890"
	help := EditingHelp{
		Purpose: "Authorize only SBXR's Cloudflare work.", Instructions: []string{"Open Manage Account > Account API Tokens; Create Token."},
		AcceptedFormat: "cfat_ plus 35 to 75 letters, digits, _ or -.", CommonMistakes: []string{"No Global API Key or broad authority."},
		Recovery: "Create the exact scoped Account API Token.", URL: "https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/", Sensitivity: InfrastructureSecret,
	}
	token := ChangeReview{Editing: &EditingPresentation{Title: "Clean VPS installation", Field: EditingField{Identity: "cloudflare-token", Label: "Cloudflare Account API Token", Required: true}, Help: help}}
	domain := ChangeReview{Editing: &EditingPresentation{Title: "Clean VPS installation", Field: EditingField{Identity: "reality-target", Label: "REALITY target hostname", Required: true}}}

	t.Run("masked by default", func(t *testing.T) {
		got := runPseudoTerminalTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: &outcomeStub{reviews: []ChangeReview{token}}}, 80, 24, "", secret, "", "\x03\r")
		if strings.Contains(got, secret) || !strings.Contains(got, "[entered]") || !strings.Contains(got, "Ctrl+R Reveal token") {
			t.Fatalf("default token frame was not masked\n%s", got)
		}
	})

	t.Run("Help is complete at exact terminal sizes", func(t *testing.T) {
		for _, size := range []struct{ width, height int }{{120, 36}, {80, 24}} {
			steps := []string{"", "\x03\r"}
			if size.width == 80 {
				steps = []string{"", "\t", "\x1b[B", "\r", "", "\x03\r"}
			}
			got := runPseudoTerminalTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: &outcomeStub{reviews: []ChangeReview{token}}}, size.width, size.height, steps...)
			for _, want := range []string{"CLOUDFLARE ACCOUNT API TOKEN HELP", "Manage Account > Account API", "Tokens;", "cfat_ plus 35 to 75", "No Global API Key", "Infrastructure Secret", "account-owned-tokens/", "Esc Return to field"} {
				if !strings.Contains(got, want) {
					t.Fatalf("%dx%d token Help omitted %q\n%s", size.width, size.height, want, got)
				}
			}
			if strings.Contains(got, "EXAMPLE ONLY") {
				t.Fatalf("%dx%d token Help exposed an example\n%s", size.width, size.height, got)
			}
			requireClosedHelpHyperlinks(t, got, help.URL)
		}
	})

	t.Run("focused reveal is deliberate", func(t *testing.T) {
		got := runPseudoTerminalTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: &outcomeStub{reviews: []ChangeReview{token}}}, 80, 24, "", secret, "\x12", "", "\x03\r")
		for _, want := range []string{secret, "TOKEN REVEALED", "screenshots and recordings can capture", "Mask "} {
			if !strings.Contains(got, want) {
				t.Fatalf("controlled Reveal omitted %q\n%s", want, got)
			}
		}
	})

	t.Run("focus loss and submission remask", func(t *testing.T) {
		stub := &outcomeStub{reviews: []ChangeReview{token}, editReview: domain}
		got := runPseudoTerminalTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 80, 24, "", secret, "\x12", "", "\t", "", "\x1b[Z", "\r", "", "\x03\r")
		if len(stub.edits) != 1 || stub.edits[0] != (EditingInput{Field: "cloudflare-token", Text: secret}) {
			t.Fatalf("secret submission = %+v", stub.edits)
		}
		if lastSecret, remasked, next := strings.LastIndex(got, secret), strings.LastIndex(got, "Ctrl+R Reveal token"), strings.LastIndex(got, "REALITY target hostname"); lastSecret < 0 || remasked < lastSecret || next < remasked {
			t.Fatalf("focus loss or screen change did not remask before the next field\n%s", got)
		}
	})

	t.Run("paste cannot reveal or activate", func(t *testing.T) {
		stub := &outcomeStub{reviews: []ChangeReview{token}}
		paste := "\x1b[200~" + secret + "\x12\nAPPLY\x1b[201~"
		got := runPseudoTerminalTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 80, 24, "", paste, "", "\x03\r")
		if strings.Contains(got, secret) || strings.Contains(got, "TOKEN REVEALED") || len(stub.edits) != 0 || len(stub.applyPlans) != 0 || stub.backCalls != 0 {
			t.Fatalf("pasted token escaped masked data input: edits=%+v apply=%+v back=%d\n%s", stub.edits, stub.applyPlans, stub.backCalls, got)
		}
	})
}

func TestRunSafeEditingFocusMatchesThePublicActionInARealPseudoTerminal(t *testing.T) {
	editing := ChangeReview{Editing: &EditingPresentation{Title: "Installation choices", Field: EditingField{Identity: "domain", Label: "Domain", Value: "owner.example.test", Required: true}}}

	t.Run("physical Enter submits the field", func(t *testing.T) {
		stub := &outcomeStub{reviews: []ChangeReview{editing}, editReview: editing}
		got := runPseudoTerminalTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 80, 24, "", "\r", "", "\x03\r")
		if len(stub.edits) != 1 || stub.edits[0] != (EditingInput{Field: "domain", Text: "owner.example.test"}) || stub.backCalls != 0 {
			t.Fatalf("text focus executed the wrong public action: edits=%+v back=%d\n%s", stub.edits, stub.backCalls, got)
		}
		if !strings.Contains(got, "> Domain:") || !strings.Contains(got, "\x1b[5 q") || !strings.Contains(got, "\x1b[8;53H") {
			t.Fatalf("text focus did not use Bubble Tea's native blinking bar cursor\n%s", got)
		}
	})

	t.Run("Space remains data and Shift Tab preserves it", func(t *testing.T) {
		stub := &outcomeStub{reviews: []ChangeReview{editing}, editReview: editing}
		_ = runPseudoTerminalTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 80, 24, "", " ", "\t", "\x1b[Z", "\r", "", "\x03\r")
		if len(stub.edits) != 1 || stub.edits[0] != (EditingInput{Field: "domain", Text: "owner.example.test "}) || stub.backCalls != 0 {
			t.Fatalf("Space or Shift+Tab changed the field action: edits=%+v back=%d", stub.edits, stub.backCalls)
		}
	})

	t.Run("visible action selection", func(t *testing.T) {
		stub := &outcomeStub{reviews: []ChangeReview{editing}, backReview: editing}
		got := runPseudoTerminalTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 80, 24, "", "\t", "", "\x1b[B", "", " ", "", "\x03\r")
		if stub.backCalls != 1 || len(stub.edits) != 0 {
			t.Fatalf("visible Back selection executed the wrong public action: edits=%+v back=%d\n%s", stub.edits, stub.backCalls, got)
		}
		for _, want := range []string{"> Review updated request", "> Back", "\x1b[1 q"} {
			if !strings.Contains(got, want) {
				t.Fatalf("action focus did not show %q\n%s", want, got)
			}
		}
		if strings.Contains(got, "> Overview") {
			t.Fatalf("persistent navigation looked selected while safe editing owned activation\n%s", got)
		}
	})

	t.Run("hostile paste remains data", func(t *testing.T) {
		stub := &outcomeStub{reviews: []ChangeReview{editing}}
		paste := "\x1b[200~\nQq\x1b[31mAPPLY\x03\x1b[201~"
		got := runPseudoTerminalTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 80, 24, "", paste, "", "\x03\r")
		if len(stub.edits) != 0 || stub.backCalls != 0 || len(stub.applyPlans) != 0 || !strings.Contains(got, "SAFE EDITING") || !strings.Contains(got, "controls neutralized") {
			t.Fatalf("hostile paste escaped text input: edits=%+v back=%d apply=%+v\n%s", stub.edits, stub.backCalls, stub.applyPlans, got)
		}
	})
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
		got := runTranscriptSteps(t, Session{Scenario: InstallationReview, Outcome: stub}, 120, 36, steps...)
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
