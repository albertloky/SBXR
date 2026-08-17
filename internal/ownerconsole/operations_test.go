package ownerconsole

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

type diagnosticsStub struct {
	view     DiagnosticsPresentation
	result   SupportBundleResult
	requests []BundleReplacement
	delay    time.Duration
}

type lifecycleStub struct {
	view     LifecyclePresentation
	reviews  map[LifecycleChange]ChangeReview
	requests []LifecycleChange
	delay    time.Duration
}

type recoveryStub struct {
	view          RecoveryPresentation
	retryResult   DurableChangeSet
	repairReview  ChangeReview
	retries       int
	repairReviews int
	delay         time.Duration
	retryContext  context.Context
}

func (stub *recoveryStub) ViewRecovery(context.Context) RecoveryPresentation { return stub.view }
func (stub *recoveryStub) RetryAutomaticRollback(ctx context.Context) RecoveryRetryResult {
	time.Sleep(stub.delay)
	stub.retryContext = ctx
	stub.retries++
	return RecoveryRetryResult{Change: stub.retryResult}
}
func (stub *recoveryStub) ReviewCurrentStateRepair(context.Context) ChangeReview {
	time.Sleep(stub.delay)
	stub.repairReviews++
	return stub.repairReview
}

func TestRunRecoveryRequiredOffersOnlyActionsProvenByCurrentMaterial(t *testing.T) {
	tests := []struct {
		kind       RecoveryKind
		want       []string
		forbidden  []string
		activate   string
		wantRetry  int
		wantRepair int
	}{
		{kind: RecoveryRollbackAvailable, want: []string{"Retry automatic rollback", "unfinished-change-set", "checksum-proven", "rollback material", "CHANGE IN PROGRESS", "rollback-operation", "automatic rollback continues"}, activate: "\r", wantRetry: 1},
		{kind: RecoveryForwardOnly, want: []string{"Continue forward-only recovery", "unfinished-change-set", "forward-only material"}, forbidden: []string{"Retry automatic rollback"}, activate: "\r", wantRetry: 1},
		{kind: RecoveryCurrentStateRepairAvailable, want: []string{"Review current-State repair", "Current-State repair"}, activate: "\r", wantRepair: 1},
		{kind: RecoveryRebuildRequired, want: []string{"Complete removal", "Rebuild from scratch", "intentionally", "absent."}, forbidden: []string{"> Retry automatic rollback", "Review current-State repair"}},
	}
	for _, test := range tests {
		t.Run(test.kind.String(), func(t *testing.T) {
			presentation := RecoveryPresentation{Kind: test.kind, CauseCode: "SYS-LINEAGE-019", Explanation: "Current typed State inspection completed.", Evidence: "RECOVERY-REDACTED-EVIDENCE", Guidance: "Rebuild from scratch from a newly reviewed Desired State."}
			switch test.kind {
			case RecoveryRollbackAvailable:
				presentation.Proof, presentation.ChangeSet, presentation.Material = ProvenUnfinishedRollback, "unfinished-change-set", "valid checksum-proven rollback material"
			case RecoveryForwardOnly:
				presentation.Proof, presentation.ChangeSet, presentation.Material = ProvenForwardOnlyRecovery, "unfinished-change-set", "forward-only material"
			case RecoveryCurrentStateRepairAvailable:
				presentation.Proof = ProvenCurrentState
			case RecoveryRebuildRequired:
				presentation.Proof = ProvenRebuildRequired
			}
			stub := &recoveryStub{view: presentation, retryResult: DurableChangeSet{Kind: ChangeSetActive, OperationID: "rollback-operation", CompletedSteps: 1, TotalSteps: 3, Checkpoint: "automatic rollback", Explanation: "Rollback resumed."}, repairReview: completePlan("current-state-repair")}
			lines := recoveryLines(presentation, true, 0, true)
			steps := sectionTraversalSteps(providerPageCount(lines, len(recoveryActions(presentation, true)), 120, 36))
			if test.activate != "" {
				steps = append(steps, test.activate, "")
			}
			steps = append(steps, "\x03\r")
			scenario := RecoveryWithRollback
			if test.kind == RecoveryCurrentStateRepairAvailable {
				scenario = ManagedStateRepair
			}
			if test.kind == RecoveryRebuildRequired {
				scenario = RecoveryWithoutRecovery
			}
			got := runTranscriptSteps(t, Session{Scenario: scenario, Recovery: stub, RecoveryOutcomes: &outcomeStub{}, Diagnostics: &diagnosticsStub{view: completeDiagnostics()}}, 120, 36, steps...)
			for _, want := range append(test.want, "View safe evidence", "Read-only diagnostics", "Check again", "Complete removal") {
				if !strings.Contains(got, want) {
					t.Fatalf("recovery omitted %q\n%s", want, got)
				}
			}
			for _, forbidden := range append(test.forbidden, "Recovery Point", "> force-start", "> force-unlock", "> adopt files", "> manual completion", "> parcel") {
				if strings.Contains(got, forbidden) {
					t.Fatalf("recovery exposed forbidden %q\n%s", forbidden, got)
				}
			}
			if test.kind == RecoveryCurrentStateRepairAvailable && strings.Contains(got, "Recovery Required") {
				t.Fatalf("current-State forward repair was mislabeled Recovery Required\n%s", got)
			}
			if test.kind == RecoveryRollbackAvailable && strings.Contains(got, "UPDATE TO") {
				t.Fatalf("automatic rollback inherited an update identity\n%s", got)
			}
			if stub.retries != test.wantRetry || stub.repairReviews != test.wantRepair {
				t.Fatalf("recovery calls retry=%d repair=%d", stub.retries, stub.repairReviews)
			}
			if test.wantRetry == 1 && stub.retryContext.Done() != nil {
				t.Fatal("automatic rollback was tied to the Console context")
			}
		})
	}
}

func TestForwardFirewallRecoverySSHCorrectionHasOnlyItsLegalActions(t *testing.T) {
	base := RecoveryPresentation{Kind: RecoveryForwardOnly, Proof: ProvenForwardOnlyRecovery, CauseCode: "SYSTEM-CHANGES-UNFINISHED", Explanation: "Fresh SSH Preservation Proof is unavailable.", ChangeSet: "install-recovery-0001", Material: "checksum-protected forward recovery material", Evidence: "SSH-PRESERVATION-REDACTED", Guidance: "Check again.", SSHBlocked: true, InstallationForward: true}
	for _, test := range []struct {
		name string
		hide bool
		want []string
	}{
		{name: "temporary observation", want: []string{"Check again", "Copy redacted evidence", "Back"}},
		{name: "restart required", hide: true, want: []string{"Copy redacted evidence", "Back"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			view := base
			view.HideCheckAgain = test.hide
			validated, ok := validatedRecovery(view)
			if !ok {
				t.Fatal("SSH recovery correction was refused")
			}
			actions := recoveryActions(validated, true)
			labels := make([]string, len(actions))
			for index, action := range actions {
				labels[index] = action.label
			}
			if !reflect.DeepEqual(labels, test.want) {
				t.Fatalf("legal actions = %v, want %v", labels, test.want)
			}
		})
	}
}

func TestRunForwardOnlyRotationShowsExactHelpOnlyAfterTheCheckpoint(t *testing.T) {
	view := RecoveryPresentation{
		Kind: RecoveryForwardOnly, Proof: ProvenForwardOnlyRecovery, CauseCode: "SYSTEM-CHANGES-RUN-TOKEN-FORWARD", Explanation: "The old Tunnel run token was removed at the irreversible checkpoint.", ChangeSet: "run-token-rotation", Material: "checksum-protected forward recovery material", Evidence: "IRREVERSIBLE-RUN-TOKEN-ROTATION-STARTED", Guidance: "Follow the exact committed-Tunnel rotation Help.",
		ExternalGuidance: CloudflareExternalGuidance{Instructions: [3]string{"Open the Cloudflare dashboard > Networking > Tunnels and select the committed SBXR Tunnel.", "Select Rotate token for only that Tunnel run token, then return to SBXR forward recovery.", "Do not rotate another Tunnel or the Dedicated Broad Cloudflare User API Token."}, HelpURL: "https://developers.cloudflare.com/tunnel/advanced/tunnel-tokens/"},
	}
	steps := append(sectionTraversalSteps(providerPageCount(recoveryLines(view, true, 0, false), len(recoveryActions(view, false)), 80, 24)), "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: RecoveryWithRollback, Recovery: &recoveryStub{view: view}}, 80, 24, steps...)
	for _, want := range []string{"Networking > Tunnels", "committed SBXR Tunnel", "Select Rotate token for only that Tunnel run", "Dedicated Broad", "Cloudflare User API Token.", "developers.cloudflare.com/tunnel/advanced/tunnel-t", "okens/"} {
		if !strings.Contains(got, want) {
			t.Fatalf("forward-only rotation Help omitted %q\n%s", want, got)
		}
	}
}

func TestRecoveryViewMapsEachKindToItsExactStatusScreen(t *testing.T) {
	tests := []struct {
		kind     RecoveryKind
		proof    RecoveryProof
		scenario Scenario
	}{
		{RecoveryRollbackAvailable, ProvenUnfinishedRollback, RecoveryWithRollback},
		{RecoveryForwardOnly, ProvenForwardOnlyRecovery, RecoveryWithRollback},
		{RecoveryCurrentStateRepairAvailable, ProvenCurrentState, ManagedStateRepair},
		{RecoveryRebuildRequired, ProvenRebuildRequired, RecoveryWithoutRecovery},
	}
	for _, test := range tests {
		view := RecoveryPresentation{Kind: test.kind, Proof: test.proof, CauseCode: "SYS-LINEAGE-CHECK", Explanation: "Typed inspection.", Evidence: "REDACTED-EVIDENCE", Guidance: "Follow the exact legal action."}
		if test.kind == RecoveryRollbackAvailable || test.kind == RecoveryForwardOnly {
			view.ChangeSet, view.Material = "unfinished-change-set", "checksum-proven material"
		}
		m := model{scenario: RecoveryWithRollback, recoveryScreen: recoveryScreenState{generation: 1}, recoveryOutcomes: &outcomeStub{}}
		updated, _ := m.Update(recoveryViewMsg{generation: 1, view: view})
		if updated.(model).scenario != test.scenario {
			t.Fatalf("%s mapped to %v, want %v", test.kind, updated.(model).scenario, test.scenario)
		}
	}
}

func TestRunRetryRollbackPresentsEveryTypedDurableResult(t *testing.T) {
	view := RecoveryPresentation{Kind: RecoveryRollbackAvailable, Proof: ProvenUnfinishedRollback, CauseCode: "SYS-LINEAGE-011", Explanation: "Typed recovery inspection.", ChangeSet: "unfinished-change-set", Material: "checksum-proven material", Evidence: "RECOVERY-EVIDENCE", Guidance: "Retry exact automatic rollback."}
	for status, expected := range map[ChangeSetStatus][2]string{ChangeSetSucceeded: {"AUTOMATIC ROLLBACK - PROVEN SUCCESS", "Managed - automatic rollback succeeded"}, ChangeSetRolledBack: {"AUTOMATIC ROLLBACK - PROVEN ROLLBACK", "Managed - proven rollback"}, ChangeSetRecoveryRequired: {"AUTOMATIC ROLLBACK - RECOVERY REQUIRED", "Recovery Required - authenticated"}} {
		stub := &recoveryStub{view: view, retryResult: DurableChangeSet{Kind: status, OperationID: "rollback-result", Explanation: "Typed retry result."}}
		steps := append(sectionTraversalSteps(providerPageCount(recoveryLines(view, true, 0, false), len(recoveryActions(view, false)), 120, 36)), "\r", "", "\x03\r")
		got := runTranscriptSteps(t, Session{Scenario: RecoveryWithRollback, Recovery: stub}, 120, 36, steps...)
		if !strings.Contains(got, strings.TrimPrefix(expected[0], "AUTOMATIC ROLLBACK - ")) || !strings.Contains(got, "rollback-result") || strings.Contains(got, "UPDATE TO") {
			t.Fatalf("retry result %s was not presented truthfully\n%s", expected[0], got)
		}
		frame := (model{width: 120, height: 36, scenario: MultiStepChangeSet, changeSet: DurableChangeSet{Kind: status, OperationID: "rollback-result"}, noColor: true}).frame()
		if !strings.Contains(frame, expected[0]) || !strings.Contains(frame, expected[1]) || strings.Contains(frame, "UPDATE TO") {
			t.Fatalf("retry frame identity was not derived from %s\n%s", expected[0], frame)
		}
	}
}

func TestRunOperationsRefuseInfrastructureSecretMarkers(t *testing.T) {
	const marker = "INFRASTRUCTURE-SECRET-MARKER-COMPLETE-TOKEN"
	diagnostics := completeDiagnostics()
	diagnostics.Modules[0].Explanation = marker
	lifecycle := completeLifecycle(ReviewUpdate)
	lifecycle.Migrations[0] = marker
	recovery := RecoveryPresentation{Kind: RecoveryRebuildRequired, Proof: ProvenRebuildRequired, CauseCode: "SYS-LINEAGE-019", Explanation: "Typed inspection completed.", Evidence: marker, Guidance: "Rebuild from scratch."}
	tests := []struct {
		name        string
		session     Session
		unavailable string
	}{
		{"diagnostics", Session{Scenario: ServicesDiagnosticsScreen, Diagnostics: &diagnosticsStub{view: diagnostics}}, "Diagnostics facts are unavailable"},
		{"lifecycle", Session{Scenario: UpdateReview, Lifecycle: &lifecycleStub{view: lifecycle}}, "Release facts are unavailable"},
		{"recovery", Session{Scenario: RecoveryWithoutRecovery, Recovery: &recoveryStub{view: recovery}}, "Recovery facts are unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := runTranscriptSteps(t, test.session, 80, 24, "", "\x03\r")
			if strings.Contains(got, marker) || !strings.Contains(got, test.unavailable) {
				t.Fatalf("unsafe %s facts rendered\n%s", test.name, got)
			}
		})
	}
	clean := completeDiagnostics()
	unsafeResult := &diagnosticsStub{view: clean, result: SupportBundleResult{Created: marker, Code: "SUPPORT-BUNDLE-CREATED", ExternalCopyWarning: clean.ExternalCopyWarning}}
	steps := append(diagnosticsTraversalSteps(clean, 120, 36), "", "\x1b[B\r", "", "\r", "", "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: ServicesDiagnosticsScreen, Diagnostics: unsafeResult}, 120, 36, steps...)
	if strings.Contains(got, marker) || !strings.Contains(got, "Support bundle result is unavailable") {
		t.Fatalf("unsafe support-bundle result rendered\n%s", got)
	}
}

func (stub *lifecycleStub) ViewLifecycle(context.Context) LifecyclePresentation { return stub.view }
func (stub *lifecycleStub) ReviewLifecycleChange(_ context.Context, change LifecycleChange) ChangeReview {
	time.Sleep(stub.delay)
	stub.requests = append(stub.requests, change)
	return stub.reviews[change]
}

func TestRunLateLifecycleAndRecoveryResultsNeverStealFocus(t *testing.T) {
	lifecycle := completeLifecycle(ReviewUpdate)
	lifecycleStub := &lifecycleStub{view: lifecycle, delay: 120 * time.Millisecond, reviews: map[LifecycleChange]ChangeReview{ReviewUpdate: completePlan("LATE-LIFECYCLE-PLAN")}}
	lifecycleSteps := append(sectionTraversalSteps(providerPageCount(lifecycleLines(lifecycle, true, 0), len(lifecycleActions(lifecycle)), 120, 36)), "", "\r", "\x1b[27u", "", "\x03\r")
	lifecycleOutput := runTranscriptSteps(t, Session{Scenario: UpdateReview, Lifecycle: lifecycleStub, LifecycleOutcomes: &outcomeStub{}}, 120, 36, lifecycleSteps...)
	if strings.Contains(lifecycleOutput, "LATE-LIFECYCLE-PLAN") {
		t.Fatalf("late lifecycle result stole focus\n%s", lifecycleOutput)
	}
	if len(lifecycleStub.requests) != 1 {
		t.Fatalf("lifecycle race did not start exactly one request: %#v", lifecycleStub.requests)
	}

	recovery := RecoveryPresentation{Kind: RecoveryRollbackAvailable, Proof: ProvenUnfinishedRollback, CauseCode: "SYS-LINEAGE-011", Explanation: "Typed recovery inspection.", ChangeSet: "unfinished-change-set", Material: "checksum-proven rollback material", Evidence: "RECOVERY-EVIDENCE", Guidance: "Retry the exact automatic rollback."}
	recoveryStub := &recoveryStub{view: recovery, delay: 120 * time.Millisecond, retryResult: DurableChangeSet{Kind: ChangeSetActive, OperationID: "LATE-RECOVERY-OPERATION"}}
	recoverySteps := append(sectionTraversalSteps(providerPageCount(recoveryLines(recovery, true, 0, false), len(recoveryActions(recovery, false)), 120, 36)), "", "\r", "\x1b[27u", "", "\x03\r")
	recoveryOutput := runTranscriptSteps(t, Session{Scenario: RecoveryWithRollback, Recovery: recoveryStub}, 120, 36, recoverySteps...)
	if strings.Contains(recoveryOutput, "LATE-RECOVERY-OPERATION") {
		t.Fatalf("late recovery result stole focus\n%s", recoveryOutput)
	}
	if recoveryStub.retries != 1 {
		t.Fatalf("recovery race did not start exactly one request: %d", recoveryStub.retries)
	}
}

func TestRunReviewsExactUpdateAndCompatibleDowngradeBeforeApply(t *testing.T) {
	for _, change := range []LifecycleChange{ReviewUpdate, ReviewDowngrade} {
		presentation := completeLifecycle(change)
		review := completePlan(PlanIdentity(change.String() + "-plan"))
		stub := &lifecycleStub{view: presentation, reviews: map[LifecycleChange]ChangeReview{change: review}}
		outcomes := &outcomeStub{}
		steps := append(sectionTraversalSteps(providerPageCount(lifecycleLines(presentation, true, 0), len(lifecycleActions(presentation)), 120, 36)), "\r", "", "\x03\r")
		got := runTranscriptSteps(t, Session{Scenario: UpdateReview, Lifecycle: stub, LifecycleOutcomes: outcomes}, 120, 36, steps...)
		for _, want := range []string{"albertloky/SBXR", presentation.Installed.Commit, presentation.Candidate.Commit, "Authenticated sequence", "Migrations", "Regenerated representations", "Affected services", "Interruption", "Cancellation", "Rollback", "Discovery cannot Apply", string(review.Plan.Identity)} {
			if !strings.Contains(got, want) {
				t.Fatalf("%s journey omitted %q\n%s", change, want, got)
			}
		}
		if len(stub.requests) != 1 || stub.requests[0] != change || len(outcomes.applyPlans) != 0 {
			t.Fatalf("%s did not stop at exact review: requests=%#v applies=%#v", change, stub.requests, outcomes.applyPlans)
		}
	}
}

func TestLifecycleKeepsExplicitDowngradeSelectionWhenNoUpdateExists(t *testing.T) {
	presentation := LifecyclePresentation{Installed: completeLifecycle(ReviewUpdate).Installed, DiscoveryCannotApply: true, DowngradeSelectionAvailable: true}
	validated, ok := validatedLifecycle(presentation)
	if !ok || !reflect.DeepEqual(lifecycleActions(validated), []string{"Select compatible downgrade", "Back"}) {
		t.Fatalf("latest-release lifecycle = (%+v, %v, %#v)", validated, ok, lifecycleActions(validated))
	}
	lines := strings.Join(lifecycleLines(validated, true, 0), "\n")
	for _, want := range []string{"No newer verified stable release", "Select compatible downgrade", "exact Owner-selected immutable release tag"} {
		if !strings.Contains(lines, want) {
			t.Fatalf("latest-release lifecycle omitted %q\n%s", want, lines)
		}
	}
}

func completeLifecycle(change LifecycleChange) LifecyclePresentation {
	installed, candidate := ReleaseIdentityPresentation{Repository: "albertloky/SBXR", Tag: "v1.4.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64), Sequence: 14}, ReleaseIdentityPresentation{Repository: "albertloky/SBXR", Tag: "v1.5.0", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64), Sequence: 15}
	if change == ReviewDowngrade {
		candidate.Tag, candidate.Sequence = "v1.3.0", 13
	}
	return LifecyclePresentation{Change: change, Installed: installed, Candidate: candidate, FreshlyVerified: true, CompatibleWithDesiredState: true, AuthenticatedSequence: "download, verify, stage, switch, verify", Migrations: []string{"migrate State schema"}, RegeneratedRepresentations: []string{"subscription links"}, AffectedServices: []string{"sbxr.service"}, RequiredChecks: []string{"Release Identity verified"}, AdvisoryChecks: []string{"outside-client acceptance remains pending"}, Interruption: "brief controlled restart", Cancellation: "before durable switch", Rollback: "automatic verified rollback", DiscoveryCannotApply: true}
}

func (stub *diagnosticsStub) ViewDiagnostics(context.Context) DiagnosticsPresentation {
	return stub.view
}

func (stub *diagnosticsStub) CreateSupportBundle(_ context.Context, replacement BundleReplacement) SupportBundleResult {
	time.Sleep(stub.delay)
	stub.requests = append(stub.requests, replacement)
	return stub.result
}

func TestRunSupportBundleIsSingleFlightAndWaitsBehindExitConfirmation(t *testing.T) {
	presentation := completeDiagnostics()
	result := SupportBundleResult{Created: "bundle-new.tar.zst", Code: "SUPPORT-BUNDLE-CREATED", ExternalCopyWarning: presentation.ExternalCopyWarning, Bundles: []SupportBundlePresentation{{Archive: "bundle-new.tar.zst", CreatedAt: "2026-08-10"}}}
	stub := &diagnosticsStub{view: presentation, result: result, delay: 120 * time.Millisecond}
	steps := append(diagnosticsTraversalSteps(presentation, 120, 36), "\x1b[B\r\r\x03", "", "\x1b[27u", "", "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: ServicesDiagnosticsScreen, Diagnostics: stub}, 120, 36, steps...)
	if len(stub.requests) != 1 || !strings.Contains(got, "Creating support bundle") || !strings.Contains(got, "Exit SBXR?") || !strings.Contains(got, "bundle-new.tar.zst") {
		t.Fatalf("support bundle was duplicated, stole Exit, or lost its result: requests=%#v\n%s", stub.requests, got)
	}
	if strings.Index(got, "bundle-new.tar.zst") < strings.Index(got, "Exit SBXR?") {
		t.Fatalf("support-bundle result appeared before Exit was dismissed\n%s", got)
	}
}

func TestValidatedSupportBundleBindsTheExactReplacement(t *testing.T) {
	current := completeDiagnostics()
	current.Bundles = []SupportBundlePresentation{{Archive: "one.tar.zst", CreatedAt: "one"}, {Archive: "two.tar.zst", CreatedAt: "two"}, {Archive: "three.tar.zst", CreatedAt: "three"}}
	created := SupportBundlePresentation{Archive: "new.tar.zst", CreatedAt: "new"}
	base := SupportBundleResult{Created: created.Archive, Code: "SUPPORT-BUNDLE-CREATED", ExternalCopyWarning: current.ExternalCopyWarning}
	tests := []struct {
		name    string
		bundles []SupportBundlePresentation
		valid   bool
	}{
		{"exact replacement", []SupportBundlePresentation{created, current.Bundles[1], current.Bundles[2]}, true},
		{"wrong deletion", []SupportBundlePresentation{current.Bundles[0], created, current.Bundles[2]}, false},
		{"duplicate", []SupportBundlePresentation{created, created, current.Bundles[2]}, false},
		{"missing created", []SupportBundlePresentation{current.Bundles[1], current.Bundles[2]}, false},
		{"unrelated inventory", []SupportBundlePresentation{created, {Archive: "other.tar.zst", CreatedAt: "other"}, current.Bundles[2]}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := base
			result.Bundles = test.bundles
			_, valid := validatedSupportBundle(result, current, BundleReplacement{Archive: "one.tar.zst"})
			if valid != test.valid {
				t.Fatalf("validation = %v, want %v", valid, test.valid)
			}
		})
	}
}

func TestRunOperationsKeepFactsAndActionsReachableAtApprovedSizes(t *testing.T) {
	for _, size := range []struct{ width, height int }{{80, 24}, {120, 36}} {
		lifecycle := completeLifecycle(ReviewUpdate)
		lifecycle.Migrations = []string{strings.Repeat("reviewed migration detail ", 8)}
		lifecycleStub := &lifecycleStub{view: lifecycle, reviews: map[LifecycleChange]ChangeReview{ReviewUpdate: completePlan("update-plan")}}
		lifecycleSteps := append(sectionTraversalSteps(providerPageCount(lifecycleLines(lifecycle, true, 0), len(lifecycleActions(lifecycle)), size.width, size.height)), "\x03\r")
		lifecycleOutput := runTranscriptSteps(t, Session{Scenario: UpdateReview, Lifecycle: lifecycleStub, LifecycleOutcomes: &outcomeStub{}}, size.width, size.height, lifecycleSteps...)
		if !strings.Contains(lifecycleOutput, "Review Update") || !strings.Contains(lifecycleOutput, "Back") {
			t.Fatalf("%dx%d lifecycle actions clipped\n%s", size.width, size.height, lifecycleOutput)
		}

		recovery := RecoveryPresentation{Kind: RecoveryRebuildRequired, Proof: ProvenRebuildRequired, CauseCode: "SYS-LINEAGE-019", Explanation: strings.Repeat("Typed recovery explanation ", 8), Evidence: "RECOVERY-REDACTED-EVIDENCE", Guidance: strings.Repeat("Rebuild guidance ", 8)}
		recoveryStub := &recoveryStub{view: recovery}
		recoverySteps := append(sectionTraversalSteps(providerPageCount(recoveryLines(recovery, true, 0, false), len(recoveryActions(recovery, false)), size.width, size.height)), "\x03\r")
		recoveryOutput := runTranscriptSteps(t, Session{Scenario: RecoveryWithoutRecovery, Recovery: recoveryStub}, size.width, size.height, recoverySteps...)
		if !strings.Contains(recoveryOutput, "Complete removal") || !strings.Contains(recoveryOutput, "Back") {
			t.Fatalf("%dx%d recovery actions clipped\n%s", size.width, size.height, recoveryOutput)
		}
	}
}

func TestRunCreatesOrExplicitlyReplacesACompletedSupportBundle(t *testing.T) {
	for _, test := range []struct {
		name        string
		bundles     []SupportBundlePresentation
		replacement BundleReplacement
	}{
		{name: "below limit"},
		{name: "at limit", bundles: []SupportBundlePresentation{{Archive: "bundle-one.tar.zst", CreatedAt: "2026-08-01"}, {Archive: "bundle-two.tar.zst", CreatedAt: "2026-08-02"}, {Archive: "bundle-three.tar.zst", CreatedAt: "2026-08-03"}}, replacement: BundleReplacement{Archive: "bundle-one.tar.zst"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			presentation := completeDiagnostics()
			presentation.Bundles = test.bundles
			resultBundles := append([]SupportBundlePresentation(nil), test.bundles...)
			if test.replacement.Archive == "" {
				resultBundles = append(resultBundles, SupportBundlePresentation{Archive: "bundle-new.tar.zst", CreatedAt: "2026-08-10"})
			} else {
				resultBundles[0] = SupportBundlePresentation{Archive: "bundle-new.tar.zst", CreatedAt: "2026-08-10"}
			}
			stub := &diagnosticsStub{view: presentation, result: SupportBundleResult{Created: "bundle-new.tar.zst", Code: "SUPPORT-BUNDLE-CREATED", ExternalCopyWarning: presentation.ExternalCopyWarning, Bundles: resultBundles}}
			steps := diagnosticsTraversalSteps(presentation, 120, 36)
			steps = append(steps, "", "\x1b[B\r", "")
			if test.replacement.Archive != "" {
				steps = append(steps, "\r", "", "\r", "", "\r", "")
			}
			steps = append(steps, "\x03\r")
			got := runTranscriptSteps(t, Session{Scenario: ServicesDiagnosticsScreen, Diagnostics: stub}, 120, 36, steps...)
			for _, want := range []string{"bundle-new.tar.zst", "SUPPORT-BUNDLE-CREATED", "outside SBXR retention"} {
				if !strings.Contains(got, want) {
					t.Fatalf("support-bundle journey omitted %q\n%s", want, got)
				}
			}
			if len(stub.requests) != 1 || stub.requests[0] != test.replacement {
				t.Fatalf("support-bundle replacement = %#v, want %#v", stub.requests, test.replacement)
			}
		})
	}
}

func completeDiagnostics() DiagnosticsPresentation {
	return DiagnosticsPresentation{
		Installation:        InstallationManaged,
		Modules:             []ModuleHealthPresentation{{Module: "State", Status: HealthHealthy, CheckedAt: "2026-08-10", Code: "STATE-CHECK", Explanation: "State is proven.", NextAction: "No action required."}},
		Services:            []ServiceHealthPresentation{{Service: "sbxr.service", Status: HealthHealthy}},
		Retention:           DiagnosticsRetention{EventDays: 30, EventMiB: 50, BundleLimit: 3},
		ExternalCopyWarning: "A copied or moved bundle is outside SBXR retention, deletion, permission, and redaction control.",
	}
}

func TestRunShowsInstallationAndModuleHealthAsSeparateTypedFacts(t *testing.T) {
	statuses := []InstallationStatus{InstallationNotInstalled, InstallationManaged, InstallationChangeInProgress, InstallationRecoveryRequired}
	health := []ModuleHealth{HealthHealthy, HealthNeedsAttention, HealthFailed, HealthUnknown}
	for index, status := range statuses {
		for _, size := range []struct{ width, height int }{{80, 24}, {120, 36}} {
			t.Run(fmt.Sprintf("%s/%dx%d", status, size.width, size.height), func(t *testing.T) {
				presentation := DiagnosticsPresentation{
					Installation: status,
					Modules: []ModuleHealthPresentation{
						{Module: "State", Status: health[index], CheckedAt: "2026-08-10 09:00 UTC", Code: "STATE-LINEAGE-CHECK", Explanation: "Typed State lineage inspection completed.", NextAction: "Open the exact State correction when required."},
						{Module: "Network Policy", Status: HealthHealthy, CheckedAt: "2026-08-10 09:00 UTC", Code: "NETWORK-POLICY-CHECK", Explanation: "Typed Network Policy inspection completed.", NextAction: "No action required."},
					},
					Services:            []ServiceHealthPresentation{{Service: "xray.service", Status: HealthHealthy}, {Service: "sing-box.service", Status: HealthNeedsAttention}},
					Retention:           DiagnosticsRetention{EventDays: 30, EventMiB: 50, BundleLimit: 3},
					ExternalCopyWarning: "A copied or moved bundle is outside SBXR retention, deletion, permission, and redaction control.",
				}
				stub := &diagnosticsStub{view: presentation}
				steps := append(diagnosticsTraversalSteps(presentation, size.width, size.height), "\x03\r")
				got := runTranscriptSteps(t, Session{Scenario: ServicesDiagnosticsScreen, Diagnostics: stub}, size.width, size.height, steps...)
				for _, want := range []string{status.String(), health[index].String(), "State", "STATE-LINEAGE-CHECK", "Typed State lineage", "Open the exact State correction", "xray.service", "Needs attention", "30 days", "50 MiB", "3 completed support bundles", "copied or moved bundle"} {
					if !strings.Contains(got, want) {
						t.Fatalf("diagnostics omitted %q\n%s", want, got)
					}
				}
				for _, forbidden := range []string{"Recovery Point", "historical restore", "raw log browser", "force-start", "force-unlock"} {
					if strings.Contains(got, forbidden) {
						t.Fatalf("diagnostics exposed forbidden %q\n%s", forbidden, got)
					}
				}
			})
		}
	}
}

func diagnosticsTraversalSteps(presentation DiagnosticsPresentation, width, height int) []string {
	actions := diagnosticsActions(presentation, false)
	lines := diagnosticsLines(presentation, true, 0, false, SupportBundleResult{}, "")
	return sectionTraversalSteps(providerPageCount(lines, len(actions), width, height))
}
