package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type controlledLifecycleViewer struct {
	installed, candidate softwarelifecycle.VerifiedRelease
	requests             []softwarelifecycle.ViewRequest
}

func (viewer *controlledLifecycleViewer) View(_ context.Context, request softwarelifecycle.ViewRequest) softwarelifecycle.ViewResult {
	viewer.requests = append(viewer.requests, request)
	if len(viewer.requests) == 1 {
		return softwarelifecycle.ViewResult{InstallationStatus: softwarelifecycle.NotInstalled, VerifiedCandidate: &viewer.installed}
	}
	return softwarelifecycle.ViewResult{InstallationStatus: softwarelifecycle.Managed, VerifiedCandidate: &viewer.candidate, UpdateEligible: true, PermittedActions: []softwarelifecycle.Action{softwarelifecycle.ReviewUpdate}}
}

func TestManagedSoftwareLifecyclePresentationSeparatesStagingFromDiscovery(t *testing.T) {
	installed := softwarelifecycle.VerifiedRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.4.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}, Sequence: 14, StateSchema: 2, MinimumUpdaterSchema: 1}
	candidate := softwarelifecycle.VerifiedRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.5.0", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}, Sequence: 15, StateSchema: 2, MinimumUpdaterSchema: 1}
	viewer := &controlledLifecycleViewer{installed: installed, candidate: candidate}
	release := state.ReleaseIdentity{Repository: installed.Identity.Repository, Tag: installed.Identity.Tag, Commit: installed.Identity.Commit, ReleaseIndexSHA256: installed.Identity.IndexSHA256}

	presentation, _, _, err := managedSoftwareLifecyclePresentationWith(t.Context(), release, viewer, softwarelifecycle.AMD64)
	if err != nil || presentation.Change != ownerconsole.ReviewUpdate || presentation.Candidate.Tag != candidate.Identity.Tag || len(viewer.requests) != 2 {
		t.Fatalf("presentation = %+v; requests = %+v; error = %v", presentation, viewer.requests, err)
	}
	if viewer.requests[0].Architecture != softwarelifecycle.AMD64 || viewer.requests[0].UpdateDiscovery != nil || viewer.requests[1].Architecture != "" || viewer.requests[1].UpdateDiscovery == nil {
		t.Fatalf("staging/discovery requests were mixed: %+v", viewer.requests)
	}
}

func TestManagedOwnerConsolePresentsFreshlyVerifiedUpdateWithoutApplying(t *testing.T) {
	installed := softwarelifecycle.VerifiedRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.4.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}, Sequence: 14, StateSchema: 1, MinimumUpdaterSchema: 1}
	candidate := softwarelifecycle.VerifiedRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.5.0", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}, Sequence: 15, StateSchema: 2, MinimumUpdaterSchema: 1}
	calls := 0
	outcome := &clientAccessOutcome{lifecycleLoad: func(context.Context) (softwarelifecycle.VerifiedRelease, softwarelifecycle.ViewResult, error) {
		calls++
		return installed, softwarelifecycle.ViewResult{InstallationStatus: softwarelifecycle.Managed, VerifiedCandidate: &candidate, MigrationSummary: "State schema 1 -> 2", UpdateEligible: true, PermittedActions: []softwarelifecycle.Action{softwarelifecycle.ReviewUpdate}}, nil
	}}

	got := outcome.ViewLifecycle(t.Context())
	if calls != 1 || got.Change != ownerconsole.ReviewUpdate || got.Installed.Tag != "v1.4.0" || got.Installed.Sequence != 14 || got.Candidate.Tag != "v1.5.0" || got.Candidate.Sequence != 15 || !got.FreshlyVerified || !got.CompatibleWithDesiredState || !got.DiscoveryCannotApply {
		t.Fatalf("ViewLifecycle() = %+v; calls=%d", got, calls)
	}
	if len(got.Migrations) != 1 || got.Migrations[0] != "State schema 1 -> 2" || len(got.RegeneratedRepresentations) != 7 || len(got.AffectedServices) != 4 || len(got.RequiredChecks) == 0 || len(got.AdvisoryChecks) == 0 {
		t.Fatalf("incomplete lifecycle presentation = %+v", got)
	}
}

func TestManagedDowngradeRejectsMalformedAndUnprovedTagsAtTheField(t *testing.T) {
	installed := softwarelifecycle.VerifiedRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}, Sequence: 20, StateSchema: 2, MinimumUpdaterSchema: 1}
	candidate := softwarelifecycle.VerifiedRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.9.0", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}, Sequence: 19, StateSchema: 2, MinimumUpdaterSchema: 1}
	launches := 0
	outcome := &clientAccessOutcome{
		loaded: true, presentation: clientAccessPresentation{Installation: ownerconsole.InstallationManaged, StateRevision: 7, StateSHA256: strings.Repeat("e", 64)},
		lifecycleLoad: func(context.Context) (softwarelifecycle.VerifiedRelease, softwarelifecycle.ViewResult, error) {
			return installed, softwarelifecycle.ViewResult{InstallationStatus: softwarelifecycle.Managed, VerifiedCandidate: &candidate, DowngradeCompatible: true, PermittedActions: []softwarelifecycle.Action{softwarelifecycle.ReviewDowngrade}}, nil
		},
		softwareLaunch: func(context.Context, clientAccessHandoffRequest) (*clientAccessHandoffSession, error) {
			launches++
			return nil, errors.New("controlled incompatible release")
		},
	}

	initial := outcome.ReviewLifecycleChange(t.Context(), ownerconsole.ReviewDowngrade)
	if initial.Editing == nil || initial.Editing.Help.URL != "https://github.com/albertloky/SBXR/releases" {
		t.Fatalf("initial review = %+v", initial)
	}
	malformed := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "release-tag", Text: "vX.Y.Z"})
	if malformed.Editing == nil || malformed.Editing.Field.Identity != "release-tag" || malformed.Editing.Feedback == "" || launches != 0 {
		t.Fatalf("malformed review = %+v; launches=%d", malformed, launches)
	}
	unproved := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "release-tag", Text: "v1.9.0"})
	if unproved.Editing == nil || unproved.Editing.Field.Value != "v1.9.0" || unproved.Editing.Feedback == "" || launches != 1 {
		t.Fatalf("unproved review = %+v; launches=%d", unproved, launches)
	}
}

func TestManagedCertificateInputsStayFieldLocalUntilExactAgreement(t *testing.T) {
	launches := []clientAccessHandoffRequest{}
	outcome := &clientAccessOutcome{providerLaunch: func(_ context.Context, request clientAccessHandoffRequest) (*clientAccessHandoffSession, error) {
		launches = append(launches, request)
		return &clientAccessHandoffSession{used: true, review: controlledSoftwareReview("certificate-plan-abcdef", "Exact certificate effects")}, nil
	}}
	initial := outcome.ReviewCertificateChange(t.Context(), ownerconsole.IssueIPCertificate)
	if initial.Editing == nil || initial.Editing.Help.URL != "https://letsencrypt.org/docs/expiration-emails/" || initial.Editing.Help.Sensitivity != ownerconsole.PersonalInformation {
		t.Fatalf("initial review = %+v", initial)
	}
	invalid := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "owner-email", Text: "Owner <owner@example.com>"})
	if invalid.Editing == nil || invalid.Editing.Field.Identity != "owner-email" || invalid.Editing.Feedback == "" || len(launches) != 0 {
		t.Fatalf("invalid email review = %+v", invalid)
	}
	agreement := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "owner-email", Text: "owner@example.com"})
	if agreement.Editing == nil || agreement.Editing.Field.Identity != "subscriber-agreement" || agreement.Editing.Help.URL != "https://letsencrypt.org/repository/" || len(agreement.Editing.Facts) != 1 {
		t.Fatalf("agreement review = %+v", agreement)
	}
	refused := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "subscriber-agreement", Text: "agree"})
	if refused.Editing == nil || refused.Editing.Field.Identity != "subscriber-agreement" || refused.Editing.Feedback == "" || outcome.providerAgree || len(launches) != 0 {
		t.Fatalf("refused agreement review = %+v; providerAgree=%t", refused, outcome.providerAgree)
	}
	approved := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "subscriber-agreement", Text: "AGREE"})
	if approved.Plan == nil || !outcome.providerAgree || len(launches) != 1 || !launches[0].Agreement || launches[0].OwnerEmail != "owner@example.com" {
		t.Fatalf("approved agreement review = %+v; providerAgree=%t launches=%+v", approved, outcome.providerAgree, launches)
	}
}

func TestManagedUpdateUsesReadOnlyPlanningSudoThenSeparateApplySudo(t *testing.T) {
	installed := softwarelifecycle.VerifiedRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.4.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}, Sequence: 14, StateSchema: 2, MinimumUpdaterSchema: 1}
	candidate := softwarelifecycle.VerifiedRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.5.0", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}, Sequence: 15, StateSchema: 2, MinimumUpdaterSchema: 1}
	var launches []clientAccessHandoffRequest
	outcome := &clientAccessOutcome{
		loaded: true, presentation: clientAccessPresentation{Installation: ownerconsole.InstallationManaged, StateRevision: 7, StateSHA256: strings.Repeat("e", 64)},
		lifecycleLoad: func(context.Context) (softwarelifecycle.VerifiedRelease, softwarelifecycle.ViewResult, error) {
			return installed, softwarelifecycle.ViewResult{InstallationStatus: softwarelifecycle.Managed, VerifiedCandidate: &candidate, UpdateEligible: true, PermittedActions: []softwarelifecycle.Action{softwarelifecycle.ReviewUpdate}}, nil
		},
		softwareLaunch: func(_ context.Context, request clientAccessHandoffRequest) (*clientAccessHandoffSession, error) {
			launches = append(launches, request)
			if request.Mode == "software-review" {
				review := controlledSoftwareReview("update-plan-abcdef123456", "Exact update effects")
				review.CandidateTag, review.CandidateCommit, review.CandidateIndexSHA256 = candidate.Identity.Tag, candidate.Identity.Commit, candidate.Identity.IndexSHA256
				return &clientAccessHandoffSession{used: true, review: review}, nil
			}
			return nil, errors.New("controlled apply sudo boundary")
		},
	}
	review := outcome.ReviewLifecycleChange(t.Context(), ownerconsole.ReviewUpdate)
	if review.Plan == nil || len(launches) != 1 || launches[0].Mode != "software-review" || launches[0].ReviewedPlanIdentity != "" || review.Plan.Effects[0] != "Exact update effects" {
		t.Fatalf("review = %+v; sudo launches = %+v", review, launches)
	}
	result := outcome.Apply(t.Context(), review.Plan.Identity)
	if len(launches) != 2 || launches[1].Mode != "software-apply" || launches[1].ReviewedPlanIdentity != string(review.Plan.Identity) || result.Kind != ownerconsole.ChangePlanRejected {
		t.Fatalf("Apply = %+v; sudo launches = %+v", result, launches)
	}
}

func TestManagedRepairUsesReadOnlyPlanningSudoThenSeparateApplySudo(t *testing.T) {
	inspection, err := systemchanges.CurrentStateDriftObservation(systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: strings.Repeat("e", 64)}, "change-0006", strings.Repeat("f", 64), 1)
	if err != nil {
		t.Fatal(err)
	}
	var launches []clientAccessHandoffRequest
	outcome := &clientAccessOutcome{loaded: true, presentation: clientAccessPresentation{Installation: ownerconsole.InstallationManaged, StateRevision: 7, StateSHA256: strings.Repeat("e", 64), Repair: inspection}, softwareLaunch: func(_ context.Context, request clientAccessHandoffRequest) (*clientAccessHandoffSession, error) {
		launches = append(launches, request)
		if request.Mode == "software-review" {
			return &clientAccessHandoffSession{used: true, review: controlledSoftwareReview("repair-plan-abcdef123456", "Owning Module: Subscription Publication")}, nil
		}
		return nil, errors.New("controlled apply sudo boundary")
	}}
	review := outcome.ReviewCurrentStateRepair(t.Context())
	if review.Plan == nil || len(launches) != 1 || launches[0].Mode != "software-review" || review.Plan.Effects[0] != "Owning Module: Subscription Publication" {
		t.Fatalf("repair review = %+v; sudo launches = %+v", review, launches)
	}
	result := outcome.Apply(t.Context(), review.Plan.Identity)
	if len(launches) != 2 || launches[1].Mode != "software-apply" || launches[1].ReviewedPlanIdentity != string(review.Plan.Identity) || result.Kind != ownerconsole.ChangePlanRejected {
		t.Fatalf("repair Apply = %+v; sudo launches = %+v", result, launches)
	}
}

func controlledSoftwareReview(identity, effect string) clientAccessHandoffReview {
	review := clientAccessHandoffReview{Identity: identity, SHA256: strings.Repeat("1", 64), DesiredStateSHA256: strings.Repeat("e", 64), VolatileSHA256: strings.Repeat("f", 64), StartingRevision: 7, CandidateRevision: 8, TotalSteps: 2}
	review.Plan = ownerconsole.PlanPresentation{Identity: ownerconsole.PlanIdentity(identity), DesiredStateRevision: 8, DesiredStateSHA256: strings.Repeat("e", 64), RelevantChecksums: []string{"Plan SHA-256 " + review.SHA256, "Volatile SHA-256 " + review.VolatileSHA256}, ObservedState: "Managed revision 7", VerifiedExternalInputs: []string{"Exact controlled inputs"}, Effects: []string{effect}, RequiredChecks: []string{"Exact controlled check"}, Interruption: "Controlled interruption", Cancellation: "Controlled cancellation", Rollback: "Controlled rollback"}
	return review
}

func TestComposedSoftwareApplyCarriesCancellationAndRestartIdentity(t *testing.T) {
	descriptors, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent, child := os.NewFile(uintptr(descriptors[0]), "parent"), os.NewFile(uintptr(descriptors[1]), "child")
	defer parent.Close()
	done := make(chan error, 1)
	go func() {
		done <- serveSoftwareApply(child, func(cancellation *systemchanges.Cancellation) systemchanges.ApplyResult {
			for !cancellation.Requested() {
			}
			return systemchanges.ApplyResult{Outcome: systemchanges.RollbackSucceeded, RestoredStatus: systemchanges.Managed}
		})
	}()
	if _, err := parent.Write([]byte("CANCEL\n")); err != nil {
		t.Fatal(err)
	}
	terminal := []byte{0}
	if _, err := io.ReadFull(parent, terminal); err != nil || terminal[0] != 'R' || <-done != nil {
		t.Fatalf("cancelled terminal = %q, %v", terminal, err)
	}
	starting := systemchanges.ReleaseBinding{Repository: softwarelifecycle.Repository, Tag: "v1.4.0", Commit: strings.Repeat("a", 40), ReleaseIndexSHA256: strings.Repeat("b", 64)}
	candidate := systemchanges.ReleaseBinding{Repository: softwarelifecycle.Repository, Tag: "v1.5.0", Commit: strings.Repeat("c", 40), ReleaseIndexSHA256: strings.Repeat("d", 64)}
	if _, err := recoverySoftwareUpdater(systemchanges.PendingChangeSet{StartingRelease: starting, CandidateRelease: candidate}); err != nil {
		t.Fatalf("transaction-scoped restart identity refused: %v", err)
	}
}
