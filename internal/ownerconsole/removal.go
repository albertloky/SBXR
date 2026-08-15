// Package ownerconsole owns the two distinct Owner acts that authorize Complete removal.
package ownerconsole

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
)

const completeRemovalPhrase = "COMPLETE REMOVAL"

type CompleteRemovalModule interface {
	ViewCompleteRemoval(context.Context) CompleteRemovalPresentation
	WatchCompleteRemoval(context.Context) <-chan CompleteRemovalPresentation
	CheckCompleteRemoval(context.Context, OperationIdentity) CompleteRemovalPresentation
	ReviewCompleteRemoval(context.Context, CompleteRemovalApproval) ChangeReview
	CancelCompleteRemoval(context.Context, OperationIdentity) CompleteRemovalPresentation
}

type CompleteRemovalKind uint8

const (
	CompleteRemovalReviewAvailable CompleteRemovalKind = iota + 1
	CompleteRemovalRollbackCapable
	CompleteRemovalCancelled
	CompleteRemovalForwardOnly
	CompleteRemovalSucceeded
)

type CompleteRemovalCheckpoint uint8

const (
	RemovalBeforeIrreversibleCheckpoint CompleteRemovalCheckpoint = iota + 1
	RemovalIrreversibleStarted
	RemovalProvenComplete
)

type CompleteRemovalTokenPhase uint8

const (
	RemovalTokenAvailable CompleteRemovalTokenPhase = iota + 1
	RemovalProviderDeletionInProgress
	RemovalTokenAwaitingOwnerRevocation
	RemovalTokenRevocationVerified
	RemovalLocalTokenDeleted
)

type CompleteRemovalProgress struct {
	OperationID                OperationIdentity
	CompletedSteps, TotalSteps uint16
}

type CompleteRemovalCancellationProof uint8

const (
	RemovalRestoredExactStart CompleteRemovalCancellationProof = iota + 1
	RemovalRestoredProvenManagedBaseline
)

type CompleteRemovalPresentation struct {
	Kind                      CompleteRemovalKind
	StartingStatus            InstallationStatus
	FinalStatus               InstallationStatus
	StartingRevision          uint64
	RestoredStatus            InstallationStatus
	RestoredRevision          uint64
	CancellationProof         CompleteRemovalCancellationProof
	Progress                  CompleteRemovalProgress
	Checkpoint                CompleteRemovalCheckpoint
	TokenPhase                CompleteRemovalTokenPhase
	ManagementTokenRevocation CloudflareExternalGuidance
	NoRecoveryMaterial        bool
	ConfirmationHelp          ConfirmationHelp
}

// CompleteRemovalApproval can only be formed after the two separate controls
// in Run have accepted the exact phrase and explicit permanent action.
type CompleteRemovalApproval struct{ approved bool }

func (approval CompleteRemovalApproval) OwnerConsoleCompleteRemovalApproval() bool {
	return approval.approved
}

type completeRemovalAction uint8

const (
	completeRemovalLocked completeRemovalAction = iota + 1
	completeRemovalReview
	completeRemovalCancel
	completeRemovalCheckAgain
	completeRemovalBack
)

type completeRemovalActionDefinition struct {
	action completeRemovalAction
	label  string
}

type completeRemovalDefinition struct {
	scenario                     Scenario
	title                        string
	acceptsInput, watchesUpdates bool
	header                       func(CompleteRemovalPresentation) string
	valid                        func(CompleteRemovalPresentation) bool
	lines                        func(CompleteRemovalPresentation, string) []string
	actions                      func(string) []completeRemovalActionDefinition
}

var completeRemovalDefinitions = [...]completeRemovalDefinition{
	CompleteRemovalReviewAvailable: {
		scenario:     CompleteRemovalConfirmation,
		title:        "COMPLETE REMOVAL - PERMANENT",
		acceptsInput: true,
		header:       func(p CompleteRemovalPresentation) string { return p.StartingStatus.String() + " - authenticated" },
		valid: func(p CompleteRemovalPresentation) bool {
			return validRemovalStart(p) && emptyRemovalProgress(p) && p.FinalStatus == 0 && p.RestoredStatus == 0 && p.RestoredRevision == 0 && p.CancellationProof == 0 && p.Checkpoint == RemovalBeforeIrreversibleCheckpoint && p.TokenPhase == RemovalTokenAvailable && emptyCloudflareExternalGuidance(p.ManagementTokenRevocation) && !p.NoRecoveryMaterial
		},
		lines: func(p CompleteRemovalPresentation, input string) []string {
			return []string{
				"STARTING STATUS - " + p.StartingStatus.String(),
				"",
				"OWNED LOCAL CATEGORIES",
				"Desired State", "Client Access Values", "Infrastructure Secrets", "certificates and ACME material",
				"transaction journal", "Rollback Snapshot", "installed release", "verified update candidate",
				"services and timers", "service identities", "prepared artifacts", "Subscription Publication artifacts",
				"SBXR-owned firewall table", "public listeners", "public services", "removal journal", "recovery runner",
				"The removal journal and recovery runner are deleted last.",
				"",
				"OWNED CLOUDFLARE CATEGORIES",
				"DNS records", "Tunnel routes", "Tunnel",
				"",
				"IRREVERSIBLE EXTERNAL REMNANTS",
				"Certificate Transparency entries cannot be erased", "DNS caches cannot be erased",
				"Copied client configurations may remain on client devices.",
				"A virtual VPS cannot promise physical secure erasure.",
				"",
				"Albert revokes the scoped Cloudflare token only after owned remote cleanup is verified.",
				"SBXR then verifies revocation before deleting its local token copy.",
				"",
				"Before Irreversible removal started: Back or Cancel restores the exact proven starting status.",
				"Before that checkpoint, SBXR removes public exposure and Tunnel routes but retains DNS records and the Tunnel.",
				"After Irreversible removal started: removal is forward-only and restoration becomes impossible.",
				"Only after that checkpoint does SBXR permanently delete the exact DNS records and Tunnel.",
				"Back and Cancel are unavailable after that durable checkpoint.",
				"",
				"Type exactly: COMPLETE REMOVAL",
				"> " + removalInput(input),
				"H Help for COMPLETE REMOVAL",
				"",
			}
		},
		actions: func(input string) []completeRemovalActionDefinition {
			action := completeRemovalActionDefinition{action: completeRemovalLocked, label: "Permanently remove SBXR  [locked]"}
			if input == completeRemovalPhrase {
				action = completeRemovalActionDefinition{action: completeRemovalReview, label: "Permanently remove SBXR"}
			}
			return []completeRemovalActionDefinition{action, {action: completeRemovalBack, label: "Back"}}
		},
	},
	CompleteRemovalRollbackCapable: {
		scenario: CompleteRemovalConfirmation,
		title:    "COMPLETE REMOVAL - ROLLBACK AVAILABLE",
		header: func(CompleteRemovalPresentation) string {
			return "Change in progress - rollback available - authenticated"
		},
		valid: func(p CompleteRemovalPresentation) bool {
			return validRemovalStart(p) && validRemovalProgress(p.Progress) && p.FinalStatus == 0 && p.RestoredStatus == 0 && p.RestoredRevision == 0 && p.CancellationProof == 0 && p.Checkpoint == RemovalBeforeIrreversibleCheckpoint && p.TokenPhase == RemovalTokenAvailable && emptyCloudflareExternalGuidance(p.ManagementTokenRevocation) && !p.NoRecoveryMaterial
		},
		lines: func(p CompleteRemovalPresentation, _ string) []string {
			return []string{
				"ROLLBACK-CAPABLE COMPLETE REMOVAL",
				"Starting status - " + p.StartingStatus.String(),
				fmt.Sprintf("Durable progress - %d of %d steps", p.Progress.CompletedSteps, p.Progress.TotalSteps),
				"",
				"Irreversible removal started has not been recorded.",
				"The active Cloudflare token remains available for exact rollback.",
				"Cancel returns to the exact proven starting status.",
				"",
			}
		},
		actions: func(string) []completeRemovalActionDefinition {
			return []completeRemovalActionDefinition{{action: completeRemovalCancel, label: "Cancel Complete removal"}, {action: completeRemovalBack, label: "Back"}}
		},
	},
	CompleteRemovalCancelled: {
		scenario: CompleteRemovalConfirmation,
		title:    "COMPLETE REMOVAL - CANCELLED",
		header:   func(p CompleteRemovalPresentation) string { return p.StartingStatus.String() + " - authenticated" },
		valid: func(p CompleteRemovalPresentation) bool {
			exact := p.CancellationProof == RemovalRestoredExactStart && p.RestoredStatus == p.StartingStatus && p.RestoredRevision == p.StartingRevision
			managedBaseline := p.StartingStatus == InstallationRecoveryRequired && p.CancellationProof == RemovalRestoredProvenManagedBaseline && p.RestoredStatus == InstallationManaged && p.RestoredRevision > 0
			return validRemovalStart(p) && emptyRemovalProgress(p) && p.FinalStatus == 0 && (exact || managedBaseline) && p.Checkpoint == RemovalBeforeIrreversibleCheckpoint && p.TokenPhase == RemovalTokenAvailable && emptyCloudflareExternalGuidance(p.ManagementTokenRevocation) && !p.NoRecoveryMaterial
		},
		lines: func(p CompleteRemovalPresentation, _ string) []string {
			return []string{
				"Cancellation completed.",
				"Starting status - " + p.StartingStatus.String(),
				"Proven restored status - " + p.RestoredStatus.String(),
				"No irreversible removal checkpoint was crossed.",
				"",
			}
		},
		actions: func(string) []completeRemovalActionDefinition {
			return []completeRemovalActionDefinition{{action: completeRemovalBack, label: "Back"}}
		},
	},
	CompleteRemovalForwardOnly: {
		scenario:       ForwardOnlyRemoval,
		title:          "IRREVERSIBLE REMOVAL STARTED",
		watchesUpdates: true,
		header:         func(CompleteRemovalPresentation) string { return "Change in progress - forward-only - authenticated" },
		valid: func(p CompleteRemovalPresentation) bool {
			guidanceValid := emptyCloudflareExternalGuidance(p.ManagementTokenRevocation)
			if p.TokenPhase == RemovalTokenAwaitingOwnerRevocation {
				guidanceValid = validCloudflareExternalGuidance(p.ManagementTokenRevocation, "https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/")
			}
			return validRemovalStart(p) && validRemovalProgress(p.Progress) && p.FinalStatus == 0 && p.RestoredStatus == 0 && p.RestoredRevision == 0 && p.CancellationProof == 0 && p.Checkpoint == RemovalIrreversibleStarted && p.TokenPhase >= RemovalProviderDeletionInProgress && p.TokenPhase <= RemovalLocalTokenDeleted && guidanceValid && !p.NoRecoveryMaterial
		},
		lines: func(p CompleteRemovalPresentation, _ string) []string {
			lines := []string{
				"FORWARD-ONLY COMPLETE REMOVAL",
				"Irreversible removal started - durable",
				fmt.Sprintf("Durable progress - %d of %d steps", p.Progress.CompletedSteps, p.Progress.TotalSteps),
				"Restart continues the exact next durable deletion.",
				"Back, Cancel, rollback, and restore are unavailable.",
				"",
			}
			if p.TokenPhase == RemovalProviderDeletionInProgress {
				lines = append(lines,
					"SBXR is deleting and verifying the exact owned DNS records and Tunnel.",
					"Do not revoke the scoped Cloudflare token yet.",
				)
			} else if p.TokenPhase == RemovalTokenAwaitingOwnerRevocation {
				lines = append(lines, "ALBERT'S EXACT REVOCATION STEP")
				lines = append(lines, p.ManagementTokenRevocation.Instructions[:]...)
				lines = append(lines, terminalHyperlinkLines(p.ManagementTokenRevocation.HelpURL, 58)...)
				lines = append(lines, "SBXR will verify token rejection, then delete the local token copy.")
			} else {
				lines = append(lines, "Cloudflare token revocation - verified", "Local token deletion - "+removalProofStatus(p.TokenPhase == RemovalLocalTokenDeleted))
			}
			return lines
		},
		actions: func(string) []completeRemovalActionDefinition { return nil },
	},
	CompleteRemovalSucceeded: {
		scenario: ForwardOnlyRemoval,
		title:    "COMPLETE REMOVAL - PROVEN COMPLETE",
		header:   func(CompleteRemovalPresentation) string { return "Not installed - authenticated" },
		valid: func(p CompleteRemovalPresentation) bool {
			return validRemovalStart(p) && p.FinalStatus == InstallationNotInstalled && p.RestoredStatus == 0 && p.RestoredRevision == 0 && p.CancellationProof == 0 && validRemovalProgress(p.Progress) && p.Progress.CompletedSteps == p.Progress.TotalSteps && p.Checkpoint == RemovalProvenComplete && p.TokenPhase == RemovalLocalTokenDeleted && emptyCloudflareExternalGuidance(p.ManagementTokenRevocation) && p.NoRecoveryMaterial
		},
		lines: func(p CompleteRemovalPresentation, _ string) []string {
			return []string{
				"PROVEN NOT INSTALLED",
				"Starting status - " + p.StartingStatus.String(),
				"All owned local and Cloudflare resources are proven absent.",
				"Not installed with no SBXR recovery material.",
				"Certificate Transparency entries cannot be erased.",
				"DNS caches cannot be erased.",
				"No post-Complete restore path exists.",
				"",
			}
		},
		actions: func(string) []completeRemovalActionDefinition { return nil },
	},
}

func completeRemovalDefinitionFor(kind CompleteRemovalKind) (completeRemovalDefinition, bool) {
	if int(kind) >= len(completeRemovalDefinitions) || kind == 0 {
		return completeRemovalDefinition{}, false
	}
	definition := completeRemovalDefinitions[kind]
	return definition, definition.header != nil && definition.valid != nil && definition.lines != nil && definition.actions != nil
}

func completeRemovalWatchesUpdates(presentation CompleteRemovalPresentation) bool {
	definition, valid := completeRemovalDefinitionFor(presentation.Kind)
	return valid && definition.watchesUpdates && presentation.TokenPhase != RemovalTokenAwaitingOwnerRevocation
}

func validRemovalStart(p CompleteRemovalPresentation) bool {
	return p.StartingStatus == InstallationManaged && p.StartingRevision > 0 || p.StartingStatus == InstallationRecoveryRequired
}

func validRemovalProgress(progress CompleteRemovalProgress) bool {
	return safeIdentifier(string(progress.OperationID)) && safeLine(string(progress.OperationID)) && progress.TotalSteps > 0 && progress.CompletedSteps <= progress.TotalSteps
}

func emptyRemovalProgress(p CompleteRemovalPresentation) bool {
	return p.Progress == (CompleteRemovalProgress{})
}

func validatedCompleteRemoval(presentation CompleteRemovalPresentation) (CompleteRemovalPresentation, bool) {
	definition, valid := completeRemovalDefinitionFor(presentation.Kind)
	helpRequired := presentation.Kind == CompleteRemovalReviewAvailable
	helpValid := helpRequired && validConfirmationHelp(presentation.ConfirmationHelp) || !helpRequired && emptyConfirmationHelp(presentation.ConfirmationHelp)
	presentation.ConfirmationHelp.Lines = append([]string(nil), presentation.ConfirmationHelp.Lines...)
	return presentation, valid && helpValid && definition.valid(presentation)
}

func validCompleteRemovalCancellation(prior, result CompleteRemovalPresentation) bool {
	if result.Kind != CompleteRemovalCancelled || result.StartingStatus != prior.StartingStatus || result.StartingRevision != prior.StartingRevision {
		return false
	}
	if result.CancellationProof == RemovalRestoredExactStart {
		return result.RestoredStatus == prior.StartingStatus && result.RestoredRevision == prior.StartingRevision
	}
	return prior.StartingStatus == InstallationRecoveryRequired && result.CancellationProof == RemovalRestoredProvenManagedBaseline && result.RestoredStatus == InstallationManaged && result.RestoredRevision > 0
}

func validCompleteRemovalTransition(prior, next CompleteRemovalPresentation) bool {
	if prior.Kind != CompleteRemovalForwardOnly || next.StartingStatus != prior.StartingStatus || next.StartingRevision != prior.StartingRevision || next.Progress.OperationID != prior.Progress.OperationID || next.Progress.TotalSteps != prior.Progress.TotalSteps || next.Progress.CompletedSteps < prior.Progress.CompletedSteps {
		return false
	}
	if next.Kind == CompleteRemovalForwardOnly {
		return next.Checkpoint == prior.Checkpoint && next.TokenPhase >= prior.TokenPhase
	}
	return next.Kind == CompleteRemovalSucceeded && next.Progress.CompletedSteps == next.Progress.TotalSteps
}

func completeRemovalActions(presentation CompleteRemovalPresentation, input string) []completeRemovalActionDefinition {
	definition, valid := completeRemovalDefinitionFor(presentation.Kind)
	if !valid {
		return []completeRemovalActionDefinition{{action: completeRemovalBack, label: "Back"}}
	}
	actions := definition.actions(input)
	if presentation.Kind == CompleteRemovalForwardOnly && presentation.TokenPhase == RemovalTokenAwaitingOwnerRevocation {
		return []completeRemovalActionDefinition{{action: completeRemovalCheckAgain, label: "Check again"}}
	}
	return actions
}

func completeRemovalLines(presentation CompleteRemovalPresentation, valid bool, input string, selected int) []string {
	definition, defined := completeRemovalDefinitionFor(presentation.Kind)
	if !valid || !defined {
		return []string{"Complete removal facts are unavailable.", "", "No status, checkpoint, progress, or destructive action was inferred.", "", "> Back"}
	}
	lines := definition.lines(presentation, input)
	actions := completeRemovalActions(presentation, input)
	labels := make([]string, len(actions))
	for index, action := range actions {
		labels[index] = action.label
	}
	return append(lines, selectedLines(labels, selected)...)
}

func removalInput(input string) string {
	if input == "" {
		return "-"
	}
	return fmt.Sprintf("%q", input)
}

func removalProofStatus(value bool) string {
	if value {
		return "verified"
	}
	return "pending"
}

var removalCategories = []string{
	"desired-state",
	"client-access-values",
	"infrastructure-secrets",
	"certificates-and-acme",
	"transaction-journal",
	"rollback-snapshot",
	"installed-release",
	"verified-update-candidate",
	"services-and-timers",
	"service-identities",
	"prepared-artifacts",
	"subscription-artifacts",
	"firewall-table",
	"public-listener",
	"public-service",
	"removal-journal",
	"recovery-runner",
	"cloudflare-dns-record",
	"cloudflare-route",
	"cloudflare-tunnel",
	"certificate-transparency-remnant",
	"dns-cache-remnant",
}

func CompleteRemovalCategories() []string {
	return append([]string(nil), removalCategories...)
}

type RemovalObserver interface {
	ReviewedCategories(reviewID string) ([]string, error)
	TypedPhrase(reviewID string) (phrase string, typedInteractively bool, err error)
	PermanentRemovalSelected(reviewID string) (bool, error)
}

type Interface struct{ observer RemovalObserver }

func New(observer RemovalObserver) Interface { return Interface{observer: observer} }

// RemovalReview is an opaque record that the Owner Console observed every category.
type RemovalReview struct {
	identity   string
	categories []string
}

// TypedRemovalConfirmation and PermanentRemovalSelection are separate opaque authorities.
type typedRemovalConfirmationCell struct {
	review, phrase string
	selected       atomic.Bool
}
type TypedRemovalConfirmation struct{ cell *typedRemovalConfirmationCell }
type PermanentRemovalSelection struct {
	review     string
	categories []string
}

func (i Interface) StartRemovalReview(identity string) (RemovalReview, error) {
	if i.observer == nil {
		return RemovalReview{}, errors.New("Owner Console removal observer unavailable")
	}
	categories, err := i.observer.ReviewedCategories(identity)
	want := append([]string(nil), removalCategories...)
	got := append([]string(nil), categories...)
	slices.Sort(want)
	slices.Sort(got)
	if err != nil || identity == "" || !slices.Equal(got, want) {
		return RemovalReview{}, errors.New("every Complete removal category must be reviewed")
	}
	return RemovalReview{identity: identity, categories: append([]string(nil), removalCategories...)}, nil
}

func (review RemovalReview) SoftwareLifecycleCompleteRemovalReview() (string, bool) {
	return review.identity, review.identity != "" && len(review.categories) == len(removalCategories)
}

func (i Interface) RecordTypedPhrase(review RemovalReview) (TypedRemovalConfirmation, error) {
	if i.observer == nil {
		return TypedRemovalConfirmation{}, errors.New("Owner Console removal observer unavailable")
	}
	phrase, typedInteractively, err := i.observer.TypedPhrase(review.identity)
	if err != nil || review.identity == "" || phrase != completeRemovalPhrase || !typedInteractively {
		return TypedRemovalConfirmation{}, errors.New("exact COMPLETE REMOVAL typing is required")
	}
	return TypedRemovalConfirmation{cell: &typedRemovalConfirmationCell{review: review.identity, phrase: phrase}}, nil
}

func (i Interface) SelectPermanentRemoval(review RemovalReview, confirmation TypedRemovalConfirmation) (PermanentRemovalSelection, error) {
	if i.observer == nil || confirmation.cell == nil || confirmation.cell.review != review.identity || confirmation.cell.phrase != completeRemovalPhrase || !confirmation.cell.selected.CompareAndSwap(false, true) {
		return PermanentRemovalSelection{}, errors.New("Owner Console removal observer unavailable")
	}
	selected, err := i.observer.PermanentRemovalSelected(review.identity)
	if err != nil || review.identity == "" || !selected {
		return PermanentRemovalSelection{}, errors.New("Complete removal review is required")
	}
	return PermanentRemovalSelection{review: review.identity, categories: append([]string(nil), removalCategories...)}, nil
}

func (confirmation TypedRemovalConfirmation) SystemChangesTypedRemovalConfirmation() (review, phrase string, valid bool) {
	if confirmation.cell == nil {
		return "", "", false
	}
	return confirmation.cell.review, confirmation.cell.phrase, confirmation.cell.review != "" && confirmation.cell.phrase == completeRemovalPhrase && confirmation.cell.selected.Load()
}

func (selection PermanentRemovalSelection) SystemChangesPermanentRemovalSelection() (review string, valid bool) {
	return selection.review, selection.review != "" && len(selection.categories) == len(removalCategories)
}
