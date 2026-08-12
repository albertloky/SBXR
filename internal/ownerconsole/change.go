package ownerconsole

import (
	"context"
	"fmt"
	"strings"
	"unicode"
)

// OutcomeModule is the presentation-safe seam for one consequential Owner
// request. The owning Module remains responsible for Plan and transaction logic.
type OutcomeModule interface {
	Review(context.Context) ChangeReview
	Fix(context.Context, CorrectionInput) ChangeReview
	CheckAgain(context.Context) ChangeReview
	Back(context.Context) ChangeReview
	Edit(context.Context, EditingInput) ChangeReview
	Apply(context.Context, PlanIdentity) ChangeResult
	Inspect(context.Context) DurableChangeSet
	RequestCancellation(context.Context, OperationIdentity) ChangeResult
}

type CorrectionSelection struct {
	Identity string
	Label    string
}

type CorrectionInput struct {
	Text      string
	Selection string
}

type EditingField struct {
	Identity string
	Label    string
	Value    string
	Required bool
}

type EditingInput struct {
	Field string
	Text  string
}

type correctionAction uint8

const (
	correctionFix correctionAction = iota
	correctionCheck
	correctionCopy
	correctionBack
)

type PlanIdentity string
type OperationIdentity string

type ChangeReview struct {
	Plan       *PlanPresentation
	Correction *CorrectionPresentation
	Editing    *EditingPresentation
}

type EditingPresentation struct {
	Title string
	Field EditingField
}

type PlanPresentation struct {
	Identity                             PlanIdentity
	DesiredStateRevision                 uint64
	DesiredStateSHA256                   string
	LineageUnavailable                   bool
	RelevantChecksums                    []string
	ObservedState                        string
	VerifiedExternalInputs               []string
	Effects                              []string
	RequiredChecks                       []string
	AdvisoryChecks                       []string
	Interruption, Cancellation, Rollback string
	ReclamationDigest                    string
	ReclamationConfirmed                 bool
}

type CorrectionPresentation struct {
	Problem, Found, Required, WhyStopped string
	FixWithSBXR                          bool
	OwnerSteps                           []string
	InputLabel                           string
	Selections                           []CorrectionSelection
	Evidence                             string
}

type ChangeResultKind uint8

const (
	ChangeStarted ChangeResultKind = iota + 1
	ChangePlanRejected
	ChangeCancellationRequested
	changeFactsUnavailable
)

type ChangeResult struct {
	Kind        ChangeResultKind
	OperationID OperationIdentity
	Explanation string
}

type ChangeSetStatus uint8

const (
	NoChangeSet ChangeSetStatus = iota
	ChangeSetActive
	ChangeSetSucceeded
	ChangeSetRolledBack
	ChangeSetRecoveryRequired
	changeSetFactsUnavailable
)

type DurableChangeSet struct {
	Kind                       ChangeSetStatus
	OperationID                OperationIdentity
	CompletedSteps, TotalSteps uint16
	Checkpoint, Explanation    string
}

func validatedChangeReview(review ChangeReview) ChangeReview {
	count := 0
	for _, present := range []bool{review.Plan != nil, review.Correction != nil, review.Editing != nil} {
		if present {
			count++
		}
	}
	if count != 1 {
		return invalidChangeReview()
	}
	if plan := review.Plan; plan != nil {
		lineage := safeSHA256(plan.DesiredStateSHA256) || plan.LineageUnavailable && plan.DesiredStateRevision == 0 && plan.DesiredStateSHA256 == ""
		reclamation := plan.ReclamationDigest == "" && !plan.ReclamationConfirmed || safeSHA256(plan.ReclamationDigest)
		if !safeIdentifier(string(plan.Identity)) || !lineage || !reclamation || !completeStrings(plan.RelevantChecksums, 32) || !safeLine(plan.ObservedState) || !completeStrings(plan.VerifiedExternalInputs, 32) || !completeStrings(plan.Effects, 64) || !completeStrings(plan.RequiredChecks, 64) || !completeStrings(plan.AdvisoryChecks, 64) || !safeLine(plan.Interruption) || !safeLine(plan.Cancellation) || !safeLine(plan.Rollback) {
			return invalidChangeReview()
		}
		copy := *plan
		copy.RelevantChecksums = append([]string(nil), plan.RelevantChecksums...)
		copy.VerifiedExternalInputs = append([]string(nil), plan.VerifiedExternalInputs...)
		copy.Effects = append([]string(nil), plan.Effects...)
		copy.RequiredChecks = append([]string(nil), plan.RequiredChecks...)
		copy.AdvisoryChecks = append([]string(nil), plan.AdvisoryChecks...)
		return ChangeReview{Plan: &copy}
	}
	if editing := review.Editing; editing != nil {
		if !safeLine(editing.Title) || !safeIdentifier(editing.Field.Identity) || !safeLine(editing.Field.Label) || !safeOptionalLine(editing.Field.Value) {
			return invalidChangeReview()
		}
		return ChangeReview{Editing: editing}
	}
	correction := review.Correction
	correctionRoute := correction.FixWithSBXR || len(correction.OwnerSteps) > 0
	requiredOwnerChoice := correction.InputLabel != "" || len(correction.Selections) > 0
	if !safeLine(correction.Problem) || !safeLine(correction.Found) || !safeLine(correction.Required) || !safeLine(correction.WhyStopped) || !safeStrings(correction.OwnerSteps, 32) || !safeOptionalLine(correction.InputLabel) || !safeSelections(correction.Selections) || !safeLine(correction.Evidence) || !correctionRoute || !requiredOwnerChoice {
		return invalidChangeReview()
	}
	copy := *correction
	copy.OwnerSteps = append([]string(nil), correction.OwnerSteps...)
	copy.Selections = append([]CorrectionSelection(nil), correction.Selections...)
	return ChangeReview{Correction: &copy}
}

func invalidChangeReview() ChangeReview {
	return ChangeReview{Correction: &CorrectionPresentation{Problem: "The typed outcome presentation is unavailable", Found: "missing, incomplete, or unsafe typed facts", Required: "one complete secret-safe Plan or Correction Flow", WhyStopped: "Owner Console never guesses or renders untrusted outcome data", Evidence: "OWNER-CONSOLE-TYPED-OUTCOME-REFUSED"}}
}

func validatedDurableChangeSet(change DurableChangeSet) DurableChangeSet {
	if change.Kind == NoChangeSet {
		return DurableChangeSet{}
	}
	if change.Kind < ChangeSetActive || change.Kind > ChangeSetRecoveryRequired || !safeIdentifier(string(change.OperationID)) || !safeOptionalLine(change.Checkpoint) || !safeOptionalLine(change.Explanation) || change.TotalSteps > 0 && change.CompletedSteps > change.TotalSteps {
		return DurableChangeSet{Kind: changeSetFactsUnavailable, OperationID: "unavailable-change-set", Explanation: "Durable Change Set facts are incomplete or unsafe."}
	}
	return change
}

func validatedChangeResult(result ChangeResult) ChangeResult {
	if result.Kind == changeFactsUnavailable && safeLine(result.Explanation) {
		return result
	}
	if result.Kind < ChangeStarted || result.Kind > ChangeCancellationRequested || !safeOptionalLine(result.Explanation) || result.Kind != ChangePlanRejected && !safeIdentifier(string(result.OperationID)) {
		return ChangeResult{Kind: changeFactsUnavailable, Explanation: "The owning Module returned incomplete or unsafe typed facts. No result was inferred."}
	}
	return result
}

func safeStrings(values []string, maximum int) bool {
	if len(values) > maximum {
		return false
	}
	for _, value := range values {
		if !safeLine(value) {
			return false
		}
	}
	return true
}

func completeStrings(values []string, maximum int) bool {
	return len(values) > 0 && safeStrings(values, maximum)
}

func safeSelections(values []CorrectionSelection) bool {
	if len(values) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !safeIdentifier(value.Identity) || !safeLine(value.Label) || seen[value.Identity] {
			return false
		}
		seen[value.Identity] = true
	}
	return true
}

func safeOptionalLine(value string) bool { return value == "" || safeLine(value) }

func safeLine(value string) bool {
	if value == "" || len(value) > 320 || strings.Contains(value, "INFRASTRUCTURE-SECRET-MARKER") || strings.Contains(value, "-----BEGIN ") {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func safeIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !unicode.IsLetter(character) && !unicode.IsDigit(character) && !strings.ContainsRune("_.:-", character) {
			return false
		}
	}
	return true
}

func safeSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func changeReviewLines(review ChangeReview, width, height, page int) []string {
	if plan := review.Plan; plan != nil {
		pages := minimumPlanPages(plan, width, height)
		if page >= len(pages) {
			page = len(pages) - 1
		}
		lines := append([]string{fmt.Sprintf("PLAN %d OF %d", page+1, len(pages))}, pages[page]...)
		if page+1 < len(pages) {
			return append(lines, "", "> Enter Next plan section", "  Esc Previous section or safe editing")
		}
		if plan.ReclamationDigest != "" {
			if plan.ReclamationConfirmed {
				return append(lines, "", "> Back", "  Review only - no host change was made")
			}
			return append(lines, "", "> Confirm exact reclamation review", "  Esc Back or Cancel - no host change")
		}
		return append(lines, "", "> Apply exact one-use Plan", "  Esc Previous plan section or safe editing")
	}
	if editing := review.Editing; editing != nil {
		return []string{"SAFE EDITING - " + editing.Title, "", "No Plan, Change Set, rollback material, or sudo exists.", editing.Field.Label + ": " + editing.Field.Value, "", "> Review updated request", "  Esc Back"}
	}
	correction := review.Correction
	if correction == nil {
		return []string{"Waiting for one typed outcome review."}
	}
	lines := correctionFactLines(correction)
	pages := minimumCorrectionPages(correction, width, height)
	if page >= len(pages) {
		page = len(pages) - 1
	}
	lines = append([]string{fmt.Sprintf("CORRECTION FLOW %d OF %d", page+1, len(pages))}, pages[page]...)
	if page+1 < len(pages) {
		return append(lines, "", "> Enter Next correction section", "  Esc Previous section or Back")
	}
	return lines
}

func correctionFactLines(correction *CorrectionPresentation) []string {
	lines := []string{"CORRECTION FLOW", "Problem: " + correction.Problem, "Found: " + correction.Found, "Required: " + correction.Required, "Why SBXR stopped: " + correction.WhyStopped}
	if correction.InputLabel != "" {
		lines = append(lines, correction.InputLabel+": [required text input]")
	}
	for _, selection := range correction.Selections {
		lines = append(lines, "Selection: "+selection.Label)
	}
	for _, step := range correction.OwnerSteps {
		lines = append(lines, "Owner step: "+step)
	}
	return append(lines, "Redacted evidence: "+correction.Evidence)
}

func minimumCorrectionPages(correction *CorrectionPresentation, width, height int) [][]string {
	// Reserve fixture title, page heading, four actions, and both feedback rows.
	return minimumPages(correctionFactLines(correction), width, max(1, height-17))
}

func minimumPlanPages(plan *PlanPresentation, width, height int) [][]string {
	// Reserve fixture title, page heading, the two final actions, and persistent
	// stale/reuse feedback.
	return minimumPages(planFactLines(plan), width, max(1, height-13))
}

func minimumPages(facts []string, width, factsPerPage int) [][]string {
	contentWidth := width - navigationWidth - 1
	if width >= 120 {
		contentWidth = 48
	}
	lines := wrapLines(facts, contentWidth)
	pages := make([][]string, 0, (len(lines)+factsPerPage-1)/factsPerPage)
	for len(lines) > 0 {
		count := min(factsPerPage, len(lines))
		pages = append(pages, append([]string(nil), lines[:count]...))
		lines = lines[count:]
	}
	return pages
}

func planFactLines(plan *PlanPresentation) []string {
	lines := []string{"Plan " + string(plan.Identity)}
	if plan.LineageUnavailable {
		lines = append(lines, "Desired State lineage unavailable - exact raw baseline preserved")
	} else {
		lines = append(lines, fmt.Sprintf("Desired State revision %d", plan.DesiredStateRevision), "Desired State SHA-256", plan.DesiredStateSHA256)
	}
	lines = append(lines, "Relevant checksums")
	lines = append(lines, plan.RelevantChecksums...)
	lines = append(lines, "Observed State: "+plan.ObservedState, "Verified external inputs")
	for _, value := range plan.VerifiedExternalInputs {
		lines = append(lines, "- "+value)
	}
	lines = append(lines, "Exact effects")
	for _, value := range plan.Effects {
		lines = append(lines, "- "+value)
	}
	for _, value := range plan.RequiredChecks {
		lines = append(lines, "Required - "+value)
	}
	for _, value := range plan.AdvisoryChecks {
		lines = append(lines, "Advisory - "+value)
	}
	if plan.ReclamationDigest != "" {
		lines = append(lines, "Reclamation review digest "+plan.ReclamationDigest)
		if plan.ReclamationConfirmed {
			lines = append(lines, "Reclamation review confirmed. No host change was made.")
		} else {
			lines = append(lines, "Type exactly: "+ReclamationPhrase, "> [required text input]")
		}
	}
	return append(lines, "Interruption: "+plan.Interruption, "Cancellation: "+plan.Cancellation, "Rollback: "+plan.Rollback)
}

func changeSetLines(change DurableChangeSet) []string {
	title := map[ChangeSetStatus]string{ChangeSetActive: "CHANGE IN PROGRESS", ChangeSetSucceeded: "PROVEN SUCCESS", ChangeSetRolledBack: "PROVEN ROLLBACK", ChangeSetRecoveryRequired: "RECOVERY REQUIRED", changeSetFactsUnavailable: "DURABLE FACTS UNAVAILABLE"}[change.Kind]
	lines := []string{title, "", "Operation " + string(change.OperationID)}
	if change.TotalSteps > 0 {
		lines = append(lines, fmt.Sprintf("Change Set progress %d of %d steps", change.CompletedSteps, change.TotalSteps))
	}
	if change.Checkpoint != "" {
		lines = append(lines, "Change Set checkpoint: "+change.Checkpoint)
	}
	if change.Explanation != "" {
		lines = append(lines, change.Explanation)
	}
	if change.Kind == ChangeSetActive {
		lines = append(lines, "", "> C Request cancellation", "  Close TUI - approved work continues")
	}
	return lines
}

func changeSetDetails(change DurableChangeSet) []string {
	if change.Kind == changeSetFactsUnavailable {
		return []string{"FACTS UNAVAILABLE", "", "No status, success, rollback,", "or Recovery Required was inferred."}
	}
	return []string{"DURABLE CHANGE SET FACTS", "", "No result is inferred from", "process exit or service reachability.", "", "Cancellation waits for a safe", "rollback checkpoint."}
}
