package ownerconsole

import (
	"context"
	"fmt"
	"strings"
)

type DiagnosticsModule interface {
	ViewDiagnostics(context.Context) DiagnosticsPresentation
	CreateSupportBundle(context.Context, BundleReplacement) SupportBundleResult
}

type InstallationStatus uint8

const (
	InstallationNotInstalled InstallationStatus = iota + 1
	InstallationManaged
	InstallationChangeInProgress
	InstallationRecoveryRequired
)

func (status InstallationStatus) String() string {
	names := [...]string{"", "Not installed", "Managed", "Change in progress", "Recovery Required"}
	if int(status) >= len(names) {
		return ""
	}
	return names[status]
}

// StartupPresentation is the secret-free, authenticated classification used
// when protected State cannot be read by the public Owner Console process.
type StartupPresentation struct {
	Status   InstallationStatus
	Access   AccessPresentation
	Recovery RecoveryPresentation
}

type ModuleHealth uint8

const (
	HealthHealthy ModuleHealth = iota + 1
	HealthNeedsAttention
	HealthFailed
	HealthUnknown
)

func (status ModuleHealth) String() string {
	names := [...]string{"", "Healthy", "Needs attention", "Failed", "Unknown"}
	if int(status) >= len(names) {
		return ""
	}
	return names[status]
}

type ModuleHealthPresentation struct {
	Module, CheckedAt, Code, Explanation, NextAction string
	Status                                           ModuleHealth
}

type ServiceHealthPresentation struct {
	Service string
	Status  ModuleHealth
}

type DiagnosticsRetention struct {
	EventDays, EventMiB, BundleLimit int
}

type SupportBundlePresentation struct {
	Archive, CreatedAt string
}

type ReclamationAdvisoryPresentation struct {
	Package, Version, DeletedExecutable, HoldStatus, Code string
	NoRollback                                            bool
}

type DiagnosticsPresentation struct {
	Installation        InstallationStatus
	Modules             []ModuleHealthPresentation
	Services            []ServiceHealthPresentation
	Reclamation         []ReclamationAdvisoryPresentation
	Bundles             []SupportBundlePresentation
	Retention           DiagnosticsRetention
	ExternalCopyWarning string
}

type BundleReplacement struct{ Archive string }

type SupportBundleResult struct {
	Created, Code, ExternalCopyWarning string
	Bundles                            []SupportBundlePresentation
}

func validatedDiagnostics(presentation DiagnosticsPresentation) (DiagnosticsPresentation, bool) {
	if presentation.Installation.String() == "" || len(presentation.Modules) == 0 || len(presentation.Modules) > 16 || len(presentation.Services) == 0 || len(presentation.Services) > 32 || len(presentation.Bundles) > 3 || presentation.Retention != (DiagnosticsRetention{EventDays: 30, EventMiB: 50, BundleLimit: 3}) || presentation.ExternalCopyWarning != "A copied or moved bundle is outside SBXR retention, deletion, permission, and redaction control." {
		return DiagnosticsPresentation{}, false
	}
	seenModules := map[string]bool{}
	for _, module := range presentation.Modules {
		if module.Status.String() == "" || !safeProviderLines([]string{module.Module, module.CheckedAt, module.Code, module.Explanation, module.NextAction}, 5) || seenModules[module.Module] {
			return DiagnosticsPresentation{}, false
		}
		seenModules[module.Module] = true
	}
	seenServices := map[string]bool{}
	for _, service := range presentation.Services {
		if service.Status.String() == "" || !safeLine(service.Service) || seenServices[service.Service] {
			return DiagnosticsPresentation{}, false
		}
		seenServices[service.Service] = true
	}
	seenBundles := map[string]bool{}
	for _, bundle := range presentation.Bundles {
		if !safeProviderLines([]string{bundle.Archive, bundle.CreatedAt}, 2) || seenBundles[bundle.Archive] {
			return DiagnosticsPresentation{}, false
		}
		seenBundles[bundle.Archive] = true
	}
	for _, advisory := range presentation.Reclamation {
		if !safeProviderLines([]string{advisory.Package, advisory.Version, advisory.DeletedExecutable, advisory.HoldStatus, advisory.Code}, 5) || !advisory.NoRollback || advisory.HoldStatus != "Held" && advisory.HoldStatus != "Hold missing" && advisory.HoldStatus != "Executable returned" && advisory.HoldStatus != "Unknown" {
			return DiagnosticsPresentation{}, false
		}
	}
	presentation.Modules = append([]ModuleHealthPresentation(nil), presentation.Modules...)
	presentation.Services = append([]ServiceHealthPresentation(nil), presentation.Services...)
	presentation.Bundles = append([]SupportBundlePresentation(nil), presentation.Bundles...)
	presentation.Reclamation = append([]ReclamationAdvisoryPresentation(nil), presentation.Reclamation...)
	return presentation, true
}

type diagnosticsAction uint8

const (
	diagnosticsCheckAgain diagnosticsAction = iota + 1
	diagnosticsCreateBundle
	diagnosticsReviewReplacement
	diagnosticsBack
)

type diagnosticsActionDefinition struct {
	label       string
	action      diagnosticsAction
	replacement BundleReplacement
}

func diagnosticsActions(presentation DiagnosticsPresentation, reviewing bool) []diagnosticsActionDefinition {
	if reviewing {
		actions := make([]diagnosticsActionDefinition, 0, len(presentation.Bundles)+1)
		for _, bundle := range presentation.Bundles {
			actions = append(actions, diagnosticsActionDefinition{label: "Replace " + bundle.Archive, action: diagnosticsCreateBundle, replacement: BundleReplacement{Archive: bundle.Archive}})
		}
		return append(actions, diagnosticsActionDefinition{label: "Cancel replacement", action: diagnosticsBack})
	}
	actions := []diagnosticsActionDefinition{{label: "Check again", action: diagnosticsCheckAgain}}
	if len(presentation.Bundles) < presentation.Retention.BundleLimit {
		actions = append(actions, diagnosticsActionDefinition{label: "Create support bundle", action: diagnosticsCreateBundle})
	} else {
		actions = append(actions, diagnosticsActionDefinition{label: "Review support-bundle replacement", action: diagnosticsReviewReplacement})
	}
	return append(actions, diagnosticsActionDefinition{label: "Back", action: diagnosticsBack})
}

func diagnosticsLines(presentation DiagnosticsPresentation, valid bool, selected int, reviewing bool, result SupportBundleResult, feedback string) []string {
	if !valid {
		return []string{"Diagnostics facts are unavailable.", "", "No installation status, Module health, service state, finding, or action was inferred.", "", "> Back"}
	}
	lines := []string{"Installation status - " + presentation.Installation.String(), "", "MODULE HEALTH"}
	for _, module := range presentation.Modules {
		lines = append(lines,
			fmt.Sprintf("%s - %s", module.Module, module.Status),
			"Checked "+module.CheckedAt+" - "+module.Code,
			module.Explanation,
			"Next action: "+module.NextAction,
		)
	}
	lines = append(lines, "", "SERVICES")
	for _, service := range presentation.Services {
		lines = append(lines, fmt.Sprintf("%s - %s", service.Service, service.Status))
	}
	if len(presentation.Reclamation) > 0 {
		lines = append(lines, "", "RECLAMATION ADVISORY")
		for _, advisory := range presentation.Reclamation {
			lines = append(lines, fmt.Sprintf("%s %s - %s", advisory.Package, advisory.Version, advisory.HoldStatus), "Deleted executable - "+advisory.DeletedExecutable, "Code - "+advisory.Code, "No rollback exists; explicit or manual package repair may restore the executable.")
		}
	}
	lines = append(lines, "",
		fmt.Sprintf("Redacted events - %d days or %d MiB, oldest eligible first", presentation.Retention.EventDays, presentation.Retention.EventMiB),
		fmt.Sprintf("Retention - at most %d completed support bundles", presentation.Retention.BundleLimit),
		"External-copy warning: "+presentation.ExternalCopyWarning,
		"",
	)
	for _, bundle := range presentation.Bundles {
		lines = append(lines, "Completed bundle - "+bundle.Archive+" - "+bundle.CreatedAt)
	}
	if result.Created != "" {
		lines = append(lines, "", "Created - "+result.Created, "Result - "+result.Code, "External-copy warning: "+result.ExternalCopyWarning)
	}
	if feedback != "" {
		lines = append(lines, "", feedback)
	}
	lines = append(lines, "")
	actions := diagnosticsActions(presentation, reviewing)
	labels := make([]string, len(actions))
	for index, action := range actions {
		labels[index] = action.label
	}
	return append(lines, selectedLines(labels, selected)...)
}

func validatedSupportBundle(result SupportBundleResult, current DiagnosticsPresentation, replacement BundleReplacement) (SupportBundleResult, bool) {
	if !safeProviderLines([]string{result.Created, result.Code}, 2) || result.ExternalCopyWarning != current.ExternalCopyWarning {
		return SupportBundleResult{}, false
	}
	before := make(map[string]SupportBundlePresentation, len(current.Bundles))
	for _, bundle := range current.Bundles {
		before[bundle.Archive] = bundle
	}
	updated := current
	updated.Bundles = result.Bundles
	if _, valid := validatedDiagnostics(updated); !valid {
		return SupportBundleResult{}, false
	}
	after := make(map[string]SupportBundlePresentation, len(result.Bundles))
	for _, bundle := range result.Bundles {
		after[bundle.Archive] = bundle
	}
	if _, existed := before[result.Created]; existed {
		return SupportBundleResult{}, false
	}
	if _, created := after[result.Created]; !created {
		return SupportBundleResult{}, false
	}
	if replacement.Archive == "" {
		if len(after) != len(before)+1 {
			return SupportBundleResult{}, false
		}
	} else {
		if _, selected := before[replacement.Archive]; !selected || len(after) != len(before) {
			return SupportBundleResult{}, false
		}
		if _, retained := after[replacement.Archive]; retained {
			return SupportBundleResult{}, false
		}
	}
	for archive, bundle := range before {
		if archive == replacement.Archive {
			continue
		}
		if after[archive] != bundle {
			return SupportBundleResult{}, false
		}
	}
	result.Bundles = append([]SupportBundlePresentation(nil), result.Bundles...)
	return result, true
}

type LifecycleModule interface {
	ViewLifecycle(context.Context) LifecyclePresentation
	ReviewLifecycleChange(context.Context, LifecycleChange) ChangeReview
}

type LifecycleChange uint8

const (
	ReviewUpdate LifecycleChange = iota + 1
	ReviewDowngrade
)

func (change LifecycleChange) String() string {
	if change == ReviewUpdate {
		return "Update"
	}
	if change == ReviewDowngrade {
		return "Downgrade"
	}
	return ""
}

type ReleaseIdentityPresentation struct {
	Repository, Tag, Commit, IndexSHA256 string
	Sequence                             uint64
}

type LifecyclePresentation struct {
	Change                      LifecycleChange
	Installed, Candidate        ReleaseIdentityPresentation
	FreshlyVerified             bool
	CompatibleWithDesiredState  bool
	AuthenticatedSequence       string
	Migrations                  []string
	RegeneratedRepresentations  []string
	AffectedServices            []string
	RequiredChecks              []string
	AdvisoryChecks              []string
	Interruption                string
	Cancellation                string
	Rollback                    string
	DiscoveryCannotApply        bool
	DowngradeSelectionAvailable bool
}

func validReleaseIdentity(identity ReleaseIdentityPresentation) bool {
	return identity.Repository == "albertloky/SBXR" && safeLine(identity.Tag) && safeHex(identity.Commit, 40) && safeSHA256(identity.IndexSHA256) && identity.Sequence > 0
}

func safeHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func validatedLifecycle(p LifecyclePresentation) (LifecyclePresentation, bool) {
	if p.DowngradeSelectionAvailable && p.Change == 0 && validReleaseIdentity(p.Installed) && p.Candidate == (ReleaseIdentityPresentation{}) && !p.FreshlyVerified && !p.CompatibleWithDesiredState && p.DiscoveryCannotApply && p.AuthenticatedSequence == "" && len(p.Migrations) == 0 && len(p.RegeneratedRepresentations) == 0 && len(p.AffectedServices) == 0 && len(p.RequiredChecks) == 0 && len(p.AdvisoryChecks) == 0 && p.Interruption == "" && p.Cancellation == "" && p.Rollback == "" {
		return p, true
	}
	validDirection := p.Change == ReviewUpdate && p.Candidate.Sequence > p.Installed.Sequence || p.Change == ReviewDowngrade && p.Candidate.Sequence < p.Installed.Sequence && p.CompatibleWithDesiredState
	if !validDirection || !validReleaseIdentity(p.Installed) || !validReleaseIdentity(p.Candidate) || !p.FreshlyVerified || !p.CompatibleWithDesiredState || !p.DiscoveryCannotApply || !safeProviderLines([]string{p.AuthenticatedSequence, p.Interruption, p.Cancellation, p.Rollback}, 4) || !completeStrings(p.Migrations, 32) || !completeStrings(p.RegeneratedRepresentations, 32) || !completeStrings(p.AffectedServices, 32) || !completeStrings(p.RequiredChecks, 32) || !completeStrings(p.AdvisoryChecks, 32) {
		return LifecyclePresentation{}, false
	}
	p.Migrations = append([]string(nil), p.Migrations...)
	p.RegeneratedRepresentations = append([]string(nil), p.RegeneratedRepresentations...)
	p.AffectedServices = append([]string(nil), p.AffectedServices...)
	p.RequiredChecks = append([]string(nil), p.RequiredChecks...)
	p.AdvisoryChecks = append([]string(nil), p.AdvisoryChecks...)
	return p, true
}

func lifecycleActions(p LifecyclePresentation) []string {
	if p.Change == 0 {
		return []string{"Select compatible downgrade", "Back"}
	}
	actions := []string{"Review " + p.Change.String()}
	if p.Change != ReviewDowngrade {
		actions = append(actions, "Select compatible downgrade")
	}
	return append(actions, "Back")
}

func lifecycleLines(p LifecyclePresentation, valid bool, selected int) []string {
	if !valid {
		return []string{"Release facts are unavailable.", "", "No update, downgrade, or Apply action was inferred.", "", "> Back"}
	}
	if p.Change == 0 {
		lines := []string{"Software release review", "Installed Release Identity - " + p.Installed.Repository + " " + p.Installed.Tag, "Installed commit - " + p.Installed.Commit, "Installed index SHA-256 - " + p.Installed.IndexSHA256, fmt.Sprintf("Installed sequence - %d", p.Installed.Sequence), "", "No newer verified stable release is currently retained.", "Update discovery cannot Apply.", "A downgrade requires an exact Owner-selected immutable release tag and a fresh compatibility check.", ""}
		return append(lines, selectedLines(lifecycleActions(p), selected)...)
	}
	lines := []string{
		p.Change.String() + " review", "Installed Release Identity - " + p.Installed.Repository + " " + p.Installed.Tag, "Installed commit - " + p.Installed.Commit, "Installed index SHA-256 - " + p.Installed.IndexSHA256, fmt.Sprintf("Installed sequence - %d", p.Installed.Sequence),
		"Candidate Release Identity - " + p.Candidate.Repository + " " + p.Candidate.Tag, "Candidate commit - " + p.Candidate.Commit, "Candidate index SHA-256 - " + p.Candidate.IndexSHA256, fmt.Sprintf("Candidate sequence - %d", p.Candidate.Sequence),
		"Freshly verified - yes", "Compatible with current proven Desired State - yes", "Authenticated sequence - " + p.AuthenticatedSequence,
		"Migrations - " + strings.Join(p.Migrations, "; "), "Regenerated representations - " + strings.Join(p.RegeneratedRepresentations, "; "), "Affected services - " + strings.Join(p.AffectedServices, "; "), "Required checks - " + strings.Join(p.RequiredChecks, "; "), "Advisory checks - " + strings.Join(p.AdvisoryChecks, "; "),
		"Interruption - " + p.Interruption, "Cancellation - " + p.Cancellation, "Rollback - " + p.Rollback, "Discovery cannot Apply.", "",
	}
	return append(lines, selectedLines(lifecycleActions(p), selected)...)
}

type RecoveryModule interface {
	ViewRecovery(context.Context) RecoveryPresentation
	RetryAutomaticRollback(context.Context) DurableChangeSet
	ReviewCurrentStateRepair(context.Context) ChangeReview
}

type RecoveryKind uint8

const (
	RecoveryRollbackAvailable RecoveryKind = iota + 1
	RecoveryForwardOnly
	RecoveryCurrentStateRepairAvailable
	RecoveryRebuildRequired
)

func (kind RecoveryKind) String() string {
	names := [...]string{"", "Rollback available", "Forward-only recovery", "Current-State repair available", "Rebuild required"}
	if int(kind) >= len(names) {
		return ""
	}
	return names[kind]
}

type RecoveryPresentation struct {
	Kind                                                            RecoveryKind
	Proof                                                           RecoveryProof
	CauseCode, Explanation, ChangeSet, Material, Evidence, Guidance string
}

type RecoveryProof uint8

const (
	ProvenUnfinishedRollback RecoveryProof = iota + 1
	ProvenForwardOnlyRecovery
	ProvenCurrentState
	ProvenRebuildRequired
)

func validatedRecovery(p RecoveryPresentation) (RecoveryPresentation, bool) {
	if p.Kind.String() == "" || !safeProviderLines([]string{p.CauseCode, p.Explanation, p.Evidence, p.Guidance}, 4) || !safeOptionalLine(p.ChangeSet) || !safeOptionalLine(p.Material) {
		return RecoveryPresentation{}, false
	}
	validVariant := p.Kind == RecoveryRollbackAvailable && p.Proof == ProvenUnfinishedRollback && p.ChangeSet != "" && p.Material != "" ||
		p.Kind == RecoveryForwardOnly && p.Proof == ProvenForwardOnlyRecovery && p.ChangeSet != "" && p.Material != "" ||
		p.Kind == RecoveryCurrentStateRepairAvailable && p.Proof == ProvenCurrentState && p.ChangeSet == "" && p.Material == "" ||
		p.Kind == RecoveryRebuildRequired && p.Proof == ProvenRebuildRequired && p.ChangeSet == "" && p.Material == ""
	if !validVariant {
		return RecoveryPresentation{}, false
	}
	return p, true
}

type recoveryAction uint8

const (
	recoveryRetry recoveryAction = iota + 1
	recoveryRepair
	recoveryCopyEvidence
	recoveryDiagnostics
	recoveryCheckAgain
	recoveryRemoval
	recoveryBack
)

type recoveryActionDefinition struct {
	label  string
	action recoveryAction
}

func recoveryActions(p RecoveryPresentation, diagnostics bool) []recoveryActionDefinition {
	actions := []recoveryActionDefinition{}
	if p.Kind == RecoveryRollbackAvailable {
		actions = append(actions, recoveryActionDefinition{"Retry automatic rollback", recoveryRetry})
	}
	if p.Kind == RecoveryForwardOnly {
		actions = append(actions, recoveryActionDefinition{"Continue forward-only recovery", recoveryRetry})
	}
	if p.Kind == RecoveryCurrentStateRepairAvailable {
		actions = append(actions, recoveryActionDefinition{"Review current-State repair", recoveryRepair})
	}
	actions = append(actions,
		recoveryActionDefinition{"View safe evidence", recoveryCopyEvidence},
	)
	if diagnostics {
		actions = append(actions, recoveryActionDefinition{"Read-only diagnostics", recoveryDiagnostics})
	}
	actions = append(actions,
		recoveryActionDefinition{"Check again", recoveryCheckAgain},
		recoveryActionDefinition{"Complete removal", recoveryRemoval},
		recoveryActionDefinition{"Back", recoveryBack},
	)
	return actions
}

func recoveryLines(p RecoveryPresentation, valid bool, selected int, diagnostics bool) []string {
	if !valid {
		return []string{"Recovery facts are unavailable.", "", "No rollback, repair, or recovery action was inferred.", "", "> Back"}
	}
	status := "Recovery Required - " + p.Kind.String()
	if p.Kind == RecoveryCurrentStateRepairAvailable {
		status = "Managed - " + p.Kind.String()
	}
	lines := []string{status, "Cause - " + p.CauseCode, p.Explanation}
	if p.ChangeSet != "" {
		lines = append(lines, "Unfinished Change Set - "+p.ChangeSet)
	}
	if p.Material != "" {
		lines = append(lines, "Recovery material - "+p.Material)
	}
	lines = append(lines, "Safe evidence - "+p.Evidence, "Guidance - "+p.Guidance)
	if p.Kind == RecoveryRebuildRequired {
		lines = append(lines, "Retry automatic rollback is intentionally absent.")
	}
	lines = append(lines, "")
	actions := recoveryActions(p, diagnostics)
	labels := make([]string, len(actions))
	for i, action := range actions {
		labels[i] = action.label
	}
	return append(lines, selectedLines(labels, selected)...)
}
