// Package healthdiagnostics assembles secret-safe typed health facts without
// inspecting or changing another Module's resources.
package healthdiagnostics

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

type InstallationStatus string

const (
	NotInstalled     InstallationStatus = "Not installed"
	Managed          InstallationStatus = "Managed"
	ChangeInProgress InstallationStatus = "Change in progress"
	RecoveryRequired InstallationStatus = "Recovery Required"
)

type RecoveryCause string

const (
	StateLineageUnprovable      RecoveryCause = "Current State lineage unprovable"
	SnapshotUnprovable          RecoveryCause = "Rollback Snapshot integrity unprovable"
	JournalUnprovable           RecoveryCause = "Recovery journal integrity unprovable"
	ForwardCheckpointUnprovable RecoveryCause = "Forward checkpoint unprovable"
	RollbackStepUnprovable      RecoveryCause = "Rollback step unprovable"
	PriorAgreementUnprovable    RecoveryCause = "Prior-State agreement unprovable"
	CurrentStateDrift           RecoveryCause = "Valid current State has drift"
	MissingSecrets              RecoveryCause = "Required secrets are missing"
	ReplacementVPS              RecoveryCause = "VPS is replaced or unavailable"
	OlderRevision               RecoveryCause = "An older completed revision was requested"
	OwnerRegret                 RecoveryCause = "Owner requested a prior configuration"
)

type HealthStatus string

const (
	Healthy        HealthStatus = "Healthy"
	NeedsAttention HealthStatus = "Needs attention"
	Failed         HealthStatus = "Failed"
	Unknown        HealthStatus = "Unknown"
)

type Role string

const (
	Required Role = "Required"
	Advisory Role = "Advisory"
)

type GateDisposition string

const (
	NotAGate                   GateDisposition = "Not a gate"
	GatePasses                 GateDisposition = "Passes"
	GateStops                  GateDisposition = "Stops"
	GateRequiresPlanDisclosure GateDisposition = "Disclose in reviewed Plan"
)

type Module string

const (
	StateModule                   Module = "State"
	NetworkPolicyModule           Module = "Network Policy"
	SystemChangesModule           Module = "System Changes"
	CloudflareTunnelModule        Module = "Cloudflare Tunnel"
	CertificateLifecycleModule    Module = "Certificate Lifecycle"
	ConnectionProfilesModule      Module = "Connection Profiles"
	SubscriptionPublicationModule Module = "Subscription Publication"
	SubscriptionServingModule     Module = "Subscription Serving"
	HealthDiagnosticsModule       Module = "Health and Diagnostics"
	SoftwareLifecycleModule       Module = "Software Lifecycle"
	OwnerConsoleModule            Module = "Owner Console"
)

type FindingCode string

type EventSeverity string
type OperationID string
type ChangeSetID string
type MutationOutcome string

// DiagnosticEvent is the Health-and-Diagnostics-owned event shape. Retention
// and construction belong to the next implementation slice.
type DiagnosticEvent struct {
	time        time.Time
	module      Module
	operation   OperationID
	changeSet   ChangeSetID
	severity    EventSeverity
	code        FindingCode
	explanation string
	outcome     MutationOutcome
}

type BundleStatus string

const (
	BundleCreated    BundleStatus = "Created"
	BundleNotCreated BundleStatus = "Not created"
)

// BundleResult is the BuildSupportBundle-owned public result. Archive
// construction and storage belong to the later bundle slice.
type BundleResult struct {
	status BundleStatus
	code   FindingCode
}

type CorrectionFlow struct {
	Problem, Found, Required, WhyStopped string
	SBXRCorrection                       string
	OwnerSteps                           []string
	CheckAgain, Back, Evidence           string
}

func (flow CorrectionFlow) Complete() bool {
	return safeText(flow.Problem, 240) && safeText(flow.Found, 240) && safeText(flow.Required, 240) &&
		safeText(flow.WhyStopped, 240) && (safeText(flow.SBXRCorrection, 240) != (len(flow.OwnerSteps) > 0)) &&
		safeTexts(flow.OwnerSteps, 8, 240) && safeText(flow.CheckAgain, 160) && safeText(flow.Back, 160) && safeText(flow.Evidence, 640)
}

type InstallationSummary struct {
	Status     InstallationStatus
	Correction CorrectionFlow

	verified               bool
	currentChangeSet       ChangeSetID
	completedSteps         int
	totalSteps             int
	rollbackAvailable      bool
	forwardRepairAvailable bool
	recoveryCause          RecoveryCause
}

func (summary InstallationSummary) CurrentChangeSet() ChangeSetID { return summary.currentChangeSet }
func (summary InstallationSummary) Progress() (int, int) {
	return summary.completedSteps, summary.totalSteps
}
func (summary InstallationSummary) RollbackAvailable() bool { return summary.rollbackAvailable }
func (summary InstallationSummary) ForwardRepairAvailable() bool {
	return summary.forwardRepairAvailable
}
func (summary InstallationSummary) RecoveryCause() RecoveryCause { return summary.recoveryCause }

// InstallationSummaryFrom accepts only System Changes' opaque, already
// validated read-only lineage inspection.
func InstallationSummaryFrom(facts systemchanges.InstallationHealthInspection) InstallationSummary {
	inspection, ok := facts.InstallationFacts()
	if !ok {
		return fallbackInstallation()
	}
	summary := InstallationSummary{
		Status:                 InstallationStatus(inspection.Status),
		verified:               true,
		currentChangeSet:       ChangeSetID(inspection.CurrentChangeSet),
		completedSteps:         inspection.CompletedSteps,
		totalSteps:             inspection.TotalSteps,
		rollbackAvailable:      inspection.RollbackAvailable,
		forwardRepairAvailable: inspection.ForwardRepairAvailable,
		recoveryCause:          RecoveryCause(inspection.RecoveryCause),
	}
	return normalizeInstallation(summary)
}

type Finding struct {
	Status HealthStatus
	Code   FindingCode
}

type Inspection func(context.Context) (Finding, error)

type NamedInspection struct {
	Module  Module
	Role    Role
	Inspect Inspection
}

type ModuleResult struct {
	CheckedAt   time.Time
	Module      Module
	Status      HealthStatus
	Code        FindingCode
	Role        Role
	Gate        GateDisposition
	Explanation string
	NextAction  string
	Correction  CorrectionFlow
}

type CheckResult struct {
	Installation InstallationSummary
	Modules      []ModuleResult
}

type Interface struct{ now func() time.Time }

func New(now func() time.Time) Interface {
	if now == nil {
		now = time.Now
	}
	return Interface{now: now}
}

// Check calls only the named inspections supplied by owning Modules. It does
// not cache observations, interpret protected data, or make mutation choices.
func (module Interface) Check(ctx context.Context, installation InstallationSummary, inspections ...NamedInspection) CheckResult {
	checkedAt := module.now().UTC()
	result := CheckResult{Installation: normalizeInstallation(installation), Modules: make([]ModuleResult, 0, len(inspections))}
	seen := make(map[Module]int, len(inspections))
	for _, inspection := range inspections {
		if !knownModule(inspection.Module) {
			continue
		}
		if index, duplicate := seen[inspection.Module]; duplicate {
			role := result.Modules[index].Role
			if role != inspection.Role {
				role = Required
			}
			result.Modules[index] = unknownResult(checkedAt, inspection.Module, role)
			continue
		}
		seen[inspection.Module] = len(result.Modules)
		result.Modules = append(result.Modules, inspect(ctx, checkedAt, inspection))
	}
	return result
}

func inspect(ctx context.Context, checkedAt time.Time, inspection NamedInspection) (result ModuleResult) {
	result = unknownResult(checkedAt, inspection.Module, inspection.Role)
	defer func() {
		if recover() != nil {
			result = unknownResult(checkedAt, inspection.Module, inspection.Role)
		}
	}()
	if inspection.Inspect == nil || ctx.Err() != nil {
		return result
	}
	if validRole(inspection.Role) != inspection.Role {
		return result
	}
	finding, err := inspection.Inspect(ctx)
	if err != nil || ctx.Err() != nil || !validFinding(inspection.Module, finding) {
		return result
	}
	result = ModuleResult{
		CheckedAt: checkedAt, Module: inspection.Module, Status: finding.Status, Code: finding.Code,
		Role: inspection.Role, Gate: gateDisposition(inspection.Role, finding.Status), Explanation: explanation(inspection.Module, finding.Status),
		NextAction: nextAction(inspection.Module, finding.Status),
	}
	if finding.Status != Healthy {
		result.Correction = resultCorrection(inspection.Module, inspection.Role, finding.Status, finding.Code)
	}
	return result
}

func unknownResult(checkedAt time.Time, module Module, role Role) ModuleResult {
	code := FindingCode("HEALTH-DIAGNOSTICS-CHECK-UNKNOWN")
	return ModuleResult{
		CheckedAt: checkedAt, Module: module, Status: Unknown, Code: code, Role: validRole(role), Gate: gateDisposition(validRole(role), Unknown),
		Explanation: explanation(module, Unknown), NextAction: nextAction(module, Unknown),
		Correction: resultCorrection(module, validRole(role), Unknown, code),
	}
}

func normalizeInstallation(summary InstallationSummary) InstallationSummary {
	if !summary.verified {
		return fallbackInstallation()
	}
	switch summary.Status {
	case NotInstalled, Managed:
		if summary.currentChangeSet == "" && summary.completedSteps == 0 && summary.totalSteps == 0 && !summary.rollbackAvailable && !summary.forwardRepairAvailable && summary.recoveryCause == "" {
			return InstallationSummary{Status: summary.Status, verified: true}
		}
	case ChangeInProgress:
		if summary.currentChangeSet != "" && summary.totalSteps > 0 && summary.completedSteps >= 0 && summary.completedSteps <= summary.totalSteps && !summary.forwardRepairAvailable && summary.recoveryCause == "" {
			summary.Correction = installationCorrection(summary)
			return summary
		}
	case RecoveryRequired:
		if validRecoverySummary(summary) {
			summary.Correction = installationCorrection(summary)
			return summary
		}
	}
	return fallbackInstallation()
}

func validRecoverySummary(summary InstallationSummary) bool {
	if !validRecoveryCause(summary.recoveryCause) || summary.completedSteps < 0 || summary.totalSteps < summary.completedSteps || summary.rollbackAvailable && summary.forwardRepairAvailable {
		return false
	}
	if summary.rollbackAvailable {
		return summary.currentChangeSet != "" && summary.totalSteps > 0 && (summary.recoveryCause == ForwardCheckpointUnprovable || summary.recoveryCause == RollbackStepUnprovable || summary.recoveryCause == PriorAgreementUnprovable)
	}
	if summary.forwardRepairAvailable {
		return summary.recoveryCause == CurrentStateDrift && summary.currentChangeSet == "" && summary.totalSteps == 0
	}
	return summary.recoveryCause != CurrentStateDrift
}

func installationCorrection(summary InstallationSummary) CorrectionFlow {
	flow := CorrectionFlow{
		Problem:    "The installation lineage could not be reported safely.",
		Found:      "Recovery Required because " + string(summary.recoveryCause) + ".",
		Required:   "One exact proven installation status and safe lineage facts.",
		WhyStopped: "Health never substitutes for installation lineage.",
		CheckAgain: "Run Check again.", Back: "Return without changing State or transaction evidence.",
	}
	if summary.Status == ChangeInProgress {
		flow.Problem = "One approved Change Set is still in progress."
		flow.Found = string(summary.currentChangeSet) + " completed " + strconv.Itoa(summary.completedSteps) + " of " + strconv.Itoa(summary.totalSteps) + " steps."
		flow.Required = "System Changes must finish or roll back the active Change Set."
		flow.WhyStopped = "Diagnostics cannot interfere with the active Change Set."
		if summary.rollbackAvailable {
			flow.SBXRCorrection = "Review Retry automatic rollback in System Changes."
		} else {
			flow.OwnerSteps = []string{"Keep the transaction evidence intact and use the System Changes read-only progress flow."}
		}
	} else if summary.rollbackAvailable {
		flow.SBXRCorrection = "Review Retry automatic rollback in System Changes."
	} else if summary.forwardRepairAvailable {
		flow.SBXRCorrection = "Build and review one forward-repair Plan for the current proven Desired State."
	} else {
		flow.OwnerSteps = []string{"Preserve transaction evidence and follow the System Changes Recovery Required flow.", "Use Complete removal and rebuild when current State cannot be proved."}
	}
	return normalizeCorrection("HEALTH-DIAGNOSTICS-INSTALLATION", flow)
}

func fallbackInstallation() InstallationSummary {
	summary := InstallationSummary{Status: RecoveryRequired, verified: true, recoveryCause: StateLineageUnprovable}
	summary.Correction = installationCorrection(summary)
	return summary
}

func validRecoveryCause(cause RecoveryCause) bool {
	switch cause {
	case StateLineageUnprovable, SnapshotUnprovable, JournalUnprovable, ForwardCheckpointUnprovable, RollbackStepUnprovable, PriorAgreementUnprovable, CurrentStateDrift, MissingSecrets, ReplacementVPS, OlderRevision, OwnerRegret:
		return true
	default:
		return false
	}
}

func validFinding(module Module, finding Finding) bool {
	return finding.Code != "" && finding.Code == NamedCheckCode(module, finding.Status)
}

func validCorrection(flow CorrectionFlow) bool {
	return safeText(flow.Problem, 240) && safeText(flow.Found, 240) && safeText(flow.Required, 240) &&
		safeText(flow.WhyStopped, 240) && (safeText(flow.SBXRCorrection, 240) != (len(flow.OwnerSteps) > 0)) &&
		safeTexts(flow.OwnerSteps, 8, 240) && safeText(flow.CheckAgain, 160) && safeText(flow.Back, 160)
}

func normalizeCorrection(code FindingCode, flow CorrectionFlow) CorrectionFlow {
	flow.OwnerSteps = append([]string(nil), flow.OwnerSteps...)
	flow.Evidence = string(code) + ": found " + flow.Found + "; required " + flow.Required
	return flow
}

func resultCorrection(module Module, role Role, status HealthStatus, code FindingCode) CorrectionFlow {
	flow := CorrectionFlow{
		Problem:    explanation(module, status),
		Found:      moduleDefinitions[module].subject + " is " + string(status) + " with " + string(code) + ".",
		Required:   requiredFact(module, role),
		WhyStopped: stoppedFact(role, status),
		CheckAgain: "Run Check again.",
		Back:       "Return without changing the installation.",
	}
	if status == Unknown {
		flow.OwnerSteps = []string{"Restore " + string(module) + "'s named typed inspection, then run Check again."}
	} else if correction := moduleDefinitions[module].correction; correction != "" {
		flow.SBXRCorrection = correction
	} else {
		flow.OwnerSteps = append([]string(nil), moduleDefinitions[module].ownerSteps...)
	}
	return normalizeCorrection(code, flow)
}

func explanation(module Module, status HealthStatus) string {
	subject := moduleDefinitions[module].subject
	switch status {
	case Healthy:
		return subject + " proved its required external behavior."
	case NeedsAttention:
		return subject + " found an actionable non-Healthy condition."
	case Failed:
		return subject + " proved required behavior is broken."
	default:
		return "A safe conclusion about " + subject + " could not be established."
	}
}

func nextAction(module Module, status HealthStatus) string {
	if status == Healthy {
		return "Return Back or continue through System Changes when its ordered gates allow it."
	}
	return moduleDefinitions[module].nextAction
}

func requiredFact(module Module, role Role) string {
	required := moduleDefinitions[module].required
	switch role {
	case Required:
		return required + " Required checks must be Healthy."
	case Advisory:
		return required + " Advisory checks must be Healthy, or Needs attention must be disclosed in the reviewed Plan."
	default:
		return required
	}
}

func stoppedFact(role Role, status HealthStatus) string {
	if gateDisposition(role, status) == GateStops {
		return "This gate fact cannot pass; System Changes decides whether to stop, roll back, or enter Recovery Required."
	}
	if gateDisposition(role, status) == GateRequiresPlanDisclosure {
		return "The condition must be disclosed in the reviewed Plan before System Changes may proceed."
	}
	return "Health and Diagnostics reports facts and never chooses or performs mutation."
}

func validRole(role Role) Role {
	if role == Required || role == Advisory {
		return role
	}
	if role != "" {
		return Required
	}
	return ""
}

func gateDisposition(role Role, status HealthStatus) GateDisposition {
	if role == "" {
		return NotAGate
	}
	if status == Healthy {
		return GatePasses
	}
	if role == Advisory && status == NeedsAttention {
		return GateRequiresPlanDisclosure
	}
	return GateStops
}

func safeText(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, control := range []string{"\x00", "\n", "\r", "\t"} {
		if strings.Contains(value, control) {
			return false
		}
	}
	return true
}

func safeTexts(values []string, maximumItems, maximumLength int) bool {
	if len(values) > maximumItems {
		return false
	}
	for _, value := range values {
		if !safeText(value, maximumLength) {
			return false
		}
	}
	return true
}

func knownModule(module Module) bool { return moduleDefinitions[module].codePrefix != "" }

// NamedCheckCode returns the reviewed finding code accepted from a Module's
// named Check seam for one exact Health Result. Arbitrary text cannot become a
// finding code.
func NamedCheckCode(module Module, status HealthStatus) FindingCode {
	prefix, suffix := moduleDefinitions[module].codePrefix, healthCodeSuffixes[status]
	if prefix == "" || suffix == "" {
		return ""
	}
	return FindingCode(prefix + suffix)
}

var healthCodeSuffixes = map[HealthStatus]string{
	Healthy: "HEALTHY", NeedsAttention: "NEEDS-ATTENTION", Failed: "FAILED", Unknown: "UNKNOWN",
}

type moduleDefinition struct {
	codePrefix, subject, required, correction, nextAction string
	ownerSteps                                            []string
}

var moduleDefinitions = map[Module]moduleDefinition{
	StateModule: {
		codePrefix: "STATE-",
		subject:    "Desired State lineage", required: "Desired State lineage must match one proven revision.",
		nextAction: "Open the State and System Changes Correction Flow, Check again, or return Back.",
		ownerSteps: []string{"Use the State and System Changes Correction Flow without adopting files or recreating secrets."},
	},
	NetworkPolicyModule: {
		codePrefix: "NETWORK-",
		subject:    "The complete Network Policy baseline", required: "The qualified addresses, listeners, firewall ownership, SSH safety, and outside dependencies must agree.",
		correction: "Build and review one separate Network Policy correction Plan.", nextAction: "Review the Network Policy Correction Flow, Check again, or return Back.",
	},
	SystemChangesModule: {
		codePrefix: "SYSTEM-CHANGES-",
		subject:    "Change Set and recovery state", required: "The lock, journal, checkpoints, rollback evidence, and Desired State lineage must agree.",
		nextAction: "Open the System Changes Recovery Required flow, Check again, or return Back.",
		ownerSteps: []string{"Preserve transaction evidence and follow the System Changes Recovery Required flow."},
	},
	CloudflareTunnelModule: {
		codePrefix: "CLOUDFLARE-",
		subject:    "Cloudflare Tunnel authority and both routes", required: "The scoped authority, Tunnel, DNS, both routes, and loopback origins must agree.",
		correction: "Build and review one separate Cloudflare Tunnel correction Plan.", nextAction: "Review the Cloudflare Tunnel Correction Flow, Check again, or return Back.",
	},
	CertificateLifecycleModule: {
		codePrefix: "CERTIFICATE-",
		subject:    "Certificate issuer, lineages, serving pointers, and scheduler", required: "Both certificate lineages and their standing policy must be proved current.",
		correction: "Build and review one separate Certificate Lifecycle correction Plan.", nextAction: "Review the Certificate Lifecycle Correction Flow, Check again, or return Back.",
	},
	ConnectionProfilesModule: {
		codePrefix: "CONNECTION-PROFILES-",
		subject:    "The six Connection Profiles and native core validation", required: "Every enabled Connection Profile must match Desired State and pass its owning native checks.",
		correction: "Build and review one separate Connection Profiles correction Plan.", nextAction: "Review the Connection Profiles Correction Flow, Check again, or return Back.",
	},
	SubscriptionPublicationModule: {
		codePrefix: "SUBSCRIPTION-PUBLICATION-",
		subject:    "The immutable subscription publication", required: "The current published representations must agree with Desired State.",
		correction: "Build and review one separate Subscription Publication correction Plan.", nextAction: "Review the Subscription Publication Correction Flow, Check again, or return Back.",
	},
	SubscriptionServingModule: {
		codePrefix: "SUBSCRIPTION-SERVING-",
		subject:    "The authenticated IP HTTPS subscription service", required: "The listener, certificate, authorization, and immutable artifacts must agree.",
		correction: "Review the owning Subscription Publication or Certificate Lifecycle correction before changing serving state.", nextAction: "Review the Subscription Serving Correction Flow, Check again, or return Back.",
	},
	HealthDiagnosticsModule: {
		codePrefix: "HEALTH-DIAGNOSTICS-",
		subject:    "The Health and Diagnostics read-only boundary", required: "Every named inspection must return one complete typed safe result.",
		nextAction: "Restore the named inspection boundary, Check again, or return Back.",
		ownerSteps: []string{"Restore the unavailable named inspection without reading arbitrary files, commands, logs, paths, or services."},
	},
	SoftwareLifecycleModule: {
		codePrefix: "SOFTWARE-LIFECYCLE-",
		subject:    "Installed Release Identity and verified software lifecycle", required: "The installed release and retained candidate must match verified release facts.",
		correction: "Build and review one separate Software Lifecycle correction Plan.", nextAction: "Review the Software Lifecycle Correction Flow, Check again, or return Back.",
	},
	OwnerConsoleModule: {
		codePrefix: "OWNER-CONSOLE-",
		subject:    "The authenticated Owner Console presentation", required: "The Owner Console must present the complete typed result without exposing protected facts.",
		nextAction: "Return Back, restore the Owner Console boundary, then Check again.",
		ownerSteps: []string{"Return Back without changing the installation and restore the Owner Console presentation boundary."},
	},
}
