package softwarelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	lifecyclecontract "github.com/albertloky/SBXR/internal/softwarelifecycle/contract"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

const RepairPlanRefused RefusalCode = "SOFTWARE-LIFECYCLE-REPAIR-PLAN-REFUSED"

type repairCandidateCell struct {
	authority      systemchanges.ForwardRepairAuthority
	revision       uint64
	sha256         string
	volatileSHA256 string
}

// RepairCandidate is the opaque fresh-observation handoff from ViewRepair.
type RepairCandidate struct{ cell *repairCandidateCell }

func (RepairCandidate) String() string   { return "current Desired State repair candidate: protected" }
func (RepairCandidate) GoString() string { return "current Desired State repair candidate: protected" }
func (RepairCandidate) MarshalJSON() ([]byte, error) {
	return nil, errors.New("current Desired State repair candidate cannot be rendered")
}

type RepairViewResult struct {
	Status           InstallationStatus
	Cause            systemchanges.RecoveryCause
	StateRevision    uint64
	StateSHA256      string
	PermittedActions []Action
	Guidance         []string
	candidate        RepairCandidate
}

func (result RepairViewResult) RepairCandidate() RepairCandidate { return result.candidate }

func (module LegacyInterface) ViewRepair(changes systemchanges.Interface) RepairViewResult {
	inspection := changes.Inspect()
	result := RepairViewResult{Status: InstallationStatus(inspection.Status), Cause: inspection.RecoveryCause}
	if inspection.Status != systemchanges.RecoveryRequired {
		return result
	}
	if inspection.RollbackAvailable {
		result.PermittedActions = []Action{RetryAutomaticRollback}
		return result
	}
	if inspection.Lock == systemchanges.LockReleased && inspection.RecoveryCause == systemchanges.CurrentStateDrift && inspection.ForwardRepairAvailable {
		authority := changes.ForwardRepairAuthority()
		revision, sha256, volatileSHA256, valid := authority.SoftwareLifecycleRepairReview()
		if valid {
			result.StateRevision, result.StateSHA256 = revision, sha256
			result.PermittedActions = []Action{ReviewRepair}
			result.candidate = RepairCandidate{cell: &repairCandidateCell{authority: authority, revision: revision, sha256: sha256, volatileSHA256: volatileSHA256}}
			return result
		}
	}
	result.PermittedActions = []Action{CompleteRemoval}
	if inspection.Correction != nil {
		result.Guidance = append([]string(nil), inspection.Correction.OwnerWorkPlan...)
	}
	if len(result.Guidance) == 0 {
		result.Guidance = []string{"Preserve secret-safe evidence and do not start unproven services.", "Separately confirm Complete removal, then rebuild from a Clean VPS."}
	}
	return result
}

type RepairContributionProof = lifecyclecontract.RepairContribution

type RepairContribution interface {
	SoftwareLifecycleRepairContribution() lifecyclecontract.RepairContribution
}

type RepairPlanRequest struct {
	Candidate    RepairCandidate
	Contribution RepairContribution
	ChangeSet    string
	Capability   ManagedCapability
	Disk         systemchanges.DiskRequirement
}

type RepairSummary struct {
	CurrentRevision, CandidateRevision      uint64
	CurrentStateSHA256                      string
	OwningModule                            systemchanges.Module
	Steps, Checks, Details                  []string
	Disk                                    systemchanges.DiskRequirement
	StateEffect, Rollback                   string
	PrivilegedMutationAfterApproval, OneUse bool
}

type RepairPlan struct {
	identity, sha256        string
	revision                uint64
	stateSHA256             string
	proof                   RepairContributionProof
	contribution            RepairContribution
	contributorType         reflect.Type
	volatileSHA256          string
	disk                    systemchanges.DiskRequirement
	summary                 RepairSummary
	used                    *atomic.Bool
	cloudflareProfilesSetUp bool
}

func PlanRepair(request RepairPlanRequest) (*RepairPlan, *InstallFinding) {
	refuse := func() (*RepairPlan, *InstallFinding) {
		return nil, &InstallFinding{Code: RepairPlanRefused, Problem: "The reviewed current-State repair Plan is incomplete or stale", NextAction: "Check again and build one fresh repair Plan"}
	}
	if request.Contribution == nil || !validRepairContributor(request.Contribution) || !installIdentityPattern.MatchString(request.ChangeSet) || !validInstallDisk(request.Disk) {
		return refuse()
	}
	revision, stateSHA256, volatileSHA256, valid := consumeRepairCandidate(request.Candidate)
	proof := request.Contribution.SoftwareLifecycleRepairContribution()
	cloudflareProfilesSetUp, capabilityValid := consumeManagedCapability(request.Capability, revision, stateSHA256)
	if !valid || !capabilityValid || !cloudflareProfilesSetUp && proof.Owner == systemchanges.CloudflareModule || !validRepairProof(proof) || proof.ChangeSet != request.ChangeSet || proof.CurrentRevision != revision || proof.CurrentStateSHA256 != stateSHA256 || proof.StableSHA256 != volatileSHA256 {
		return refuse()
	}
	return buildRepairPlan(request, proof, revision, stateSHA256, volatileSHA256)
}

func buildRepairPlan(request RepairPlanRequest, proof RepairContributionProof, revision uint64, stateSHA256, volatileSHA256 string) (*RepairPlan, *InstallFinding) {
	refuse := func() (*RepairPlan, *InstallFinding) {
		return nil, &InstallFinding{Code: RepairPlanRefused, Problem: "The reviewed current-State repair Plan is incomplete or stale", NextAction: "Check again and build one fresh repair Plan"}
	}
	cloudflareProfilesSetUp, capabilityValid := consumeManagedCapability(request.Capability, revision, stateSHA256)
	if request.Contribution == nil || !capabilityValid || !cloudflareProfilesSetUp && proof.Owner == systemchanges.CloudflareModule || !validRepairProof(proof) || proof.ChangeSet != request.ChangeSet || proof.CurrentRevision != revision || proof.CurrentStateSHA256 != stateSHA256 || proof.StableSHA256 != volatileSHA256 || !installIdentityPattern.MatchString(request.ChangeSet) || !validInstallDisk(request.Disk) {
		return refuse()
	}
	bound := struct {
		Revision                uint64
		StateSHA256             string
		Proof                   RepairContributionProof
		CloudflareProfilesSetUp bool
		Disk                    systemchanges.DiskRequirement
	}{revision, stateSHA256, proof, cloudflareProfilesSetUp, request.Disk}
	encoded, err := json.Marshal(bound)
	if err != nil {
		return refuse()
	}
	digest := sha256.Sum256(encoded)
	checksum := hex.EncodeToString(digest[:])
	steps := make([]string, len(proof.Steps))
	for index := range proof.Steps {
		steps[index] = string(proof.Steps[index].Forward())
	}
	checks := make([]string, len(proof.Checks))
	for index := range proof.Checks {
		checks[index] = proof.Checks[index].Code
	}
	summary := RepairSummary{
		CurrentRevision: revision, CandidateRevision: revision + 1, CurrentStateSHA256: stateSHA256, OwningModule: proof.Owner,
		Steps: steps, Checks: checks, Details: append([]string(nil), proof.Details...), Disk: request.Disk,
		StateEffect:                     fmt.Sprintf("publish revision %d with unchanged Owner intent after repaired resources pass required gates", revision+1),
		Rollback:                        "restore the exact pre-repair managed resources and current Desired State from the one transaction Rollback Snapshot",
		PrivilegedMutationAfterApproval: true, OneUse: true,
	}
	return &RepairPlan{identity: request.ChangeSet + "-plan-" + checksum[:12], sha256: checksum, revision: revision, stateSHA256: stateSHA256, proof: proof, contribution: request.Contribution, contributorType: reflect.TypeOf(request.Contribution), volatileSHA256: volatileSHA256, disk: request.Disk, summary: summary, used: &atomic.Bool{}, cloudflareProfilesSetUp: cloudflareProfilesSetUp}, nil
}

func validRepairContributor(contribution RepairContribution) bool {
	typeOf := reflect.TypeOf(contribution)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || typeOf.Elem().Name() != "Plan" {
		return false
	}
	switch typeOf.Elem().PkgPath() {
	case "github.com/albertloky/SBXR/internal/connectionprofiles", "github.com/albertloky/SBXR/internal/cloudflaretunnel", "github.com/albertloky/SBXR/internal/subscriptionpublication":
		return true
	default:
		return false
	}
}

func consumeRepairCandidate(candidate RepairCandidate) (uint64, string, string, bool) {
	if candidate.cell == nil {
		return 0, "", "", false
	}
	revision, sha256, volatileSHA256, valid := candidate.cell.authority.SoftwareLifecycleForwardRepair()
	return revision, sha256, volatileSHA256, valid && revision == candidate.cell.revision && sha256 == candidate.cell.sha256 && volatileSHA256 == candidate.cell.volatileSHA256
}

func validRepairProof(proof RepairContributionProof) bool {
	want := map[string]systemchanges.Module{
		"Connection Profiles":      systemchanges.ConnectionProfilesModule,
		"Cloudflare Tunnel":        systemchanges.CloudflareModule,
		"Subscription Publication": systemchanges.SubscriptionModule,
	}
	if want[proof.Name] != proof.Owner || !installIdentityPattern.MatchString(proof.Identity) || !hashPattern.MatchString(proof.SHA256) || !hashPattern.MatchString(proof.StableSHA256) || !installIdentityPattern.MatchString(proof.ChangeSet) || proof.CurrentRevision == 0 || !hashPattern.MatchString(proof.CurrentStateSHA256) || len(proof.Steps) == 0 || len(proof.Checks) == 0 || len(proof.Details) == 0 || strings.Contains(strings.ToUpper(proof.Identity), "SECRET") {
		return false
	}
	pre, post := false, false
	for _, step := range proof.Steps {
		if step.Owner() != proof.Owner {
			return false
		}
	}
	for _, check := range proof.Checks {
		if check.Owner != proof.Owner || check.Scope != systemchanges.ServerSideCheck || check.Classification != systemchanges.Required || check.Status != systemchanges.Healthy {
			return false
		}
		pre = pre || check.Phase == systemchanges.PrePublication
		post = post || check.Phase == systemchanges.PostPublication
	}
	return pre && post
}

func (plan *RepairPlan) Identity() string {
	if plan == nil {
		return ""
	}
	return plan.identity
}

func (plan *RepairPlan) SHA256() string {
	if plan == nil {
		return ""
	}
	return plan.sha256
}

func (plan *RepairPlan) Summary() RepairSummary {
	if plan == nil {
		return RepairSummary{}
	}
	result := plan.summary
	result.Steps = append([]string(nil), result.Steps...)
	result.Checks = append([]string(nil), result.Checks...)
	result.Details = append([]string(nil), result.Details...)
	return result
}

func (plan *RepairPlan) String() string {
	if plan == nil {
		return "Software Lifecycle repair Plan: unavailable"
	}
	return fmt.Sprintf("Software Lifecycle repair Plan %s: revision %d -> %d, repair %s toward current Desired State", plan.identity, plan.summary.CurrentRevision, plan.summary.CandidateRevision, plan.summary.OwningModule)
}
func (plan *RepairPlan) GoString() string { return plan.String() }
func (*RepairPlan) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Software Lifecycle repair Plan cannot be rendered")
}

func (plan *RepairPlan) StateSoftwareRepair() (revision uint64, stateSHA256 string, valid bool) {
	if plan == nil || plan.revision == 0 || !hashPattern.MatchString(plan.stateSHA256) || !validRepairProof(plan.proof) {
		return 0, "", false
	}
	return plan.revision, plan.stateSHA256, true
}

type subscriptionRepairPreparer interface {
	PrepareSubscriptionPublication() ([]byte, error)
}

func (plan *RepairPlan) PrepareSubscriptionPublication() ([]byte, error) {
	if plan == nil || plan.proof.Owner != systemchanges.SubscriptionModule {
		return nil, errors.New("Subscription Publication repair is unavailable")
	}
	preparer, ok := plan.contribution.(subscriptionRepairPreparer)
	if !ok {
		return nil, errors.New("Subscription Publication repair is unavailable")
	}
	return preparer.PrepareSubscriptionPublication()
}

type RepairRecheck struct {
	Candidate    RepairCandidate
	Contribution RepairContribution
	Capability   ManagedCapability
}

type RepairApproval interface {
	AuthorizeAndRecheck(context.Context) (RepairRecheck, error)
}

type RepairApplyRequest struct {
	Approval      RepairApproval
	PreparedState systemchanges.PreparedStateCommit
	SystemChanges systemchanges.Interface
	Cancellation  *systemchanges.Cancellation
}

func (plan *RepairPlan) Apply(ctx context.Context, request RepairApplyRequest) systemchanges.ApplyResult {
	if plan == nil || plan.used == nil || !plan.used.CompareAndSwap(false, true) {
		return repairRefused("SOFTWARE-LIFECYCLE-REPAIR-PLAN-USED", "The reviewed repair Plan was already consumed")
	}
	if request.Approval == nil || reflect.ValueOf(request.Approval).Kind() == reflect.Pointer && reflect.ValueOf(request.Approval).IsNil() {
		return repairRefused("SOFTWARE-LIFECYCLE-REPAIR-APPROVAL", "Ordinary system sudo approval is unavailable")
	}
	rechecked, err := request.Approval.AuthorizeAndRecheck(ctx)
	if err != nil {
		return repairRefused("SOFTWARE-LIFECYCLE-REPAIR-APPROVAL", "Ordinary system sudo was denied, cancelled, or expired")
	}
	revision, stateSHA256, volatileSHA256, valid := consumeRepairCandidate(rechecked.Candidate)
	cloudflareProfilesSetUp, capabilityValid := consumeManagedCapability(rechecked.Capability, revision, stateSHA256)
	if !valid || !capabilityValid || cloudflareProfilesSetUp != plan.cloudflareProfilesSetUp || revision != plan.revision || stateSHA256 != plan.stateSHA256 || volatileSHA256 != plan.volatileSHA256 || rechecked.Contribution == nil || reflect.TypeOf(rechecked.Contribution) != plan.contributorType || !reflect.DeepEqual(rechecked.Contribution.SoftwareLifecycleRepairContribution(), plan.proof) {
		return repairRefused("SOFTWARE-LIFECYCLE-REPAIR-STALE", "The current Desired State, Observed State, or owning Module repair changed after approval")
	}
	prepared, ok := request.PreparedState.(interface {
		SystemChangesPreparedState() (changeSet string, revision uint64, startingSHA256, candidateSHA256, planIdentity, planSHA256 string, valid bool)
	})
	if !ok {
		return repairRefused("SOFTWARE-LIFECYCLE-REPAIR-PREPARED", "The prepared State has no exact repair binding")
	}
	changeSet, candidateRevision, startingSHA256, candidateSHA256, planIdentity, planSHA256, preparedValid := prepared.SystemChangesPreparedState()
	if !preparedValid || changeSet != plan.proof.ChangeSet || candidateRevision != plan.revision+1 || startingSHA256 != plan.stateSHA256 || !hashPattern.MatchString(candidateSHA256) || planIdentity != plan.identity || planSHA256 != plan.sha256 {
		return repairRefused("SOFTWARE-LIFECYCLE-REPAIR-PREPARED", "The prepared State differs from the reviewed current-State repair")
	}
	change, err := systemchanges.NewChangeSet(systemchanges.ChangeSetSpec{
		Identity: plan.proof.ChangeSet, Mutation: systemchanges.RepairMutation, OutcomeOwner: plan.proof.Owner,
		StartingState: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: plan.revision, SHA256: plan.stateSHA256}, TargetStateSHA256: candidateSHA256,
		Plan: systemchanges.PlanBinding{Identity: plan.identity, SHA256: plan.sha256, VolatileSHA256: plan.volatileSHA256}, PreparedState: request.PreparedState,
		Steps: plan.proof.Steps, Checks: plan.proof.Checks, Timeouts: systemchanges.Timeouts{Step: 5 * time.Minute, Check: 5 * time.Minute}, Disk: plan.disk,
	})
	if err != nil {
		return repairRefused("SOFTWARE-LIFECYCLE-REPAIR-PREPARED", "The prepared repair cannot form one complete Change Set")
	}
	if request.Cancellation != nil {
		return request.SystemChanges.ApplyWithCancellation(change, request.Cancellation)
	}
	return request.SystemChanges.Apply(change)
}

func repairRefused(code, problem string) systemchanges.ApplyResult {
	return systemchanges.ApplyResult{Outcome: systemchanges.Refused, NothingChanged: true, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: systemchanges.EvidenceRules{SecretSafeOnly: true}, Finding: &systemchanges.Finding{Code: code, Owner: systemchanges.SoftwareModule, Problem: problem, Found: "the reviewed current-State repair authority is unavailable or changed", Required: "one fresh exact current Desired State repair review", WhyStopped: "repair never adopts Observed State or bypasses transaction proof", NextAction: "Check again and create a fresh repair Plan."}}
}
