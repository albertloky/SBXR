package softwarelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

const UpdatePlanRefused RefusalCode = "SOFTWARE-LIFECYCLE-UPDATE-PLAN-REFUSED"
const DowngradePlanRefused RefusalCode = "SOFTWARE-LIFECYCLE-DOWNGRADE-PLAN-REFUSED"

type UpdatePlanRequest struct {
	Installed           VerifiedRelease
	InstalledCandidate  InstallCandidate
	Candidate           InstallCandidate
	StartingRevision    uint64
	StartingStateSHA256 string
	ChangeSet           string
	DesiredStateSHA256  string
	Contributions       []UpdateContribution
	Capability          ManagedCapability
	Disk                systemchanges.DiskRequirement
}

type DowngradePlanRequest UpdatePlanRequest

type UpdateRecheck struct {
	Installed           VerifiedRelease
	InstalledCandidate  InstallCandidate
	Candidate           InstallCandidate
	StartingRevision    uint64
	StartingStateSHA256 string
	Contributions       []UpdateContribution
	Capability          ManagedCapability
}

type UpdateApproval interface {
	AuthorizeAndRecheck(context.Context) (UpdateRecheck, error)
}

type UpdateApplyRequest struct {
	Approval      UpdateApproval
	PreparedState systemchanges.PreparedStateCommit
	SystemChanges systemchanges.Interface
	Cancellation  *systemchanges.Cancellation
}

type UpdateSummary struct {
	Operation                                                            Action
	CurrentRelease, CandidateRelease                                     ReleaseIdentity
	CurrentRevision, CandidateRevision                                   uint64
	MigrationPath, AffectedServices, SubscriptionRepresentations, Checks []string
	Disk                                                                 systemchanges.DiskRequirement
	Compatibility                                                        string
	Interruption, Cancellation, Rollback                                 string
	PrivilegedMutationAfterApproval, OneUse                              bool
}

type UpdatePlan struct {
	identity, sha256, volatileSHA256 string
	request                          UpdatePlanRequest
	proofs                           []InstallContributionProof
	steps                            []systemchanges.Step
	checks                           []systemchanges.Check
	summary                          UpdateSummary
	used                             *atomic.Bool
	cloudflareProfilesSetUp          bool
}

type UpdateContribution interface {
	SoftwareLifecycleUpdateContribution() InstallContributionProof
}

type ManagedCapability interface {
	SoftwareLifecycleManagedCapability() (revision uint64, stateSHA256 string, cloudflareProfilesSetUp bool, valid bool)
}

func PlanUpdate(request UpdatePlanRequest) (*UpdatePlan, *InstallFinding) {
	return planReleaseChange(request, ReviewUpdate)
}

func PlanDowngrade(request DowngradePlanRequest) (*UpdatePlan, *InstallFinding) {
	return planReleaseChange(UpdatePlanRequest(request), ReviewDowngrade)
}

func planReleaseChange(request UpdatePlanRequest, operation Action) (*UpdatePlan, *InstallFinding) {
	code := UpdatePlanRefused
	problem, next := "The reviewed update Plan is incomplete or stale", "Reload Managed State and build a fresh update Plan"
	eligible := eligibleUpdate
	if operation == ReviewDowngrade {
		code = DowngradePlanRefused
		problem, next = "The reviewed downgrade Plan is incomplete, stale, or incompatible", "Select and freshly verify a compatible older release"
		eligible = eligibleDowngrade
	}
	refuse := func() (*UpdatePlan, *InstallFinding) {
		return nil, &InstallFinding{Code: code, Problem: problem, NextAction: next}
	}
	cloudflareProfilesSetUp, capabilityValid := consumeManagedCapability(request.Capability, request.StartingRevision, request.StartingStateSHA256)
	if !validInstalled(request.Installed) || !validInstallCandidate(request.InstalledCandidate) || !reflect.DeepEqual(request.InstalledCandidate.cell.verified, request.Installed) || request.InstalledCandidate.cell.staged.Identity != request.Installed.Identity || !validInstallCandidate(request.Candidate) || !eligible(request.Installed, request.Candidate.cell.verified) || request.StartingRevision == 0 || !hashPattern.MatchString(request.StartingStateSHA256) || !installIdentityPattern.MatchString(request.ChangeSet) || !hashPattern.MatchString(request.DesiredStateSHA256) || !capabilityValid || !validInstallDisk(request.Disk) {
		return refuse()
	}
	want := map[InstallContributionName]systemchanges.Module{ProfilesInstallContribution: systemchanges.ConnectionProfilesModule, SubscriptionInstallContribution: systemchanges.SubscriptionModule}
	if cloudflareProfilesSetUp {
		want[CloudflareInstallContribution] = systemchanges.CloudflareModule
	}
	proofs := make([]InstallContributionProof, 0, len(want))
	seen := map[InstallContributionName]bool{}
	var steps []systemchanges.Step
	var checks []systemchanges.Check
	stable := ""
	for _, contribution := range request.Contributions {
		if contribution == nil {
			return refuse()
		}
		proof := contribution.SoftwareLifecycleUpdateContribution()
		name := InstallContributionName(proof.Name)
		owner, ok := want[name]
		if !ok || seen[name] || proof.Owner != owner || proof.ChangeSet != request.ChangeSet || proof.DesiredStateSHA256 != request.DesiredStateSHA256 || proof.Privileged || !validInstallProof(proof) {
			return refuse()
		}
		seen[name] = true
		proofs = append(proofs, proof)
		steps = append(steps, proof.Steps...)
		checks = append(checks, proof.Checks...)
		stable += proof.StableSHA256
	}
	if len(seen) != len(want) {
		return refuse()
	}
	softwareStep, err := systemchanges.NewStep(systemchanges.SoftwareModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		return refuse()
	}
	steps = append([]systemchanges.Step{softwareStep}, steps...)
	checks = append([]systemchanges.Check{
		{Owner: systemchanges.SoftwareModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "SOFTWARE-LIFECYCLE-UPDATE-STAGED"},
		{Owner: systemchanges.SoftwareModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "SOFTWARE-LIFECYCLE-UPDATE-AGREEMENT"},
	}, checks...)
	bound := struct {
		Installed                                         VerifiedRelease
		InstalledStaged                                   StagedRelease
		InstalledArchiveSHA256, InstalledComponentsSHA256 string
		Candidate                                         VerifiedRelease
		StartingRevision                                  uint64
		StartingState, ChangeSet, DesiredState            string
		Proofs                                            []InstallContributionProof
		CloudflareProfilesSetUp                           bool
		Disk                                              systemchanges.DiskRequirement
	}{request.Installed, request.InstalledCandidate.cell.staged, sha256Hex(request.InstalledCandidate.cell.archive), sha256Hex(request.InstalledCandidate.cell.components), request.Candidate.cell.verified, request.StartingRevision, request.StartingStateSHA256, request.ChangeSet, request.DesiredStateSHA256, proofs, cloudflareProfilesSetUp, request.Disk}
	encoded, err := json.Marshal(bound)
	if err != nil {
		return refuse()
	}
	digest := sha256.Sum256(encoded)
	volatile := sha256.Sum256([]byte(stable))
	checkNames := make([]string, len(checks))
	for index := range checks {
		checkNames[index] = checks[index].Code
	}
	sort.Strings(checkNames)
	affectedServices := []string{"sbxr-subscription.service", "xray.service"}
	interruption := "restart Xray and subscription serving after their prepared replacements validate"
	if cloudflareProfilesSetUp {
		affectedServices = []string{"cloudflared.service", "sbxr-subscription.service", "sing-box.service", "xray.service"}
		interruption = "restart only cloudflared, Xray, sing-box, and subscription serving after their prepared replacements validate"
	}
	summary := UpdateSummary{
		Operation:      operation,
		CurrentRelease: request.Installed.Identity, CandidateRelease: request.Candidate.cell.staged.Identity,
		CurrentRevision: request.StartingRevision, CandidateRevision: request.StartingRevision + 1,
		MigrationPath:               updateMigrationPath(request.Installed.StateSchema, request.Candidate.cell.verified.StateSchema),
		AffectedServices:            affectedServices,
		SubscriptionRepresentations: []string{"raw", "base64", "v2rayN", "Shadowrocket", "Karing", "Mihomo", "sing-box"},
		Checks:                      checkNames, Disk: request.Disk,
		Interruption:                    interruption,
		Cancellation:                    "Back before Apply changes nothing; cancellation after start waits for a safe checkpoint and restores the prior release and State",
		Rollback:                        "restore the exact prior release, service material, subscriptions, units, and Desired State from the one transaction snapshot",
		PrivilegedMutationAfterApproval: true, OneUse: true,
		Compatibility: "The authenticated candidate supports the complete sequential migration from the current Desired State schema",
	}
	if operation == ReviewDowngrade {
		summary.Compatibility = fmt.Sprintf("Current Desired State schema %d is supported by the selected release", request.Installed.StateSchema)
	}
	checksum := hex.EncodeToString(digest[:])
	return &UpdatePlan{identity: request.ChangeSet + "-plan-" + checksum[:12], sha256: checksum, volatileSHA256: hex.EncodeToString(volatile[:]), request: request, proofs: proofs, steps: steps, checks: checks, summary: summary, used: &atomic.Bool{}, cloudflareProfilesSetUp: cloudflareProfilesSetUp}, nil
}

func consumeManagedCapability(capability ManagedCapability, revision uint64, stateSHA256 string) (bool, bool) {
	typeOf := reflect.TypeOf(capability)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || typeOf.Elem().PkgPath() != "github.com/albertloky/SBXR/internal/state" || typeOf.Elem().Name() != "SoftwareLifecycleCapability" {
		return false, false
	}
	gotRevision, gotSHA256, cloudflareProfilesSetUp, valid := capability.SoftwareLifecycleManagedCapability()
	return cloudflareProfilesSetUp, valid && gotRevision == revision && gotSHA256 == stateSHA256
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func updateMigrationPath(from, to uint64) []string {
	result := make([]string, 0, to-from)
	for schema := from; schema < to; schema++ {
		result = append(result, fmt.Sprintf("State schema %d -> %d: preserve all Owner meaning; regenerate release-bound material", schema, schema+1))
	}
	return result
}

func (plan *UpdatePlan) Apply(ctx context.Context, request UpdateApplyRequest) systemchanges.ApplyResult {
	if plan == nil || plan.used == nil || !plan.used.CompareAndSwap(false, true) {
		return updateRefused("SOFTWARE-LIFECYCLE-UPDATE-PLAN-USED", "The reviewed update Plan was already consumed")
	}
	if request.Approval == nil || reflect.ValueOf(request.Approval).Kind() == reflect.Pointer && reflect.ValueOf(request.Approval).IsNil() {
		return updateRefused("SOFTWARE-LIFECYCLE-UPDATE-APPROVAL", "Ordinary system sudo approval is unavailable")
	}
	rechecked, err := request.Approval.AuthorizeAndRecheck(ctx)
	if err != nil {
		return updateRefused("SOFTWARE-LIFECYCLE-UPDATE-APPROVAL", "Ordinary system sudo was denied, cancelled, or expired")
	}
	freshSHA256, stableSHA256, contributionsMatch := sameUpdateContributions(plan.proofs, rechecked.Contributions)
	cloudflareProfilesSetUp, capabilityValid := consumeManagedCapability(rechecked.Capability, rechecked.StartingRevision, rechecked.StartingStateSHA256)
	if !reflect.DeepEqual(rechecked.Installed, plan.request.Installed) || !sameInstallCandidate(rechecked.InstalledCandidate, plan.request.InstalledCandidate) || !sameInstallCandidate(rechecked.Candidate, plan.request.Candidate) || rechecked.StartingRevision != plan.request.StartingRevision || rechecked.StartingStateSHA256 != plan.request.StartingStateSHA256 || !capabilityValid || cloudflareProfilesSetUp != plan.cloudflareProfilesSetUp || !contributionsMatch || stableSHA256 != plan.volatileSHA256 {
		return updateRefused("SOFTWARE-LIFECYCLE-UPDATE-STALE", "The installed release, State, candidate, or prepared Module facts changed after approval")
	}
	prepared, ok := request.PreparedState.(interface {
		SystemChangesPreparedState() (changeSet string, revision uint64, startingSHA256, candidateSHA256, planIdentity, planSHA256 string, valid bool)
		SoftwareLifecyclePreparedRelease() (repository, tag, commit, releaseIndexSHA256 string, valid bool)
		SoftwareLifecyclePreparedMigration() (from, to uint64, steps int, networkFree bool)
	})
	if !ok {
		return updateRefused("SOFTWARE-LIFECYCLE-UPDATE-PREPARED", "The prepared State has no exact update binding")
	}
	changeSet, revision, startingSHA256, candidateSHA256, planIdentity, planSHA256, valid := prepared.SystemChangesPreparedState()
	repository, tag, commit, indexSHA256, releaseValid := prepared.SoftwareLifecyclePreparedRelease()
	from, to, migrationSteps, networkFree := prepared.SoftwareLifecyclePreparedMigration()
	identity := plan.summary.CandidateRelease
	if !valid || !releaseValid || !networkFree || changeSet != plan.request.ChangeSet || revision != plan.request.StartingRevision+1 || startingSHA256 != plan.request.StartingStateSHA256 || candidateSHA256 != plan.request.DesiredStateSHA256 || planIdentity != plan.identity || planSHA256 != plan.sha256 || repository != identity.Repository || tag != identity.Tag || commit != identity.Commit || indexSHA256 != identity.IndexSHA256 || from != plan.request.Installed.StateSchema || to != plan.request.Candidate.cell.verified.StateSchema || migrationSteps != int(to-from) {
		return updateRefused("SOFTWARE-LIFECYCLE-UPDATE-PREPARED", "The prepared State differs from the reviewed release, migration, or revision")
	}
	change, err := systemchanges.NewChangeSet(systemchanges.ChangeSetSpec{
		Identity: plan.request.ChangeSet, Mutation: systemchanges.UpdateMutation, OutcomeOwner: systemchanges.SoftwareModule,
		StartingState:     systemchanges.StateLineage{Status: systemchanges.Managed, Revision: plan.request.StartingRevision, SHA256: plan.request.StartingStateSHA256},
		TargetStateSHA256: plan.request.DesiredStateSHA256,
		Plan:              systemchanges.PlanBinding{Identity: plan.identity, SHA256: plan.sha256, VolatileSHA256: freshSHA256}, PreparedState: request.PreparedState,
		Steps: plan.steps, Checks: plan.checks, Timeouts: systemchanges.Timeouts{Step: 10 * time.Minute, Check: 5 * time.Minute}, Disk: plan.request.Disk,
	})
	if err != nil {
		return updateRefused("SOFTWARE-LIFECYCLE-UPDATE-PREPARED", "The prepared update cannot form one complete Change Set")
	}
	if request.Cancellation != nil {
		return request.SystemChanges.ApplyWithCancellation(change, request.Cancellation)
	}
	return request.SystemChanges.Apply(change)
}

func sameUpdateContributions(want []InstallContributionProof, got []UpdateContribution) (string, string, bool) {
	if len(want) != len(got) {
		return "", "", false
	}
	byName := make(map[InstallContributionName]InstallContributionProof, len(want))
	for _, proof := range want {
		byName[InstallContributionName(proof.Name)] = proof
	}
	seen := map[InstallContributionName]bool{}
	var fresh, stable string
	for _, contribution := range got {
		if contribution == nil {
			return "", "", false
		}
		proof := contribution.SoftwareLifecycleUpdateContribution()
		name := InstallContributionName(proof.Name)
		expected, ok := byName[name]
		if !ok || seen[name] || !reflect.DeepEqual(proof, expected) {
			return "", "", false
		}
		seen[name] = true
		fresh += proof.SHA256
		stable += proof.StableSHA256
	}
	if len(seen) != len(byName) {
		return "", "", false
	}
	freshDigest, stableDigest := sha256.Sum256([]byte(fresh)), sha256.Sum256([]byte(stable))
	return hex.EncodeToString(freshDigest[:]), hex.EncodeToString(stableDigest[:]), true
}

func updateRefused(code, problem string) systemchanges.ApplyResult {
	return systemchanges.ApplyResult{Outcome: systemchanges.Refused, NothingChanged: true, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: systemchanges.EvidenceRules{SecretSafeOnly: true}, Finding: &systemchanges.Finding{Code: code, Owner: systemchanges.SoftwareModule, Problem: problem, Found: "the reviewed update authority is unavailable or changed", Required: "one fresh exact Managed update review followed by approval and a complete recheck", WhyStopped: "stale or incomplete authority cannot switch code and State", NextAction: "Return to review and create a fresh update Plan."}}
}

func (plan *UpdatePlan) Identity() string {
	if plan == nil {
		return ""
	}
	return plan.identity
}
func (plan *UpdatePlan) SHA256() string {
	if plan == nil {
		return ""
	}
	return plan.sha256
}

func (plan *UpdatePlan) VolatileSHA256() string {
	if plan == nil {
		return ""
	}
	return plan.volatileSHA256
}
func (plan *UpdatePlan) Summary() UpdateSummary {
	if plan == nil {
		return UpdateSummary{}
	}
	result := plan.summary
	result.MigrationPath = append([]string(nil), result.MigrationPath...)
	result.AffectedServices = append([]string(nil), result.AffectedServices...)
	result.SubscriptionRepresentations = append([]string(nil), result.SubscriptionRepresentations...)
	result.Checks = append([]string(nil), result.Checks...)
	return result
}
func (plan *UpdatePlan) String() string {
	if plan == nil {
		return "Software Lifecycle update Plan: unavailable"
	}
	return fmt.Sprintf("Software Lifecycle %s Plan %s: revision %d -> %d, %s -> %s, one atomic rollback snapshot", strings.ToLower(strings.TrimPrefix(string(plan.summary.Operation), "Review ")), plan.identity, plan.summary.CurrentRevision, plan.summary.CandidateRevision, plan.summary.CurrentRelease.Tag, plan.summary.CandidateRelease.Tag)
}
func (plan *UpdatePlan) GoString() string { return plan.String() }

func (plan *UpdatePlan) StateSoftwareUpdate() ([]byte, bool) {
	if plan == nil || plan.used == nil {
		return nil, false
	}
	binding := struct {
		StartingRevision                   uint64
		StartingStateSHA256, DesiredSHA256 string
		Current, Candidate                 ReleaseIdentity
		FromSchema, ToSchema               uint64
	}{plan.request.StartingRevision, plan.request.StartingStateSHA256, plan.request.DesiredStateSHA256, plan.request.Installed.Identity, plan.request.Candidate.cell.staged.Identity, plan.request.Installed.StateSchema, plan.request.Candidate.cell.verified.StateSchema}
	encoded, err := json.Marshal(binding)
	return encoded, err == nil
}
