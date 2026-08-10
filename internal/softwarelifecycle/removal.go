package softwarelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync/atomic"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

const CompleteRemovalPlanRefused RefusalCode = "SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-PLAN-REFUSED"

type completeRemovalCandidateCell struct {
	authority              systemchanges.CompleteRemovalAuthority
	status                 systemchanges.InstallationStatus
	revision               uint64
	sha256, volatileSHA256 string
}

type CompleteRemovalCandidate struct{ cell *completeRemovalCandidateCell }

func (CompleteRemovalCandidate) String() string   { return "Complete removal candidate: protected" }
func (CompleteRemovalCandidate) GoString() string { return "Complete removal candidate: protected" }
func (CompleteRemovalCandidate) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Complete removal candidate cannot be rendered")
}

type CompleteRemovalViewResult struct {
	Status           InstallationStatus
	StateRevision    uint64
	StateSHA256      string
	PermittedActions []Action
	candidate        CompleteRemovalCandidate
}

func (result CompleteRemovalViewResult) Candidate() CompleteRemovalCandidate { return result.candidate }

func (Interface) ViewCompleteRemoval(changes systemchanges.Interface) CompleteRemovalViewResult {
	authority := changes.CompleteRemovalAuthority()
	status, revision, stateSHA256, volatileSHA256, valid := authority.SoftwareLifecycleCompleteRemovalReview()
	if !valid {
		return CompleteRemovalViewResult{}
	}
	return CompleteRemovalViewResult{Status: InstallationStatus(status), StateRevision: revision, StateSHA256: stateSHA256, PermittedActions: []Action{ReviewCompleteRemoval}, candidate: CompleteRemovalCandidate{cell: &completeRemovalCandidateCell{authority: authority, status: status, revision: revision, sha256: stateSHA256, volatileSHA256: volatileSHA256}}}
}

type CompleteRemovalReview interface {
	SoftwareLifecycleCompleteRemovalReview() (identity string, valid bool)
}

type CompleteRemovalPlanRequest struct {
	Candidate             CompleteRemovalCandidate
	Review                CompleteRemovalReview
	ChangeSet             string
	PublicAuthorities     []systemchanges.PublicRemovalAuthority
	CloudflareAuthorities []systemchanges.CloudflareRemovalAuthority
	Disk                  systemchanges.DiskRequirement
}

type CompleteRemovalSummary struct {
	StartingStatus                InstallationStatus
	StateRevision                 uint64
	OwnedLocalCategories          []string
	CloudflareCategories          []string
	IrreversibleRemnants          []string
	CancellationBoundary          string
	TokenRevocationResponsibility string
	Rollback, FinalProof          string
	Disk                          systemchanges.DiskRequirement
	SudoAfterApproval, OneUse     bool
}

type removalProof struct {
	ReviewID           string
	Public, Cloudflare []removalResourceProof
}

type removalResourceProof struct {
	Resource, ImmutableID, InventorySHA256 string
	TokenActive, TokenAvailable            bool
}

type CompleteRemovalPlan struct {
	identity, sha256, changeSet, stateSHA256, volatileSHA256 string
	revision                                                 uint64
	status                                                   systemchanges.InstallationStatus
	proof                                                    removalProof
	disk                                                     systemchanges.DiskRequirement
	summary                                                  CompleteRemovalSummary
	used                                                     atomic.Bool
}

type CompleteRemovalRecheck struct {
	Candidate             CompleteRemovalCandidate
	Review                CompleteRemovalReview
	PublicAuthorities     []systemchanges.PublicRemovalAuthority
	CloudflareAuthorities []systemchanges.CloudflareRemovalAuthority
	TypedConfirmation     systemchanges.TypedRemovalConfirmation
	PermanentSelection    systemchanges.PermanentRemovalSelection
}

type CompleteRemovalApproval interface {
	AuthorizeAndRecheck(context.Context) (CompleteRemovalRecheck, error)
}

type CompleteRemovalApplyRequest struct {
	Approval      CompleteRemovalApproval
	PreparedState systemchanges.PreparedStateCommit
	SystemChanges systemchanges.Interface
	Cancellation  *systemchanges.Cancellation
}

func PlanCompleteRemoval(request CompleteRemovalPlanRequest) (*CompleteRemovalPlan, *InstallFinding) {
	refuse := func() (*CompleteRemovalPlan, *InstallFinding) {
		return nil, &InstallFinding{Code: CompleteRemovalPlanRefused, Problem: "The reviewed Complete removal Plan is incomplete or stale", NextAction: "Check again and build one fresh Complete removal Plan"}
	}
	if request.Review == nil || !installIdentityPattern.MatchString(request.ChangeSet) || !validInstallDisk(request.Disk) {
		return refuse()
	}
	status, revision, stateSHA256, volatileSHA256, valid := consumeCompleteRemovalCandidate(request.Candidate)
	reviewID, reviewValid := request.Review.SoftwareLifecycleCompleteRemovalReview()
	if !valid || !trustedRemovalValue(request.Review, "github.com/albertloky/SBXR/internal/ownerconsole", "RemovalReview") || !reviewValid || !installIdentityPattern.MatchString(reviewID) {
		return refuse()
	}
	proof, valid := removalPlanProof(reviewID, request.PublicAuthorities, request.CloudflareAuthorities)
	if !valid {
		return refuse()
	}
	bound := struct {
		Status                                 systemchanges.InstallationStatus
		Revision                               uint64
		StateSHA256, VolatileSHA256, ChangeSet string
		Proof                                  removalProof
		Disk                                   systemchanges.DiskRequirement
	}{status, revision, stateSHA256, volatileSHA256, request.ChangeSet, proof, request.Disk}
	encoded, err := json.Marshal(bound)
	if err != nil {
		return refuse()
	}
	digest := sha256.Sum256(encoded)
	checksum := hex.EncodeToString(digest[:])
	rollbackStatus := "the exact proven " + string(status) + " starting status"
	if status == systemchanges.RecoveryRequired && revision > 0 {
		rollbackStatus = "Recovery Required, or Managed only when the transaction-bound State proves the exact earlier Managed baseline"
	}
	summary := CompleteRemovalSummary{
		StartingStatus: InstallationStatus(status), StateRevision: revision,
		OwnedLocalCategories:          []string{"Desired State", "Client Access Values", "Infrastructure Secrets", "certificates and ACME material", "transaction journal", "Rollback Snapshot", "installed release", "verified update candidate", "services and timers", "service identities", "prepared artifacts", "Subscription Publication artifacts", "SBXR-owned firewall table", "public listeners", "public services", "removal journal", "recovery runner"},
		CloudflareCategories:          []string{"Tunnel routes before the checkpoint", "DNS records and Tunnel after the checkpoint"},
		IrreversibleRemnants:          []string{"Certificate Transparency entries cannot be erased", "DNS caches cannot be erased"},
		CancellationBoundary:          "Back or cancel restores the exact proven starting status until Irreversible removal started is durable; cancellation is impossible afterward",
		TokenRevocationResponsibility: "Albert revokes the scoped Cloudflare token only after owned remote cleanup is verified; SBXR verifies revocation before deleting the local copy",
		Rollback:                      "restore every changed exposure and Tunnel route from the one transaction Rollback Snapshot before the checkpoint to " + rollbackStatus,
		FinalProof:                    "Not installed with no retained SBXR recovery material", Disk: request.Disk, SudoAfterApproval: true, OneUse: true,
	}
	return &CompleteRemovalPlan{identity: request.ChangeSet + "-plan-" + checksum[:12], sha256: checksum, changeSet: request.ChangeSet, stateSHA256: stateSHA256, volatileSHA256: volatileSHA256, revision: revision, status: status, proof: proof, disk: request.Disk, summary: summary}, nil
}

func consumeCompleteRemovalCandidate(candidate CompleteRemovalCandidate) (systemchanges.InstallationStatus, uint64, string, string, bool) {
	if candidate.cell == nil {
		return "", 0, "", "", false
	}
	status, revision, stateSHA256, volatileSHA256, valid := candidate.cell.authority.SoftwareLifecycleCompleteRemoval()
	return status, revision, stateSHA256, volatileSHA256, valid && status == candidate.cell.status && revision == candidate.cell.revision && stateSHA256 == candidate.cell.sha256 && volatileSHA256 == candidate.cell.volatileSHA256
}

func removalPlanProof(reviewID string, public []systemchanges.PublicRemovalAuthority, cloudflare []systemchanges.CloudflareRemovalAuthority) (removalProof, bool) {
	proof := removalProof{ReviewID: reviewID}
	publicInventory, cloudflareInventory := map[string][]string(nil), map[string][]string(nil)
	for _, authority := range public {
		if !trustedRemovalValue(authority, "github.com/albertloky/SBXR/internal/networkpolicy", "RemovalAuthority") {
			return removalProof{}, false
		}
		review, resource, immutableID, inventory, valid := authority.SystemChangesPublicRemovalAuthority()
		if !valid || review != reviewID || !safeRemovalIdentity(resource) || !safeRemovalIdentity(immutableID) || publicInventory != nil && !reflect.DeepEqual(canonicalInventory(publicInventory), canonicalInventory(inventory)) {
			return removalProof{}, false
		}
		publicInventory = inventory
		proof.Public = append(proof.Public, removalResourceProof{Resource: resource, ImmutableID: immutableID, InventorySHA256: inventorySHA256(inventory)})
	}
	for _, authority := range cloudflare {
		if !trustedRemovalValue(authority, "github.com/albertloky/SBXR/internal/cloudflaretunnel", "RemovalAuthority") {
			return removalProof{}, false
		}
		value := authority.SystemChangesCloudflareRemovalAuthority()
		if !value.Valid || value.ReviewID != reviewID || !value.TokenActive || !value.TokenAvailable || !safeRemovalIdentity(string(value.Resource)) || !safeRemovalIdentity(value.ImmutableID) || cloudflareInventory != nil && !reflect.DeepEqual(canonicalInventory(cloudflareInventory), canonicalInventory(value.Inventory)) {
			return removalProof{}, false
		}
		cloudflareInventory = value.Inventory
		proof.Cloudflare = append(proof.Cloudflare, removalResourceProof{Resource: string(value.Resource), ImmutableID: value.ImmutableID, InventorySHA256: inventorySHA256(value.Inventory), TokenActive: value.TokenActive, TokenAvailable: value.TokenAvailable})
	}
	if !proofCoversInventory(proof.Public, publicInventory, []string{"firewall-table", "public-listener", "public-service"}) || !proofCoversInventory(proof.Cloudflare, cloudflareInventory, []string{"cloudflare-dns-record", "cloudflare-route", "cloudflare-tunnel"}) {
		return removalProof{}, false
	}
	sort.Slice(proof.Public, func(i, j int) bool {
		return proof.Public[i].Resource+proof.Public[i].ImmutableID < proof.Public[j].Resource+proof.Public[j].ImmutableID
	})
	sort.Slice(proof.Cloudflare, func(i, j int) bool {
		return proof.Cloudflare[i].Resource+proof.Cloudflare[i].ImmutableID < proof.Cloudflare[j].Resource+proof.Cloudflare[j].ImmutableID
	})
	return proof, true
}

func proofCoversInventory(proofs []removalResourceProof, inventory map[string][]string, categories []string) bool {
	if len(inventory) != len(categories) {
		return false
	}
	want, got := []string{}, []string{}
	for _, category := range categories {
		identities, ok := inventory[category]
		if !ok {
			return false
		}
		for _, identity := range identities {
			if !safeRemovalIdentity(identity) {
				return false
			}
			want = append(want, category+"="+identity)
		}
	}
	for _, proof := range proofs {
		got = append(got, proof.Resource+"="+proof.ImmutableID)
	}
	sort.Strings(want)
	sort.Strings(got)
	return reflect.DeepEqual(got, want)
}

func canonicalInventory(inventory map[string][]string) map[string][]string {
	copy := make(map[string][]string, len(inventory))
	for category, identities := range inventory {
		copy[category] = append([]string(nil), identities...)
		sort.Strings(copy[category])
	}
	return copy
}

func inventorySHA256(inventory map[string][]string) string {
	encoded, _ := json.Marshal(canonicalInventory(inventory))
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func safeRemovalIdentity(value string) bool { return installIdentityPattern.MatchString(value) }

func trustedRemovalValue(value any, packagePath, name string) bool {
	typeOf := reflect.TypeOf(value)
	return typeOf != nil && typeOf.Kind() == reflect.Struct && typeOf.PkgPath() == packagePath && typeOf.Name() == name
}

func (plan *CompleteRemovalPlan) Identity() string {
	if plan == nil {
		return ""
	}
	return plan.identity
}
func (plan *CompleteRemovalPlan) SHA256() string {
	if plan == nil {
		return ""
	}
	return plan.sha256
}
func (plan *CompleteRemovalPlan) Summary() CompleteRemovalSummary {
	if plan == nil {
		return CompleteRemovalSummary{}
	}
	result := plan.summary
	result.OwnedLocalCategories = append([]string(nil), result.OwnedLocalCategories...)
	result.CloudflareCategories = append([]string(nil), result.CloudflareCategories...)
	result.IrreversibleRemnants = append([]string(nil), result.IrreversibleRemnants...)
	return result
}
func (plan *CompleteRemovalPlan) String() string {
	if plan == nil {
		return "Software Lifecycle Complete removal Plan: unavailable"
	}
	return fmt.Sprintf("Software Lifecycle Complete removal Plan %s: %s revision %d; ordinary system sudo after approval; rollback remains possible until Irreversible removal started", plan.identity, plan.status, plan.revision)
}
func (plan *CompleteRemovalPlan) GoString() string { return plan.String() }
func (*CompleteRemovalPlan) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Software Lifecycle Complete removal Plan cannot be rendered")
}

func (plan *CompleteRemovalPlan) StateCompleteRemoval() (revision uint64, stateSHA256 string, valid bool) {
	if plan == nil || plan.status == systemchanges.RecoveryRequired && plan.revision == 0 && plan.stateSHA256 == "" {
		return 0, "", false
	}
	if plan.revision == 0 || !hashPattern.MatchString(plan.stateSHA256) {
		return 0, "", false
	}
	return plan.revision, plan.stateSHA256, true
}

func (plan *CompleteRemovalPlan) StateUnprovenCompleteRemoval() (changeSet, identity, sha256 string, valid bool) {
	if plan == nil || plan.status != systemchanges.RecoveryRequired || plan.revision != 0 || plan.stateSHA256 != "" {
		return "", "", "", false
	}
	return plan.changeSet, plan.identity, plan.sha256, true
}

func (plan *CompleteRemovalPlan) Apply(ctx context.Context, request CompleteRemovalApplyRequest) systemchanges.ApplyResult {
	if plan == nil || !plan.used.CompareAndSwap(false, true) {
		return completeRemovalRefused("SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-PLAN-USED", "The reviewed Complete removal Plan was already consumed")
	}
	if request.Approval == nil || reflect.ValueOf(request.Approval).Kind() == reflect.Pointer && reflect.ValueOf(request.Approval).IsNil() {
		return completeRemovalRefused("SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-APPROVAL", "Ordinary system sudo and both Owner confirmations are unavailable")
	}
	rechecked, err := request.Approval.AuthorizeAndRecheck(ctx)
	if err != nil {
		return completeRemovalRefused("SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-APPROVAL", "Approval was denied, cancelled, or expired")
	}
	if rechecked.Review == nil {
		return completeRemovalRefused("SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-STALE", "State, ownership, token availability, or reviewed removal categories changed after approval")
	}
	status, revision, stateSHA256, volatileSHA256, valid := consumeCompleteRemovalCandidate(rechecked.Candidate)
	reviewID, reviewValid := rechecked.Review.SoftwareLifecycleCompleteRemovalReview()
	proof, proofValid := removalPlanProof(reviewID, rechecked.PublicAuthorities, rechecked.CloudflareAuthorities)
	if !valid || status != plan.status || revision != plan.revision || stateSHA256 != plan.stateSHA256 || volatileSHA256 != plan.volatileSHA256 || !trustedRemovalValue(rechecked.Review, "github.com/albertloky/SBXR/internal/ownerconsole", "RemovalReview") || !reviewValid || !proofValid || !reflect.DeepEqual(proof, plan.proof) {
		return completeRemovalRefused("SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-STALE", "State, ownership, token availability, or reviewed removal categories changed after approval")
	}
	prepared, ok := request.PreparedState.(interface {
		SystemChangesPreparedState() (changeSet string, revision uint64, startingSHA256, candidateSHA256, planIdentity, planSHA256 string, valid bool)
	})
	if !ok {
		return completeRemovalRefused("SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-PREPARED", "The prepared State has no exact Complete removal binding")
	}
	changeSet, candidateRevision, startingSHA256, candidateSHA256, planIdentity, planSHA256, preparedValid := prepared.SystemChangesPreparedState()
	unproven := plan.status == systemchanges.RecoveryRequired && plan.revision == 0 && plan.stateSHA256 == ""
	preparedMatches := unproven && candidateRevision == 0 && startingSHA256 == "" && candidateSHA256 == "" || !unproven && candidateRevision == plan.revision+1 && startingSHA256 == plan.stateSHA256 && candidateSHA256 == plan.stateSHA256
	if !preparedValid || changeSet != plan.changeSet || !preparedMatches || planIdentity != plan.identity || planSHA256 != plan.sha256 {
		return completeRemovalRefused("SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-PREPARED", "The prepared State differs from the reviewed unchanged starting lineage")
	}
	steps, stepErr := completeRemovalSteps(rechecked.PermanentSelection, rechecked.PublicAuthorities, rechecked.CloudflareAuthorities)
	if stepErr != nil {
		return completeRemovalRefused("SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-AUTHORIZATION", "The exact typed confirmation, permanent selection, or owning resource proof was refused")
	}
	checks := []systemchanges.Check{
		{Owner: systemchanges.SoftwareModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "SOFTWARE-LIFECYCLE-REMOVAL-EXTERNAL-ABSENT"},
		{Owner: systemchanges.SoftwareModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "SOFTWARE-LIFECYCLE-REMOVAL-NOT-INSTALLED"},
	}
	change, err := systemchanges.NewChangeSet(systemchanges.ChangeSetSpec{
		Identity: changeSet, Mutation: systemchanges.CompleteRemovalMutation, OutcomeOwner: systemchanges.SoftwareModule,
		StartingState: systemchanges.StateLineage{Status: plan.status, Revision: plan.revision, SHA256: plan.stateSHA256}, TargetStateSHA256: plan.stateSHA256,
		Plan: systemchanges.PlanBinding{Identity: plan.identity, SHA256: plan.sha256, VolatileSHA256: plan.volatileSHA256}, PreparedState: request.PreparedState,
		TypedRemovalConfirmation: rechecked.TypedConfirmation, PermanentRemovalSelection: rechecked.PermanentSelection,
		Steps: steps, Checks: checks, Timeouts: systemchanges.Timeouts{Step: 5 * time.Minute, Check: 5 * time.Minute}, Disk: plan.disk,
	})
	if err != nil {
		return completeRemovalRefused("SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-AUTHORIZATION", "The confirmed removal could not form one exact Change Set")
	}
	if request.Cancellation != nil {
		return request.SystemChanges.ApplyWithCancellation(change, request.Cancellation)
	}
	return request.SystemChanges.Apply(change)
}

func completeRemovalSteps(selection systemchanges.PermanentRemovalSelection, public []systemchanges.PublicRemovalAuthority, cloudflare []systemchanges.CloudflareRemovalAuthority) ([]systemchanges.Step, error) {
	type authority struct {
		resource, identity string
		public             systemchanges.PublicRemovalAuthority
		cloudflare         systemchanges.CloudflareRemovalAuthority
	}
	ordered := make([]authority, 0, len(public)+len(cloudflare))
	for _, value := range public {
		_, resource, identity, _, _ := value.SystemChangesPublicRemovalAuthority()
		ordered = append(ordered, authority{resource: resource, identity: identity, public: value})
	}
	for _, value := range cloudflare {
		proof := value.SystemChangesCloudflareRemovalAuthority()
		ordered = append(ordered, authority{resource: string(proof.Resource), identity: proof.ImmutableID, cloudflare: value})
	}
	order := map[string]int{"firewall-table": 0, "public-listener": 1, "public-service": 2, "cloudflare-route": 3, "cloudflare-dns-record": 4, "cloudflare-tunnel": 5}
	sort.Slice(ordered, func(i, j int) bool {
		return order[ordered[i].resource] < order[ordered[j].resource] || order[ordered[i].resource] == order[ordered[j].resource] && ordered[i].identity < ordered[j].identity
	})
	steps := make([]systemchanges.Step, 0, len(ordered))
	for _, value := range ordered {
		var step systemchanges.Step
		var err error
		if value.public != nil {
			step, err = systemchanges.NewPublicExposureRemovalStep(selection, value.public)
		} else {
			step, err = systemchanges.NewCloudflareRemovalStep(selection, value.cloudflare)
		}
		if err != nil {
			return nil, err
		}
		steps = append(steps, step)
	}
	return steps, nil
}

func completeRemovalRefused(code, problem string) systemchanges.ApplyResult {
	return systemchanges.ApplyResult{Outcome: systemchanges.Refused, NothingChanged: true, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: systemchanges.EvidenceRules{SecretSafeOnly: true}, Finding: &systemchanges.Finding{Code: code, Owner: systemchanges.SoftwareModule, Problem: problem, Found: "the reviewed Complete removal authority is unavailable or changed", Required: "one fresh exact review plus both Owner confirmations", WhyStopped: "Complete removal cannot guess ownership or bypass rollback safety", NextAction: "Check again and create a fresh Complete removal Plan."}}
}
