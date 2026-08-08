package subscriptionpublication

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

var planIdentityPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

type RelevantChecksums struct {
	ConnectionProfiles string `json:"connection_profiles"`
	Subscription       string `json:"subscription"`
}

type PlanRequest struct {
	Source                  connectionprofiles.PublicationSource
	Secrets                 state.ClientAccessReader
	Subscription            state.SubscriptionSettings
	ChangeSet               string
	StartingState           systemchanges.StateLineage
	DesiredStateRevision    uint64
	DesiredStateSHA256      string
	ManagedInputsSHA256     string
	RelevantChecksums       RelevantChecksums
	CompatibilityDefinition CompatibilityDefinition
	SelectedAddress         string
	ReleaseIdentity         state.ReleaseIdentity
	ClientAccessMutation    *ClientAccessMutation
}

type PlanSummary struct {
	Identity, ChangeSet, DesiredStateSHA256, ManagedInputsSHA256 string
	SelectedAddress, CompatibilityDefinition                     string
	RelevantChecksums                                            RelevantChecksums
	DesiredStateRevision                                         uint64
	ReleaseIdentity                                              state.ReleaseIdentity
	Representations                                              []string
	ProfileCount                                                 int
	Omissions                                                    []connectionprofiles.PublicationOmission
	ValidationComplete                                           bool
	Replacement, Rollback                                        string
	ClientAccessEffect                                           string
}

type Plan struct {
	identity, sha256 string
	binding          planBinding
	summary          PlanSummary
	bundle           []byte
	steps            []systemchanges.Step
	checks           []systemchanges.Check
	prepared, used   atomic.Bool
}

type planBinding struct {
	Subscription         state.SubscriptionSettings
	ChangeSet            string
	StartingState        systemchanges.StateLineage
	DesiredStateRevision uint64
	DesiredStateSHA256   string
	ManagedInputsSHA256  string
}

type PlanResult struct {
	Plan    *Plan
	Finding *systemchanges.Finding
}

func (module Interface) Plan(ctx context.Context, request PlanRequest) PlanResult {
	refuse := func(code, found string) PlanResult {
		return PlanResult{Finding: &systemchanges.Finding{Code: code, Owner: systemchanges.SubscriptionModule, Problem: "The Subscription Publication Plan is incomplete or stale", Found: found, Required: "one exact validated complete artifact set bound to revision N+1", WhyStopped: "publication cannot guess or expose protected inputs", NextAction: "Reload the typed source and create a fresh Plan."}}
	}
	action, effect := ClientAccessAction(""), ""
	source := request.Source
	secrets := request.Secrets
	if request.ClientAccessMutation != nil {
		action, effect = request.ClientAccessMutation.action, request.ClientAccessMutation.effect
		if request.Subscription != request.ClientAccessMutation.subscription || request.SelectedAddress != request.ClientAccessMutation.address || !connectionprofiles.PublicationSourceMatches(request.Source, request.ClientAccessMutation.source) {
			return refuse("SUBSCRIPTION-PUBLICATION-PLAN-INPUT", "the Client Access mutation does not match the typed candidate")
		}
		source = request.ClientAccessMutation.source
		secrets = clientAccessPlanReader{mutation: request.ClientAccessMutation, fallback: request.Secrets}
	}
	_, validAction := clientAccessEffect(action)
	if ctx == nil || request.Secrets == nil || secrets == nil || !planIdentityPattern.MatchString(request.ChangeSet) || request.DesiredStateRevision != request.StartingState.Revision+1 || !validPlanSHA(request.DesiredStateSHA256) || !validPlanSHA(request.ManagedInputsSHA256) || !validPlanSHA(request.RelevantChecksums.ConnectionProfiles) || !validPlanSHA(request.RelevantChecksums.Subscription) || request.CompatibilityDefinition != CurrentCompatibilityDefinition || request.Subscription.ListenPort == 0 || request.Subscription.CertificateID == "" || secrets.ReadClientAccessValue(request.Subscription.Token) == "" || !validRelease(request.ReleaseIdentity) || !validAction {
		return refuse("SUBSCRIPTION-PUBLICATION-PLAN-INPUT", "a required typed binding is missing or invalid")
	}
	address, err := netip.ParseAddr(request.SelectedAddress)
	if err != nil || !address.IsGlobalUnicast() || request.StartingState.Status != systemchanges.Managed && request.StartingState.Status != systemchanges.NotInstalled || request.StartingState.Status == systemchanges.Managed && !validPlanSHA(request.StartingState.SHA256) {
		return refuse("SUBSCRIPTION-PUBLICATION-PLAN-LINEAGE", "the selected address or starting lineage is invalid")
	}
	if request.ClientAccessMutation != nil && !request.ClientAccessMutation.used.CompareAndSwap(false, true) {
		return refuse("SUBSCRIPTION-PUBLICATION-PLAN-ONE-USE", "the Client Access mutation was already planned")
	}
	var rendered Artifacts
	if request.ClientAccessMutation != nil && request.ClientAccessMutation.rotation != nil {
		err = request.ClientAccessMutation.rotation.WithClientAccessReader(func(generated state.ClientAccessReader) error {
			rendered, err = module.Render(ctx, source, clientAccessPlanReader{mutation: request.ClientAccessMutation, generated: generated, fallback: request.Secrets})
			return err
		})
	} else {
		rendered, err = module.Render(ctx, source, secrets)
	}
	if err != nil {
		return refuse("SUBSCRIPTION-PUBLICATION-PLAN-VALIDATION", "the complete candidate failed rendering or full-document validation")
	}
	artifacts := map[string][]byte{
		"base64": rendered.Base64, "raw": rendered.Raw, "v2rayn": rendered.V2RayN, "shadowrocket": rendered.Shadowrocket,
		"karing": rendered.Karing.Body, "mihomo": rendered.Mihomo, "sing-box": rendered.SingBox.Body,
	}
	omissions := make([]Omission, len(rendered.Omissions))
	for index, omission := range rendered.Omissions {
		omissions[index] = Omission{ID: string(omission.ID)}
	}
	names := Names()
	metadata := Metadata{Schema: "sbxr-subscription-artifact-set-v1", ChangeSet: request.ChangeSet, SelectedAddress: request.SelectedAddress, DesiredStateSHA256: request.DesiredStateSHA256, ManagedInputsSHA256: request.ManagedInputsSHA256, RelevantChecksums: request.RelevantChecksums, Compatibility: string(request.CompatibilityDefinition), DesiredStateRevision: request.DesiredStateRevision, ReleaseIdentity: request.ReleaseIdentity, ClientAccessAction: action, Representations: names[:7], ProfileCount: rendered.ProfileCount, Omissions: omissions, ValidationComplete: true}
	set, err := NewPreparedArtifactSet(artifacts, metadata)
	if err != nil {
		return refuse("SUBSCRIPTION-PUBLICATION-PLAN-METADATA", "candidate metadata could not be encoded")
	}
	bundle, err := set.Bundle()
	if err != nil {
		return refuse("SUBSCRIPTION-PUBLICATION-PLAN-METADATA", "candidate artifact bundle could not be encoded")
	}
	sha := BundleSHA256(bundle)
	step, err := systemchanges.NewStep(systemchanges.SubscriptionModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		return refuse("SUBSCRIPTION-PUBLICATION-PLAN-TRANSACTION", "the reversible activation step was refused")
	}
	checks := []systemchanges.Check{
		{Owner: systemchanges.SubscriptionModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "SUBSCRIPTION-PUBLICATION-CANDIDATE"},
		{Owner: systemchanges.SubscriptionModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "SUBSCRIPTION-PUBLICATION-ACTIVATION"},
		{Owner: systemchanges.SubscriptionModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "SUBSCRIPTION-PUBLICATION-SERVING-AGREEMENT"},
	}
	identity := "subscriptions-" + sha[:12]
	summary := PlanSummary{Identity: identity, ChangeSet: request.ChangeSet, DesiredStateSHA256: request.DesiredStateSHA256, ManagedInputsSHA256: request.ManagedInputsSHA256, SelectedAddress: request.SelectedAddress, CompatibilityDefinition: string(request.CompatibilityDefinition), RelevantChecksums: request.RelevantChecksums, DesiredStateRevision: request.DesiredStateRevision, ReleaseIdentity: request.ReleaseIdentity, Representations: append([]string(nil), names[:7]...), ProfileCount: rendered.ProfileCount, Omissions: source.Omissions(), ValidationComplete: true, Replacement: "complete artifact set N to N+1", Rollback: "restore the exact prior complete artifact set", ClientAccessEffect: effect}
	binding := planBinding{Subscription: request.Subscription, ChangeSet: request.ChangeSet, StartingState: request.StartingState, DesiredStateRevision: request.DesiredStateRevision, DesiredStateSHA256: request.DesiredStateSHA256, ManagedInputsSHA256: request.ManagedInputsSHA256}
	return PlanResult{Plan: &Plan{identity: identity, sha256: sha, binding: binding, summary: summary, bundle: append([]byte(nil), bundle...), steps: []systemchanges.Step{step}, checks: checks}}
}

func validPlanSHA(value string) bool {
	decoded, err := hex.DecodeString(value)
	return len(value) == 64 && err == nil && hex.EncodeToString(decoded) == value
}

func validRelease(value state.ReleaseIdentity) bool {
	commit, commitErr := hex.DecodeString(value.Commit)
	return value.Repository != "" && value.Tag != "" && (len(value.Commit) == 40 || len(value.Commit) == 64) && commitErr == nil && hex.EncodeToString(commit) == value.Commit && validPlanSHA(value.ReleaseIndexSHA256)
}

func (plan *Plan) Identity() string {
	if plan == nil {
		return ""
	}
	return plan.identity
}
func (plan *Plan) SHA256() string {
	if plan == nil {
		return ""
	}
	return plan.sha256
}
func (plan *Plan) VolatileSHA256() string {
	if plan == nil {
		return ""
	}
	return plan.binding.ManagedInputsSHA256
}
func (plan *Plan) Steps() []systemchanges.Step {
	if plan == nil {
		return nil
	}
	return append([]systemchanges.Step(nil), plan.steps...)
}
func (plan *Plan) Checks() []systemchanges.Check {
	if plan == nil {
		return nil
	}
	return append([]systemchanges.Check(nil), plan.checks...)
}
func (plan *Plan) Summary() PlanSummary {
	if plan == nil {
		return PlanSummary{}
	}
	summary := plan.summary
	summary.Representations = append([]string(nil), summary.Representations...)
	summary.Omissions = append([]connectionprofiles.PublicationOmission(nil), summary.Omissions...)
	return summary
}
func (plan *Plan) String() string {
	if plan == nil {
		return "Subscription Publication Plan: unavailable"
	}
	return fmt.Sprintf("Subscription Publication Plan %s: %d Connection Profiles, 7 validated representations, bodies redacted", plan.identity, plan.summary.ProfileCount)
}
func (plan *Plan) GoString() string { return plan.String() }
func (*Plan) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Subscription Publication Plan cannot be rendered")
}

// PrepareSubscriptionPublication is State's one-use protected artifact handoff.
func (plan *Plan) PrepareSubscriptionPublication() ([]byte, error) {
	if plan == nil || !plan.prepared.CompareAndSwap(false, true) || len(plan.bundle) == 0 {
		return nil, errors.New("Subscription Publication prepared artifact authority unavailable")
	}
	return append([]byte(nil), plan.bundle...), nil
}

// ValidateSubscription binds State's subscription credential and listener to this Plan.
func (plan *Plan) ValidateSubscription(settings state.SubscriptionSettings, secrets state.ClientAccessReader) error {
	if plan == nil || secrets == nil || settings != plan.binding.Subscription || secrets.ReadClientAccessValue(settings.Token) == "" {
		return errors.New("Subscription Publication Plan does not match the typed subscription settings")
	}
	return nil
}

func (plan *Plan) Apply(module systemchanges.Interface, prepared systemchanges.PreparedStateCommit, starting systemchanges.StateLineage, managedInputsSHA256 string, disk systemchanges.DiskRequirement) systemchanges.ApplyResult {
	if plan == nil || !plan.used.CompareAndSwap(false, true) || prepared == nil || starting != plan.binding.StartingState || managedInputsSHA256 != plan.binding.ManagedInputsSHA256 {
		return module.Apply(nil)
	}
	changeSet, revision, startingSHA256, candidateSHA256, planIdentity, planSHA256, valid := prepared.SystemChangesPreparedState()
	if !valid || changeSet != plan.binding.ChangeSet || revision != plan.binding.DesiredStateRevision || startingSHA256 != starting.SHA256 || candidateSHA256 != plan.binding.DesiredStateSHA256 || planIdentity != plan.identity || planSHA256 != plan.sha256 {
		return module.Apply(nil)
	}
	mutation := systemchanges.SettingChangeMutation
	if starting.Status == systemchanges.NotInstalled {
		mutation = systemchanges.InstallationMutation
	}
	change, err := systemchanges.NewChangeSet(systemchanges.ChangeSetSpec{Identity: plan.binding.ChangeSet, Mutation: mutation, OutcomeOwner: systemchanges.SubscriptionModule, StartingState: starting, TargetStateSHA256: candidateSHA256, Plan: systemchanges.PlanBinding{Identity: plan.identity, SHA256: plan.sha256, VolatileSHA256: managedInputsSHA256}, PreparedState: prepared, Steps: plan.steps, Checks: plan.checks, Timeouts: systemchanges.Timeouts{Step: time.Minute, Check: time.Minute}, Disk: disk})
	if err != nil {
		return module.Apply(nil)
	}
	return module.Apply(change)
}
