package cloudflareprofilesetup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type PlanRequest struct {
	StateLoad               state.LoadRequest
	NetworkPolicy           networkpolicy.Request
	CloudflareTunnel        cloudflaretunnel.PlanRequest
	CertificateLifecycle    certificatelifecycle.PlanRequest
	ConnectionProfiles      connectionprofiles.RegistryPlanRequest
	SubscriptionPublication subscriptionpublication.PlanRequest
	StatePrepare            state.PrepareRequest
	SoftwareLifecycleSHA256 string
	Disk                    systemchanges.DiskRequirement
	Confirmation            systemchanges.CloudflareSetupConfirmation
}

type PlanResult struct {
	Plan       *Plan
	Approval   Approval
	Correction *Correction
}

type Plan struct {
	identity, sha256, volatileSHA256 string
	changeSet                        string
	starting                         systemchanges.StateLineage
	prepared                         systemchanges.PreparedStateCommit
	steps                            []systemchanges.Step
	checks                           []systemchanges.Check
	disk                             systemchanges.DiskRequirement
	confirmation                     systemchanges.CloudflareSetupConfirmation
	review                           []string
	used                             atomic.Bool
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
	return plan.volatileSHA256
}

func (plan *Plan) Review() []string {
	if plan == nil {
		return nil
	}
	return append([]string(nil), plan.review...)
}

func (plan *Plan) String() string {
	if plan == nil {
		return "Cloudflare Profile Setup Plan: unavailable"
	}
	return fmt.Sprintf("Cloudflare Profile Setup Plan %s: Managed revision %d to %d; one Change Set; all five deferred profiles; six-profile publication; Irreversible Cloudflare setup started; Complete, Rolled back, or Recovery Required", plan.identity, plan.starting.Revision, plan.starting.Revision+1)
}

func (plan *Plan) GoString() string { return plan.String() }
func (*Plan) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Cloudflare Profile Setup Plan cannot be rendered as JSON")
}

type approvalCell struct{ plan *Plan }
type Approval struct{ cell *approvalCell }

func (Approval) String() string   { return "Cloudflare Profile Setup approval: redacted" }
func (Approval) GoString() string { return "Cloudflare Profile Setup approval: redacted" }
func (Approval) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Cloudflare Profile Setup approval cannot be rendered")
}

func (module *Interface) Plan(ctx context.Context, request PlanRequest) PlanResult {
	if module == nil || module.dependencies.validate() != nil || ctx == nil {
		return refusedPlan("CLOUDFLARE-SETUP-DEPENDENCIES", "all seven setup dependencies are required")
	}
	inspection := module.dependencies.SystemChanges.Inspect()
	if inspection.Status != systemchanges.Managed || inspection.Lock != systemchanges.LockReleased || inspection.CurrentChangeSet != "" {
		return refusedPlan("CLOUDFLARE-SETUP-TRANSACTION", "System Changes is not ready for one Managed Change Set")
	}
	loaded, err := module.dependencies.State.Load(request.StateLoad)
	if err != nil || loaded.Status != state.Managed || loaded.Snapshot == nil || !allDeferred(loaded.Snapshot.DesiredState.ConnectionProfiles) {
		return refusedPlan("CLOUDFLARE-SETUP-STATE", "one proven Managed revision with five profiles Not set up is required")
	}
	startingRevision := loaded.Snapshot.Revision
	desiredSHA256, err := state.CandidateSHA256(request.StatePrepare.Candidate)
	if err != nil || !validSHA256(desiredSHA256) || !validSHA256(request.SoftwareLifecycleSHA256) || !validRequestBinding(request, startingRevision, desiredSHA256) {
		return refusedPlan("CLOUDFLARE-SETUP-BINDING", "the revision, Change Set, Desired State, or shared facts disagree")
	}

	network := module.dependencies.NetworkPolicy(request.NetworkPolicy)
	if network.Outcome != networkpolicy.Healthy || network.CloudflareProfileSetup == nil || network.CloudflareProfileSetup.Binding.StartingRevision != startingRevision || network.CloudflareProfileSetup.Binding.CandidateRevision != startingRevision+1 || network.CloudflareProfileSetup.Binding.ChangeSetID != request.CloudflareTunnel.ChangeSet || network.CloudflareProfileSetup.Binding.DesiredStateSHA256 != desiredSHA256 {
		return refusedPlan("CLOUDFLARE-SETUP-NETWORK", "Network Policy refused the complete setup candidate")
	}

	request.CloudflareTunnel.Authority.NetworkPath = network.CloudflareTunnelPath
	cloudflare := module.dependencies.CloudflareTunnel(ctx, request.CloudflareTunnel)
	if cloudflare.Plan == nil || cloudflare.Health.Outcome != cloudflaretunnel.Healthy {
		return refusedPlan("CLOUDFLARE-SETUP-CLOUDFLARE", "Cloudflare Tunnel refused the selected authority or provider plan")
	}

	http01, ok := network.CloudflareProfileSetup.HTTP01Contribution()
	if !ok {
		return refusedPlan("CLOUDFLARE-SETUP-NETWORK", "temporary sbxr-domain HTTP-01 authority is unavailable")
	}
	request.CertificateLifecycle.HTTP01 = http01
	request.CertificateLifecycle.FreshDNS = certificatelifecycle.NewFreshDNSAuthority(network, cloudflare.Plan)
	certificate := module.dependencies.CertificateLifecycle(ctx, request.CertificateLifecycle)
	if certificate.Plan == nil || certificate.Health.Outcome != certificatelifecycle.Healthy {
		return refusedPlan("CLOUDFLARE-SETUP-CERTIFICATE", "Certificate Lifecycle refused sbxr-domain setup")
	}

	request.ConnectionProfiles.Candidate.Exposure = networkpolicy.NewListenerContribution(network)
	profiles := module.dependencies.ConnectionProfiles(ctx, request.ConnectionProfiles)
	if profiles.Plan == nil || profiles.Health.Outcome != connectionprofiles.Healthy {
		return refusedPlan("CLOUDFLARE-SETUP-PROFILES", "Connection Profiles refused the atomic five-profile candidate")
	}
	start, candidate, startingSHA, profileDesiredSHA, profileChangeSet, valid := profiles.Plan.StateProfileSetupConnectionProfiles()
	if !valid || start != startingRevision || candidate != startingRevision+1 || startingSHA != request.CloudflareTunnel.StartingStateSHA256 || profileDesiredSHA != desiredSHA256 || profileChangeSet != request.CloudflareTunnel.ChangeSet {
		return refusedPlan("CLOUDFLARE-SETUP-CONTRIBUTION", "Connection Profiles returned a mismatched or reused contribution")
	}

	publication := module.dependencies.SubscriptionPublication(ctx, request.SubscriptionPublication)
	if publication.Plan == nil {
		return refusedPlan("CLOUDFLARE-SETUP-PUBLICATION", "Subscription Publication refused six-profile publication")
	}
	summary := publication.Plan.Summary()
	if summary.ChangeSet != request.CloudflareTunnel.ChangeSet || summary.DesiredStateRevision != startingRevision+1 || summary.DesiredStateSHA256 != desiredSHA256 || summary.ProfileCount != 6 || !summary.ValidationComplete {
		return refusedPlan("CLOUDFLARE-SETUP-CONTRIBUTION", "Subscription Publication returned a mismatched contribution")
	}

	plan, wiring, err := composePlan(request, loaded, network, cloudflare.Plan, certificate.Plan, profiles.Plan, publication.Plan)
	if err != nil {
		return refusedPlan("CLOUDFLARE-SETUP-CONTRIBUTION", "the seven contributions do not form one complete Plan")
	}
	request.StatePrepare.Loaded = loaded
	request.StatePrepare.ChangeSet = state.ChangeSetIdentity(plan.changeSet)
	request.StatePrepare.ProfileSetupCertificate = certificate.Plan
	request.StatePrepare.SemanticValidators = state.SemanticValidators{ConnectionProfiles: wiring, Subscription: wiring, Cloudflare: wiring, Certificates: wiring, NetworkPolicy: wiring, SoftwareLifecycle: wiring}
	request.StatePrepare.ServiceMaterials = state.ServiceMaterialsFor(request.StatePrepare.Candidate)
	request.StatePrepare.SubscriptionPublication = wiring
	request.StatePrepare.ReviewedInputs, err = state.NewReviewedInputs(state.PlanIdentity(plan.identity), plan.sha256, wiring.managed)
	if err != nil {
		return refusedPlan("CLOUDFLARE-SETUP-STATE", "State review binding could not be created")
	}
	prepared, err := module.dependencies.State.Prepare(request.StatePrepare, cloudflare.Plan)
	if err != nil {
		return refusedPlan("CLOUDFLARE-SETUP-STATE", "State refused the complete revision candidate")
	}
	plan.prepared = prepared
	approval := Approval{cell: &approvalCell{plan: plan}}
	return PlanResult{Plan: plan, Approval: approval}
}

func validRequestBinding(request PlanRequest, revision uint64, desiredSHA string) bool {
	changeSet := request.CloudflareTunnel.ChangeSet
	return changeSet != "" && request.CloudflareTunnel.StartingRevision == revision && request.CloudflareTunnel.StartingStateSHA256 != "" && request.CloudflareTunnel.DesiredStateSHA256 == desiredSHA &&
		request.CertificateLifecycle.ChangeSet == changeSet && request.CertificateLifecycle.StartingRevision == revision && request.CertificateLifecycle.StartingStateSHA256 == request.CloudflareTunnel.StartingStateSHA256 && request.CertificateLifecycle.DesiredStateSHA256 == desiredSHA &&
		request.ConnectionProfiles.ChangeSet == changeSet && request.ConnectionProfiles.StartingStateSHA256 == request.CloudflareTunnel.StartingStateSHA256 && request.ConnectionProfiles.DesiredStateSHA256 == desiredSHA &&
		request.SubscriptionPublication.ChangeSet == changeSet && request.SubscriptionPublication.StartingState.Status == systemchanges.Managed && request.SubscriptionPublication.StartingState.Revision == revision && request.SubscriptionPublication.StartingState.SHA256 == request.CloudflareTunnel.StartingStateSHA256 && request.SubscriptionPublication.DesiredStateRevision == revision+1 && request.SubscriptionPublication.DesiredStateSHA256 == desiredSHA &&
		request.StatePrepare.ChangeSet == state.ChangeSetIdentity(changeSet)
}

func refusedPlan(code, found string) PlanResult {
	return PlanResult{Correction: &Correction{Code: code, Problem: "Cloudflare Profile Setup Plan is unavailable", Found: found, Required: "one fresh complete contribution from each of the seven owning Modules", WhyStopped: "setup never accepts stale, partial, reused, or caller-made authority", NextAction: "Correct the named dependency, then build and review a fresh Plan."}}
}

type setupWiring struct {
	identity, sha256 string
	current          state.DesiredState
	candidate        state.DesiredState
	network          networkpolicy.Result
	cloudflare       *cloudflaretunnel.Plan
	certificate      *certificatelifecycle.Plan
	profiles         *connectionprofiles.Plan
	publication      *subscriptionpublication.Plan
	managed          state.ManagedInputChecksums
}

func (w *setupWiring) Identity() string { return w.identity }
func (w *setupWiring) SHA256() string   { return w.sha256 }
func (w *setupWiring) PrepareSubscriptionPublication() ([]byte, error) {
	return w.publication.PrepareSubscriptionPublication()
}
func (w *setupWiring) ValidateConnectionProfiles(value state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) error {
	return w.profiles.ValidateConnectionProfiles(value, secrets)
}
func (w *setupWiring) PrepareConnectionProfiles(value state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) ([]byte, []byte, error) {
	return w.profiles.PrepareConnectionProfiles(value, secrets)
}
func (w *setupWiring) ValidateSubscription(value state.SubscriptionSettings, secrets state.ClientAccessReader) error {
	return w.publication.ValidateSubscription(value, secrets)
}
func (w *setupWiring) ValidateCloudflare(value state.CloudflareSettings, secrets state.InfrastructureSecretReader) error {
	if secrets == nil || !w.cloudflare.MatchesDesiredState(value.AccountID, value.ZoneID, value.ZoneName, value.TunnelName, value.XHTTPHostname, value.WebSocketHostname, value.DirectHostname, w.candidate.NetworkPolicy.PublicIPv4, w.candidate.NetworkPolicy.PublicIPv6, secrets.ReadInfrastructureSecret(value.ManagementToken)) {
		return errors.New("Cloudflare Tunnel Plan does not match Desired State")
	}
	return nil
}
func (w *setupWiring) ValidateCertificates(value state.CertificateSettings) error {
	if !w.certificate.MatchesDesiredState(value.RenewalPolicy, value.OwnerEmail, value.ACMEAccountID, value.IPCertificateID, value.IPServingPointer, value.DomainCertificateID, value.DomainServingPointer, value.DomainHostname) {
		return errors.New("Certificate Lifecycle Plan does not match Desired State")
	}
	return nil
}
func (w *setupWiring) ValidateNetworkPolicy(value state.NetworkPolicyInputs) error {
	if value != w.candidate.NetworkPolicy || !w.network.MatchesDesiredState(value.SSHPort, value.PublicIPv4, value.PublicIPv6, value.PrimarySubscriptionAddress) {
		return errors.New("Network Policy Plan does not match Desired State")
	}
	return nil
}
func (w *setupWiring) ValidateSoftwareLifecycle(value state.SoftwareLifecycleIntent) error {
	if value.Installation != w.current.Installation || value.Software != w.current.Software || value.Installation != w.candidate.Installation || value.Software != w.candidate.Software {
		return errors.New("Cloudflare Profile Setup changed Software Lifecycle State")
	}
	return nil
}

func composePlan(request PlanRequest, loaded state.Result, network networkpolicy.Result, cloudflare *cloudflaretunnel.Plan, certificate *certificatelifecycle.Plan, profiles *connectionprofiles.Plan, publication *subscriptionpublication.Plan) (*Plan, *setupWiring, error) {
	networkBytes, err := json.Marshal(network.CloudflareProfileSetup)
	if err != nil {
		return nil, nil, err
	}
	networkDigest := sha256.Sum256(networkBytes)
	managed, err := state.NewManagedInputChecksums(profiles.SHA256(), publication.SHA256(), cloudflare.SHA256(), certificate.SHA256(), hex.EncodeToString(networkDigest[:]), request.SoftwareLifecycleSHA256)
	if err != nil {
		return nil, nil, err
	}
	bound := struct {
		ChangeSet                                  string
		StartingRevision, CandidateRevision        uint64
		StartingSHA256, DesiredSHA256              string
		Network, Cloudflare, Certificate, Profiles string
		Publication, SoftwareLifecycle             string
	}{request.CloudflareTunnel.ChangeSet, loaded.Snapshot.Revision, loaded.Snapshot.Revision + 1, request.CloudflareTunnel.StartingStateSHA256, request.CloudflareTunnel.DesiredStateSHA256, hex.EncodeToString(networkDigest[:]), cloudflare.SHA256(), certificate.SHA256(), profiles.SHA256(), publication.SHA256(), request.SoftwareLifecycleSHA256}
	encoded, err := json.Marshal(bound)
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(encoded)
	sha := hex.EncodeToString(digest[:])
	volatile := sha256.Sum256([]byte(strings.Join([]string{profiles.VolatileSHA256(), publication.VolatileSHA256(), hex.EncodeToString(networkDigest[:])}, "\n")))
	steps := append([]systemchanges.Step(nil), cloudflare.Steps()...)
	steps = append(steps, certificate.Steps()...)
	steps = append(steps, profiles.Steps()...)
	firewall, err := systemchanges.NewFirewallPolicyStep(network.CloudflareProfileSetup.CandidatePolicy.Nftables, request.StatePrepare.Candidate.NetworkPolicy.SSHPort)
	if err != nil {
		return nil, nil, err
	}
	steps = append(steps, firewall)
	steps = append(steps, publication.Steps()...)
	checks := append([]systemchanges.Check(nil), cloudflare.Checks()...)
	checks = append(checks, certificate.Checks()...)
	checks = append(checks, profiles.Checks()...)
	checks = append(checks, publication.Checks()...)
	plan := &Plan{
		identity: "cloudflare-setup-" + sha[:24], sha256: sha, volatileSHA256: hex.EncodeToString(volatile[:]), changeSet: request.CloudflareTunnel.ChangeSet,
		starting: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: loaded.Snapshot.Revision, SHA256: request.CloudflareTunnel.StartingStateSHA256},
		steps:    steps, checks: checks, disk: request.Disk, confirmation: request.Confirmation,
		review: []string{"Starting authority and Release Identity", "selected provider authority and immutable ownership", "domain, three hostnames, ports, address families, and collisions", "one Tunnel, two routes, DNS-only records, and temporary TCP 80", "sbxr-domain, local services, artifacts, exposure, and gates", "five profile credential categories and six-profile publication", "interruptions, residue, reversible outcome, and forward-only outcome", "Irreversible Cloudflare setup started; Complete, Rolled back, or Recovery Required"},
	}
	wiring := &setupWiring{identity: plan.identity, sha256: plan.sha256, current: loaded.Snapshot.DesiredState, candidate: request.StatePrepare.Candidate, network: network, cloudflare: cloudflare, certificate: certificate, profiles: profiles, publication: publication, managed: managed}
	return plan, wiring, nil
}

type ApplyKind string

const (
	ApplyComplete         ApplyKind = "Complete"
	ApplyRolledBack       ApplyKind = "Rolled back"
	ApplyRecoveryRequired ApplyKind = "Recovery Required"
	ApplyRefused          ApplyKind = "Refused"
)

type ApplyResult struct {
	Kind       ApplyKind
	Operation  string
	Correction *Correction
}

func (module *Interface) Apply(approval Approval) ApplyResult {
	if module == nil || approval.cell == nil || approval.cell.plan == nil || module.dependencies.SystemChanges.Apply == nil {
		return ApplyResult{Kind: ApplyRefused, Correction: refusedPlan("CLOUDFLARE-SETUP-APPROVAL", "one exact opaque approval is required").Correction}
	}
	plan := approval.cell.plan
	if !plan.used.CompareAndSwap(false, true) {
		return ApplyResult{Kind: ApplyRefused, Operation: plan.changeSet, Correction: refusedPlan("CLOUDFLARE-SETUP-PLAN-USED", "the Plan was already consumed").Correction}
	}
	changeSet, err := systemchanges.NewChangeSet(systemchanges.ChangeSetSpec{Identity: plan.changeSet, Mutation: systemchanges.CloudflareProfileSetupMutation, OutcomeOwner: systemchanges.CloudflareProfileSetupModule, StartingState: plan.starting, TargetStateSHA256: planSHA256(plan.prepared), Plan: systemchanges.PlanBinding{Identity: plan.identity, SHA256: plan.sha256, VolatileSHA256: plan.volatileSHA256}, PreparedState: plan.prepared, CloudflareSetupConfirmation: plan.confirmation, Steps: plan.steps, Checks: plan.checks, Timeouts: systemchanges.Timeouts{Step: 5 * time.Minute, Check: 5 * time.Minute}, Disk: plan.disk})
	if err != nil {
		return ApplyResult{Kind: ApplyRefused, Operation: plan.changeSet, Correction: refusedPlan("CLOUDFLARE-SETUP-CHANGE-SET", "System Changes refused the composed Change Set").Correction}
	}
	result := module.dependencies.SystemChanges.Apply(changeSet)
	output := ApplyResult{Operation: plan.changeSet}
	switch result.Outcome {
	case systemchanges.Completed:
		output.Kind = ApplyComplete
	case systemchanges.RollbackSucceeded:
		output.Kind = ApplyRolledBack
	case systemchanges.RecoveryRequiredOutcome:
		output.Kind = ApplyRecoveryRequired
	default:
		output.Kind = ApplyRefused
		output.Correction = refusedPlan("CLOUDFLARE-SETUP-APPLY", "System Changes refused the approved Change Set").Correction
	}
	return output
}

func planSHA256(prepared systemchanges.PreparedStateCommit) string {
	if prepared == nil {
		return ""
	}
	_, _, _, candidate, _, _, valid := prepared.SystemChangesPreparedState()
	if !valid {
		return ""
	}
	return candidate
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
