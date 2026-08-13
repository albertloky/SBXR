package main

import (
	"context"
	"errors"
	"reflect"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

const completeRemovalTotalSteps uint16 = 20

var completeRemovalDisk = systemchanges.DiskRequirement{PreparationBytes: 8 << 20, TemporaryBytes: 8 << 20, SnapshotBytes: 64 << 20, JournalBytes: 8 << 20, RollbackBytes: 16 << 20, OverheadBytes: 256 << 20}

type builtCompleteRemoval struct {
	changeSet                         string
	plan                              *softwarelifecycle.CompleteRemovalPlan
	prepared                          *state.PreparedCommit
	candidate                         softwarelifecycle.CompleteRemovalCandidate
	review                            ownerconsole.RemovalReview
	typed                             ownerconsole.TypedRemovalConfirmation
	selection                         ownerconsole.PermanentRemovalSelection
	public                            []systemchanges.PublicRemovalAuthority
	cloudflare                        []systemchanges.CloudflareRemovalAuthority
	desired                           state.DesiredState
	token                             cloudflaretunnel.ManagementToken
	module                            state.Interface
	starting                          systemchanges.Observation
	disk                              systemchanges.DiskRequirement
	typedConfirmed, permanentSelected bool
}

type completeRemovalReviewObserver struct{ typed, permanent bool }

func (completeRemovalReviewObserver) ReviewedCategories(string) ([]string, error) {
	return ownerconsole.CompleteRemovalCategories(), nil
}
func (observer completeRemovalReviewObserver) TypedPhrase(string) (string, bool, error) {
	return "COMPLETE REMOVAL", observer.typed, nil
}
func (observer completeRemovalReviewObserver) PermanentRemovalSelected(string) (bool, error) {
	return observer.permanent, nil
}

type completePublicRemovalObserver struct {
	observation networkpolicy.RemovalObservation
}

func (observer completePublicRemovalObserver) ObserveRemovalResource(review, resource, identity string) (networkpolicy.RemovalObservation, error) {
	value := observer.observation
	value.ReviewID, value.Resource, value.ImmutableID = review, resource, identity
	return value, nil
}

type completeCloudflareRemovalObserver struct {
	observation cloudflaretunnel.RemovalObservation
}

func (observer completeCloudflareRemovalObserver) ObserveRemovalResource(review, resource, identity string) (cloudflaretunnel.RemovalObservation, error) {
	value := observer.observation
	value.ReviewID, value.Resource, value.ImmutableID = review, resource, identity
	return value, nil
}

func buildCompleteRemoval(ctx context.Context, changeSet string, prepareState bool) (*builtCompleteRemoval, error) {
	if ctx == nil || !validClientAccessChangeSet(changeSet) {
		return nil, errors.New("complete Complete removal inputs are required")
	}
	if pending, err := pendingStartupRecovery(); err != nil || pending {
		return nil, errors.New("an unfinished Change Set must recover before Complete removal")
	}
	module := statefilesystem.New()
	observed, release, err := managedLoadEvidence()
	if err != nil {
		return nil, errors.New("proven Cloudflare ownership and token authority are unavailable")
	}
	loaded, err := module.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: observed.StateRevision, LastCompletedChangeSet: state.ChangeSetIdentity(observed.LastChangeSet), ReleaseIdentity: release}})
	if err != nil || loaded.Snapshot == nil {
		return nil, errors.New("current proven State is unavailable")
	}
	built := &builtCompleteRemoval{changeSet: changeSet, module: module, desired: loaded.Snapshot.DesiredState, starting: observed, disk: completeRemovalDisk}
	err = module.WithManagedCloudflareSecrets(loaded, func(snapshot state.Snapshot, secrets state.InfrastructureSecretReader) error {
		token, tokenErr := cloudflaretunnel.NewManagementToken(secrets.ReadInfrastructureSecret(snapshot.DesiredState.Cloudflare.ManagementToken))
		if tokenErr != nil {
			return tokenErr
		}
		built.token = token
		return built.planRemoval(ctx, changeSet)
	})
	if err != nil {
		return nil, err
	}
	if prepareState {
		built.prepared, err = module.PrepareCompleteRemovalCommit(state.PrepareRequest{Loaded: loaded, CandidateReleaseIdentity: release, ChangeSet: state.ChangeSetIdentity(changeSet), Candidate: loaded.Snapshot.DesiredState}, built.plan)
	}
	return built, err
}

func (built *builtCompleteRemoval) planRemoval(ctx context.Context, changeSet string) error {
	base, err := systemubuntu.NewInstallHost("/", softwarelifecycle.ManagedUnitNames())
	if err != nil {
		return err
	}
	host := newCompleteRemovalHost(base, built.desired, cloudflaretunnel.NewProductionAPI(), built.token)
	if !host.allUnits(ctx, "is-active") || !host.allUnits(ctx, "is-enabled") {
		return errors.New("owned public services are not in the proven Managed state")
	}
	if body, commandErr := host.run(ctx, nil, "nft", "-j", "list", "table", "inet", "sbxr"); commandErr != nil || len(body) == 0 {
		return errors.New("owned firewall table is unavailable")
	}
	provider, err := host.observeTunnel(ctx)
	if err != nil || provider.TunnelID != built.desired.Cloudflare.TunnelID || !reflect.DeepEqual(provider.Routes, host.managedRoutes()) || !managedDNSMatches(provider.DNSRecords, managedTunnelExpected(built.desired).DNSRecords) {
		return errors.New("owned Cloudflare inventory differs from Desired State")
	}
	observation := built.starting
	changes := systemchanges.New(systemubuntu.NewAt("/", func() (systemchanges.Observation, error) { return observation, nil }, nil))
	view := (softwarelifecycle.Interface{}).ViewCompleteRemoval(changes)
	if view.Candidate() == (softwarelifecycle.CompleteRemovalCandidate{}) {
		return errors.New("Complete removal candidate unavailable")
	}
	console := ownerconsole.New(completeRemovalReviewObserver{})
	review, err := console.StartRemovalReview(changeSet)
	if err != nil {
		return err
	}
	publicInventory := map[string][]string{"firewall-table": {"inet-sbxr"}, "public-listener": {"sbxr-public-listeners"}, "public-service": {"sbxr-public-services"}}
	publicModule := networkpolicy.NewRemoval(completePublicRemovalObserver{networkpolicy.RemovalObservation{OwnedBySBXR: true, Inventory: publicInventory}})
	for resource, identities := range publicInventory {
		for _, identity := range identities {
			authority, proofErr := publicModule.ProveRemovalResource(changeSet, resource, identity)
			if proofErr != nil {
				return proofErr
			}
			built.public = append(built.public, authority)
		}
	}
	dns := []string{built.desired.Cloudflare.XHTTPDNSRecordID, built.desired.Cloudflare.WebSocketDNSRecordID}
	if built.desired.Cloudflare.DirectIPv4RecordID != "" {
		dns = append(dns, built.desired.Cloudflare.DirectIPv4RecordID)
	}
	if built.desired.Cloudflare.DirectIPv6RecordID != "" {
		dns = append(dns, built.desired.Cloudflare.DirectIPv6RecordID)
	}
	cloudflareInventory := map[string][]string{"cloudflare-dns-record": dns, "cloudflare-route": {built.desired.Cloudflare.TunnelID + "-routes"}, "cloudflare-tunnel": {built.desired.Cloudflare.TunnelID}}
	cloudflareModule := cloudflaretunnel.NewRemoval(completeCloudflareRemovalObserver{cloudflaretunnel.RemovalObservation{OwnedBySBXR: true, TokenActive: true, TokenAvailableLocally: true, Inventory: cloudflareInventory}})
	for resource, identities := range cloudflareInventory {
		for _, identity := range identities {
			authority, proofErr := cloudflareModule.ProveRemovalResource(changeSet, resource, identity)
			if proofErr != nil {
				return proofErr
			}
			built.cloudflare = append(built.cloudflare, authority)
		}
	}
	plan, finding := softwarelifecycle.PlanCompleteRemoval(softwarelifecycle.CompleteRemovalPlanRequest{Candidate: view.Candidate(), Review: review, ChangeSet: changeSet, PublicAuthorities: built.public, CloudflareAuthorities: built.cloudflare, Disk: built.disk})
	if finding != nil || plan == nil {
		return errors.New("Complete removal Plan refused")
	}
	built.plan, built.candidate, built.review = plan, view.Candidate(), review
	return err
}

type completeRemovalApproval struct{ built *builtCompleteRemoval }

func (approval completeRemovalApproval) AuthorizeAndRecheck(ctx context.Context) (softwarelifecycle.CompleteRemovalRecheck, error) {
	if approval.built == nil {
		return softwarelifecycle.CompleteRemovalRecheck{}, errors.New("Complete removal approval unavailable")
	}
	if !approval.built.typedConfirmed || !approval.built.permanentSelected {
		return softwarelifecycle.CompleteRemovalRecheck{}, errors.New("Complete removal approval unavailable")
	}
	rechecked, err := buildCompleteRemoval(ctx, approval.built.changeSet, false)
	if err != nil || rechecked.plan.Identity() != approval.built.plan.Identity() || rechecked.plan.SHA256() != approval.built.plan.SHA256() {
		return softwarelifecycle.CompleteRemovalRecheck{}, errors.New("Complete removal facts changed after approval")
	}
	console := ownerconsole.New(completeRemovalReviewObserver{typed: true, permanent: true})
	typed, err := console.RecordTypedPhrase(rechecked.review)
	if err != nil {
		return softwarelifecycle.CompleteRemovalRecheck{}, err
	}
	selection, err := console.SelectPermanentRemoval(rechecked.review, typed)
	return softwarelifecycle.CompleteRemovalRecheck{Candidate: rechecked.candidate, Review: rechecked.review, PublicAuthorities: rechecked.public, CloudflareAuthorities: rechecked.cloudflare, TypedConfirmation: typed, PermanentSelection: selection}, err
}

func applyCompleteRemoval(ctx context.Context, built *builtCompleteRemoval, cancellation *systemchanges.Cancellation) systemchanges.ApplyResult {
	if built == nil || built.plan == nil || built.prepared == nil {
		return systemchanges.Interface{}.Apply(nil)
	}
	base, err := systemubuntu.NewInstallHost("/", softwarelifecycle.ManagedUnitNames())
	if err != nil {
		return systemchanges.Interface{}.Apply(nil)
	}
	host := newCompleteRemovalHost(base, built.desired, cloudflaretunnel.NewProductionAPI(), built.token)
	observation := func() (systemchanges.Observation, error) {
		current, observeErr := installRecoveryObservation()
		if observeErr == nil {
			current.VolatileSHA256 = built.starting.VolatileSHA256
		}
		return current, observeErr
	}
	adapter := systemubuntu.NewAt("/", observation, host, built.module)
	return built.plan.Apply(ctx, softwarelifecycle.CompleteRemovalApplyRequest{Approval: completeRemovalApproval{built}, PreparedState: built.prepared, SystemChanges: systemchanges.New(adapter), Cancellation: cancellation})
}
