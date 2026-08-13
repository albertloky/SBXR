package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	profilesubuntu "github.com/albertloky/SBXR/internal/connectionprofiles/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwaregithub "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/github"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type softwareChangeAction string

const (
	softwareUpdate    softwareChangeAction = "update"
	softwareDowngrade softwareChangeAction = "downgrade"
)

type builtSoftwareChange struct {
	action                   softwareChangeAction
	changeSet                string
	plan                     *softwarelifecycle.UpdatePlan
	prepared                 *state.PreparedCommit
	installed, candidate     softwarelifecycle.VerifiedRelease
	installedCandidate, next softwarelifecycle.InstallCandidate
	contributions            []softwarelifecycle.UpdateContribution
	starting                 systemchanges.StateLineage
	desired                  state.DesiredState
	disk                     systemchanges.DiskRequirement
	totalSteps               int
	cloudflare               cloudflaretunnel.Executor
	profilePlan              *connectionprofiles.Plan
	publication              *subscriptionpublication.Plan
	module                   state.Interface
}

type softwareChangeProfileHost struct {
	profilesubuntu.RealityHost
	candidate profilesubuntu.CandidateHost
}

func (host softwareChangeProfileHost) ValidateReality(ctx context.Context, version string, document io.Reader) error {
	return host.candidate.ValidateReality(ctx, version, document)
}

func (host softwareChangeProfileHost) ValidateSingBox(ctx context.Context, version string, document io.Reader) error {
	return host.candidate.ValidateSingBox(ctx, version, document)
}

func prepareSoftwareChange(ctx context.Context, action softwareChangeAction, tag, changeSet string) (*builtSoftwareChange, error) {
	if ctx == nil || action != softwareUpdate && action != softwareDowngrade || !validClientAccessChangeSet(changeSet) {
		return nil, errors.New("complete Software Lifecycle change inputs are required")
	}
	if pending, err := pendingStartupRecovery(); err != nil || pending {
		return nil, errors.New("an unfinished Change Set must recover before a Software Lifecycle Plan")
	}
	observed, release, err := managedLoadEvidence()
	if err != nil {
		return nil, err
	}
	installed, installedCandidate, candidate, next, err := verifiedSoftwareChangeCandidates(ctx, release, action, tag)
	if err != nil {
		return nil, err
	}
	module := statefilesystem.New()
	loaded, err := module.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: observed.StateRevision, LastCompletedChangeSet: state.ChangeSetIdentity(observed.LastChangeSet), ReleaseIdentity: release}})
	if err != nil || loaded.Snapshot == nil {
		return nil, errors.New("current Managed State is unavailable")
	}
	_, archive, components, valid := next.SoftwareLifecyclePreparedArchive()
	_, _, _, priorValid := installedCandidate.SoftwareLifecyclePreparedArchive()
	if !valid || !priorValid {
		return nil, errors.New("candidate release material is unavailable")
	}
	candidateBytes := len(archive) + len(components)
	// The protected snapshot contains the candidate archives and the expanded
	// prior release tree. Bind the same hard upper bound enforced by its reader.
	snapshotBytes := uint64(6 * softwarelifecycle.MaxAssetBytes)
	disk := systemchanges.DiskRequirement{PreparationBytes: uint64(candidateBytes), TemporaryBytes: uint64(candidateBytes), SnapshotBytes: snapshotBytes, JournalBytes: 8 << 20, RollbackBytes: snapshotBytes, OverheadBytes: 256 << 20}
	var built *builtSoftwareChange
	err = module.WithManagedConnectionProfileSecrets(loaded, func(snapshot state.Snapshot, profileSecrets state.ConnectionProfileSecretReader) error {
		return module.WithManagedSubscriptionSecrets(loaded, func(_ state.Snapshot, publicationSecrets state.ClientAccessReader) error {
			return module.WithManagedCloudflareSecrets(loaded, func(_ state.Snapshot, cloudflareSecrets state.InfrastructureSecretReader) error {
				var buildErr error
				built, buildErr = buildSoftwareChange(ctx, module, loaded, snapshot, profileSecrets, publicationSecrets, cloudflareSecrets, action, changeSet, disk, installed, installedCandidate, candidate, next)
				return buildErr
			})
		})
	})
	return built, err
}

func verifiedSoftwareChangeCandidates(ctx context.Context, release state.ReleaseIdentity, action softwareChangeAction, selectedTag string) (softwarelifecycle.VerifiedRelease, softwarelifecycle.InstallCandidate, softwarelifecycle.VerifiedRelease, softwarelifecycle.InstallCandidate, error) {
	source := softwaregithub.New()
	module := softwarelifecycle.New(source, softwarelifecycle.VerifierQualification{Version: softwaregithub.Version, SigningFingerprint: softwaregithub.SigningFingerprint}, time.Now, softwareubuntu.NewStager())
	architecture := softwarelifecycle.Architecture(runtime.GOARCH)
	current := module.View(ctx, softwarelifecycle.ViewRequest{Tag: release.Tag, Architecture: architecture, InstallationStatus: softwarelifecycle.NotInstalled})
	installed, installedCandidate := current.VerifiedCandidate, current.InstallCandidate()
	if current.Refusal != nil || installed == nil || installed.Identity.Repository != release.Repository || installed.Identity.Tag != release.Tag || installed.Identity.Commit != release.Commit || installed.Identity.IndexSHA256 != release.ReleaseIndexSHA256 {
		return softwarelifecycle.VerifiedRelease{}, softwarelifecycle.InstallCandidate{}, softwarelifecycle.VerifiedRelease{}, softwarelifecycle.InstallCandidate{}, errors.New("installed release could not be freshly verified")
	}
	if action == softwareUpdate {
		if !softwareReleaseTag.MatchString(selectedTag) {
			return softwarelifecycle.VerifiedRelease{}, softwarelifecycle.InstallCandidate{}, softwarelifecycle.VerifiedRelease{}, softwarelifecycle.InstallCandidate{}, errors.New("reviewed update release tag is unavailable")
		}
	}
	view := module.View(ctx, softwarelifecycle.ViewRequest{Tag: selectedTag, Architecture: architecture, InstallationStatus: softwarelifecycle.Managed, Installed: installed})
	want := softwarelifecycle.ReviewUpdate
	if action == softwareDowngrade {
		want = softwarelifecycle.ReviewDowngrade
	}
	if view.Refusal != nil || view.VerifiedCandidate == nil || len(view.PermittedActions) != 1 || view.PermittedActions[0] != want {
		return softwarelifecycle.VerifiedRelease{}, softwarelifecycle.InstallCandidate{}, softwarelifecycle.VerifiedRelease{}, softwarelifecycle.InstallCandidate{}, errors.New("selected release is not a freshly verified compatible change")
	}
	return *installed, installedCandidate, *view.VerifiedCandidate, view.UpdateCandidate(), nil
}

func buildSoftwareChange(ctx context.Context, module state.Interface, loaded state.Result, snapshot state.Snapshot, profileSecrets state.ConnectionProfileSecretReader, publicationSecrets state.ClientAccessReader, cloudflareSecrets state.InfrastructureSecretReader, action softwareChangeAction, changeSet string, disk systemchanges.DiskRequirement, installed softwarelifecycle.VerifiedRelease, installedCandidate softwarelifecycle.InstallCandidate, candidate softwarelifecycle.VerifiedRelease, next softwarelifecycle.InstallCandidate) (*builtSoftwareChange, error) {
	desired := snapshot.DesiredState
	desiredSHA, err := state.CandidateSHA256(desired)
	if err != nil {
		return nil, err
	}
	token, err := cloudflaretunnel.NewManagementToken(cloudflareSecrets.ReadInfrastructureSecret(desired.Cloudflare.ManagementToken))
	if err != nil {
		return nil, err
	}
	network, xhttp, websocket, err := observeManagedClientAccessWithToken(ctx, snapshot, token, disk)
	if err != nil {
		return nil, err
	}
	exposure := networkpolicy.NewListenerContribution(network)
	currentRegistry, err := clientAccessRegistryRequest(desired, snapshot.Revision, profileSecrets, exposure, xhttp, websocket)
	if err != nil {
		return nil, err
	}
	candidateHost, err := profilesubuntu.NewCandidateHost(next)
	if err != nil {
		return nil, err
	}
	profileModule := connectionprofiles.New(softwareChangeProfileHost{RealityHost: profilesubuntu.NewRealityHost("/"), candidate: candidateHost})
	profiles := profileModule.PlanRegistry(ctx, connectionprofiles.RegistryPlanRequest{Current: currentRegistry, Candidate: currentRegistry, ChangeSet: changeSet, StartingStateSHA256: desiredSHA, DesiredStateSHA256: desiredSHA, ReleaseUpdate: true})
	if profiles.Plan == nil {
		return nil, fmt.Errorf("Connection Profiles release update refused: %s", profiles.Health.Code)
	}
	unit, ok := next.ManagedUnit("cloudflared.service")
	if !ok {
		return nil, errors.New("candidate cloudflared.service is unavailable")
	}
	api := cloudflaretunnel.NewProductionAPI()
	cloudflareModule := cloudflaretunnel.New(api, cloudflaretunnel.SystemClock{})
	cloudflareResult := cloudflareModule.Plan(ctx, cloudflaretunnel.PlanRequest{
		Authority: cloudflaretunnel.ViewRequest{AccountID: desired.Cloudflare.AccountID, ZoneID: desired.Cloudflare.ZoneID, ZoneName: desired.Cloudflare.ZoneName, Token: token, NetworkPath: network.CloudflareTunnelPath},
		ChangeSet: changeSet, StartingRevision: snapshot.Revision, StartingStateSHA256: desiredSHA, DesiredStateSHA256: desiredSHA,
		TunnelName: desired.Cloudflare.TunnelName, XHTTPHostname: desired.Cloudflare.XHTTPHostname, WebSocketHostname: desired.Cloudflare.WebSocketHostname, DirectHostname: desired.Cloudflare.DirectHostname,
		PublicIPv4: desired.NetworkPolicy.PublicIPv4, PublicIPv6: desired.NetworkPolicy.PublicIPv6, CloudflaredVersion: trimVersion(desired.Software.CloudflaredVersion),
		ManagedRepair: cloudflaretunnel.OwnedTunnelBinding{TunnelID: desired.Cloudflare.TunnelID, XHTTPDNSRecordID: desired.Cloudflare.XHTTPDNSRecordID, WebSocketDNSRecordID: desired.Cloudflare.WebSocketDNSRecordID, DirectIPv4RecordID: desired.Cloudflare.DirectIPv4RecordID, DirectIPv6RecordID: desired.Cloudflare.DirectIPv6RecordID},
		ReleaseUpdate: true, CandidateServiceUnit: string(unit),
	})
	if cloudflareResult.Plan == nil {
		return nil, fmt.Errorf("Cloudflare release update refused: %s", cloudflareResult.Health.Code)
	}
	source, err := connectionprofiles.PublicationSourceFor(desired.NetworkPolicy.PrimarySubscriptionAddress, desired.ConnectionProfiles)
	if err != nil {
		return nil, err
	}
	managedDigest := sha256.Sum256([]byte(profiles.Plan.SHA256() + cloudflareResult.Plan.SHA256() + desiredSHA))
	subscriptionDigest := sha256.Sum256([]byte(fmt.Sprintf("software-release:%d:%s", desired.Subscription.ListenPort, desired.Subscription.CertificateID)))
	publication := subscriptionpublication.NewIntegrated(installSingBoxValidator{host: candidateHost}).Plan(ctx, subscriptionpublication.PlanRequest{
		Source: source, Secrets: publicationSecrets, Subscription: desired.Subscription, ChangeSet: changeSet,
		StartingState: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: snapshot.Revision, SHA256: desiredSHA}, DesiredStateRevision: snapshot.Revision + 1, DesiredStateSHA256: desiredSHA,
		ManagedInputsSHA256: hex.EncodeToString(managedDigest[:]), RelevantChecksums: subscriptionpublication.RelevantChecksums{ConnectionProfiles: profiles.Plan.SHA256(), Subscription: hex.EncodeToString(subscriptionDigest[:])},
		CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, SelectedAddress: desired.NetworkPolicy.PrimarySubscriptionAddress,
		ReleaseIdentity: state.ReleaseIdentity{Repository: candidate.Identity.Repository, Tag: candidate.Identity.Tag, Commit: candidate.Identity.Commit, ReleaseIndexSHA256: candidate.Identity.IndexSHA256},
	})
	if publication.Plan == nil {
		return nil, errors.New("Subscription Publication release update refused")
	}
	contributions := []softwarelifecycle.UpdateContribution{profiles.Plan, cloudflareResult.Plan, publication.Plan}
	request := softwarelifecycle.UpdatePlanRequest{Installed: installed, InstalledCandidate: installedCandidate, Candidate: next, StartingRevision: snapshot.Revision, StartingStateSHA256: desiredSHA, ChangeSet: changeSet, DesiredStateSHA256: desiredSHA, Contributions: contributions, Disk: disk}
	var plan *softwarelifecycle.UpdatePlan
	if action == softwareDowngrade {
		plan, _ = softwarelifecycle.PlanDowngrade(softwarelifecycle.DowngradePlanRequest(request))
	} else {
		plan, _ = softwarelifecycle.PlanUpdate(request)
	}
	if plan == nil {
		return nil, errors.New("Software Lifecycle release Plan refused")
	}
	wiring := &softwareChangeWiring{profiles: profiles.Plan, cloudflare: cloudflareResult.Plan, publication: publication.Plan, current: desired, network: network, plan: plan}
	checksums, err := softwareChangeChecksums(wiring)
	if err != nil {
		return nil, err
	}
	reviewed, err := state.NewReviewedInputs(state.PlanIdentity(plan.Identity()), plan.SHA256(), checksums)
	if err != nil {
		return nil, err
	}
	prepared, err := module.PrepareSoftwareUpdateCommit(state.PrepareRequest{
		Loaded: loaded, CandidateReleaseIdentity: state.ReleaseIdentity{Repository: candidate.Identity.Repository, Tag: candidate.Identity.Tag, Commit: candidate.Identity.Commit, ReleaseIndexSHA256: candidate.Identity.IndexSHA256}, ChangeSet: state.ChangeSetIdentity(changeSet), Candidate: desired,
		SemanticValidators: state.SemanticValidators{ConnectionProfiles: wiring, Subscription: wiring, Cloudflare: wiring, Certificates: wiring, NetworkPolicy: wiring, SoftwareLifecycle: wiring}, ServiceMaterials: state.ServiceMaterialsFor(desired), SubscriptionPublication: wiring, ReviewedInputs: reviewed,
	}, plan)
	if err != nil {
		return nil, err
	}
	cloudflareExecutor, err := cloudflareResult.Plan.Executor(api)
	if err != nil {
		return nil, err
	}
	total := 1
	for _, contribution := range contributions {
		total += len(contribution.SoftwareLifecycleUpdateContribution().Steps)
	}
	return &builtSoftwareChange{action: action, changeSet: changeSet, plan: plan, prepared: prepared, installed: installed, candidate: candidate, installedCandidate: installedCandidate, next: next, contributions: contributions, starting: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: snapshot.Revision, SHA256: desiredSHA}, desired: desired, disk: disk, totalSteps: total, cloudflare: cloudflareExecutor, profilePlan: profiles.Plan, publication: publication.Plan, module: module}, nil
}

type softwareChangeWiring struct {
	profiles    *connectionprofiles.Plan
	cloudflare  *cloudflaretunnel.Plan
	publication *subscriptionpublication.Plan
	current     state.DesiredState
	network     networkpolicy.Result
	plan        *softwarelifecycle.UpdatePlan
}

func (w *softwareChangeWiring) Identity() string { return w.plan.Identity() }
func (w *softwareChangeWiring) SHA256() string   { return w.plan.SHA256() }

func (w *softwareChangeWiring) ValidateConnectionProfiles(value state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) error {
	return w.profiles.ValidateConnectionProfiles(value, secrets)
}
func (w *softwareChangeWiring) PrepareConnectionProfiles(value state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) ([]byte, []byte, error) {
	return w.profiles.PrepareConnectionProfiles(value, secrets)
}
func (w *softwareChangeWiring) ValidateSubscription(value state.SubscriptionSettings, secrets state.ClientAccessReader) error {
	return w.publication.ValidateSubscription(value, secrets)
}
func (w *softwareChangeWiring) PrepareSubscriptionPublication() ([]byte, error) {
	return w.publication.PrepareSubscriptionPublication()
}
func (w *softwareChangeWiring) ValidateCloudflare(value state.CloudflareSettings, secrets state.InfrastructureSecretReader) error {
	if value != w.current.Cloudflare || !w.cloudflare.MatchesDesiredState(value.AccountID, value.ZoneID, value.ZoneName, value.TunnelName, value.XHTTPHostname, value.WebSocketHostname, value.DirectHostname, w.current.NetworkPolicy.PublicIPv4, w.current.NetworkPolicy.PublicIPv6, secrets.ReadInfrastructureSecret(value.ManagementToken)) {
		return errors.New("Software Lifecycle Plan changed Cloudflare Desired State")
	}
	return nil
}
func (w *softwareChangeWiring) ValidateCertificates(value state.CertificateSettings) error {
	if value != w.current.Certificates {
		return errors.New("Software Lifecycle Plan changed Certificate Desired State")
	}
	return nil
}
func (w *softwareChangeWiring) ValidateNetworkPolicy(value state.NetworkPolicyInputs) error {
	if value != w.current.NetworkPolicy || !w.network.MatchesDesiredState(value.SSHPort, value.PublicIPv4, value.PublicIPv6, value.PrimarySubscriptionAddress) {
		return errors.New("Software Lifecycle Plan changed Network Policy Desired State")
	}
	return nil
}
func (w *softwareChangeWiring) ValidateSoftwareLifecycle(value state.SoftwareLifecycleIntent) error {
	if value != (state.SoftwareLifecycleIntent{Installation: w.current.Installation, Software: w.current.Software}) || w.plan == nil {
		return errors.New("Software Lifecycle Plan changed Owner meaning")
	}
	return nil
}

func softwareChangeChecksums(w *softwareChangeWiring) (state.ManagedInputChecksums, error) {
	digest := func(value string) string { sum := sha256.Sum256([]byte(value)); return hex.EncodeToString(sum[:]) }
	return state.NewManagedInputChecksums(w.profiles.SHA256(), w.publication.SHA256(), w.cloudflare.SHA256(), digest("unchanged-certificates:"+w.plan.SHA256()), digest("unchanged-network:"+w.plan.SHA256()), w.plan.SHA256())
}
