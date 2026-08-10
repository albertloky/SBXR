package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	certificateubuntu "github.com/albertloky/SBXR/internal/certificatelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	profilesubuntu "github.com/albertloky/SBXR/internal/connectionprofiles/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/state"
	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type managedProviderAction string

const (
	managedCloudflareReplace managedProviderAction = "cloudflare-replace-token"
	managedCloudflareRemove  managedProviderAction = "cloudflare-remove-token"
	managedCloudflareRotate  managedProviderAction = "cloudflare-rotate-run-token"
	managedCertificateIP     managedProviderAction = "certificate-ip"
	managedCertificateDomain managedProviderAction = "certificate-domain"
)

func validManagedProviderAction(action managedProviderAction) bool {
	switch action {
	case managedCloudflareReplace, managedCloudflareRemove, managedCloudflareRotate, managedCertificateIP, managedCertificateDomain:
		return true
	default:
		return false
	}
}

type managedProviderBuildRequest struct {
	Action            managedProviderAction
	ChangeSet         string
	Token, OwnerEmail string
	Agreement         bool
	StandingRenewal   bool
	Disk              systemchanges.DiskRequirement
}

type providerPlan interface {
	Identity() string
	SHA256() string
	Steps() []systemchanges.Step
	Checks() []systemchanges.Check
}

type builtManagedProvider struct {
	plan                 providerPlan
	changeSet            string
	cloudflarePlan       *cloudflaretunnel.Plan
	certificatePlan      *certificatelifecycle.Plan
	prepared             *state.PreparedCommit
	starting             systemchanges.StateLineage
	disk                 systemchanges.DiskRequirement
	volatileSHA, certbot string
	totalSteps           int
	subscriptionPort     uint16
	cloudflare           cloudflaretunnel.Executor
	certificate          certificateubuntu.TransactionExecutor
}

type managedProviderWiring struct {
	plan        providerPlan
	profiles    clientAccessProfilePlan
	publication clientAccessPublicationPlan
	current     state.DesiredState
	network     networkpolicy.Result
	cloudflare  *cloudflaretunnel.Plan
	certificate *certificatelifecycle.Plan
}

func (w *managedProviderWiring) Identity() string { return w.plan.Identity() }
func (w *managedProviderWiring) SHA256() string   { return w.plan.SHA256() }
func (w *managedProviderWiring) ValidateConnectionProfiles(value state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) error {
	return w.profiles.ValidateConnectionProfiles(value, secrets)
}
func (w *managedProviderWiring) PrepareConnectionProfiles(value state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) ([]byte, []byte, error) {
	return w.profiles.PrepareConnectionProfiles(value, secrets)
}
func (w *managedProviderWiring) ValidateSubscription(value state.SubscriptionSettings, secrets state.ClientAccessReader) error {
	return w.publication.ValidateSubscription(value, secrets)
}
func (w *managedProviderWiring) PrepareSubscriptionPublication() ([]byte, error) {
	return w.publication.PrepareSubscriptionPublication()
}
func (w *managedProviderWiring) ValidateCloudflare(value state.CloudflareSettings, secrets state.InfrastructureSecretReader) error {
	if w.cloudflare == nil {
		if value == w.current.Cloudflare {
			return nil
		}
		return errors.New("certificate change altered Cloudflare State")
	}
	if secrets == nil || !w.cloudflare.MatchesDesiredState(value.AccountID, value.ZoneID, value.ZoneName, value.TunnelName, value.XHTTPHostname, value.WebSocketHostname, value.DirectHostname, w.current.NetworkPolicy.PublicIPv4, w.current.NetworkPolicy.PublicIPv6, secrets.ReadInfrastructureSecret(value.ManagementToken)) {
		return errors.New("Cloudflare Plan does not match Desired State")
	}
	return nil
}
func (w *managedProviderWiring) ValidateCertificates(value state.CertificateSettings) error {
	if w.certificate == nil {
		if value == w.current.Certificates {
			return nil
		}
		return errors.New("Cloudflare change altered certificate State")
	}
	if !w.certificate.MatchesDesiredState(value.RenewalPolicy, value.OwnerEmail, value.ACMEAccountID, value.IPCertificateID, value.IPServingPointer, value.DomainCertificateID, value.DomainServingPointer, value.DomainHostname) {
		return errors.New("Certificate Plan does not match Desired State")
	}
	return nil
}
func (w *managedProviderWiring) ValidateNetworkPolicy(value state.NetworkPolicyInputs) error {
	if value != w.current.NetworkPolicy || !w.network.MatchesDesiredState(value.SSHPort, value.PublicIPv4, value.PublicIPv6, value.PrimarySubscriptionAddress) {
		return errors.New("provider change altered Network Policy State")
	}
	return nil
}
func (w *managedProviderWiring) ValidateSoftwareLifecycle(value state.SoftwareLifecycleIntent) error {
	if value.Installation != w.current.Installation || value.Software != w.current.Software {
		return errors.New("provider change altered Software Lifecycle State")
	}
	return nil
}

func prepareManagedProvider(ctx context.Context, request managedProviderBuildRequest) (*builtManagedProvider, state.Interface, error) {
	if ctx == nil || request.ChangeSet == "" || request.Disk == (systemchanges.DiskRequirement{}) {
		return nil, state.Interface{}, errors.New("complete managed provider inputs are required")
	}
	if pending, err := pendingInstallRecovery(); err != nil || pending {
		return nil, state.Interface{}, errors.New("an unfinished Change Set must recover before a provider Plan")
	}
	observed, release, err := managedLoadEvidence()
	if err != nil {
		return nil, state.Interface{}, err
	}
	module := statefilesystem.New()
	loaded, err := module.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: observed.StateRevision, LastCompletedChangeSet: state.ChangeSetIdentity(observed.LastChangeSet), ReleaseIdentity: release}})
	if err != nil {
		return nil, state.Interface{}, err
	}
	var built *builtManagedProvider
	err = module.WithManagedConnectionProfileSecrets(loaded, func(snapshot state.Snapshot, profileSecrets state.ConnectionProfileSecretReader) error {
		if request.StandingRenewal {
			request.OwnerEmail = snapshot.DesiredState.Certificates.OwnerEmail
			request.Agreement = true
		}
		return module.WithManagedSubscriptionSecrets(loaded, func(_ state.Snapshot, publicationSecrets state.ClientAccessReader) error {
			return module.WithManagedCloudflareSecrets(loaded, func(_ state.Snapshot, cloudflareSecrets state.InfrastructureSecretReader) error {
				if request.Action == managedCertificateIP || request.Action == managedCertificateDomain {
					var buildErr error
					built, buildErr = buildManagedCertificate(ctx, module, loaded, snapshot, profileSecrets, publicationSecrets, cloudflareSecrets, request)
					return buildErr
				}
				var buildErr error
				built, buildErr = buildManagedCloudflare(ctx, module, loaded, snapshot, profileSecrets, publicationSecrets, cloudflareSecrets, request)
				return buildErr
			})
		})
	})
	if err == nil {
		built.volatileSHA, err = clientAccessVolatileSHA("/")
	}
	return built, module, err
}

func buildManagedCertificate(ctx context.Context, module state.Interface, loaded state.Result, snapshot state.Snapshot, profileSecrets state.ConnectionProfileSecretReader, publicationSecrets state.ClientAccessReader, cloudflareSecrets state.InfrastructureSecretReader, request managedProviderBuildRequest) (*builtManagedProvider, error) {
	if request.OwnerEmail == "" || !request.Agreement {
		return nil, errors.New("reviewed Owner email and subscriber agreement are required")
	}
	network, xhttp, websocket, err := observeManagedClientAccess(ctx, snapshot, cloudflareSecrets, request.Disk)
	if err != nil {
		return nil, err
	}
	token, err := cloudflaretunnel.NewManagementToken(cloudflareSecrets.ReadInfrastructureSecret(snapshot.DesiredState.Cloudflare.ManagementToken))
	if err != nil {
		return nil, err
	}
	api := cloudflaretunnel.NewProductionAPI()
	desired := snapshot.DesiredState
	dns, err := api.ObserveCertificateDNS(ctx, cloudflaretunnel.CertificateDNSRequest{ZoneID: desired.Cloudflare.ZoneID, ZoneName: desired.Cloudflare.ZoneName, Hostname: desired.Cloudflare.DirectHostname, PublicIPv4: desired.NetworkPolicy.PublicIPv4, PublicIPv6: desired.NetworkPolicy.PublicIPv6, IPv4RecordID: desired.Cloudflare.DirectIPv4RecordID, IPv6RecordID: desired.Cloudflare.DirectIPv6RecordID, Token: token})
	if err != nil {
		return nil, err
	}
	startingSHA, err := state.CandidateSHA256(desired)
	if err != nil {
		return nil, err
	}
	candidate := managedCertificateCandidate(desired, request.OwnerEmail, request.StandingRenewal)
	candidateSHA, err := state.CandidateSHA256(candidate)
	if err != nil {
		return nil, err
	}
	http01, ok := network.HTTP01Contribution()
	if !ok {
		return nil, errors.New("exact temporary HTTP-01 authority is unavailable")
	}
	lineage := certificatelifecycle.IPLineage
	if request.Action == managedCertificateDomain {
		lineage = certificatelifecycle.DomainLineage
	}
	directTLS := connectionprofiles.NewDirectTLSContribution(connectionprofiles.DirectTLSRequest{Revision: snapshot.Revision, DestinationIP: desired.NetworkPolicy.PrimarySubscriptionAddress, Hostname: desired.Cloudflare.DirectHostname, Hysteria2: connectionprofiles.DirectTLSConsumer{Port: desired.ConnectionProfiles.Hysteria2.Port, CertificatePointer: desired.Certificates.DomainServingPointer}, TUIC: connectionprofiles.DirectTLSConsumer{Port: desired.ConnectionProfiles.TUIC.Port, CertificatePointer: desired.Certificates.DomainServingPointer}, AnyTLS: connectionprofiles.DirectTLSConsumer{Port: desired.ConnectionProfiles.AnyTLS.Port, CertificatePointer: desired.Certificates.DomainServingPointer}})
	certificateModule := certificatelifecycle.New(certificateubuntu.New(), installClock{})
	planResult := certificateModule.Plan(ctx, certificatelifecycle.PlanRequest{View: certificateViewRequest(desired, network, dns), Lineage: lineage, ChangeSet: string(request.ChangeSet), StartingRevision: snapshot.Revision, StartingStateSHA256: startingSHA, DesiredStateSHA256: candidateSHA, HTTP01: http01, DirectTLS: directTLS, OwnerEmail: request.OwnerEmail, SubscriberAgreementReviewed: request.Agreement, StandingRenewal: request.StandingRenewal, RenewalPolicyApproved: request.StandingRenewal && desired.Certificates.RenewalPolicy})
	if planResult.Plan == nil {
		return nil, fmt.Errorf("Certificate Lifecycle Plan refused: %s", planResult.Health.Code)
	}
	wiring, err := buildManagedProviderWiring(ctx, planResult.Plan, desired, snapshot, profileSecrets, publicationSecrets, network, xhttp, websocket, request)
	if err != nil {
		return nil, err
	}
	preparedRequest, err := providerPrepareRequest(loaded, snapshot, candidate, wiring, request)
	if err != nil {
		return nil, err
	}
	var prepared *state.PreparedCommit
	if !request.StandingRenewal {
		prepared, err = module.PrepareCommit(preparedRequest)
	} else if lineage == certificatelifecycle.IPLineage {
		prepared, err = module.PrepareIPCertificateRenewalCommit(preparedRequest)
	} else {
		prepared, err = module.PrepareDomainCertificateRenewalCommit(preparedRequest)
	}
	if err != nil {
		return nil, err
	}
	certbot := filepath.Join("/opt/sbxr/releases", snapshot.ReleaseIdentity.Tag, "certbot/bin/certbot")
	executor, err := certificateubuntu.NewTransactionExecutor(certbot)
	if err != nil {
		return nil, err
	}
	return &builtManagedProvider{plan: planResult.Plan, changeSet: request.ChangeSet, certificatePlan: planResult.Plan, prepared: prepared, starting: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: snapshot.Revision, SHA256: startingSHA}, disk: request.Disk, totalSteps: len(planResult.Plan.Steps()), subscriptionPort: desired.Subscription.ListenPort, certificate: executor, certbot: certbot}, nil
}

func managedCertificateCandidate(desired state.DesiredState, ownerEmail string, standing bool) state.DesiredState {
	if !standing {
		desired.Certificates.OwnerEmail = ownerEmail
	}
	return desired
}

func buildManagedCloudflare(ctx context.Context, module state.Interface, loaded state.Result, snapshot state.Snapshot, profileSecrets state.ConnectionProfileSecretReader, publicationSecrets state.ClientAccessReader, cloudflareSecrets state.InfrastructureSecretReader, request managedProviderBuildRequest) (*builtManagedProvider, error) {
	desired := snapshot.DesiredState
	startingSHA, err := state.CandidateSHA256(desired)
	if err != nil {
		return nil, err
	}
	api := cloudflaretunnel.NewProductionAPI()
	cloudflareModule := cloudflaretunnel.New(api, cloudflaretunnel.SystemClock{})
	currentToken := cloudflaretunnel.ManagementToken{}
	observationToken, err := cloudflaretunnel.NewManagementToken(cloudflareSecrets.ReadInfrastructureSecret(desired.Cloudflare.ManagementToken))
	if desired.Cloudflare.ManagementTokenRemoved {
		if request.Action != managedCloudflareReplace {
			return nil, errors.New("removed Cloudflare authority must be replaced before this action")
		}
		observationToken, err = cloudflaretunnel.NewManagementToken(request.Token)
	} else {
		currentToken = observationToken
	}
	if err != nil {
		return nil, err
	}
	network, xhttp, websocket, err := observeManagedClientAccessWithToken(ctx, snapshot, observationToken, request.Disk)
	if err != nil {
		return nil, err
	}
	currentView := cloudflaretunnel.ViewResult{}
	if !desired.Cloudflare.ManagementTokenRemoved {
		currentView = cloudflareModule.View(ctx, cloudflaretunnel.ViewRequest{AccountID: desired.Cloudflare.AccountID, ZoneID: desired.Cloudflare.ZoneID, ZoneName: desired.Cloudflare.ZoneName, Token: currentToken, NetworkPath: network.CloudflareTunnelPath})
		if currentView.Health.Outcome != cloudflaretunnel.Healthy {
			return nil, fmt.Errorf("current Cloudflare authority refused: %s", currentView.Health.Code)
		}
	}
	candidate := desired
	planRequest := cloudflaretunnel.PlanRequest{ChangeSet: string(request.ChangeSet), StartingRevision: snapshot.Revision, StartingStateSHA256: startingSHA, TunnelName: desired.Cloudflare.TunnelName, XHTTPHostname: desired.Cloudflare.XHTTPHostname, WebSocketHostname: desired.Cloudflare.WebSocketHostname, DirectHostname: desired.Cloudflare.DirectHostname, PublicIPv4: desired.NetworkPolicy.PublicIPv4, PublicIPv6: desired.NetworkPolicy.PublicIPv6, CloudflaredVersion: trimVersion(desired.Software.CloudflaredVersion)}
	var final = candidate
	switch request.Action {
	case managedCloudflareReplace:
		replacement, tokenErr := cloudflaretunnel.NewManagementToken(request.Token)
		if tokenErr != nil {
			return nil, tokenErr
		}
		candidate.Cloudflare.ManagementToken = state.InfrastructureSecret{}
		candidate.Cloudflare.ManagementTokenRemoved = false
		candidate.Cloudflare.ManagementTokenState = ""
		final = candidate
		final.Cloudflare.ManagementToken = state.NewInfrastructureSecret(request.Token)
		planRequest.Authority = cloudflaretunnel.ViewRequest{AccountID: desired.Cloudflare.AccountID, ZoneID: desired.Cloudflare.ZoneID, ZoneName: desired.Cloudflare.ZoneName, Token: replacement, NetworkPath: network.CloudflareTunnelPath}
		planRequest.ManagementToken = cloudflaretunnel.ManagementTokenChange{Action: cloudflaretunnel.ManagementTokenReplace, CurrentTokenID: currentView.Credential.ID, StartingTokenRemoved: desired.Cloudflare.ManagementTokenRemoved}
	case managedCloudflareRemove:
		inventory, inventoryErr := module.ManagementTokenInventory(loaded)
		if inventoryErr != nil {
			return nil, inventoryErr
		}
		candidate.Cloudflare.ManagementToken = state.InfrastructureSecret{}
		candidate.Cloudflare.ManagementTokenRemoved = true
		candidate.Cloudflare.ManagementTokenState = state.CloudflareManagementUnmanaged
		final = candidate
		planRequest.Authority = cloudflaretunnel.ViewRequest{AccountID: desired.Cloudflare.AccountID, ZoneID: desired.Cloudflare.ZoneID, ZoneName: desired.Cloudflare.ZoneName}
		planRequest.ManagementToken = cloudflaretunnel.ManagementTokenChange{Action: cloudflaretunnel.ManagementTokenRemove, CurrentTokenID: currentView.Credential.ID, Inventory: inventory, Resolution: cloudflaretunnel.MarkDependenciesUnmanaged}
	case managedCloudflareRotate:
		planRequest.Authority = cloudflaretunnel.ViewRequest{AccountID: desired.Cloudflare.AccountID, ZoneID: desired.Cloudflare.ZoneID, ZoneName: desired.Cloudflare.ZoneName, Token: currentToken, NetworkPath: network.CloudflareTunnelPath}
		planRequest.RunTokenRotation = cloudflaretunnel.OwnedTunnelBinding{TunnelID: desired.Cloudflare.TunnelID, XHTTPDNSRecordID: desired.Cloudflare.XHTTPDNSRecordID, WebSocketDNSRecordID: desired.Cloudflare.WebSocketDNSRecordID, DirectIPv4RecordID: desired.Cloudflare.DirectIPv4RecordID, DirectIPv6RecordID: desired.Cloudflare.DirectIPv6RecordID}
	default:
		return nil, errors.New("unsupported Cloudflare action")
	}
	if request.Action == managedCloudflareRotate {
		planRequest.DesiredStateSHA256 = startingSHA
	} else {
		planRequest.DesiredStateSHA256, err = state.ManagementTokenTemplateSHA256(candidate)
		if err != nil {
			return nil, err
		}
	}
	planResult := cloudflareModule.Plan(ctx, planRequest)
	if planResult.Plan == nil {
		return nil, fmt.Errorf("Cloudflare Plan refused: %s", planResult.Health.Code)
	}
	wiring, err := buildManagedProviderWiring(ctx, planResult.Plan, desired, snapshot, profileSecrets, publicationSecrets, network, xhttp, websocket, request)
	if err != nil {
		return nil, err
	}
	preparedRequest, err := providerPrepareRequest(loaded, snapshot, candidate, wiring, request)
	if err != nil {
		return nil, err
	}
	preparedRequest.ServiceMaterials = state.ServiceMaterialsFor(final)
	var prepared *state.PreparedCommit
	if request.Action == managedCloudflareRotate {
		prepared, err = module.PrepareRunTokenRotationCommit(preparedRequest, planResult.Plan)
	} else {
		prepared, err = module.PrepareManagementTokenCommit(preparedRequest, planResult.Plan)
	}
	if err != nil {
		return nil, err
	}
	var executor cloudflaretunnel.Executor
	if request.Action == managedCloudflareRotate {
		executor, err = planResult.Plan.Executor(api)
		if err != nil {
			return nil, err
		}
	}
	return &builtManagedProvider{plan: planResult.Plan, changeSet: request.ChangeSet, cloudflarePlan: planResult.Plan, prepared: prepared, starting: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: snapshot.Revision, SHA256: startingSHA}, disk: request.Disk, totalSteps: len(planResult.Plan.Steps()), subscriptionPort: desired.Subscription.ListenPort, cloudflare: executor}, nil
}

func buildManagedProviderWiring(ctx context.Context, plan providerPlan, desired state.DesiredState, snapshot state.Snapshot, profileSecrets state.ConnectionProfileSecretReader, publicationSecrets state.ClientAccessReader, network networkpolicy.Result, xhttp cloudflaretunnel.XHTTPRouteHealth, websocket cloudflaretunnel.WebSocketRouteHealth, request managedProviderBuildRequest) (*managedProviderWiring, error) {
	desiredSHA, err := state.CandidateSHA256(desired)
	if err != nil {
		return nil, err
	}
	exposure := networkpolicy.NewListenerContribution(network)
	registryRequest, err := clientAccessRegistryRequest(desired, snapshot.Revision, profileSecrets, connectionprofiles.RegistryExposureAuthority(exposure), xhttp, websocket)
	if err != nil {
		return nil, err
	}
	host := profilesubuntu.NewRealityHost("/")
	profiles := connectionprofiles.New(host).PlanUnchangedRegistry(ctx, registryRequest, string(request.ChangeSet), desiredSHA)
	if profiles.Plan == nil {
		return nil, fmt.Errorf("unchanged Connection Profiles Plan refused: %s", profiles.Health.Code)
	}
	source, err := connectionprofiles.PublicationSourceFor(desired.NetworkPolicy.PrimarySubscriptionAddress, desired.ConnectionProfiles)
	if err != nil {
		return nil, err
	}
	publicationModule := subscriptionpublication.NewIntegrated(installedSingBoxValidator{host: host, version: trimVersion(desired.Software.SingBoxVersion)})
	managedDigest := sha256.Sum256([]byte(plan.SHA256() + desiredSHA))
	subscriptionDigest := sha256.Sum256([]byte(fmt.Sprintf("provider:%d:%s", desired.Subscription.ListenPort, desired.Subscription.CertificateID)))
	publication := publicationModule.Plan(ctx, subscriptionpublication.PlanRequest{Source: source, Secrets: publicationSecrets, Subscription: desired.Subscription, ChangeSet: string(request.ChangeSet), StartingState: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: snapshot.Revision, SHA256: desiredSHA}, DesiredStateRevision: snapshot.Revision + 1, DesiredStateSHA256: desiredSHA, ManagedInputsSHA256: hex.EncodeToString(managedDigest[:]), RelevantChecksums: subscriptionpublication.RelevantChecksums{ConnectionProfiles: profiles.Plan.SHA256(), Subscription: hex.EncodeToString(subscriptionDigest[:])}, CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, SelectedAddress: desired.NetworkPolicy.PrimarySubscriptionAddress, ReleaseIdentity: snapshot.ReleaseIdentity})
	if publication.Plan == nil {
		return nil, errors.New("unchanged Subscription Publication Plan refused")
	}
	wiring := &managedProviderWiring{plan: plan, profiles: profiles.Plan, publication: publication.Plan, current: desired, network: network}
	if value, ok := plan.(*cloudflaretunnel.Plan); ok {
		wiring.cloudflare = value
	}
	if value, ok := plan.(*certificatelifecycle.Plan); ok {
		wiring.certificate = value
	}
	return wiring, nil
}

func providerPrepareRequest(loaded state.Result, snapshot state.Snapshot, candidate state.DesiredState, wiring *managedProviderWiring, request managedProviderBuildRequest) (state.PrepareRequest, error) {
	digest := func(value string) string { sum := sha256.Sum256([]byte(value)); return hex.EncodeToString(sum[:]) }
	checksums, err := state.NewManagedInputChecksums(digest("profiles:"+wiring.plan.SHA256()), digest("publication:"+wiring.plan.SHA256()), digest("cloudflare:"+wiring.plan.SHA256()), digest("certificates:"+wiring.plan.SHA256()), digest("network:"+wiring.plan.SHA256()), digest("software:"+wiring.plan.SHA256()))
	if err != nil {
		return state.PrepareRequest{}, err
	}
	reviewed, err := state.NewReviewedInputs(state.PlanIdentity(wiring.Identity()), wiring.SHA256(), checksums)
	if err != nil {
		return state.PrepareRequest{}, err
	}
	return state.PrepareRequest{Loaded: loaded, CandidateReleaseIdentity: snapshot.ReleaseIdentity, ChangeSet: state.ChangeSetIdentity(request.ChangeSet), Candidate: candidate, SemanticValidators: state.SemanticValidators{ConnectionProfiles: wiring, Subscription: wiring, Cloudflare: wiring, Certificates: wiring, NetworkPolicy: wiring, SoftwareLifecycle: wiring}, ServiceMaterials: state.ServiceMaterialsFor(candidate), SubscriptionPublication: wiring, ReviewedInputs: reviewed}, nil
}
