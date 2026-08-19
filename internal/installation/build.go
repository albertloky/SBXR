package installation

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	profilesubuntu "github.com/albertloky/SBXR/internal/connectionprofiles/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type builtInstall struct {
	candidate     softwarelifecycle.InstallCandidate
	desired       state.DesiredState
	desiredSHA256 string
	plan          *softwarelifecycle.InstallPlan
	wiring        *installWiring
	contributions []softwarelifecycle.InstallContribution
	networkIntent networkpolicy.Intent
	network       func(networkpolicy.Request) networkpolicy.Result
	disk          systemchanges.DiskRequirement
	totalSteps    int
	health        healthdiagnostics.InstallationSummary
}

func (built *builtInstall) prepareState(module state.Interface) (*state.PreparedCommit, error) {
	if built == nil || built.plan == nil || built.wiring == nil {
		return nil, errors.New("complete install Plan unavailable")
	}
	loaded, err := module.Load(state.LoadRequest{Baseline: state.CleanVPS})
	if err != nil {
		return nil, err
	}
	proofs := make(map[softwarelifecycle.InstallContributionName]softwarelifecycle.InstallContributionProof, len(built.contributions))
	for _, contribution := range built.contributions {
		proof := contribution.SoftwareLifecycleInstallContribution()
		proofs[softwarelifecycle.InstallContributionName(proof.Name)] = proof
	}
	checksums, err := state.NewManagedInputChecksums(
		proofs[softwarelifecycle.ProfilesInstallContribution].SHA256,
		proofs[softwarelifecycle.SubscriptionInstallContribution].SHA256,
		sha256Text("Cloudflare absent in revision 1"),
		proofs[softwarelifecycle.CertificateInstallContribution].SHA256,
		proofs[softwarelifecycle.NetworkInstallContribution].SHA256,
		built.plan.SHA256(),
	)
	if err != nil {
		return nil, err
	}
	reviewed, err := state.NewReviewedInputs(state.PlanIdentity(built.plan.Identity()), built.plan.SHA256(), checksums)
	if err != nil {
		return nil, err
	}
	release := candidateRelease(built.candidate)
	request := state.PrepareRequest{
		Loaded:                   loaded,
		CandidateReleaseIdentity: state.ReleaseIdentity{Repository: release.Repository, Tag: release.Tag, Commit: release.Commit, ReleaseIndexSHA256: release.IndexSHA256},
		ChangeSet:                state.ChangeSetIdentity("install-" + built.desired.Installation.ID[:16]),
		Candidate:                built.desired,
		SemanticValidators:       state.SemanticValidators{ConnectionProfiles: built.wiring, Subscription: built.wiring, Certificates: built.wiring, NetworkPolicy: built.wiring, SoftwareLifecycle: built.wiring},
		ServiceMaterials:         state.ServiceMaterialsFor(built.desired),
		SubscriptionPublication:  built.wiring,
		ReviewedInputs:           reviewed,
	}
	return module.PrepareCommit(request)
}

func sha256Text(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

type installClientReader struct {
	profiles state.ClientAccessReader
	token    state.ClientAccessValue
	rawToken string
}

func (reader installClientReader) ReadClientAccessValue(value state.ClientAccessValue) string {
	if value == reader.token {
		return reader.rawToken
	}
	return reader.profiles.ReadClientAccessValue(value)
}

type installSingBoxValidator struct{ host profilesubuntu.CandidateHost }

func (validator installSingBoxValidator) ValidateSingBox(ctx context.Context, document io.Reader) error {
	return validator.host.ValidateSingBox(ctx, "1.13.16", document)
}

type buildDependencies struct {
	stage    func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error)
	network  func(networkpolicy.Request) networkpolicy.Result
	random   io.Reader
	sshProof networkpolicy.SSHPreservationProof
}

type reclamationReviewError struct {
	plan *networkpolicy.ReclamationPlan
}

func (err *reclamationReviewError) Error() string { return "Reclaimable VPS review is required" }

type networkPolicyRefusal struct{ finding networkpolicy.Finding }

func (*networkPolicyRefusal) Error() string {
	return "Clean VPS Network Policy refused the installation"
}

func refusedNetworkPolicy(results ...networkpolicy.Result) error {
	for _, result := range results {
		for _, finding := range result.Findings {
			if finding.Classification == networkpolicy.Required && finding.Outcome == networkpolicy.Failed {
				return &networkPolicyRefusal{finding: finding}
			}
		}
	}
	return errors.New("Clean VPS Network Policy refused the installation")
}

type installReleaseStager struct {
	stage func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error)
}

func (stager installReleaseStager) Stage(ctx context.Context, request softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
	return stager.stage(ctx, request)
}

func buildInstallWith(ctx context.Context, request softwareubuntu.InstallHandoffRequest, dependencies buildDependencies) (*builtInstall, error) {
	if dependencies.stage == nil || dependencies.network == nil || dependencies.random == nil {
		return nil, errors.New("install composition dependencies unavailable")
	}
	candidate, err := softwarelifecycle.RebuildInstallCandidate(ctx, request.Candidate, installReleaseStager{dependencies.stage})
	if err != nil {
		return nil, errors.New("verified install candidate could not be rebuilt")
	}
	xrayVersion, singBoxVersion, cloudflaredVersion, certbotVersion, valid := candidate.ManagedComponentVersions()
	if !valid {
		return nil, errors.New("managed component versions are unavailable")
	}
	_, archive, components, valid := candidate.SoftwareLifecyclePreparedArchive()
	if !valid {
		return nil, errors.New("prepared release is unavailable")
	}
	disk := systemchanges.DiskRequirement{PreparationBytes: uint64(len(archive) + len(components)), TemporaryBytes: uint64(len(archive) + len(components)), SnapshotBytes: 32 << 20, JournalBytes: 8 << 20, RollbackBytes: uint64(len(archive) + len(components)), OverheadBytes: 256 << 20}
	networkDisk := networkpolicy.DiskRequirement{PreparationBytes: disk.PreparationBytes, TemporaryBytes: disk.TemporaryBytes, SnapshotBytes: disk.SnapshotBytes, JournalBytes: disk.JournalBytes, RollbackBytes: disk.RollbackBytes, OverheadBytes: disk.OverheadBytes}
	draft := request.Draft
	intent := networkpolicy.Intent{Revision: 1, Baseline: networkpolicy.Clean, PublicIPv4: draft.PublicIPv4, PublicIPv6: draft.PublicIPv6, PrimarySubscriptionAddress: draft.PrimaryAddress, SSHPort: draft.SSHPort, SubscriptionPort: draft.SubscriptionPort, Profiles: networkpolicy.Profiles{VLESSRealityVision: networkpolicy.Profile{Enabled: true, Port: draft.RealityPort}}, Disk: networkDisk}
	baseNetwork := dependencies.network(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PreApproval, ReclamationReview: true, ReviewedReclamationSHA256: request.ReviewedReclamationSHA256})
	if baseNetwork.Reclamation != nil && request.ReviewedReclamationSHA256 == "" {
		return nil, &reclamationReviewError{plan: baseNetwork.Reclamation}
	}
	httpIntent := intent
	httpIntent.TemporaryHTTPLineage = networkpolicy.SBXRIP
	httpNetwork := dependencies.network(networkpolicy.Request{Intent: httpIntent, Stage: networkpolicy.PreApproval, ReclamationReview: true, ReviewedReclamationSHA256: request.ReviewedReclamationSHA256})
	http01, postFirewallHTTP := networkpolicy.PrepareHTTP01AfterFirewallReclamation(baseNetwork, intent, httpIntent)
	if baseNetwork.Outcome == networkpolicy.Failed || httpNetwork.Outcome == networkpolicy.Failed && !postFirewallHTTP {
		return nil, refusedNetworkPolicy(baseNetwork, httpNetwork)
	}
	if !postFirewallHTTP {
		http01, postFirewallHTTP = httpNetwork.HTTP01Contribution()
	}
	if !postFirewallHTTP {
		return nil, errors.New("temporary HTTP-01 authority is unavailable")
	}

	credentials, err := connectionprofiles.GenerateRealityCredentialsFrom(dependencies.random)
	if err != nil {
		return nil, err
	}
	registry, err := connectionprofiles.NewRevisionOneRegistry(connectionprofiles.RegistryViewRequest{ClientAddress: draft.PrimaryAddress, Reality: connectionprofiles.ViewRequest{Revision: 1, Port: draft.RealityPort, Target: connectionprofiles.RealityTarget{Address: request.RealityTarget, ServerName: request.RealityServerName}, Fingerprint: "chrome", XrayVersion: xrayVersion}}, credentials)
	if err != nil {
		return nil, err
	}
	registry.Exposure = networkpolicy.NewListenerContribution(baseNetwork)
	registryInputs, err := connectionprofiles.NewFreshRegistryInputs(registry)
	if err != nil {
		return nil, err
	}
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(dependencies.random, tokenBytes); err != nil {
		return nil, errors.New("subscription token generation failed")
	}
	rawSubscriptionToken := hex.EncodeToString(tokenBytes)
	subscriptionToken := state.NewClientAccessValue(rawSubscriptionToken)
	networkState := state.NetworkPolicyInputs{SSHPort: draft.SSHPort, PublicIPv4: draft.PublicIPv4, PublicIPv6: draft.PublicIPv6, PrimarySubscriptionAddress: draft.PrimaryAddress}
	desired := state.DesiredState{Installation: state.InstallationIdentity{ID: request.Session}, ConnectionProfiles: registryInputs.Profiles(), Subscription: state.SubscriptionSettings{Token: subscriptionToken, ListenPort: draft.SubscriptionPort, CertificateID: "sbxr-ip"}, Certificates: state.CertificateSettings{RenewalPolicy: true, OwnerEmail: draft.OwnerEmail, ACMEAccountID: "letsencrypt", IPCertificateID: "sbxr-ip", IPServingPointer: "/var/lib/sbxr/certificates/ip/current"}, NetworkPolicy: networkState, Software: state.SoftwareSettings{XrayVersion: xrayVersion, SingBoxVersion: singBoxVersion, CloudflaredVersion: cloudflaredVersion, CertbotVersion: certbotVersion, AutomaticUpdateDiscovery: true}}
	if policy, ok := baseNetwork.ReclamationPolicy(); ok && policy.Held != nil {
		desired.Reclamation = state.ReclamationPolicy{Version: policy.Version, Held: state.HeldPackagePolicy{Name: policy.Held.Name, Version: policy.Held.Version, DeletedExecutable: policy.Path, SHA256: policy.SHA256}}
	}
	desiredSHA256, err := state.CandidateSHA256(desired)
	if err != nil {
		return nil, fmt.Errorf("Desired State candidate refused: %w", err)
	}
	changeSet := "install-" + request.Session[:16]
	certificateModule := certificatelifecycle.NewForFreshInstallation(candidate, installClock{})
	certificateRequest := certificatelifecycle.PlanRequest{View: certificatelifecycle.ViewRequest{SelectedIP: draft.PrimaryAddress, QualifiedAddresses: selectedAddresses(draft), HTTP01: certificatelifecycle.HTTP01Prerequisites{AddressQualified: true, RouteReachable: true, Port80Available: true, TimeSynchronized: true, FirewallOwned: true}}, ChangeSet: changeSet, StartingRevision: 1, DesiredStateSHA256: desiredSHA256, HTTP01: http01, OwnerEmail: draft.OwnerEmail, SubscriberAgreementReviewed: draft.SubscriberAgreementReviewed}
	certificateRequest.Lineage = certificatelifecycle.IPLineage
	certificateRequest.FreshInstallation = systemchanges.NewFreshInstallationAuthority(baseNetwork.FreshInstallationProof())
	ipPlan := certificateModule.Plan(ctx, certificateRequest).Plan
	if ipPlan == nil {
		return nil, errors.New("IP Certificate Lifecycle install Plan is required")
	}

	candidateHost, err := profilesubuntu.NewCandidateHost(candidate)
	if err != nil {
		return nil, err
	}
	startingRegistry := registry
	startingRegistry.Reality.Revision, startingRegistry.XHTTP.Revision, startingRegistry.WebSocket.Revision = 0, 0, 0
	startingRegistry.Hysteria2.Revision, startingRegistry.TUIC.Revision, startingRegistry.AnyTLS.Revision = 0, 0, 0
	startingRegistry.Reality.Port = 0
	profileResult := connectionprofiles.New(candidateHost).PlanRegistry(ctx, connectionprofiles.RegistryPlanRequest{Current: startingRegistry, Candidate: registry, ChangeSet: changeSet, DesiredStateSHA256: desiredSHA256, FreshInstallation: systemchanges.NewFreshInstallationAuthority(baseNetwork.FreshInstallationProof())})
	if profileResult.Plan == nil {
		return nil, errors.New("Connection Profiles install Plan refused")
	}

	var subscriptionPlan *subscriptionpublication.Plan
	if err := registryInputs.WithClientAccessReader(func(profileReader state.ClientAccessReader) error {
		reader := installClientReader{profiles: profileReader, token: subscriptionToken, rawToken: rawSubscriptionToken}
		managedDigest := sha256.Sum256([]byte(profileResult.Plan.SHA256() + desiredSHA256))
		subscriptionDigest := sha256.Sum256([]byte(rawSubscriptionToken + fmt.Sprint(draft.SubscriptionPort)))
		module := subscriptionpublication.NewIntegrated(installSingBoxValidator{candidateHost})
		result := module.Plan(ctx, subscriptionpublication.PlanRequest{Source: registryInputs.PublicationSource(), Secrets: reader, Subscription: desired.Subscription, ChangeSet: changeSet, StartingState: systemchanges.StateLineage{Status: systemchanges.NotInstalled}, DesiredStateRevision: 1, DesiredStateSHA256: desiredSHA256, ManagedInputsSHA256: hex.EncodeToString(managedDigest[:]), RelevantChecksums: subscriptionpublication.RelevantChecksums{ConnectionProfiles: profileResult.Plan.SHA256(), Subscription: hex.EncodeToString(subscriptionDigest[:])}, CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, SelectedAddress: draft.PrimaryAddress, ReleaseIdentity: state.ReleaseIdentity{Repository: candidateRelease(candidate).Repository, Tag: candidateRelease(candidate).Tag, Commit: candidateRelease(candidate).Commit, ReleaseIndexSHA256: candidateRelease(candidate).IndexSHA256}})
		subscriptionPlan = result.Plan
		if subscriptionPlan == nil {
			return errors.New("Subscription Publication install Plan refused")
		}
		return nil
	}); err != nil {
		return nil, err
	}

	certificateContribution, valid := certificatelifecycle.NewFreshInstallContribution(ipPlan)
	if !valid {
		return nil, errors.New("complete Certificate Lifecycle install contribution unavailable")
	}
	contributions := []softwarelifecycle.InstallContribution{softwarelifecycle.NewReviewedNetworkInstallContribution(baseNetwork, changeSet, desiredSHA256), profileResult.Plan, subscriptionPlan, certificateContribution}
	installPlan, finding := softwarelifecycle.PlanInstall(softwarelifecycle.InstallPlanRequest{Candidate: candidate, ChangeSet: changeSet, DesiredStateSHA256: desiredSHA256, Contributions: contributions, Disk: disk, ReviewedReclamationSHA256: request.ReviewedReclamationSHA256, SSHPreservation: systemchanges.NewSSHPreservationAuthority(dependencies.sshProof)})
	if finding != nil || installPlan == nil || request.ReviewedPlanSHA256 != "" && installPlan.SHA256() != request.ReviewedPlanSHA256 {
		return nil, errors.New("reviewed install Plan changed")
	}
	wiring := &installWiring{install: installPlan, profiles: profileResult.Plan, subscription: subscriptionPlan, ip: ipPlan, network: baseNetwork, networkState: networkState}
	totalSteps := 1
	for _, contribution := range contributions {
		totalSteps += len(contribution.SoftwareLifecycleInstallContribution().Steps)
	}
	health := healthdiagnostics.InstallationSummaryFrom(systemchanges.NewNotInstalledHealthInspection(baseNetwork.FreshInstallationProof()))
	return &builtInstall{candidate: candidate, desired: desired, desiredSHA256: desiredSHA256, plan: installPlan, wiring: wiring, contributions: contributions, networkIntent: intent, network: dependencies.network, disk: disk, totalSteps: totalSteps, health: health}, nil
}

type installEntropyReader struct {
	key     []byte
	counter uint64
	buffer  []byte
}

func newInstallEntropyReader(key []byte) io.Reader {
	return &installEntropyReader{key: append([]byte(nil), key...)}
}

func (reader *installEntropyReader) Read(destination []byte) (int, error) {
	written := 0
	for written < len(destination) {
		if len(reader.buffer) == 0 {
			reader.counter++
			counter := make([]byte, 8)
			binary.BigEndian.PutUint64(counter, reader.counter)
			digest := hmac.New(sha256.New, reader.key)
			_, _ = digest.Write([]byte("SBXR revision 1 install entropy"))
			_, _ = digest.Write(counter)
			reader.buffer = digest.Sum(nil)
		}
		count := copy(destination[written:], reader.buffer)
		reader.buffer = reader.buffer[count:]
		written += count
	}
	return written, nil
}

type installClock struct{}

func (installClock) Now() time.Time { return time.Now() }

func trimVersion(version string) string {
	if len(version) > 0 && version[0] == 'v' {
		return version[1:]
	}
	return version
}

func selectedAddresses(draft softwarelifecycle.InstallationDraft) []string {
	result := []string{}
	if draft.PublicIPv4 != "" {
		result = append(result, draft.PublicIPv4)
	}
	if draft.PublicIPv6 != "" {
		result = append(result, draft.PublicIPv6)
	}
	return result
}

func candidateRelease(candidate softwarelifecycle.InstallCandidate) softwarelifecycle.ReleaseIdentity {
	staged, _, _, _ := candidate.SoftwareLifecyclePreparedArchive()
	return staged.Identity
}
