package proxyinstallation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type controlledHost struct {
	subscriptionPreflight           *hostadapter.SubscriptionPreflight
	stagedOwnership                 []byte
	failOwnershipSync, failLateSync bool
	subscriptionAbsence             *hostadapter.Observation
	inspection                      hostadapter.Inspection
	preflight                       hostadapter.Preflight
	ownership                       []byte
	checkpoints                     [][]byte
	operations                      []hostadapter.Operation
	configuration                   []byte
	configurationReads              int
	enabled                         bool
	active                          bool
	listener                        bool
	busy                            bool
	lockHeld                        bool
	lockChangesFacts                bool
	statusBusy                      bool
	activeUnknown                   bool
	hostUnknown                     bool
	configUnknown                   bool
	fails                           map[hostadapter.Operation]bool
	failPublish                     setupPhase
	latePublish                     bool
	publishFailed                   bool
	cancelOn                        hostadapter.Operation
	cancel                          context.CancelFunc
	removal                         *hostadapter.RemovalInspection
	failRemovalPublish              map[int]bool
	lateRemovalPublish              map[int]bool
	finalizing                      bool
	finalRemovalFails               int
	failSubscriptionPreparation     bool
	failSubscriptionCheckpoint      int
	subscriptionPrepared            bool
	subscriptionServing             hostadapter.ServingAuthority
	subscriptionRenewal             hostadapter.RenewalAuthority
	subscriptionCredential          []byte
	subscriptionCredentialCount     int
	subscriptionRotationCredential  []byte
	subscriptionRotationServing     hostadapter.ServingAuthority
	subscriptionStopped             bool
	subscriptionOverlap             bool
	failRotationEffect              string
	renewalProblem                  bool
	publicIPDrift                   bool
	subscriptionStarts              int
	clientIdentityTarget            []byte
	clientIdentityStartup           *hostadapter.ProxyStartupAuthority
	clientIdentityFail              string
	proxyStartAuthorization         string
	failClientCheckpoint            clientIdentityRotationCheckpoint
	failClientCompletion            bool
	clientSubscriptionArtifact      []byte
	clientPublishedCertificate      *hostadapter.ServingAuthority
	clientCertificateInvalid        bool
}

func (*controlledHost) PlanProxyStartupIntegration() (hostadapter.ProxyStartupAuthority, hostadapter.Observation) {
	sum := sha256.Sum256([]byte(hostadapter.ProxyStartupDropIn))
	return hostadapter.ProxyStartupAuthority{DropInSHA256: hex.EncodeToString(sum[:]), DirectoryCreated: true}, hostadapter.Observation{Observed: true, Accepted: true}
}
func (host *controlledHost) ClientIdentityPreparationIdle() hostadapter.Observation {
	return hostadapter.Observation{Observed: true, Accepted: len(host.clientIdentityTarget) == 0 && host.proxyStartAuthorization == ""}
}

func (host *controlledHost) PrepareClientIdentityTarget(body []byte, digest string) bool {
	if host.clientIdentityFail == "prepare" {
		host.clientIdentityFail = ""
		return false
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != digest {
		return false
	}
	host.clientIdentityTarget = bytes.Clone(body)
	return true
}

func (host *controlledHost) PublishProxyStartupIntegration(authority hostadapter.ProxyStartupAuthority) bool {
	if host.clientIdentityFail == "startup" {
		host.clientIdentityFail = ""
		return false
	}
	host.clientIdentityStartup = &authority
	return true
}

func (host *controlledHost) ReloadProxyStartupIntegration(context.Context) bool {
	if host.clientIdentityFail == "reload" {
		host.clientIdentityFail = ""
		return false
	}
	return true
}
func (host *controlledHost) VerifyProxyStartupIntegration(_ context.Context, authority hostadapter.ProxyStartupAuthority) bool {
	if host.clientIdentityFail == "route" {
		host.clientIdentityFail = ""
		return false
	}
	return host.clientIdentityStartup != nil && *host.clientIdentityStartup == authority
}
func (host *controlledHost) ConsumeProxyStartAuthorization(target string) bool {
	if host.proxyStartAuthorization != target {
		return false
	}
	host.proxyStartAuthorization = ""
	return true
}
func (host *controlledHost) StopProxyForClientIdentityRotation(context.Context) bool {
	if host.clientIdentityFail == "stop" {
		host.clientIdentityFail = ""
		return false
	}
	host.active, host.listener = false, false
	return true
}
func (host *controlledHost) ProxyQuiescentForClientIdentityRotation(context.Context) bool {
	if host.clientIdentityFail == "quiescence" {
		host.clientIdentityFail = ""
		return false
	}
	return !host.active && !host.listener
}
func (host *controlledHost) PublishClientIdentityConfiguration(source, target string) bool {
	if host.clientIdentityFail == "publish" {
		host.clientIdentityFail = ""
		return false
	}
	current := sha256.Sum256(host.configuration)
	replacement := sha256.Sum256(host.clientIdentityTarget)
	if hex.EncodeToString(replacement[:]) != target {
		return false
	}
	if hex.EncodeToString(current[:]) == target {
		return true
	}
	if hex.EncodeToString(current[:]) != source {
		return false
	}
	host.configuration = bytes.Clone(host.clientIdentityTarget)
	return true
}
func (host *controlledHost) StartProxyForClientIdentityRotation(context.Context, string) bool {
	if host.clientIdentityFail == "start" {
		host.clientIdentityFail = ""
		return false
	}
	host.active, host.listener = true, true
	return true
}
func (host *controlledHost) RemoveClientIdentityTarget(_, target string) bool {
	if host.clientIdentityFail == "remove" {
		host.clientIdentityFail = ""
		return false
	}
	digest := sha256.Sum256(host.clientIdentityTarget)
	if len(host.clientIdentityTarget) > 0 && hex.EncodeToString(digest[:]) != target {
		return false
	}
	host.clientIdentityTarget = nil
	return true
}
func (host *controlledHost) RestoreClientIdentityRotation(context.Context, string, string, *hostadapter.ProxyStartupAuthority) bool {
	host.clientIdentityTarget = nil
	host.active, host.listener = true, true
	return true
}
func (host *controlledHost) InspectClientIdentityRotation(source, target, canonical string, startup *hostadapter.ProxyStartupAuthority, targetRequired, startupRequired, forward bool) hostadapter.Observation {
	targetAccepted := !targetRequired || len(host.clientIdentityTarget) > 0
	startupAccepted := !startupRequired || startup != nil && host.clientIdentityStartup != nil && *startup == *host.clientIdentityStartup
	return hostadapter.Observation{Observed: true, Accepted: (canonical == source || canonical == target) && targetAccepted && startupAccepted}
}
func (host *controlledHost) RemoveProxyStartupIntegration(context.Context, hostadapter.ProxyStartupAuthority) bool {
	host.clientIdentityStartup = nil
	return true
}

func (host *controlledHost) PrepareSubscription(_ context.Context, input hostadapter.SubscriptionEnableInput) hostadapter.SubscriptionEnableResult {
	host.subscriptionPrepared = true
	host.subscriptionCredential = bytes.Clone(input.Credential)
	host.subscriptionCredentialCount++
	host.subscriptionServing = input.Serving
	host.subscriptionServing.CertificateGeneration = 1
	host.subscriptionServing.CertificateSHA256 = [4]string{strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), strings.Repeat("4", 64)}
	host.subscriptionRenewal = input.Renewal
	resources := input.Resources
	for checkpoint := 1; checkpoint < hostadapter.SubscriptionServingCheckpoint; checkpoint++ {
		if !input.Authorize(checkpoint, nil) {
			return hostadapter.SubscriptionEnableResult{Resources: resources}
		}
	}
	for checkpoint := hostadapter.SubscriptionServingCheckpoint; checkpoint < hostadapter.SubscriptionActivationCheckpoint; checkpoint++ {
		if !input.Authorize(checkpoint, &host.subscriptionServing) {
			return hostadapter.SubscriptionEnableResult{Resources: resources}
		}
	}
	if host.failSubscriptionPreparation {
		return hostadapter.SubscriptionEnableResult{Resources: resources}
	}
	return hostadapter.SubscriptionEnableResult{Serving: host.subscriptionServing, Renewal: host.subscriptionRenewal, Resources: resources, Prepared: true}
}

func (host *controlledHost) InspectPreparedSubscription(_ context.Context, serving hostadapter.ServingAuthority, renewal hostadapter.RenewalAuthority) hostadapter.Observation {
	if host.failRotationEffect == "verify" {
		host.failRotationEffect = ""
		return hostadapter.Observation{Observed: true}
	}
	accepted := host.subscriptionPrepared && serving == host.subscriptionServing && renewal == host.subscriptionRenewal
	return hostadapter.Observation{Observed: true, Accepted: accepted}
}

func (host *controlledHost) ActivatePreparedSubscription(context.Context, hostadapter.ServingAuthority, hostadapter.RenewalAuthority) bool {
	if host.failRotationEffect == "activate" {
		host.failRotationEffect = ""
		return false
	}
	host.subscriptionStarts++
	host.subscriptionStopped = false
	return host.subscriptionPrepared
}

func (host *controlledHost) ServingPublicIPv4(context.Context, string) bool {
	return !host.publicIPDrift
}

func (host *controlledHost) PrepareSubscriptionRotation(input hostadapter.SubscriptionRotationInput) bool {
	if input.Source != host.subscriptionServing || len(input.Credential) != 43 {
		return false
	}
	host.subscriptionRotationCredential = bytes.Clone(input.Credential)
	host.subscriptionRotationServing = input.Target
	host.subscriptionCredentialCount++
	if host.failRotationEffect == "prepare" {
		host.failRotationEffect = ""
		return false
	}
	return true
}

func (host *controlledHost) StopSubscriptionRotation(_ context.Context, input hostadapter.SubscriptionRotationInput) bool {
	if input.Source != host.subscriptionServing {
		return false
	}
	host.subscriptionStopped = true
	if host.failRotationEffect == "stop" {
		host.failRotationEffect = ""
		return false
	}
	return true
}

func (host *controlledHost) PublishSubscriptionRotation(input hostadapter.SubscriptionRotationInput) bool {
	if !host.subscriptionStopped && input.Target != host.subscriptionServing || input.Target != host.subscriptionRotationServing || input.Source != host.subscriptionServing && input.Target != host.subscriptionServing {
		return false
	}
	if host.failRotationEffect == "publish" {
		host.failRotationEffect = ""
		return false
	}
	host.subscriptionOverlap = !host.subscriptionStopped
	host.subscriptionCredential = bytes.Clone(host.subscriptionRotationCredential)
	host.subscriptionServing = input.Target
	return true
}

func (host *controlledHost) RestoreSubscriptionRotation(context.Context, hostadapter.SubscriptionRotationInput) bool {
	host.subscriptionRotationCredential = nil
	host.subscriptionRotationServing = hostadapter.ServingAuthority{}
	host.subscriptionStopped = false
	return true
}

func (host *controlledHost) RemoveSubscriptionRotation(context.Context, hostadapter.SubscriptionRotationInput, *hostadapter.ServingExclusion) bool {
	host.subscriptionRotationCredential = nil
	host.subscriptionRotationServing = hostadapter.ServingAuthority{}
	return true
}

func (host *controlledHost) SubscriptionRotationStagingEmpty() bool {
	return len(host.subscriptionRotationCredential) == 0 || host.subscriptionServing == host.subscriptionRotationServing
}

func (host *controlledHost) ReadSubscriptionLink(serving hostadapter.ServingAuthority, publicIPv4 string) ([]byte, bool) {
	if serving != host.subscriptionServing || len(host.subscriptionCredential) != 43 {
		return nil, false
	}
	return []byte("https://" + publicIPv4 + ":8443/s/" + string(host.subscriptionCredential)), true
}

func (host *controlledHost) CleanupPreparedSubscription(context.Context, hostadapter.SubscriptionCleanupInput) bool {
	host.subscriptionPrepared = false
	host.subscriptionServing = hostadapter.ServingAuthority{}
	host.subscriptionRenewal = hostadapter.RenewalAuthority{}
	host.subscriptionCredential = nil
	return true
}

func (host *controlledHost) RemoveSubscriptionResources(context.Context, hostadapter.SubscriptionResourceAuthority, *hostadapter.ServingAuthority) bool {
	return true
}

func (host *controlledHost) InspectRenewal(hostadapter.RenewalAuthority) hostadapter.RenewalInspection {
	if host.renewalProblem {
		return hostadapter.RenewalInspection{Observation: hostadapter.Observation{Observed: true}, State: hostadapter.RenewalAttemptFailed}
	}
	return hostadapter.RenewalInspection{Observation: hostadapter.Observation{Observed: true, Accepted: true}, State: hostadapter.RenewalAttemptHealthy}
}

func (*controlledHost) PrepareRenewalRecorder(hostadapter.RenewalAuthority) (hostadapter.RenewalAttemptRunner, bool) {
	return nil, false
}

func (*controlledHost) RecordRenewalHook(hostadapter.RenewalAuthority, string, map[string]string) bool {
	return false
}

func (host *controlledHost) InspectCertificateActivation(context.Context, hostadapter.RenewalAuthority, hostadapter.ServingAuthority) hostadapter.CertificateActivationInspection {
	loaded := host.subscriptionServing
	if host.subscriptionStopped {
		loaded = hostadapter.ServingAuthority{}
	}
	published := host.subscriptionServing
	if host.clientPublishedCertificate != nil {
		published = *host.clientPublishedCertificate
	}
	if host.clientCertificateInvalid || len(host.clientSubscriptionArtifact) != 0 {
		return hostadapter.CertificateActivationInspection{Observed: true, Loaded: loaded}
	}
	return hostadapter.CertificateActivationInspection{Published: published, Loaded: loaded, Observed: true, Accepted: true}
}

func (*controlledHost) ActivateServing(context.Context, hostadapter.RenewalAuthority, hostadapter.ServingAuthority) bool {
	return true
}

func (host *controlledHost) InspectServingFiles(hostadapter.ServingAuthority, bool) hostadapter.Observation {
	return hostadapter.Observation{Observed: true, Accepted: true}
}

func (host *controlledHost) AcquireServingExclusion() (*hostadapter.ServingExclusion, bool) {
	return &hostadapter.ServingExclusion{}, true
}

func (host *controlledHost) AcquireRenewalExclusion(hostadapter.RenewalAuthority) (*hostadapter.RenewalExclusion, bool) {
	return &hostadapter.RenewalExclusion{}, true
}

func (host *controlledHost) RemoveServingRuntime(context.Context, hostadapter.ServingAuthority, *hostadapter.ServingExclusion) bool {
	host.subscriptionPrepared = false
	return true
}

func (*controlledHost) ServingRuntimeAbsent(hostadapter.ServingAuthority) bool { return true }
func (*controlledHost) RemoveRenewalIntegration(context.Context, hostadapter.RenewalAuthority, *hostadapter.RenewalExclusion) bool {
	return true
}
func (*controlledHost) RenewalIntegrationAbsent(hostadapter.RenewalAuthority) bool { return true }

func (host *controlledHost) PreflightSubscription(context.Context, string) hostadapter.SubscriptionPreflight {
	if host.subscriptionPreflight != nil {
		return *host.subscriptionPreflight
	}
	yes := hostadapter.Observation{Observed: true, Accepted: true}
	return hostadapter.SubscriptionPreflight{TCP80: yes, TCP8443: yes, Clock: yes, PackageLocks: yes, RenewalIdle: yes, Dependencies: yes, Firewall: yes}
}

func TestPinnedPackageProvenanceUsesCanonicalServiceUnitPath(t *testing.T) {
	if hostSetupSpec.ServiceUnitPath != "/usr/lib/systemd/system/sing-box.service" {
		t.Fatalf("service unit provenance path = %q", hostSetupSpec.ServiceUnitPath)
	}
	want := map[string]bool{
		"/lib/systemd/system/sing-box.service":     false,
		"/usr/lib/systemd/system/sing-box.service": false,
	}
	for _, resource := range footprint {
		if _, ok := want[resource.Name]; ok {
			want[resource.Name] = true
		}
	}
	for name, present := range want {
		if !present {
			t.Errorf("footprint omitted %s", name)
		}
	}
}

func TestProductionUsesOnlyLiveProvenRealityDestination(t *testing.T) {
	want := []hostadapter.Destination{{Address: "google.com:443", ServerName: "google.com"}}
	if !reflect.DeepEqual(destinations, want) {
		t.Fatalf("destinations = %#v, want %#v", destinations, want)
	}
}

type controlledHostFacts struct {
	inspection                                  hostadapter.Inspection
	preflight                                   hostadapter.Preflight
	ownership, configuration                    []byte
	operations                                  []hostadapter.Operation
	enabled, active, listener, busy, statusBusy bool
}

func (host *controlledHost) facts() controlledHostFacts {
	return controlledHostFacts{
		inspection: host.inspection, preflight: host.preflight,
		ownership: bytes.Clone(host.ownership), configuration: bytes.Clone(host.configuration), operations: slices.Clone(host.operations),
		enabled: host.enabled, active: host.active, listener: host.listener, busy: host.busy, statusBusy: host.statusBusy,
	}
}

func acceptedHost() *controlledHost { return &controlledHost{preflight: acceptedPreflightFacts()} }

func (host *controlledHost) Inspect(_ context.Context, requested []hostadapter.Resource) hostadapter.Inspection {
	if host.inspection.Resources == nil {
		resources := observedAbsent(requested)
		for index := range resources {
			switch resources[index].Name {
			case hostSetupSpec.OwnershipPath:
				resources[index].Present = len(host.ownership) > 0 && !host.finalizing
			case finalOwnershipPath:
				resources[index].Present = len(host.ownership) > 0 && host.finalizing
			case hostadapter.ClientIdentityTargetPath:
				resources[index].Present = len(host.clientIdentityTarget) > 0
			case hostadapter.ProxyStartupDropInPath:
				resources[index].Present = host.clientIdentityStartup != nil
			}
		}
		return hostadapter.Inspection{Resources: resources, Complete: true}
	}
	return host.inspection
}

func (host *controlledHost) Preflight(_ context.Context, requested []hostadapter.Resource, _ []hostadapter.Destination) hostadapter.Preflight {
	if host.preflight.Resources == nil {
		host.preflight.Resources = observedAbsent(requested)
	}
	return host.preflight
}

func (host *controlledHost) ReadOwnership(name string) ([]byte, error) {
	if name == hostSetupSpec.OwnershipNextPath {
		if host.stagedOwnership == nil {
			return nil, os.ErrNotExist
		}
		return bytes.Clone(host.stagedOwnership), nil
	}
	if len(host.ownership) == 0 {
		return nil, os.ErrNotExist
	}
	if host.finalizing != (name == finalOwnershipPath) {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(host.ownership), nil
}

func (host *controlledHost) ReadConfiguration(_ context.Context, _ hostadapter.SetupSpec, expectedDigest string) ([]byte, error) {
	host.configurationReads++
	sum := sha256.Sum256(host.configuration)
	if hex.EncodeToString(sum[:]) != expectedDigest {
		return nil, errors.New("configuration mismatch")
	}
	return bytes.Clone(host.configuration), nil
}

func (host *controlledHost) MutationInProgress(string) (bool, bool) { return host.statusBusy, true }

func (host *controlledHost) PublishOwnership(_, _ string, expected, next []byte) error {
	if !bytes.Equal(expected, host.ownership) {
		return errors.New("ownership changed")
	}
	record, _ := decodeOwnership(next)
	if host.failClientCheckpoint != "" && record.ClientRotation != nil && record.ClientRotation.Checkpoint == host.failClientCheckpoint {
		host.failClientCheckpoint = ""
		return errors.New("client rotation checkpoint failed")
	}
	if host.failClientCompletion && record.ClientRotation == nil && bytes.Contains(host.ownership, []byte(`"client_identity_rotation"`)) {
		host.failClientCompletion = false
		return errors.New("client rotation completion failed")
	}
	if record.Direction == removalRequired && host.failRemovalPublish[record.RemovalCheckpoint] {
		delete(host.failRemovalPublish, record.RemovalCheckpoint)
		return errors.New("removal checkpoint failed")
	}
	if host.failSubscriptionCheckpoint > 0 && record.Enablement != nil && record.Enablement.Checkpoint == host.failSubscriptionCheckpoint {
		host.failSubscriptionCheckpoint = -1
		return errors.New("subscription checkpoint failed")
	}
	if record.Phase == host.failPublish && !host.publishFailed && !host.latePublish {
		host.publishFailed = true
		return errors.New("checkpoint failed")
	}
	host.ownership = bytes.Clone(next)
	host.checkpoints = append(host.checkpoints, bytes.Clone(next))
	if record.Direction == removalRequired && host.lateRemovalPublish[record.RemovalCheckpoint] {
		delete(host.lateRemovalPublish, record.RemovalCheckpoint)
		host.failOwnershipSync = host.failLateSync
		return errors.New("late removal checkpoint failure")
	}
	if record.Phase == host.failPublish && !host.publishFailed && host.latePublish {
		host.publishFailed = true
		return errors.New("late checkpoint failure")
	}
	return nil
}

func (host *controlledHost) RemoveOwnership(_, _ string, expected []byte) error {
	if !bytes.Equal(expected, host.ownership) {
		return errors.New("ownership changed")
	}
	host.ownership = nil
	return nil
}

func (host *controlledHost) RemoveFinalOwnership(_, _, _ string, expected []byte) error {
	if !bytes.Equal(expected, host.ownership) {
		return errors.New("ownership changed")
	}
	if host.finalRemovalFails > 0 {
		host.finalRemovalFails--
		host.finalizing = true
		return errors.New("simulated process death")
	}
	host.finalizing = false
	return host.RemoveOwnership("", "", expected)
}

func (host *controlledHost) AcquireMutationLock(string) (*hostadapter.MutationLock, bool, error) {
	host.lockHeld = true
	if host.lockChangesFacts {
		host.preflight.MutationLockAvailable = false
	}
	return &hostadapter.MutationLock{}, host.busy, nil
}

func (host *controlledHost) AcquireSubscriptionReviewLock(string) (*hostadapter.MutationLock, bool, error) {
	return &hostadapter.MutationLock{}, host.busy || host.statusBusy, nil
}

func (host *controlledHost) AcquirePackageLocks() (*hostadapter.PackageLocks, bool, error) {
	return &hostadapter.PackageLocks{}, host.busy, nil
}

func (host *controlledHost) Apply(_ context.Context, input hostadapter.OperationInput) hostadapter.OperationResult {
	host.operations = append(host.operations, input.Operation)
	if host.fails[input.Operation] {
		return hostadapter.OperationResult{}
	}
	switch input.Operation {
	case hostadapter.InstallConfiguration:
		host.configuration = bytes.Clone(input.Body)
	case hostadapter.EnableService:
		host.enabled = true
	case hostadapter.StartService:
		host.active, host.listener = true, true
	case hostadapter.StopDisableService:
		host.enabled, host.active, host.listener = false, false, false
	}
	if input.Operation == host.cancelOn && host.cancel != nil {
		host.cancel()
	}
	return hostadapter.OperationResult{OK: true, Fact: "accepted"}
}

func (host *controlledHost) InspectRunning(_ context.Context, _ hostadapter.SetupSpec, _, ownership []byte, _, _ string) hostadapter.RunningInspection {
	if host.removal != nil {
		return host.removal.RunningInspection
	}
	prepared := false
	for _, operation := range host.operations {
		if operation == hostadapter.ValidateConfiguration {
			prepared = true
		}
	}
	fact := func(accepted bool) hostadapter.Observation {
		return hostadapter.Observation{Observed: true, Accepted: accepted}
	}
	active := fact(host.active)
	if host.activeUnknown {
		active = hostadapter.Observation{}
	}
	hostFact, configuration := fact(true), fact(prepared)
	if host.hostUnknown {
		hostFact = hostadapter.Observation{}
	}
	if host.configUnknown {
		configuration = hostadapter.Observation{}
	}
	return hostadapter.RunningInspection{
		OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", PublicIPv4: "8.8.8.8", Host: hostFact, PublicIPv4Matches: fact(true),
		Ownership: fact(bytes.Equal(ownership, host.ownership)), TransactionFilesAbsent: fact(true), APTKey: fact(prepared), APTSource: fact(prepared), Package: fact(prepared), Hold: fact(prepared),
		PackageIdentity: fact(prepared), Configuration: configuration, State: fact(prepared), Validation: fact(prepared), ServiceProvenance: fact(prepared),
		ServiceEnabled: fact(host.enabled), ServiceActive: active, Listener: fact(host.listener),
	}
}

func (host *controlledHost) InspectActivation(ctx context.Context, spec hostadapter.SetupSpec, source, ownership []byte, digest, publicIPv4 string, _ hostadapter.Destination) hostadapter.ActivationInspection {
	return hostadapter.ActivationInspection{RunningInspection: host.InspectRunning(ctx, spec, source, ownership, digest, publicIPv4), DestinationCompatible: true, ListenerAvailable: !host.listener}
}

func (host *controlledHost) InspectRemoval(ctx context.Context, spec hostadapter.SetupSpec, source, ownership []byte, digest, publicIPv4 string) hostadapter.RemovalInspection {
	if host.removal != nil {
		return *host.removal
	}
	accepted := hostadapter.Observation{Observed: true, Accepted: true}
	return hostadapter.RemovalInspection{
		RunningInspection: host.InspectRunning(ctx, spec, source, ownership, digest, publicIPv4),
		PackageLocks:      accepted, ConfigurationEntries: accepted, StateEntries: accepted,
		IdentityExclusive: accepted, ProcessExclusive: accepted, ServiceSafe: accepted,
	}
}

func observedAbsent(requested []hostadapter.Resource) []hostadapter.Resource {
	resources := make([]hostadapter.Resource, len(requested))
	copy(resources, requested)
	for index := range resources {
		resources[index].Observed = true
	}
	return resources
}

func acceptedPreflightFacts() hostadapter.Preflight {
	return hostadapter.Preflight{
		Resources: observedAbsent(footprint),
		OSID:      "ubuntu", OSVersion: "24.04", Architecture: "amd64", PublicIPv4: "8.8.8.8",
		ClockSynchronized: true, TCP443Available: true, MutationLockAvailable: true, PackageLocksAvailable: true,
		Destinations: []hostadapter.DestinationObservation{{Destination: hostadapter.Destination{Address: "google.com:443", ServerName: "google.com"}, DNS: true, TCP: true, TLS13: true, HTTP2: true, CertificateName: true}},
	}
}

type acceptedSingBox struct{}

func (acceptedSingBox) PrepareIdentity() (singboxadapter.Identity, error) {
	return singboxadapter.Identity{UUID: "11111111-2222-4333-8444-555555555555", PrivateKey: "private", PublicKey: "public", ShortID: "01020304"}, nil
}

func (acceptedSingBox) ValidIdentity(identity singboxadapter.Identity) bool {
	return identity.UUID == "11111111-2222-4333-8444-555555555555" && identity.PrivateKey == "private" && identity.PublicKey == "public" && identity.ShortID == "01020304"
}

func (adapter acceptedSingBox) EncodeServerConfiguration(identity singboxadapter.Identity, _, _ string) ([]byte, error) {
	if !adapter.ValidIdentity(identity) {
		return nil, errors.New("invalid identity")
	}
	return []byte(`{"inbound":"secret-safe-test-fixture"}` + "\n"), nil
}

func (adapter acceptedSingBox) EncodeClientConfiguration(_ []byte, publicIPv4 string) ([]byte, error) {
	return []byte(fmt.Sprintf(`{"server":%q,"uuid":"11111111-2222-4333-8444-555555555555","public_key":"public","short_id":"01020304"}`+"\n", publicIPv4)), nil
}

func (acceptedSingBox) ReplaceClientIdentity([]byte) ([]byte, error) {
	return []byte(`{"inbound":"replacement-secret-safe-test-fixture"}` + "\n"), nil
}

type readyLifecycle struct{}

type mutableLifecycle struct {
	readyLifecycle
	result softwarelifecycle.Result
}

func (l *mutableLifecycle) Status(context.Context) softwarelifecycle.Result { return l.result }
func (l *mutableLifecycle) StatusUnderMutationLock(context.Context, *softwarelifecycle.MutationLockAuthority) softwarelifecycle.Result {
	return l.result
}

func (readyLifecycle) Status(context.Context) softwarelifecycle.Result {
	identity := testInstalledIdentity()
	return softwarelifecycle.Result{State: softwarelifecycle.Ready, Installed: &identity, Code: softwarelifecycle.StatusReady}
}

func (lifecycle readyLifecycle) StatusUnderMutationLock(ctx context.Context, _ *softwarelifecycle.MutationLockAuthority) softwarelifecycle.Result {
	return lifecycle.Status(ctx)
}

func testInstalledIdentity() softwarelifecycle.ReleaseIdentity {
	return softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v3.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
}

func (readyLifecycle) Check(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}

func (readyLifecycle) Update(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}

func (readyLifecycle) Recover(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}

type mismatchedLifecycle struct{ readyLifecycle }

func (mismatchedLifecycle) Status(context.Context) softwarelifecycle.Result {
	identity := softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v3.0.1", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
	return softwarelifecycle.Result{State: softwarelifecycle.Ready, Installed: &identity, Code: softwarelifecycle.StatusReady}
}

type lockSensitiveLifecycle struct {
	readyLifecycle
	host *controlledHost
}

func (lifecycle *lockSensitiveLifecycle) Status(ctx context.Context) softwarelifecycle.Result {
	if lifecycle.host.lockHeld {
		return softwarelifecycle.Result{State: softwarelifecycle.UpdateInProgress, Code: softwarelifecycle.StatusUpdateInProgress}
	}
	return lifecycle.readyLifecycle.Status(ctx)
}

func (lifecycle *lockSensitiveLifecycle) StatusUnderMutationLock(ctx context.Context, _ *softwarelifecycle.MutationLockAuthority) softwarelifecycle.Result {
	return lifecycle.readyLifecycle.Status(ctx)
}

func TestOwnerCanReviewAndDeclineCleanSetup(t *testing.T) {
	installation := newInstalledInterface(readyLifecycle{}, acceptedHost(), acceptedSingBox{})

	review := installation.Review(t.Context(), StartSetupAction)

	wantActions := []Action{StartSetupAction, ViewDetailsAction, CompleteRemovalAction}
	if review.Version != "v3.0.0" || review.Status != NotSetUp || review.Result.Code != StatusNotSetUp || !reflect.DeepEqual(review.LegalActions, wantActions) || review.Prepared == nil {
		t.Fatalf("Review() = %#v", review)
	}
	plan := strings.Join(review.Plan, "\n")
	for _, required := range []string{"Ubuntu 24.04 amd64", "8.8.8.8:443", "google.com:443", "sing-box 1.13.19 amd64", "803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1", "24597120 bytes", "one generated Client Identity", "/var/lib/sbxr/proxy-ownership.json", "Infrastructure Secret", "will not change SSH, firewall, routing, or provider settings"} {
		if !strings.Contains(plan, required) {
			t.Errorf("plan missing %q:\n%s", required, plan)
		}
	}

	result := installation.Execute(t.Context(), *review.Prepared, Declined, nil)
	if result.Status != NotSetUp || result.Message != "No changes were made." || result.Code != ActionCancelled {
		t.Fatalf("Execute() = %#v", result)
	}
}

func TestSetupRevalidationAcceptsItsAcquiredMutationLock(t *testing.T) {
	host := acceptedHost()
	host.lockChangesFacts = true
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	review := installation.Review(t.Context(), StartSetupAction)
	var phases []string

	result := installation.Execute(t.Context(), *review.Prepared, Approved, func(progress Progress) {
		phases = append(phases, progress.Phase)
	})

	if result.Status != Running || result.Code != SetupComplete || !slices.Contains(phases, string(hostadapter.ValidateConfiguration)) {
		t.Fatalf("Execute() = %#v, phases = %v", result, phases)
	}
}

func TestSetupRevalidatesInstalledReleaseWhileItOwnsTheSharedLock(t *testing.T) {
	host := acceptedHost()
	lifecycle := &lockSensitiveLifecycle{host: host}
	installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	review := installation.Review(t.Context(), StartSetupAction)
	var phases []string

	result := installation.Execute(t.Context(), *review.Prepared, Approved, func(progress Progress) {
		phases = append(phases, progress.Phase)
	})

	if result.Status != Running || result.Code != SetupComplete || !slices.Contains(phases, string(hostadapter.ValidateConfiguration)) {
		t.Fatalf("Execute() = %#v, phases = %v", result, phases)
	}
}

func TestUnfinishedActionsRevalidateInstalledReleaseUnderTheirOwnedSharedLock(t *testing.T) {
	for _, test := range []struct {
		name     string
		finish   Action
		failures map[hostadapter.Operation]bool
		want     ResultCode
	}{
		{name: "cleanup", finish: FinishCleanupAction, failures: map[hostadapter.Operation]bool{hostadapter.InstallPackage: true, hostadapter.RemovePackage: true}, want: SetupCleanedUp},
		{name: "setup", finish: FinishSetupAction, failures: map[hostadapter.Operation]bool{hostadapter.StartService: true}, want: SetupComplete},
	} {
		t.Run(test.name, func(t *testing.T) {
			host := acceptedHost()
			host.fails = test.failures
			installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			start := installation.Review(t.Context(), StartSetupAction)
			installation.Execute(t.Context(), *start.Prepared, Approved, nil)
			host.fails = nil
			host.lockHeld = false
			restarted := newInstalledInterface(&lockSensitiveLifecycle{host: host}, host, acceptedSingBox{})
			finish := restarted.Review(t.Context(), test.finish)

			result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil)

			if result.Code != test.want {
				t.Fatalf("Execute() = %#v", result)
			}
		})
	}
}

func TestOwnerCanReviewAndDeclineCompleteRemovalWithoutMutation(t *testing.T) {
	for _, status := range []Status{NotSetUp, Running} {
		t.Run(string(status), func(t *testing.T) {
			host := acceptedHost()
			installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			if status == Running {
				setup := installation.Review(t.Context(), StartSetupAction)
				if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
					t.Fatalf("setup = %#v", result)
				}
			}
			before := host.facts()

			review := installation.Review(t.Context(), CompleteRemovalAction)

			if review.Prepared == nil || review.Status != status {
				t.Fatalf("Review() = %#v", review)
			}
			plan := strings.Join(review.Plan, "\n")
			for _, required := range []string{
				"Complete removal deletes SBXR, proxy credentials, and every proved V3-owned resource from this VPS.",
				"Outside copies of the Client Configuration cannot be deleted by SBXR.",
				"SBXR preserves SSH, firewall, routing, forwarding, provider settings, shared package-manager state, and every unrelated resource.",
				"Exact confirmation required: REMOVE SBXR",
			} {
				if !strings.Contains(plan, required) {
					t.Errorf("plan missing %q:\n%s", required, plan)
				}
			}
			result := installation.Execute(t.Context(), *review.Prepared, Declined, nil)
			if result.Status != status || result.Message != "No changes were made." || result.Code != ActionCancelled || !reflect.DeepEqual(host.facts(), before) {
				t.Fatalf("Execute() = %#v ownership=%q operations=%v", result, host.ownership, host.operations)
			}
			if reused := installation.Execute(t.Context(), *review.Prepared, Approved, nil); reused.Code != ActionRefused || !reflect.DeepEqual(host.facts(), before) {
				t.Fatalf("reused Execute() = %#v ownership=%q operations=%v", reused, host.ownership, host.operations)
			}
			for _, secret := range []string{"11111111-2222-4333-8444-555555555555", "private", "secret-safe-test-fixture"} {
				if strings.Contains(plan, secret) {
					t.Errorf("plan disclosed %q", secret)
				}
			}
		})
	}
}

func TestCompleteRemovalReviewRefusesEveryUnsafeOwnedFact(t *testing.T) {
	tests := []struct {
		name   string
		change func(*hostadapter.RemovalInspection)
	}{
		{"changed bytes metadata links types or ownership", func(facts *hostadapter.RemovalInspection) { facts.Configuration.Accepted = false }},
		{"package identity or hold", func(facts *hostadapter.RemovalInspection) { facts.Package.Accepted = false }},
		{"package hold", func(facts *hostadapter.RemovalInspection) { facts.Hold.Accepted = false }},
		{"service identity", func(facts *hostadapter.RemovalInspection) { facts.ServiceProvenance.Accepted = false }},
		{"system identity", func(facts *hostadapter.RemovalInspection) { facts.Host.Accepted = false }},
		{"unknown directory entries", func(facts *hostadapter.RemovalInspection) { facts.ConfigurationEntries.Accepted = false }},
		{"unexpected state membership", func(facts *hostadapter.RemovalInspection) { facts.StateEntries.Accepted = false }},
		{"reused package identities", func(facts *hostadapter.RemovalInspection) { facts.IdentityExclusive.Accepted = false }},
		{"outside process use", func(facts *hostadapter.RemovalInspection) { facts.ProcessExclusive.Accepted = false }},
		{"outside listener use", func(facts *hostadapter.RemovalInspection) { facts.ServiceSafe.Accepted = false }},
		{"package lock conflict", func(facts *hostadapter.RemovalInspection) { facts.PackageLocks.Accepted = false }},
		{"unknown fact", func(facts *hostadapter.RemovalInspection) {
			facts.StateEntries.Observed = false
			facts.StateEntries.Accepted = false
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host := acceptedHost()
			installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			setup := installation.Review(t.Context(), StartSetupAction)
			if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
				t.Fatalf("setup = %#v", result)
			}
			facts := host.InspectRemoval(t.Context(), hostSetupSpec, aptSourceBody, host.ownership, strings.Repeat("0", 64), "8.8.8.8")
			test.change(&facts)
			host.removal = &facts
			before := host.facts()

			review := installation.Review(t.Context(), CompleteRemovalAction)
			details := installation.Review(t.Context(), ViewDetailsAction)

			if review.Prepared != nil || review.Result.Code != ActionRefused || review.Result.FailedCheck != "Complete removal preflight" || !strings.Contains(strings.Join(review.Details, "\n"), "Safe correction:") || !strings.Contains(strings.Join(details.Details, "\n"), "Safe correction:") || !reflect.DeepEqual(host.facts(), before) {
				t.Fatalf("Review() = %#v ownership=%q operations=%v", review, host.ownership, host.operations)
			}
		})
	}
}

func TestCompleteRemovalAllowsStoppedOrDisabledServiceReduction(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}
	host.enabled, host.active, host.listener = false, false, false

	review := installation.Review(t.Context(), CompleteRemovalAction)

	if review.Prepared == nil {
		t.Fatalf("Review() = %#v", review)
	}
}

func TestCompleteRemovalTreatsOnlyContractPermittedAbsenceAsAlreadyRemoved(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}
	accepted := installation.Review(t.Context(), CompleteRemovalAction)
	record, _ := decodeOwnership(host.ownership)
	facts := host.InspectRemoval(t.Context(), hostSetupSpec, aptSourceBody, host.ownership, record.ConfigurationSHA256, record.PublicIPv4)
	if accepted.Prepared == nil || !facts.TransactionFilesAbsent.Accepted {
		t.Fatalf("contract-permitted absent transaction resources = %#v", accepted)
	}
	host.removal = &hostadapter.RemovalInspection{}
	missingRequired := installation.Review(t.Context(), CompleteRemovalAction)
	if missingRequired.Prepared != nil || missingRequired.Result.Code != ActionRefused {
		t.Fatalf("unproved missing required resource = %#v", missingRequired)
	}
}

func TestApprovedCompleteRemovalRevalidatesBeforeTheExpectedCommitmentRefusal(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}

	review := installation.Review(t.Context(), CompleteRemovalAction)
	before := slices.Clone(host.operations)
	host.active = false
	changed := installation.Execute(t.Context(), *review.Prepared, Approved, nil)
	if changed.Code != ActionRefused || changed.FailedCheck != "Prepared Action facts" || !reflect.DeepEqual(host.operations, before) {
		t.Fatalf("changed Execute() = %#v operations=%v", changed, host.operations)
	}

	host.active = true
	review = installation.Review(t.Context(), CompleteRemovalAction)
	unchanged := installation.Execute(t.Context(), *review.Prepared, Approved, nil)
	if unchanged.Code != ActionRefused || unchanged.FailedCheck != "Complete removal commitment" || !reflect.DeepEqual(host.operations, before) {
		t.Fatalf("unchanged Execute() = %#v operations=%v", unchanged, host.operations)
	}
}

func TestApprovedCompleteRemovalCommitsThenFinishesForwardToNotInstalled(t *testing.T) {
	host := acceptedHost()
	lifecycle := &controlledRemovalLifecycle{ready: true}
	installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}
	setupCheckpoints := len(host.checkpoints)

	review := installation.Review(t.Context(), CompleteRemovalAction)
	result := installation.Execute(t.Context(), *review.Prepared, Approved, nil)

	if result.Status != "" || result.Message != "SBXR is not installed." || result.Code != CompleteRemovalCompleted {
		t.Fatalf("Execute() = %#v", result)
	}
	if lifecycle.executable || lifecycle.installedRecord || len(host.ownership) != 0 {
		t.Fatalf("remaining lifecycle=%#v ownership=%q", lifecycle, host.ownership)
	}
	if len(host.checkpoints) == setupCheckpoints {
		t.Fatal("no durable removal checkpoint")
	}
	committed, ok := decodeOwnership(host.checkpoints[setupCheckpoints])
	if !ok || committed.Phase != removalCommitted || committed.Direction != removalRequired {
		t.Fatalf("first checkpoint = %#v ok=%v", committed, ok)
	}
}

func TestCompleteRemovalRestartsFromEveryDurableDeletionCheckpoint(t *testing.T) {
	for checkpoint := 0; checkpoint <= 11; checkpoint++ {
		t.Run(fmt.Sprintf("checkpoint-%d", checkpoint), func(t *testing.T) {
			host := acceptedHost()
			host.failRemovalPublish = map[int]bool{checkpoint: true}
			lifecycle := &controlledRemovalLifecycle{ready: true}
			installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
			setup := installation.Review(t.Context(), StartSetupAction)
			if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
				t.Fatalf("setup = %#v", result)
			}

			removal := installation.Review(t.Context(), CompleteRemovalAction)
			interrupted := installation.Execute(t.Context(), *removal.Prepared, Approved, nil)
			if checkpoint == 0 {
				if interrupted.Status != Running || interrupted.Code != ActionRefused {
					t.Fatalf("pre-commit failure = %#v", interrupted)
				}
				removal = installation.Review(t.Context(), CompleteRemovalAction)
			} else {
				if interrupted.Status != RemovalIncomplete || interrupted.Code != RemovalNeedsCompletion {
					t.Fatalf("interrupted = %#v", interrupted)
				}
				restarted := newInstalledInterface(lifecycle, host, acceptedSingBox{})
				status := restarted.Review(t.Context(), StatusAction)
				if status.Status != RemovalIncomplete || !reflect.DeepEqual(status.LegalActions, []Action{FinishRemovalAction, ViewDetailsAction}) {
					t.Fatalf("restart status = %#v", status)
				}
				removal = restarted.Review(t.Context(), FinishRemovalAction)
				installation = restarted
			}
			finished := installation.Execute(t.Context(), *removal.Prepared, Approved, nil)
			if finished.Code != CompleteRemovalCompleted || len(host.ownership) != 0 {
				t.Fatalf("finished = %#v ownership=%q", finished, host.ownership)
			}
		})
	}
}

func TestCompleteRemovalRestartsAfterProcessDeathDuringFinalOwnershipRemoval(t *testing.T) {
	host := acceptedHost()
	host.finalRemovalFails = 1
	lifecycle := &controlledRemovalLifecycle{ready: true}
	installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	removal := installation.Review(t.Context(), CompleteRemovalAction)
	interrupted := installation.Execute(t.Context(), *removal.Prepared, Approved, nil)
	if interrupted.Status != RemovalIncomplete || !host.finalizing {
		t.Fatalf("interrupted = %#v finalizing=%t", interrupted, host.finalizing)
	}

	restarted := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	status := restarted.Review(t.Context(), StatusAction)
	if status.Status != RemovalIncomplete || !reflect.DeepEqual(status.LegalActions, []Action{FinishRemovalAction, ViewDetailsAction}) {
		t.Fatalf("restart status = %#v", status)
	}
	finish := restarted.Review(t.Context(), FinishRemovalAction)
	if result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted || len(host.ownership) != 0 {
		t.Fatalf("finish = %#v ownership=%q", result, host.ownership)
	}
}

func TestCompleteRemovalRecoversLateCheckpointIOAndManagedTermination(t *testing.T) {
	t.Run("late checkpoint I/O", func(t *testing.T) {
		host := acceptedHost()
		host.lateRemovalPublish = map[int]bool{4: true}
		lifecycle := &controlledRemovalLifecycle{ready: true}
		installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
		setup := installation.Review(t.Context(), StartSetupAction)
		installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
		removal := installation.Review(t.Context(), CompleteRemovalAction)
		if result := installation.Execute(t.Context(), *removal.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted {
			t.Fatalf("Execute() = %#v", result)
		}
	})

	t.Run("managed termination", func(t *testing.T) {
		host := acceptedHost()
		lifecycle := &controlledRemovalLifecycle{ready: true}
		installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
		setup := installation.Review(t.Context(), StartSetupAction)
		installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
		ctx, cancel := context.WithCancel(t.Context())
		host.cancelOn, host.cancel = hostadapter.RemovePackageHold, cancel
		removal := installation.Review(ctx, CompleteRemovalAction)
		interrupted := installation.Execute(ctx, *removal.Prepared, Approved, nil)
		if interrupted.Status != RemovalIncomplete || interrupted.FailedCheck != "Managed termination" {
			t.Fatalf("interrupted = %#v", interrupted)
		}
		restarted := newInstalledInterface(lifecycle, host, acceptedSingBox{})
		finish := restarted.Review(t.Context(), FinishRemovalAction)
		if result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted {
			t.Fatalf("finish = %#v", result)
		}
	})
}

type controlledRemovalLifecycle struct {
	ready, executable, installedRecord  bool
	failExecutable, failInstalledRecord bool
}

func (lifecycle *controlledRemovalLifecycle) Status(context.Context) softwarelifecycle.Result {
	if lifecycle.ready {
		identity := testInstalledIdentity()
		lifecycle.executable, lifecycle.installedRecord = true, true
		return softwarelifecycle.Result{State: softwarelifecycle.Ready, Installed: &identity}
	}
	return softwarelifecycle.Result{State: softwarelifecycle.RecoveryRequiredState}
}
func (lifecycle *controlledRemovalLifecycle) StatusUnderMutationLock(ctx context.Context, _ *softwarelifecycle.MutationLockAuthority) softwarelifecycle.Result {
	return lifecycle.Status(ctx)
}
func (*controlledRemovalLifecycle) Check(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}
func (*controlledRemovalLifecycle) Update(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}
func (*controlledRemovalLifecycle) Recover(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}
func (lifecycle *controlledRemovalLifecycle) InspectCompleteRemoval(_ context.Context, expected softwarelifecycle.ReleaseIdentity) softwarelifecycle.CompleteRemovalInspection {
	if expected != testInstalledIdentity() {
		return softwarelifecycle.CompleteRemovalInspection{}
	}
	return softwarelifecycle.CompleteRemovalInspection{Valid: true, ExecutablePresent: lifecycle.executable, InstalledRecordPresent: lifecycle.installedRecord, StateDirectoryEmpty: true}
}
func (lifecycle *controlledRemovalLifecycle) RemoveCompleteRemovalExecutable(context.Context, softwarelifecycle.ReleaseIdentity) bool {
	if lifecycle.failExecutable {
		lifecycle.failExecutable = false
		return false
	}
	lifecycle.executable = false
	lifecycle.ready = false
	return true
}
func (lifecycle *controlledRemovalLifecycle) RemoveCompleteRemovalInstalledRecord(context.Context, softwarelifecycle.ReleaseIdentity) bool {
	if lifecycle.failInstalledRecord {
		lifecycle.failInstalledRecord = false
		return false
	}
	lifecycle.installedRecord = false
	return true
}

func TestApprovedSetupReachesLocallyVerifiedRunning(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	review := installation.Review(t.Context(), StartSetupAction)
	var progress []string

	result := installation.Execute(t.Context(), *review.Prepared, Approved, func(event Progress) { progress = append(progress, event.Phase) })

	if string(result.Status) != "Running" || result.Message != "Proxy setup is complete and locally verified." || string(result.Code) != "PROXY-INSTALLATION-SETUP-COMPLETE" {
		t.Fatalf("Execute() = %#v", result)
	}
	wantPhases := []setupPhase{ownershipRecorded, aptKeyInstalled, aptSourceInstalled, serviceMasked, packageInstalled, packageHeld, stateDirectoryCreated, configurationInstalled, configurationValidated, serviceUnmasked, activationCommitted, serviceEnabled, serviceStarted, runningPhase}
	if len(host.checkpoints) != len(wantPhases) {
		t.Fatalf("checkpoints=%d, want %d", len(host.checkpoints), len(wantPhases))
	}
	for index, body := range host.checkpoints {
		record, ok := decodeOwnership(body)
		if !ok || record.Phase != wantPhases[index] {
			t.Fatalf("checkpoint %d = %q, valid=%t", index, record.Phase, ok)
		}
	}
	if len(progress) != len(wantPhases) {
		t.Fatalf("progress = %v", progress)
	}
	for _, secret := range []string{"11111111-2222-4333-8444-555555555555", "private"} {
		if bytes.Contains(host.ownership, []byte(secret)) {
			t.Fatalf("Ownership Record disclosed %q", secret)
		}
	}
}

func TestOwnerCanReviewDeclineAndDiscloseOneRunningClientConfiguration(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(&lockSensitiveLifecycle{host: host}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}
	host.lockHeld = false

	review := installation.Review(t.Context(), ShowClientConfigurationAction)
	if review.Prepared == nil || !reflect.DeepEqual(review.LegalActions, []Action{ViewDetailsAction, ShowClientConfigurationAction, CompleteRemovalAction, EnableSubscriptionAction, RotateClientIdentityAction}) {
		t.Fatalf("Review() = %#v", review)
	}
	warnings := strings.Join(review.Plan, "\n")
	for _, required := range []string{"contains a credential", "anyone with a copy can use the proxy", "terminal history or recording", "no client file", "outside copies survive Complete removal"} {
		if !strings.Contains(strings.ToLower(warnings), strings.ToLower(required)) {
			t.Errorf("warning missing %q:\n%s", required, warnings)
		}
	}
	if result := installation.Execute(t.Context(), *review.Prepared, Declined, nil); result.Code != ActionCancelled {
		t.Fatalf("declined Execute() = %#v", result)
	}

	review = installation.Review(t.Context(), ShowClientConfigurationAction)
	var configurations [][]byte
	reporter := func(progress Progress) {
		if len(progress.ClientConfiguration) > 0 {
			configurations = append(configurations, bytes.Clone(progress.ClientConfiguration))
		}
	}
	result := installation.Execute(t.Context(), *review.Prepared, Approved, reporter)
	if result.Status != Running || result.Code != ClientConfigurationDisclosed || len(configurations) != 1 || !json.Valid(configurations[0]) {
		t.Fatalf("approved Execute() = %#v", result)
	}
	configuration := string(configurations[0])
	for _, required := range []string{"8.8.8.8", "11111111-2222-4333-8444-555555555555", "public", "01020304"} {
		if !strings.Contains(configuration, required) {
			t.Errorf("configuration missing %q: %s", required, configuration)
		}
	}
	if strings.Contains(configuration, "private") || len(host.operations) != 11 {
		t.Fatalf("disclosure leaked private key or mutated host: configuration=%s operations=%v", configuration, host.operations)
	}
	if strings.Contains(fmt.Sprintf("%#v", result), "private") {
		t.Fatalf("disclosure result leaked the private key: %#v", result)
	}
	if reused := installation.Execute(t.Context(), *review.Prepared, Approved, reporter); reused.Code != ActionRefused || len(configurations) != 1 {
		t.Fatalf("reused Execute() = %#v", reused)
	}
	host.lockHeld = false
	review = installation.Review(t.Context(), ShowClientConfigurationAction)
	if repeated := installation.Execute(t.Context(), *review.Prepared, Approved, reporter); repeated.Code != ClientConfigurationDisclosed || len(configurations) != 2 {
		t.Fatalf("repeated Execute() = %#v configurations=%d", repeated, len(configurations))
	}
	host.lockHeld = false
	review = installation.Review(t.Context(), ShowClientConfigurationAction)
	if missingBoundary := installation.Execute(t.Context(), *review.Prepared, Approved, nil); missingBoundary.Code != ActionRefused || missingBoundary.FailedCheck != "Presentation boundary" || host.configurationReads != 2 {
		t.Fatalf("missing-boundary Execute() = %#v reads=%d", missingBoundary, host.configurationReads)
	}

	host.lockHeld = false
	review = installation.Review(t.Context(), ShowClientConfigurationAction)
	host.active = false
	if changed := installation.Execute(t.Context(), *review.Prepared, Approved, reporter); changed.Code != ActionRefused || len(configurations) != 2 || host.configurationReads != 2 {
		t.Fatalf("changed-fact Execute() = %#v reads=%d", changed, host.configurationReads)
	}
}

func TestOwnerCanReviewAndDeclineSubscriptionEnablement(t *testing.T) {
	for _, confirmation := range []Confirmation{Declined, 0} {
		t.Run(fmt.Sprint(confirmation), func(t *testing.T) {
			host := acceptedHost()
			installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			setup := installation.Review(t.Context(), StartSetupAction)
			installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
			before := host.facts()
			review := installation.Review(t.Context(), Action("Enable subscription"))
			if review.Prepared == nil || review.Status != Running || review.SubscriptionStatus != SubscriptionNotEnabled || !slices.Contains(review.LegalActions, Action("Enable subscription")) {
				t.Fatalf("enable review = %#v", review)
			}
			plan := strings.Join(review.Plan, "\n")
			for _, want := range []string{"Enable subscription", "8.8.8.8", "8443", "80", "provider", "snapd", "Certbot", "sbxr-subscription", "renewal", "shared", "Karing"} {
				if !strings.Contains(plan, want) {
					t.Errorf("Plan missing %q: %s", want, plan)
				}
			}
			result := installation.Execute(t.Context(), *review.Prepared, confirmation, func(event Progress) { t.Fatalf("declined attempt emitted progress: %#v", event) })
			want := ActionCancelled
			if confirmation == 0 {
				want = ActionRefused
			}
			if result.Code != want || result.ProxyTraffic != ProvedWorking || confirmation == Declined && result.Message != "No changes were made." {
				t.Fatalf("result = %#v", result)
			}
			if reused := installation.Execute(t.Context(), *review.Prepared, Approved, nil); reused.Code != ActionRefused {
				t.Fatalf("reused = %#v", reused)
			}
			if !reflect.DeepEqual(before, host.facts()) {
				t.Fatal("subscription review/execute mutated host")
			}
		})
	}
}

func TestOwnerCanEnableOneVerifiedSubscriptionGeneration(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Code != SetupComplete {
		t.Fatalf("setup = %#v", result)
	}

	review := installation.Review(t.Context(), EnableSubscriptionAction)
	var links [][]byte
	result := installation.Execute(t.Context(), *review.Prepared, Approved, func(progress Progress) {
		if len(progress.SubscriptionLink) > 0 {
			links = append(links, bytes.Clone(progress.SubscriptionLink))
		}
	})

	if result.Code != SubscriptionEnabled || result.Status != Running || result.SubscriptionStatus != SubscriptionAvailable || len(links) != 1 {
		t.Fatalf("enable = %#v links=%q", result, links)
	}
	if !strings.HasPrefix(string(links[0]), "https://8.8.8.8:8443/s/") || len(strings.TrimPrefix(string(links[0]), "https://8.8.8.8:8443/s/")) != 43 {
		t.Fatalf("link = %q", links[0])
	}
	record, ok := decodeOwnership(host.ownership)
	if !ok || record.Schema != 2 || record.Serving == nil || record.Renewal == nil || record.Enablement != nil || !host.subscriptionPrepared {
		t.Fatalf("ownership = %#v valid=%t", record, ok)
	}
	if bytes.Contains(host.ownership, host.subscriptionCredential) || bytes.Contains(host.ownership, links[0]) {
		t.Fatal("Ownership Record contains a subscription credential")
	}
}

func TestOwnerCanRotateSubscriptionLinkWithoutChangingProxyAccess(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	enable := installation.Review(t.Context(), EnableSubscriptionAction)
	installation.Execute(t.Context(), *enable.Prepared, Approved, nil)
	oldCredential := bytes.Clone(host.subscriptionCredential)
	oldConfiguration := bytes.Clone(host.configuration)

	review := installation.Review(t.Context(), RotateSubscriptionLinkAction)
	if review.Prepared == nil || !slices.Contains(review.LegalActions, RotateSubscriptionLinkAction) {
		t.Fatalf("rotation review = %#v", review)
	}
	plan := strings.Join(review.Plan, "\n")
	for _, want := range []string{"no overlap", "Karing", "Client Identity", "Proxy Profile", "copied"} {
		if !strings.Contains(plan, want) {
			t.Errorf("rotation Plan missing %q: %s", want, plan)
		}
	}
	var links [][]byte
	result := installation.Execute(t.Context(), *review.Prepared, Approved, func(progress Progress) {
		if len(progress.SubscriptionLink) != 0 {
			links = append(links, bytes.Clone(progress.SubscriptionLink))
		}
	})
	if result.Code != SubscriptionLinkRotated || result.SubscriptionStatus != SubscriptionAvailable || len(links) != 1 {
		t.Fatalf("rotation = %#v links=%q", result, links)
	}
	if bytes.Equal(oldCredential, host.subscriptionCredential) || !bytes.Equal(oldConfiguration, host.configuration) || host.subscriptionCredentialCount != 2 || host.subscriptionOverlap {
		t.Fatalf("old=%q new=%q generations=%d overlap=%t", oldCredential, host.subscriptionCredential, host.subscriptionCredentialCount, host.subscriptionOverlap)
	}
}

func rotationTarget(source hostadapter.ServingAuthority) (hostadapter.ServingAuthority, []byte) {
	credential := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq")
	digest := sha256.Sum256(credential)
	target := source
	target.LinkID = "abcdefabcdefabcdefabcdefabcdefab"
	target.CredentialSHA256 = hex.EncodeToString(digest[:])
	return target, credential
}

func rotationOperation(source, target hostadapter.ServingAuthority, checkpoint subscriptionRotationCheckpoint) subscriptionRotation {
	direction := "cleanup"
	var completed []string
	if checkpoint == rotationStopAuthorized {
		completed = []string{"target prepared"}
	}
	if checkpoint == rotationCommitted {
		direction, completed = "forward", []string{"target prepared", "source stopped"}
	}
	return subscriptionRotation{OperationID: strings.Repeat("8", 32), Kind: "rotate subscription link", Direction: direction, Effects: slices.Clone(subscriptionRotationEffects), Completed: completed, Source: source, Target: target, Checkpoint: checkpoint}
}

func TestSubscriptionRotationRestartUsesDurableRecoveryDirection(t *testing.T) {
	for _, checkpoint := range []subscriptionRotationCheckpoint{rotationTargetAuthorized, rotationStopAuthorized, rotationCommitted} {
		t.Run(string(checkpoint), func(t *testing.T) {
			host := acceptedHost()
			installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			setup := installation.Review(t.Context(), StartSetupAction)
			installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
			enable := installation.Review(t.Context(), EnableSubscriptionAction)
			installation.Execute(t.Context(), *enable.Prepared, Approved, nil)
			source := host.subscriptionServing
			target, credential := rotationTarget(source)
			record, _ := decodeOwnership(host.ownership)
			operation := rotationOperation(source, target, checkpoint)
			record.Rotation = &operation
			host.subscriptionRotationServing, host.subscriptionRotationCredential = target, credential
			if checkpoint == rotationCommitted {
				record.Serving = &target
				host.subscriptionStopped = true
			}
			updateSubscriptionResources(&record, testInstalledIdentity())
			host.ownership = ownershipBytes(record)

			restarted := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			review := restarted.Review(t.Context(), FinishSubscriptionChangeAction)
			if review.Prepared == nil || !strings.Contains(strings.Join(review.Plan, "\n"), map[bool]string{true: "selected replacement", false: "old generation"}[checkpoint == rotationCommitted]) {
				t.Fatalf("finish review = %#v", review)
			}
			result := restarted.Execute(t.Context(), *review.Prepared, Approved, func(Progress) {})
			if checkpoint == rotationCommitted {
				if result.Code != SubscriptionLinkRotated || host.subscriptionServing != target {
					t.Fatalf("forward finish = %#v serving=%#v", result, host.subscriptionServing)
				}
			} else if result.Code != SubscriptionChangeCleanedUp || host.subscriptionServing != source {
				t.Fatalf("cleanup finish = %#v serving=%#v", result, host.subscriptionServing)
			}
			committed, ok := decodeOwnership(host.ownership)
			if !ok || committed.Rotation != nil {
				t.Fatalf("committed ownership = %#v valid=%t", committed, ok)
			}
		})
	}
}

func TestSubscriptionRotationRecoversEachLateEffectWithoutAnotherTarget(t *testing.T) {
	for _, effect := range []string{"prepare", "stop", "publish", "activate", "verify"} {
		t.Run(effect, func(t *testing.T) {
			host := acceptedHost()
			installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			setup := installation.Review(t.Context(), StartSetupAction)
			installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
			enable := installation.Review(t.Context(), EnableSubscriptionAction)
			installation.Execute(t.Context(), *enable.Prepared, Approved, nil)
			host.failRotationEffect = effect
			rotate := installation.Review(t.Context(), RotateSubscriptionLinkAction)
			if result := installation.Execute(t.Context(), *rotate.Prepared, Approved, nil); result.Code != SubscriptionChangeNeedsCompletion {
				t.Fatalf("interrupted rotation = %#v", result)
			}
			restarted := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			finish := restarted.Review(t.Context(), FinishSubscriptionChangeAction)
			if finish.Prepared == nil {
				t.Fatalf("finish review = %#v", finish)
			}
			result := restarted.Execute(t.Context(), *finish.Prepared, Approved, func(Progress) {})
			forward := effect == "publish" || effect == "activate" || effect == "verify"
			if forward && result.Code != SubscriptionLinkRotated || !forward && result.Code != SubscriptionChangeCleanedUp {
				t.Fatalf("finish = %#v", result)
			}
			if host.subscriptionCredentialCount != 2 {
				t.Fatalf("credential generations = %d", host.subscriptionCredentialCount)
			}
		})
	}
}

func TestFailedRevocationKeepsOldLinkWorkingAndSecurityProblemVisible(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	enable := installation.Review(t.Context(), EnableSubscriptionAction)
	installation.Execute(t.Context(), *enable.Prepared, Approved, nil)
	oldCredential := bytes.Clone(host.subscriptionCredential)
	record, _ := decodeOwnership(host.ownership)
	record.SubscriptionCompromised = true
	host.ownership = ownershipBytes(record)
	host.failRotationEffect = "prepare"
	rotate := installation.Review(t.Context(), RotateSubscriptionLinkAction)
	installation.Execute(t.Context(), *rotate.Prepared, Approved, nil)
	restarted := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	finish := restarted.Review(t.Context(), FinishSubscriptionChangeAction)
	if result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != SubscriptionChangeCleanedUp || result.SubscriptionStatus != SubscriptionProblemDetected {
		t.Fatalf("cleanup = %#v", result)
	}
	problem := restarted.Review(t.Context(), StatusAction)
	if problem.SubscriptionStatus != SubscriptionProblemDetected || !slices.Contains(problem.LegalActions, RotateSubscriptionLinkAction) || !bytes.Equal(oldCredential, host.subscriptionCredential) || !strings.Contains(strings.Join(problem.Details, "\n"), "security problem") {
		t.Fatalf("problem = %#v credential=%q", problem, host.subscriptionCredential)
	}
	retry := restarted.Review(t.Context(), RotateSubscriptionLinkAction)
	if retry.Prepared == nil {
		t.Fatalf("retry = %#v", retry)
	}
	if result := restarted.Execute(t.Context(), *retry.Prepared, Approved, func(Progress) {}); result.Code != SubscriptionLinkRotated || result.SubscriptionStatus != SubscriptionAvailable {
		t.Fatalf("retry result = %#v", result)
	}
}

func TestSubscriptionFaultNeitherAutomaticallyAllowsNorBlocksRotation(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	enable := installation.Review(t.Context(), EnableSubscriptionAction)
	installation.Execute(t.Context(), *enable.Prepared, Approved, nil)
	host.renewalProblem = true
	if review := installation.Review(t.Context(), RotateSubscriptionLinkAction); review.Prepared == nil || review.SubscriptionStatus != SubscriptionProblemDetected {
		t.Fatalf("unrelated renewal fault blocked safe rotation: %#v", review)
	}
	host.publicIPDrift = true
	if review := installation.Review(t.Context(), RotateSubscriptionLinkAction); review.Prepared != nil || review.Result.Code != ActionRefused {
		t.Fatalf("public-IP drift allowed rotation: %#v", review)
	}
}

func TestSubscriptionRotationRevalidatesMutableServingFacts(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	enable := installation.Review(t.Context(), EnableSubscriptionAction)
	installation.Execute(t.Context(), *enable.Prepared, Approved, nil)
	rotate := installation.Review(t.Context(), RotateSubscriptionLinkAction)
	host.subscriptionServing.CertificateGeneration++
	before := host.subscriptionCredentialCount
	if result := installation.Execute(t.Context(), *rotate.Prepared, Approved, nil); result.Code != ActionRefused || host.subscriptionCredentialCount != before {
		t.Fatalf("changed serving facts = %#v generations=%d", result, host.subscriptionCredentialCount)
	}
}

func TestCompleteRemovalTakesOverSubscriptionRotationWithoutStartingEitherGeneration(t *testing.T) {
	host := acceptedHost()
	lifecycle := &controlledRemovalLifecycle{ready: true}
	installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	enable := installation.Review(t.Context(), EnableSubscriptionAction)
	installation.Execute(t.Context(), *enable.Prepared, Approved, nil)
	record, _ := decodeOwnership(host.ownership)
	target, credential := rotationTarget(*record.Serving)
	operation := rotationOperation(*record.Serving, target, rotationStopAuthorized)
	record.Rotation = &operation
	host.subscriptionRotationServing, host.subscriptionRotationCredential = target, credential
	updateSubscriptionResources(&record, testInstalledIdentity())
	host.ownership = ownershipBytes(record)

	restarted := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	removal := restarted.Review(t.Context(), CompleteRemovalAction)
	if removal.Prepared == nil {
		t.Fatalf("removal review = %#v", removal)
	}
	if result := restarted.Execute(t.Context(), *removal.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted || len(host.subscriptionRotationCredential) != 0 {
		t.Fatalf("removal = %#v target=%q", result, host.subscriptionRotationCredential)
	}
}

func TestCompleteRemovalTakesOverCommittedRotationBeforeTargetPublication(t *testing.T) {
	host := acceptedHost()
	lifecycle := &controlledRemovalLifecycle{ready: true}
	installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	enable := installation.Review(t.Context(), EnableSubscriptionAction)
	installation.Execute(t.Context(), *enable.Prepared, Approved, nil)
	source := host.subscriptionServing
	record, _ := decodeOwnership(host.ownership)
	target, credential := rotationTarget(source)
	operation := rotationOperation(source, target, rotationCommitted)
	record.Serving, record.Rotation = &target, &operation
	host.subscriptionRotationServing, host.subscriptionRotationCredential, host.subscriptionStopped = target, credential, true
	updateSubscriptionResources(&record, testInstalledIdentity())
	host.ownership = ownershipBytes(record)
	starts := host.subscriptionStarts

	restarted := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	removal := restarted.Review(t.Context(), CompleteRemovalAction)
	if removal.Prepared == nil {
		t.Fatalf("removal review = %#v", removal)
	}
	if result := restarted.Execute(t.Context(), *removal.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted || host.subscriptionStarts != starts {
		t.Fatalf("removal = %#v starts=%d want=%d", result, host.subscriptionStarts, starts)
	}
}

func TestSubscriptionResourcesKeepTheirCreatingRelease(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	record, _ := decodeOwnership(host.ownership)
	legacy := legacyProxyCreator
	record.Release = legacy
	for index := range record.ResourceCreatingReleases {
		record.ResourceCreatingReleases[index] = legacy
	}
	original := slices.Clone(record.Resources)
	host.ownership = ownershipBytes(record)
	review := installation.Review(t.Context(), EnableSubscriptionAction)
	if result := installation.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionEnabled {
		t.Fatalf("enable = %#v", result)
	}
	committed, ok := decodeOwnership(host.ownership)
	if !ok {
		t.Fatal("committed ownership invalid")
	}
	creators := map[string]softwarelifecycle.ReleaseIdentity{}
	for index, resource := range committed.Resources {
		creators[subscriptionResourceIdentity(resource)] = committed.ResourceCreatingReleases[index]
	}
	for _, resource := range original {
		if creators[subscriptionResourceIdentity(resource)] != legacy {
			t.Fatalf("original resource %q was relabelled", resource)
		}
	}
	for _, resource := range committed.Resources[len(original):] {
		if creators[resource] != testInstalledIdentity() {
			t.Fatalf("new resource %q has creator %#v", resource, creators[resource])
		}
	}
}

func TestEnablementCheckpointFailureRecoversWithoutAnotherCredential(t *testing.T) {
	for checkpoint := 1; checkpoint <= hostadapter.SubscriptionActivationCheckpoint; checkpoint++ {
		t.Run(strconv.Itoa(checkpoint), func(t *testing.T) {
			host := acceptedHost()
			installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			setup := installation.Review(t.Context(), StartSetupAction)
			installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
			host.failSubscriptionCheckpoint = checkpoint
			enable := installation.Review(t.Context(), EnableSubscriptionAction)
			if result := installation.Execute(t.Context(), *enable.Prepared, Approved, nil); result.Code != SubscriptionChangeNeedsCompletion {
				t.Fatalf("enable = %#v", result)
			}
			restarted := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			finish := restarted.Review(t.Context(), FinishSubscriptionChangeAction)
			if finish.Prepared == nil {
				t.Fatalf("finish review = %#v", finish)
			}
			if result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != SubscriptionChangeCleanedUp {
				t.Fatalf("finish = %#v", result)
			}
			if host.subscriptionCredentialCount != 1 {
				t.Fatalf("credential generations = %d", host.subscriptionCredentialCount)
			}
		})
	}
}

func TestInterruptedPrecommitEnablementCleansUpThroughFreshFinish(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	host.failSubscriptionPreparation = true
	enable := installation.Review(t.Context(), EnableSubscriptionAction)
	if result := installation.Execute(t.Context(), *enable.Prepared, Approved, nil); result.Code != SubscriptionChangeNeedsCompletion {
		t.Fatalf("interrupted enable = %#v", result)
	}
	restarted := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	finish := restarted.Review(t.Context(), FinishSubscriptionChangeAction)
	if finish.Prepared == nil || finish.SubscriptionStatus != SubscriptionChangeIncomplete || !strings.Contains(strings.Join(finish.Plan, "\n"), "clean") {
		t.Fatalf("finish review = %#v", finish)
	}
	if result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != SubscriptionChangeCleanedUp || result.SubscriptionStatus != SubscriptionNotEnabled {
		t.Fatalf("finish = %#v", result)
	}
	record, ok := decodeOwnership(host.ownership)
	if !ok || record.Schema != 2 || record.Enablement != nil || record.Serving != nil {
		t.Fatalf("clean ownership = %#v valid=%t", record, ok)
	}
}

func TestCompleteRemovalDeletesCommittedSubscriptionAuthority(t *testing.T) {
	host := acceptedHost()
	lifecycle := &controlledRemovalLifecycle{ready: true}
	installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	enable := installation.Review(t.Context(), EnableSubscriptionAction)
	if result := installation.Execute(t.Context(), *enable.Prepared, Approved, func(Progress) {}); result.Code != SubscriptionEnabled {
		t.Fatalf("enable = %#v", result)
	}
	view := installation.Review(t.Context(), ViewDetailsAction)
	if view.SubscriptionStatus != SubscriptionAvailable || len(view.SubscriptionLink) == 0 {
		t.Fatalf("view = %#v", view)
	}
	removal := installation.Review(t.Context(), CompleteRemovalAction)
	if removal.Prepared == nil {
		t.Fatalf("removal review = %#v", removal)
	}
	if result := installation.Execute(t.Context(), *removal.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted || len(host.ownership) != 0 {
		t.Fatalf("removal = %#v ownership=%q", result, host.ownership)
	}
}

func TestCompleteRemovalTakesOverInterruptedSubscriptionEnablement(t *testing.T) {
	host := acceptedHost()
	host.failSubscriptionPreparation = true
	lifecycle := &controlledRemovalLifecycle{ready: true}
	installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	enable := installation.Review(t.Context(), EnableSubscriptionAction)
	if result := installation.Execute(t.Context(), *enable.Prepared, Approved, nil); result.Code != SubscriptionChangeNeedsCompletion {
		t.Fatalf("enable = %#v", result)
	}
	restarted := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	removal := restarted.Review(t.Context(), CompleteRemovalAction)
	if removal.Prepared == nil || !slices.Contains(removal.LegalActions, CompleteRemovalAction) {
		t.Fatalf("removal review = %#v", removal)
	}
	if result := restarted.Execute(t.Context(), *removal.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted {
		t.Fatalf("removal = %#v", result)
	}
}

func TestSubscriptionDeclineDoesNotClearEarlierPendingWork(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	review := installation.Review(t.Context(), EnableSubscriptionAction)
	if review.Prepared == nil {
		t.Fatalf("review = %#v", review)
	}
	host.stagedOwnership = bytes.Clone(host.ownership)
	before := bytes.Clone(host.stagedOwnership)
	result := installation.Execute(t.Context(), *review.Prepared, Declined, nil)
	if result.Code != ActionCancelled || !bytes.Equal(before, host.stagedOwnership) {
		t.Fatalf("decline cleared pending work: %#v", result)
	}
	if next := installation.Review(t.Context(), EnableSubscriptionAction); next.Prepared != nil || next.Result.Code != ActionRefused {
		t.Fatalf("pending work allowed enablement: %#v", next)
	}
}

func TestSubscriptionReviewRefusesUnsafeAuthorityAndPreservesSecrets(t *testing.T) {
	for _, change := range []string{"unknown ownership", "subscription material", "pending", "incompatible", "proxy stopped", "active change"} {
		t.Run(change, func(t *testing.T) {
			host := acceptedHost()
			installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			setup := installation.Review(t.Context(), StartSetupAction)
			installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
			switch change {
			case "unknown ownership":
				host.ownership = []byte(`{"schema":99,"secret":"subscription-secret-marker"}`)
			case "subscription material":
				host.subscriptionAbsence = &hostadapter.Observation{Observed: true}
			case "pending":
				host.stagedOwnership = bytes.Clone(host.ownership)
			case "incompatible":
				installation = newInstalledInterface(mismatchedLifecycle{}, host, acceptedSingBox{})
			case "proxy stopped":
				host.active = false
			case "active change":
				host.statusBusy = true
			}
			before := host.facts()
			review := installation.Review(t.Context(), EnableSubscriptionAction)
			if review.Prepared != nil || review.Result.Code != ActionRefused || review.Result.FailedCheck == "" || review.Result.Correction == "" || slices.Contains(review.LegalActions, EnableSubscriptionAction) {
				t.Fatalf("unsafe review = %#v", review)
			}
			for _, secret := range []string{"subscription-secret-marker", "11111111-2222-4333-8444-555555555555", "private-infrastructure-secret"} {
				if strings.Contains(fmt.Sprintf("%#v", review), secret) {
					t.Fatal("review leaked secret")
				}
			}
			if !reflect.DeepEqual(before, host.facts()) || host.configurationReads != 0 {
				t.Fatal("unsafe review mutated or disclosed configuration")
			}
		})
	}
}

func TestSubscriptionReviewGatesFreshSafetyFacts(t *testing.T) {
	for _, check := range []string{"TCP80", "TCP8443", "Clock", "PackageLocks", "RenewalIdle", "Dependencies", "Firewall"} {
		for _, observed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/observed=%t", check, observed), func(t *testing.T) {
				host := acceptedHost()
				installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
				setup := installation.Review(t.Context(), StartSetupAction)
				installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
				facts := host.PreflightSubscription(t.Context(), "8.8.8.8")
				reflect.ValueOf(&facts).Elem().FieldByName(check).Set(reflect.ValueOf(hostadapter.Observation{Observed: observed}))
				host.subscriptionPreflight = &facts
				before := host.facts()
				for _, action := range []Action{StatusAction, ViewDetailsAction, EnableSubscriptionAction} {
					review := installation.Review(t.Context(), action)
					if review.Status != Running || review.ProxyTraffic != ProvedWorking || review.Prepared != nil || slices.Contains(review.LegalActions, EnableSubscriptionAction) || !slices.Contains(review.LegalActions, ShowClientConfigurationAction) || !slices.Contains(review.LegalActions, CompleteRemovalAction) {
						t.Fatalf("unsafe review = %#v", review)
					}
					if action == EnableSubscriptionAction && (review.Result.Code != ActionRefused || review.Result.FailedCheck == "" || review.Result.Correction == "") {
						t.Fatalf("missing correction: %#v", review)
					}
				}
				if !reflect.DeepEqual(before, host.facts()) {
					t.Fatal("unsafe review mutated host")
				}
			})
		}
	}
}

func TestSubscriptionApprovalRevalidatesAndConsumesAuthorityWithoutMutation(t *testing.T) {
	for _, change := range []string{"review", "module", "ownership", "pending", "proxy", "subscription", "preflight", "lock", "release"} {
		t.Run(change, func(t *testing.T) {
			host := acceptedHost()
			lifecycle := &mutableLifecycle{result: readyLifecycle{}.Status(t.Context())}
			installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
			setup := installation.Review(t.Context(), StartSetupAction)
			installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
			review := installation.Review(t.Context(), EnableSubscriptionAction)
			if review.Prepared == nil {
				t.Fatalf("review = %#v", review)
			}
			switch change {
			case "review":
				installation.Review(t.Context(), StatusAction)
			case "module":
				installation = newInstalledInterface(lifecycle, host, acceptedSingBox{})
			case "ownership":
				host.ownership = append(host.ownership, '\n')
			case "pending":
				host.stagedOwnership = bytes.Clone(host.ownership)
			case "proxy":
				host.active = false
			case "subscription":
				host.subscriptionAbsence = &hostadapter.Observation{}
			case "preflight":
				host.subscriptionPreflight = &hostadapter.SubscriptionPreflight{}
			case "lock":
				host.statusBusy = true
			case "release":
				lifecycle.result = softwarelifecycle.Result{}
			}
			before := host.facts()
			result := installation.Execute(t.Context(), *review.Prepared, Approved, func(Progress) { t.Fatal("unexpected progress/disclosure") })
			if result.Code != ActionRefused || result.FailedCheck == "Enable subscription unavailable" {
				t.Fatalf("stale authority not diagnosed: %#v", result)
			}
			if !reflect.DeepEqual(before, host.facts()) {
				t.Fatal("stale approval mutated state")
			}
		})
	}
}

func TestEveryPreCommitFailureCleansUpToNotSetUp(t *testing.T) {
	for _, operation := range []hostadapter.Operation{hostadapter.InstallAPTKey, hostadapter.InstallAPTSource, hostadapter.MaskService, hostadapter.InstallPackage, hostadapter.HoldPackage, hostadapter.CreateStateDirectory, hostadapter.InstallConfiguration, hostadapter.ValidateConfiguration} {
		t.Run(string(operation), func(t *testing.T) {
			host := acceptedHost()
			host.fails = map[hostadapter.Operation]bool{operation: true}
			installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			review := installation.Review(t.Context(), StartSetupAction)

			result := installation.Execute(t.Context(), *review.Prepared, Approved, nil)

			if result.Status != NotSetUp || result.Code != SetupCleanedUp || len(host.ownership) != 0 {
				t.Fatalf("Execute() = %#v ownership=%q operations=%v", result, host.ownership, host.operations)
			}
		})
	}
}

func TestInterruptedCleanupExposesOnlyFinishCleanupAndResumes(t *testing.T) {
	host := acceptedHost()
	host.fails = map[hostadapter.Operation]bool{hostadapter.InstallPackage: true, hostadapter.RemovePackage: true}
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	review := installation.Review(t.Context(), StartSetupAction)
	result := installation.Execute(t.Context(), *review.Prepared, Approved, nil)
	if result.Status != SetupIncomplete || result.Code != SetupNeedsCleanup || len(host.ownership) == 0 {
		t.Fatalf("Execute() = %#v ownership=%q", result, host.ownership)
	}

	restarted := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	status := restarted.Review(t.Context(), StatusAction)
	if !reflect.DeepEqual(status.LegalActions, []Action{FinishCleanupAction, ViewDetailsAction}) {
		t.Fatalf("restart status = %#v", status)
	}
	finish := restarted.Review(t.Context(), FinishCleanupAction)
	host.fails = nil
	result = restarted.Execute(t.Context(), *finish.Prepared, Approved, nil)
	if result.Status != NotSetUp || result.Code != SetupCleanedUp || len(host.ownership) != 0 {
		t.Fatalf("Finish cleanup = %#v ownership=%q", result, host.ownership)
	}
}

func TestCommittedSetupNeverRollsBackAndFinishSetupResumes(t *testing.T) {
	host := acceptedHost()
	host.fails = map[hostadapter.Operation]bool{hostadapter.StartService: true}
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	review := installation.Review(t.Context(), StartSetupAction)
	result := installation.Execute(t.Context(), *review.Prepared, Approved, nil)
	if result.Status != SetupIncomplete || result.Code != SetupNeedsCompletion {
		t.Fatalf("Execute() = %#v", result)
	}
	for _, operation := range host.operations {
		if operation == hostadapter.RemovePackage || operation == hostadapter.RemoveAPTSource || operation == hostadapter.RemoveAPTKey {
			t.Fatalf("committed setup rolled back through %q", operation)
		}
	}
	restarted := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	status := restarted.Review(t.Context(), StatusAction)
	if !reflect.DeepEqual(status.LegalActions, []Action{FinishSetupAction, ViewDetailsAction}) {
		t.Fatalf("restart status = %#v", status)
	}
	finish := restarted.Review(t.Context(), FinishSetupAction)
	host.fails = nil
	result = restarted.Execute(t.Context(), *finish.Prepared, Approved, nil)
	if result.Status != Running || result.Code != SetupComplete {
		t.Fatalf("Finish setup = %#v", result)
	}
}

func TestLateActivationCheckpointFailureContinuesForward(t *testing.T) {
	host := acceptedHost()
	host.failPublish, host.latePublish = activationCommitted, true
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	review := installation.Review(t.Context(), StartSetupAction)

	result := installation.Execute(t.Context(), *review.Prepared, Approved, nil)

	if result.Status != Running || result.Code != SetupComplete {
		t.Fatalf("Execute() = %#v", result)
	}
	for _, operation := range host.operations {
		if operation == hostadapter.RemovePackage {
			t.Fatal("late committed write triggered rollback")
		}
	}
}

func TestEveryCheckpointIOFailureKeepsTheLegalRecoveryDirection(t *testing.T) {
	for _, phase := range []setupPhase{ownershipRecorded, aptKeyInstalled, aptSourceInstalled, serviceMasked, packageInstalled, packageHeld, stateDirectoryCreated, configurationInstalled, configurationValidated, serviceUnmasked, activationCommitted, serviceEnabled, serviceStarted, runningPhase} {
		for _, late := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s late=%t", phase, late), func(t *testing.T) {
				host := acceptedHost()
				host.failPublish, host.latePublish = phase, late
				installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
				review := installation.Review(t.Context(), StartSetupAction)
				result := installation.Execute(t.Context(), *review.Prepared, Approved, nil)

				switch {
				case phase == ownershipRecorded && !late:
					if result.Code != ActionRefused || len(host.ownership) != 0 {
						t.Fatalf("Execute() = %#v ownership=%q", result, host.ownership)
					}
				case phaseAtOrAfter(phase, serviceEnabled) && !late:
					if result.Status != SetupIncomplete || result.Code != SetupNeedsCompletion {
						t.Fatalf("Execute() = %#v", result)
					}
					host.failPublish = ""
					restarted := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
					finish := restarted.Review(t.Context(), FinishSetupAction)
					if finish.Prepared == nil {
						t.Fatalf("Finish setup Review() = %#v", finish)
					}
					if result = restarted.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != SetupComplete {
						t.Fatalf("Finish setup Execute() = %#v", result)
					}
				case phaseAtOrAfter(phase, activationCommitted) && late:
					if result.Status != Running || result.Code != SetupComplete {
						t.Fatalf("Execute() = %#v", result)
					}
				default:
					if result.Status != NotSetUp || result.Code != SetupCleanedUp || len(host.ownership) != 0 {
						t.Fatalf("Execute() = %#v ownership=%q", result, host.ownership)
					}
				}
			})
		}
	}
}

func TestRestartDerivesStatusAndOnlyLegalFinishingActionFromEveryCheckpoint(t *testing.T) {
	source := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, source, acceptedSingBox{})
	review := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *review.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("fixture setup = %#v", result)
	}
	for _, body := range source.checkpoints {
		record, ok := decodeOwnership(body)
		if !ok {
			t.Fatalf("invalid fixture checkpoint: %q", body)
		}
		host := acceptedHost()
		host.ownership = bytes.Clone(body)
		if record.Phase == runningPhase {
			host.operations = []hostadapter.Operation{hostadapter.ValidateConfiguration}
			host.enabled, host.active, host.listener = true, true, true
		}
		status := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{}).Review(t.Context(), StatusAction)
		switch {
		case record.Phase == runningPhase:
			if status.Status != Running || status.Result.Code != SetupComplete {
				t.Fatalf("%s status = %#v", record.Phase, status)
			}
		case phaseAtOrAfter(record.Phase, activationCommitted):
			if status.Status != SetupIncomplete || !reflect.DeepEqual(status.LegalActions, []Action{FinishSetupAction, ViewDetailsAction}) {
				t.Fatalf("%s status = %#v", record.Phase, status)
			}
		default:
			if status.Status != SetupIncomplete || !reflect.DeepEqual(status.LegalActions, []Action{FinishCleanupAction, ViewDetailsAction}) {
				t.Fatalf("%s status = %#v", record.Phase, status)
			}
		}
	}
}

func TestStatusDerivesChangeInProgressFromTheMutationLock(t *testing.T) {
	host := acceptedHost()
	host.statusBusy = true
	status := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{}).Review(t.Context(), StatusAction)
	if status.Status != ChangeInProgress || status.Result.Code != StatusChangeInProgress || !reflect.DeepEqual(status.LegalActions, []Action{ViewDetailsAction}) {
		t.Fatalf("Review() = %#v", status)
	}
}

func TestManagedTerminationStopsAfterTheCurrentDurableCheckpoint(t *testing.T) {
	tests := []struct {
		name     string
		cancelOn hostadapter.Operation
		fail     hostadapter.Operation
		code     ResultCode
	}{
		{"pre-commit setup", hostadapter.InstallPackage, "", SetupNeedsCleanup},
		{"committed setup", hostadapter.EnableService, "", SetupNeedsCompletion},
		{"cleanup", hostadapter.RemovePackageArtifact, hostadapter.HoldPackage, SetupNeedsCleanup},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			host := acceptedHost()
			host.cancelOn, host.cancel = test.cancelOn, cancel
			if test.fail != "" {
				host.fails = map[hostadapter.Operation]bool{test.fail: true}
			}
			installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
			review := installation.Review(ctx, StartSetupAction)
			result := installation.Execute(ctx, *review.Prepared, Approved, nil)
			if result.Status != SetupIncomplete || result.Code != test.code || result.FailedCheck != "Managed termination" {
				t.Fatalf("Execute() = %#v operations=%v", result, host.operations)
			}
		})
	}
}

func TestFinishingActionsRevalidateAuthorityAndActivationFactsBeforeMutation(t *testing.T) {
	t.Run("changed cleanup authority", func(t *testing.T) {
		host := acceptedHost()
		host.fails = map[hostadapter.Operation]bool{hostadapter.InstallPackage: true, hostadapter.RemovePackage: true}
		installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
		start := installation.Review(t.Context(), StartSetupAction)
		installation.Execute(t.Context(), *start.Prepared, Approved, nil)
		restarted := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
		finish := restarted.Review(t.Context(), FinishCleanupAction)
		record, _ := decodeOwnership(host.ownership)
		record.CleanupCheckpoint++
		host.ownership = ownershipBytes(record)
		before := len(host.operations)

		result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil)

		if result.Code != ActionRefused || len(host.operations) != before {
			t.Fatalf("Execute() = %#v operations=%v", result, host.operations[before:])
		}
	})

	t.Run("changed cleanup host facts", func(t *testing.T) {
		host := acceptedHost()
		host.fails = map[hostadapter.Operation]bool{hostadapter.InstallPackage: true, hostadapter.RemovePackage: true}
		installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
		start := installation.Review(t.Context(), StartSetupAction)
		installation.Execute(t.Context(), *start.Prepared, Approved, nil)
		restarted := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
		finish := restarted.Review(t.Context(), FinishCleanupAction)
		host.inspection = hostadapter.Inspection{Resources: observedAbsent(footprint), Complete: true}
		host.inspection.Resources[2].Present = true
		before := len(host.operations)

		result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil)

		if result.Code != ActionRefused || len(host.operations) != before {
			t.Fatalf("Execute() = %#v operations=%v", result, host.operations[before:])
		}
	})

	t.Run("changed activation facts", func(t *testing.T) {
		host := acceptedHost()
		host.fails = map[hostadapter.Operation]bool{hostadapter.StartService: true}
		installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
		start := installation.Review(t.Context(), StartSetupAction)
		installation.Execute(t.Context(), *start.Prepared, Approved, nil)
		restarted := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
		finish := restarted.Review(t.Context(), FinishSetupAction)
		host.fails = nil
		host.listener = true
		before := len(host.operations)

		result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil)

		if result.Code != ActionRefused || len(host.operations) != before {
			t.Fatalf("Execute() = %#v operations=%v", result, host.operations[before:])
		}
	})
}

func TestExecuteRefusesLockConflictBeforeMutation(t *testing.T) {
	host := acceptedHost()
	host.busy = true
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	review := installation.Review(t.Context(), StartSetupAction)

	result := installation.Execute(t.Context(), *review.Prepared, Approved, nil)

	if result.Code != ActionRefused || result.FailedCheck != "SBXR mutation lock" || len(host.operations) != 0 || len(host.ownership) != 0 {
		t.Fatalf("Execute() = %#v operations=%v ownership=%q", result, host.operations, host.ownership)
	}
}

func TestFreshInspectionReportsConflictingFootprintAsProblemDetected(t *testing.T) {
	resources := observedAbsent(footprint)
	resources[3].Present = true
	host := &controlledHost{inspection: hostadapter.Inspection{Resources: resources, Complete: true}, preflight: acceptedPreflightFacts()}
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})

	review := installation.Review(t.Context(), StatusAction)

	if review.Status != ProblemDetected || review.Result.Code != StatusProblemDetected || review.Result.Message != "A proxy problem was detected. View details before continuing." || !reflect.DeepEqual(review.LegalActions, []Action{StartSetupAction, ViewDetailsAction, CompleteRemovalAction}) {
		t.Fatalf("Review() = %#v", review)
	}
}

func TestFreshInspectionReportsUnknownFootprintAsProblemDetected(t *testing.T) {
	resources := observedAbsent(footprint)
	for index := range resources {
		if resources[index].Name == "/etc/sing-box" {
			resources[index].Observed = false
		}
	}
	installation := newInstalledInterface(readyLifecycle{}, &controlledHost{inspection: hostadapter.Inspection{Resources: resources}}, acceptedSingBox{})

	review := installation.Review(t.Context(), StatusAction)

	if review.Status != ProblemDetected || review.Result.Code != StatusProblemDetected || !strings.Contains(strings.Join(review.Details, "\n"), "/etc/sing-box could not be inspected") {
		t.Fatalf("Review() = %#v", review)
	}
}

func TestExecuteRefusesUntrustedPreparedAuthority(t *testing.T) {
	newInstallation := func(host *controlledHost) Interface {
		return newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	}
	assertRefused := func(t *testing.T, result Result, failedCheck string) {
		t.Helper()
		if result.Code != ActionRefused || result.FailedCheck != failedCheck {
			t.Fatalf("Execute() = %#v", result)
		}
	}

	t.Run("invalid", func(t *testing.T) {
		host := &controlledHost{preflight: acceptedPreflightFacts()}
		assertRefused(t, newInstallation(host).Execute(t.Context(), PreparedAction{}, Approved, nil), "Prepared Action")
	})

	t.Run("mismatched module", func(t *testing.T) {
		host := &controlledHost{preflight: acceptedPreflightFacts()}
		first, second := newInstallation(host), newInstallation(host)
		prepared := first.Review(t.Context(), StartSetupAction).Prepared
		assertRefused(t, second.Execute(t.Context(), *prepared, Approved, nil), "Prepared Action")
	})

	t.Run("stale after a later review", func(t *testing.T) {
		host := &controlledHost{preflight: acceptedPreflightFacts()}
		installation := newInstallation(host)
		prepared := installation.Review(t.Context(), StartSetupAction).Prepared
		installation.Review(t.Context(), StatusAction)
		assertRefused(t, installation.Execute(t.Context(), *prepared, Approved, nil), "Prepared Action")
	})

	t.Run("reused", func(t *testing.T) {
		host := &controlledHost{preflight: acceptedPreflightFacts()}
		installation := newInstallation(host)
		prepared := installation.Review(t.Context(), StartSetupAction).Prepared
		installation.Execute(t.Context(), *prepared, Declined, nil)
		assertRefused(t, installation.Execute(t.Context(), *prepared, Approved, nil), "Prepared Action")
	})

	t.Run("changed facts", func(t *testing.T) {
		host := &controlledHost{preflight: acceptedPreflightFacts()}
		installation := newInstallation(host)
		prepared := installation.Review(t.Context(), StartSetupAction).Prepared
		host.preflight.PublicIPv4 = "1.1.1.1"
		assertRefused(t, installation.Execute(t.Context(), *prepared, Approved, nil), "Prepared Action facts")
	})
}

func TestReviewRefusesEveryFailedSetupPreflight(t *testing.T) {
	tests := []struct {
		name   string
		failed string
		change func(*hostadapter.Preflight)
	}{
		{"changed footprint", "Clean proxy footprint", func(facts *hostadapter.Preflight) {
			facts.Resources[3].Present = true
		}},
		{"unsupported Ubuntu", "Ubuntu version", func(facts *hostadapter.Preflight) { facts.OSVersion = "22.04" }},
		{"unsupported architecture", "Architecture", func(facts *hostadapter.Preflight) { facts.Architecture = "arm64" }},
		{"reserved IPv4", "Public IPv4", func(facts *hostadapter.Preflight) { facts.PublicIPv4 = "203.0.113.7" }},
		{"unsynchronized clock", "Synchronized clock", func(facts *hostadapter.Preflight) { facts.ClockSynchronized = false }},
		{"occupied port", "Public TCP port 443", func(facts *hostadapter.Preflight) { facts.TCP443Available = false }},
		{"busy mutation lock", "SBXR mutation lock", func(facts *hostadapter.Preflight) { facts.MutationLockAvailable = false }},
		{"busy package locks", "Ubuntu package locks", func(facts *hostadapter.Preflight) { facts.PackageLocksAvailable = false }},
		{"no compatible destination", "REALITY destination", func(facts *hostadapter.Preflight) { facts.Destinations[0].HTTP2 = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := acceptedPreflightFacts()
			test.change(&facts)
			installation := newInstalledInterface(readyLifecycle{}, &controlledHost{preflight: facts}, acceptedSingBox{})

			review := installation.Review(t.Context(), StartSetupAction)

			if review.Prepared != nil || review.Result.Code != ActionRefused || review.Result.FailedCheck != test.failed || review.Result.Correction == "" {
				t.Fatalf("Review() = %#v", review)
			}
		})
	}
}

func TestReviewReturnsSecretSafeNotSetUpDetails(t *testing.T) {
	installation := newInstalledInterface(readyLifecycle{}, acceptedHost(), acceptedSingBox{})

	review := installation.Review(t.Context(), ViewDetailsAction)
	details := strings.Join(review.Details, "\n")
	for _, required := range []string{
		"SBXR version: v3.0.0",
		"Release Identity: albertloky/SBXR v3.0.0 " + strings.Repeat("a", 40) + " " + strings.Repeat("b", 64),
		"Ubuntu: 24.04 amd64",
		"Proxy Installation Status: Not set up",
		"Required unfinished direction: none",
		"Mutation lock: Available",
		"Ownership Record: Absent",
		"Proxy Package Identity: https://deb.sagernet.org/; signing-key bytes SHA-256 803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1; sing-box 1.13.19 amd64; DEB 24597120 bytes; DEB SHA-256 fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf; Absent",
		"Package hold: Absent",
		"Protected configuration identity: Absent",
		"Packaged validation result: Not applicable",
		"systemd unit provenance: Absent",
		"Service enabled: No",
		"Service active: No",
		"Expected public listener ownership: Absent",
		"Client Identity: Absent",
	} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
	for _, secret := range []string{"11111111-2222-4333-8444-555555555555", "private"} {
		if strings.Contains(details, secret) {
			t.Errorf("details disclose %q", secret)
		}
	}
}

func TestViewDetailsReportsFreshActiveMutationCheckpoint(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}
	host.statusBusy = true

	review := installation.Review(t.Context(), ViewDetailsAction)
	details := strings.Join(review.Details, "\n")
	if review.Status != ChangeInProgress || review.Result.Code != StatusChangeInProgress || !reflect.DeepEqual(review.LegalActions, []Action{ViewDetailsAction}) {
		t.Fatalf("Review() = %#v", review)
	}
	for _, required := range []string{
		"Proxy Installation Status: Change in progress",
		"Mutation lock: In use",
		"Ownership Record: Valid; phase Running; cleanup checkpoint 0",
		"Required unfinished direction: none",
	} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
}

func TestViewDetailsExplainsTheRequiredUnfinishedDirection(t *testing.T) {
	host := acceptedHost()
	host.fails = map[hostadapter.Operation]bool{hostadapter.StartService: true}
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != SetupIncomplete {
		t.Fatalf("setup = %#v", result)
	}

	review := installation.Review(t.Context(), ViewDetailsAction)
	details := strings.Join(review.Details, "\n")
	for _, required := range []string{
		"Proxy Installation Status: Setup incomplete",
		"Required unfinished direction: setup required",
		"Ownership Record: Valid; phase Service enabled; cleanup checkpoint 0",
		"Public endpoint: 8.8.8.8:443",
		"Client Identity: Present",
	} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
}

func TestViewDetailsExplainsCleanupRequired(t *testing.T) {
	host := acceptedHost()
	host.fails = map[hostadapter.Operation]bool{hostadapter.InstallPackage: true, hostadapter.RemovePackage: true}
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != SetupIncomplete {
		t.Fatalf("setup = %#v", result)
	}

	details := strings.Join(installation.Review(t.Context(), ViewDetailsAction).Details, "\n")
	for _, required := range []string{"Proxy Installation Status: Setup incomplete", "Required unfinished direction: cleanup required", "Ownership Record: Valid; phase Service masked"} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
}

func TestReviewReturnsCompleteSecretSafeRunningDetails(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}

	review := installation.Review(t.Context(), ViewDetailsAction)
	details := strings.Join(review.Details, "\n")
	record, _ := decodeOwnership(host.ownership)
	for _, required := range []string{
		"SBXR version: v3.0.0",
		"Release Identity: albertloky/SBXR v3.0.0 " + strings.Repeat("a", 40) + " " + strings.Repeat("b", 64),
		"Ubuntu: 24.04 amd64",
		"Proxy Installation Status: Running",
		"Required unfinished direction: none",
		"Mutation lock: Available",
		"Ownership Record: Valid; phase Running; cleanup checkpoint 0",
		"Proxy Package Identity: https://deb.sagernet.org/; signing-key bytes SHA-256 803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1; sing-box 1.13.19 amd64; DEB 24597120 bytes; DEB SHA-256 fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf",
		"Package hold: Present",
		"Protected configuration identity: /etc/sing-box/config.json SHA-256 " + record.ConfigurationSHA256 + "; Matches",
		"Packaged validation result: Accepted",
		"systemd unit provenance: /usr/lib/systemd/system/sing-box.service from sing-box; Matches",
		"Service enabled: Yes",
		"Service active: Yes",
		"Expected public listener ownership: sing-box on TCP 8.8.8.8:443; Matches",
		"Public endpoint: 8.8.8.8:443",
		"Selected destination: google.com:443",
		"Server name: google.com",
		"Client Identity: Present",
	} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
	for _, secret := range []string{"11111111-2222-4333-8444-555555555555", "private", "secret-safe-test-fixture"} {
		if strings.Contains(details, secret) {
			t.Errorf("details disclose %q", secret)
		}
	}
}

func TestReviewReportsRunningDriftWithExactSafeCorrection(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}
	host.active = false

	review := installation.Review(t.Context(), ViewDetailsAction)
	details := strings.Join(review.Details, "\n")
	if review.Status != ProblemDetected || review.Result.Code != StatusProblemDetected || !reflect.DeepEqual(review.LegalActions, []Action{ViewDetailsAction, CompleteRemovalAction}) {
		t.Fatalf("Review() = %#v", review)
	}
	for _, required := range []string{
		"Detected mismatch: sing-box.service is not active",
		"Safe correction: Start sing-box.service from the exact installed package, then inspect again.",
	} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
	for _, forbidden := range []string{"generic repair", "adopt", "force", "override"} {
		if strings.Contains(strings.ToLower(details), forbidden) {
			t.Errorf("details contain forbidden generic action %q:\n%s", forbidden, details)
		}
	}
}

func TestReviewDistinguishesUnavailableObservationFromConfirmedDrift(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}
	host.active = false
	host.activeUnknown = true
	host.hostUnknown = true
	host.configUnknown = true

	review := installation.Review(t.Context(), ViewDetailsAction)
	details := strings.Join(review.Details, "\n")
	for _, required := range []string{
		"Ubuntu: Unavailable",
		"Service active: Unavailable",
		"Client Identity: Absent",
		"Detected mismatch: service active state could not be inspected",
		"Safe correction: Restore working systemctl active-state inspection for sing-box.service, then inspect again.",
	} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
	if strings.Contains(details, "sing-box.service is not active") || strings.Contains(details, "Start sing-box.service") {
		t.Fatalf("unavailable observation reported as confirmed drift:\n%s", details)
	}
	if strings.Contains(details, "Client Identity: Unavailable") {
		t.Fatalf("Client Identity escaped its binary vocabulary:\n%s", details)
	}
}

func TestValidOwnershipIdentityMismatchKeepsKnownDetails(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}

	for _, test := range []struct {
		name       string
		busy       bool
		status     Status
		lock       string
		correction string
	}{
		{"idle", false, ProblemDetected, "Available", "Restore the exact installed SBXR Release Identity"},
		{"active mutation", true, ChangeInProgress, "In use", "Wait for the active atomic mutation"},
	} {
		t.Run(test.name, func(t *testing.T) {
			host.statusBusy = test.busy
			review := newInstalledInterface(mismatchedLifecycle{}, host, acceptedSingBox{}).Review(t.Context(), ViewDetailsAction)
			details := strings.Join(review.Details, "\n")
			if review.Status != test.status {
				t.Fatalf("status = %s, want %s", review.Status, test.status)
			}
			for _, required := range []string{
				"Ownership Record: Valid; phase Running; cleanup checkpoint 0",
				"Mutation lock: " + test.lock,
				"Public endpoint: 8.8.8.8:443",
				"Selected destination: google.com:443",
				"Server name: google.com",
				test.correction,
			} {
				if !strings.Contains(details, required) {
					t.Errorf("details missing %q:\n%s", required, details)
				}
			}
			if strings.Contains(details, "Invalid or unsafe") {
				t.Fatalf("valid Ownership Record was reported invalid:\n%s", details)
			}
		})
	}
}

func TestViewDetailsKeepsOwnershipProblemsCompleteAndSecretSafe(t *testing.T) {
	host := acceptedHost()
	host.ownership = []byte(`{"client_uuid":"11111111-2222-4333-8444-555555555555"}`)
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})

	review := installation.Review(t.Context(), ViewDetailsAction)
	details := strings.Join(review.Details, "\n")
	for _, required := range []string{
		"SBXR version: v3.0.0",
		"Release Identity: albertloky/SBXR v3.0.0",
		"Ubuntu: 24.04 amd64",
		"Proxy Installation Status: Problem detected",
		"Mutation lock: Available",
		"Ownership Record: Invalid or unsafe; checkpoint unavailable",
		"Proxy Package Identity:",
		"Public endpoint: Unavailable",
		"Selected destination: Unavailable",
		"Server name: Unavailable",
		"Client Identity: Absent",
		"Safe correction: Restore the exact supported root-owned Ownership Record and its original provenance, then inspect again.",
	} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
	if strings.Contains(details, "11111111-2222-4333-8444-555555555555") {
		t.Fatalf("details disclosed invalid record bytes:\n%s", details)
	}
}

func TestActiveMutationDetailsStayCompleteWhenOwnershipIsInvalid(t *testing.T) {
	host := acceptedHost()
	host.statusBusy = true
	host.ownership = []byte(`not-json`)
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})

	review := installation.Review(t.Context(), ViewDetailsAction)
	details := strings.Join(review.Details, "\n")
	for _, required := range []string{
		"Ubuntu: 24.04 amd64",
		"Proxy Installation Status: Change in progress",
		"Mutation lock: In use",
		"Ownership Record: Invalid or unsafe; checkpoint unavailable",
		"Proxy Package Identity:",
		"Public endpoint: Unavailable",
		"Safe correction: Wait for the active atomic mutation and checkpoint to finish, then inspect again.",
	} {
		if !strings.Contains(details, required) {
			t.Errorf("details missing %q:\n%s", required, details)
		}
	}
}

func TestReviewRefusesIllegalActionsWithoutAuthority(t *testing.T) {
	installation := newInstalledInterface(readyLifecycle{}, acceptedHost(), acceptedSingBox{})

	illegal := installation.Review(t.Context(), FinishSetupAction)
	if illegal.Result.Code != ActionRefused || illegal.Result.FailedCheck != "Legal action" || illegal.Prepared != nil {
		t.Fatalf("Finish setup Review() = %#v", illegal)
	}
}

func TestReviewSupportedSchema2PreservesOwnershipBytes(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Status != Running {
		t.Fatalf("setup = %#v", result)
	}
	var record map[string]any
	if err := json.Unmarshal(host.ownership, &record); err != nil {
		t.Fatal(err)
	}
	record["schema"] = 2
	resources := record["permitted_resources"].([]any)
	resources[0] = "/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-2"
	origins := make([]softwarelifecycle.ReleaseIdentity, len(resources))
	for i := range origins {
		origins[i] = testInstalledIdentity()
	}
	record["resource_creating_releases"] = origins
	host.ownership, _ = json.Marshal(record)
	before := host.facts()
	for _, action := range []Action{StatusAction, ViewDetailsAction, CompleteRemovalAction, EnableSubscriptionAction} {
		review := installation.Review(t.Context(), action)
		if review.Status != Running || (action == CompleteRemovalAction || action == EnableSubscriptionAction) && review.Prepared == nil {
			t.Fatalf("schema-2 %s = %#v", action, review)
		}
		if action == EnableSubscriptionAction {
			if result := installation.Execute(t.Context(), *review.Prepared, Declined, nil); result.Code != ActionCancelled {
				t.Fatalf("schema-2 decline: %#v", result)
			}
		}
	}
	if !reflect.DeepEqual(before, host.facts()) {
		t.Fatal("read-only inspection changed the installation")
	}
}

func TestCompatibleCreatingReleaseIsPreservedWhenRemovalSelectsInstalledFinisher(t *testing.T) {
	host := acceptedHost()
	lifecycle := &controlledRemovalLifecycle{ready: true}
	installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	record, _ := decodeOwnership(host.ownership)
	creator := softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v3.0.21", Commit: "989094b9766f02bf17510a71753c6a5c736bf120", IndexSHA256: "90463aa73a2c81542b44ea833c762bb2cd44d2d585fb7bd322279f678feea331"}
	record.Release = creator
	host.ownership = ownershipBytes(record)
	before := bytes.Clone(host.ownership)
	review := installation.Review(t.Context(), CompleteRemovalAction)
	if review.Status != Running || review.Prepared == nil || !bytes.Equal(before, host.ownership) {
		t.Fatalf("compatible removal review = %#v", review)
	}
	host.fails = map[hostadapter.Operation]bool{hostadapter.StopDisableService: true}
	if result := installation.Execute(t.Context(), *review.Prepared, Approved, nil); result.Status != RemovalIncomplete {
		t.Fatalf("removal = %#v", result)
	}
	committed, ok := decodeOwnership(host.ownership)
	if !ok || committed.Schema != 2 || committed.Release != creator || committed.FinishingRelease == nil || *committed.FinishingRelease != testInstalledIdentity() {
		t.Fatalf("commitment = %#v", committed)
	}
	for _, origin := range committed.ResourceCreatingReleases {
		if origin != creator {
			t.Fatal("resource provenance was relabelled")
		}
	}
	delete(host.fails, hostadapter.StopDisableService)
	restarted := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	finish := restarted.Review(t.Context(), FinishRemovalAction)
	if finish.Prepared == nil {
		t.Fatalf("finish review = %#v", finish)
	}
	if result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted {
		t.Fatalf("finish = %#v", result)
	}
}

func TestSubscriptionAbsenceMustBeProvedWithoutMaskingHealthyProxy(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	for _, test := range []struct {
		name string
		fact hostadapter.Observation
		want SubscriptionStatus
	}{
		{"absent", hostadapter.Observation{Observed: true, Accepted: true}, SubscriptionNotEnabled},
		{"unknown", hostadapter.Observation{}, SubscriptionProblemDetected},
		{"unexpected material", hostadapter.Observation{Observed: true}, SubscriptionProblemDetected},
	} {
		t.Run(test.name, func(t *testing.T) {
			host.subscriptionAbsence = &test.fact
			before := host.facts()
			review := installation.Review(t.Context(), CompleteRemovalAction)
			if review.Status != Running || review.SubscriptionStatus != test.want || review.Result.SubscriptionStatus != test.want {
				t.Fatalf("review = %#v", review)
			}
			if (review.Prepared != nil) != (test.want == SubscriptionNotEnabled) {
				t.Fatalf("unsafe removal admission = %#v", review)
			}
			if !reflect.DeepEqual(before, host.facts()) {
				t.Fatal("inspection mutated state")
			}
		})
	}
}

func (host *controlledHost) InspectSubscriptionAbsence(context.Context) hostadapter.Observation {
	if host.subscriptionAbsence != nil {
		return *host.subscriptionAbsence
	}
	return hostadapter.Observation{Observed: true, Accepted: true}
}

func TestRunningWithoutSubscriptionOffersReviewedClientIdentityRotation(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Code != SetupComplete {
		t.Fatalf("setup = %#v", result)
	}

	review := installation.Review(t.Context(), RotateClientIdentityAction)
	if review.Prepared == nil || review.Status != Running || review.SubscriptionStatus != SubscriptionNotEnabled || !slices.Contains(review.LegalActions, RotateClientIdentityAction) {
		t.Fatalf("rotation review = %#v", review)
	}
	plan := strings.Join(review.Plan, "\n")
	for _, want := range []string{"Action: Rotate Client Identity", "disconnect", "same Subscription Link", "extended outage", "Show client configuration", "leaked Subscription Link"} {
		if !strings.Contains(plan, want) {
			t.Errorf("Plan missing %q: %s", want, plan)
		}
	}
}

func TestReviewedClientIdentityRotationReplacesOnlyUUID(t *testing.T) {
	host := acceptedHost()
	singbox := singboxadapter.New()
	installation := newInstalledInterface(readyLifecycle{}, host, singbox)
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Code != SetupComplete {
		t.Fatalf("setup = %#v", result)
	}
	source := bytes.Clone(host.configuration)
	sourceFacts, err := singbox.CurrentConnectionFacts(source, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}

	review := installation.Review(t.Context(), RotateClientIdentityAction)
	var phases []string
	result := installation.Execute(t.Context(), *review.Prepared, Approved, func(progress Progress) {
		if progress.Phase != "" {
			phases = append(phases, progress.Phase)
		}
		if len(progress.ClientConfiguration) != 0 || len(progress.SubscriptionLink) != 0 {
			t.Fatal("rotation disclosed a secret")
		}
	})
	if result.Code != ClientIdentityRotated || result.Status != Running || result.SubscriptionStatus != SubscriptionNotEnabled || result.ProxyTraffic != ProvedWorking || result.SubscriptionServing != ProvedStopped {
		t.Fatalf("rotation = %#v", result)
	}
	targetFacts, err := singbox.CurrentConnectionFacts(host.configuration, "8.8.8.8")
	if err != nil || sourceFacts.UUID == targetFacts.UUID {
		t.Fatalf("target facts = %#v, %v", targetFacts, err)
	}
	sourceFacts.UUID = targetFacts.UUID
	if sourceFacts != targetFacts {
		t.Fatalf("noncredential facts changed: source %#v target %#v", sourceFacts, targetFacts)
	}
	record, ok := decodeOwnership(host.ownership)
	targetDigest := sha256.Sum256(host.configuration)
	if !ok || record.Schema != 2 || record.ClientRotation != nil || record.Startup == nil || hex.EncodeToString(targetDigest[:]) != record.ConfigurationSHA256 {
		t.Fatalf("completed authority = %#v", record)
	}
	for _, want := range []string{"Checking Client Identity rotation safety", "Preparing replacement Client Identity", "Preparing Client Identity startup protection", "Stopping old Client Identity access", "Committing Client Identity revocation", "Activating replacement Client Identity", "Finishing Client Identity rotation", "Verifying Client Identity rotation result"} {
		if !slices.Contains(phases, want) {
			t.Errorf("missing phase %q: %v", want, phases)
		}
	}
}

func TestClientIdentityRotationRecoveryNeverRestoresAfterRevocation(t *testing.T) {
	for _, test := range []struct {
		name, fail string
		wantCode   ResultCode
		wantChange bool
	}{
		{"pre-revocation cleanup", "stop", ClientIdentityRotationCleanedUp, false},
		{"post-revocation finish", "start", ClientIdentityRotationFinished, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			host := acceptedHost()
			singbox := singboxadapter.New()
			installation := newInstalledInterface(readyLifecycle{}, host, singbox)
			setup := installation.Review(t.Context(), StartSetupAction)
			installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
			source := bytes.Clone(host.configuration)
			host.clientIdentityFail = test.fail
			rotate := installation.Review(t.Context(), RotateClientIdentityAction)
			if result := installation.Execute(t.Context(), *rotate.Prepared, Approved, nil); result.Code != ClientIdentityRotationNeedsFinish {
				t.Fatalf("interruption = %#v", result)
			}
			pending, ok := decodeOwnership(host.ownership)
			if !ok || pending.ClientRotation == nil {
				t.Fatalf("pending authority = %#v", pending)
			}
			target := bytes.Clone(host.clientIdentityTarget)
			restarted := newInstalledInterface(readyLifecycle{}, host, singbox)
			finish := restarted.Review(t.Context(), FinishClientIdentityAction)
			if finish.Prepared == nil || finish.Status != ChangeIncomplete || !slices.Equal(finish.LegalActions, []Action{FinishClientIdentityAction, ViewDetailsAction, CompleteRemovalAction}) {
				t.Fatalf("finish review = %#v", finish)
			}
			result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil)
			if result.Code != test.wantCode {
				t.Fatalf("finish = %#v", result)
			}
			if test.wantChange != !bytes.Equal(source, host.configuration) || test.wantChange && !bytes.Equal(target, host.configuration) {
				t.Fatalf("wrong recovery direction: source=%s target=%s current=%s", source, target, host.configuration)
			}
		})
	}
}

func TestClientIdentityRecoveryFreshlyVerifiesTheStartupRoute(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, singboxadapter.New())
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	host.clientIdentityFail = "start"
	rotate := installation.Review(t.Context(), RotateClientIdentityAction)
	installation.Execute(t.Context(), *rotate.Prepared, Approved, nil)

	restarted := newInstalledInterface(readyLifecycle{}, host, singboxadapter.New())
	finish := restarted.Review(t.Context(), FinishClientIdentityAction)
	plan := strings.Join(finish.Plan, "\n")
	for _, want := range []string{"Selected direction:", "Remaining effects:", "Proxy traffic availability:", "Subscription serving availability: proved stopped"} {
		if !strings.Contains(plan, want) {
			t.Errorf("Finish Plan missing %q: %s", want, plan)
		}
	}
	host.clientIdentityFail = "route"
	result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil)
	if result.Code != ClientIdentityRotationNeedsFinish || result.FailedCheck != "Effective startup route" {
		t.Fatalf("stale startup route was trusted: %#v", result)
	}
}

func TestClientIdentityFailureUsesTheStableResultContract(t *testing.T) {
	result := clientIdentityFailed("test check", "test correction")
	if result.Code != ClientIdentityRotationFailed || result.Message != "Client Identity rotation failed. Follow the correction before retrying." || result.FailedCheck != "test check" || result.Correction != "test correction" {
		t.Fatalf("failure result = %#v", result)
	}
}

func TestOrdinaryProxyStartupFailsClosedDuringClientIdentityCutover(t *testing.T) {
	host := acceptedHost()
	singbox := singboxadapter.New()
	installation := newInstalledInterface(readyLifecycle{}, host, singbox)
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	host.clientIdentityFail = "stop"
	rotate := installation.Review(t.Context(), RotateClientIdentityAction)
	installation.Execute(t.Context(), *rotate.Prepared, Approved, nil)
	record, ok := decodeOwnership(host.ownership)
	if !ok || record.ClientRotation == nil || record.ClientRotation.Checkpoint != clientRotationGated {
		t.Fatalf("gate authority = %#v", record)
	}
	if authorizeProxyStart(t.Context(), readyLifecycle{}, host) {
		t.Fatal("ordinary start bypassed the durable cutover gate")
	}
	host.statusBusy = true
	host.proxyStartAuthorization = record.ClientRotation.Source
	if !authorizeProxyStart(t.Context(), readyLifecycle{}, host) || host.proxyStartAuthorization != "" {
		t.Fatal("reviewed finishing start was not consumed exactly once")
	}
	if authorizeProxyStart(t.Context(), readyLifecycle{}, host) {
		t.Fatal("consumed finishing authority was reusable")
	}
}

func TestCompletedStartupIntegrationIsReusedForLaterClientIdentityRotation(t *testing.T) {
	host := acceptedHost()
	singbox := singboxadapter.New()
	installation := newInstalledInterface(readyLifecycle{}, host, singbox)
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	for attempt := 0; attempt < 2; attempt++ {
		review := installation.Review(t.Context(), RotateClientIdentityAction)
		if review.Prepared == nil {
			t.Fatalf("review %d = %#v", attempt, review)
		}
		if result := installation.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != ClientIdentityRotated {
			t.Fatalf("rotation %d = %#v", attempt, result)
		}
	}
	record, ok := decodeOwnership(host.ownership)
	if !ok || record.Startup == nil || !record.Startup.DirectoryCreated {
		t.Fatalf("startup provenance was not preserved: %#v", record.Startup)
	}
}

func TestClientIdentityRotationFinishesEveryInterruptedHostEffect(t *testing.T) {
	for _, test := range []struct {
		failure  string
		wantCode ResultCode
	}{
		{"prepare", ClientIdentityRotationCleanedUp},
		{"startup", ClientIdentityRotationCleanedUp},
		{"reload", ClientIdentityRotationCleanedUp},
		{"route", ClientIdentityRotationCleanedUp},
		{"stop", ClientIdentityRotationCleanedUp},
		{"quiescence", ClientIdentityRotationCleanedUp},
		{"publish", ClientIdentityRotationFinished},
		{"start", ClientIdentityRotationFinished},
		{"remove", ClientIdentityRotationFinished},
	} {
		t.Run(test.failure, func(t *testing.T) {
			host := acceptedHost()
			singbox := singboxadapter.New()
			installation := newInstalledInterface(readyLifecycle{}, host, singbox)
			setup := installation.Review(t.Context(), StartSetupAction)
			installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
			host.clientIdentityFail = test.failure
			rotate := installation.Review(t.Context(), RotateClientIdentityAction)
			if result := installation.Execute(t.Context(), *rotate.Prepared, Approved, nil); result.Code != ClientIdentityRotationNeedsFinish {
				t.Fatalf("interruption = %#v", result)
			}
			restarted := newInstalledInterface(readyLifecycle{}, host, singbox)
			finish := restarted.Review(t.Context(), FinishClientIdentityAction)
			if finish.Prepared == nil {
				t.Fatalf("finish review = %#v", finish)
			}
			if result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != test.wantCode {
				t.Fatalf("finish = %#v", result)
			}
		})
	}
}

func TestClientIdentityRotationFinishesEveryInterruptedDurablePublication(t *testing.T) {
	for _, test := range []struct {
		name       string
		checkpoint clientIdentityRotationCheckpoint
		completion bool
		wantCode   ResultCode
	}{
		{"target prepared", clientRotationTargetPrepared, false, ClientIdentityRotationCleanedUp},
		{"integration published", clientRotationIntegrationPublished, false, ClientIdentityRotationCleanedUp},
		{"systemd reloaded", clientRotationReloaded, false, ClientIdentityRotationCleanedUp},
		{"route verified", clientRotationRouteVerified, false, ClientIdentityRotationCleanedUp},
		{"cutover gated", clientRotationGated, false, ClientIdentityRotationCleanedUp},
		{"source stopped", clientRotationStopped, false, ClientIdentityRotationCleanedUp},
		{"source quiescent", clientRotationQuiescent, false, ClientIdentityRotationCleanedUp},
		{"source revoked", clientRotationRevoked, false, ClientIdentityRotationCleanedUp},
		{"target published", clientRotationTargetPublished, false, ClientIdentityRotationFinished},
		{"target started", clientRotationTargetStarted, false, ClientIdentityRotationFinished},
		{"completion", "", true, ClientIdentityRotationFinished},
	} {
		t.Run(test.name, func(t *testing.T) {
			host := acceptedHost()
			singbox := singboxadapter.New()
			installation := newInstalledInterface(readyLifecycle{}, host, singbox)
			setup := installation.Review(t.Context(), StartSetupAction)
			installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
			host.failClientCheckpoint, host.failClientCompletion = test.checkpoint, test.completion
			rotate := installation.Review(t.Context(), RotateClientIdentityAction)
			if result := installation.Execute(t.Context(), *rotate.Prepared, Approved, nil); result.Code != ClientIdentityRotationNeedsFinish {
				t.Fatalf("interruption = %#v", result)
			}
			restarted := newInstalledInterface(readyLifecycle{}, host, singbox)
			finish := restarted.Review(t.Context(), FinishClientIdentityAction)
			if finish.Prepared == nil {
				t.Fatalf("finish review = %#v", finish)
			}
			if result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != test.wantCode {
				t.Fatalf("finish = %#v", result)
			}
		})
	}
}

func TestCompleteRemovalTakesOverClientIdentityRotationWithoutStartingEitherGeneration(t *testing.T) {
	for _, failure := range []string{"stop", "start"} {
		t.Run(failure, func(t *testing.T) {
			host := acceptedHost()
			lifecycle := &controlledRemovalLifecycle{ready: true}
			installation := newInstalledInterface(lifecycle, host, singboxadapter.New())
			setup := installation.Review(t.Context(), StartSetupAction)
			installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
			host.clientIdentityFail = failure
			rotate := installation.Review(t.Context(), RotateClientIdentityAction)
			installation.Execute(t.Context(), *rotate.Prepared, Approved, nil)
			starts := len(host.operations)
			removal := installation.Review(t.Context(), CompleteRemovalAction)
			if removal.Prepared == nil {
				t.Fatalf("removal review = %#v", removal)
			}
			if result := installation.Execute(t.Context(), *removal.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted {
				t.Fatalf("removal = %#v", result)
			}
			if len(host.operations) < starts || host.clientIdentityTarget != nil || host.clientIdentityStartup != nil || host.active || host.listener {
				t.Fatalf("removal revived or retained rotation state: %#v", host)
			}
		})
	}
}

func TestSchema2RefusesUnknownOrContradictoryAuthority(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	original := bytes.Clone(host.ownership)
	for _, change := range []func(string) string{
		func(s string) string { return strings.Replace(s, `"schema":1`, `"schema":99,"Schema":1`, 1) },
		func(s string) string { return strings.Replace(s, `"Tag":`, `"tag":"v3.0.999","Tag":`, 1) },
		func(s string) string { return strings.Replace(s, `"schema":1`, `"schema":2,"schema":1`, 1) },
		func(s string) string {
			return strings.Replace(s, `"cleanup_checkpoint":0`, `"cleanup_checkpoint":null`, 1)
		},
		func(s string) string { return strings.Replace(s, `"cleanup_checkpoint":0,`, ``, 1) },
		func(s string) string { return strings.Replace(s, `"schema":1`, `"schema":2`, 1) },
		func(s string) string {
			return strings.Replace(s, `"schema":1`, `"schema":1,"operation":{"kind":"enable"}`, 1)
		},
	} {
		host.ownership = []byte(change(string(original)))
		review := installation.Review(t.Context(), CompleteRemovalAction)
		if review.Prepared != nil || review.Status != ProblemDetected || review.SubscriptionStatus != SubscriptionProblemDetected {
			t.Fatalf("accepted invalid authority: %#v", review)
		}
	}
}

func TestRemovalDoesNotUseVisibleButUnsynchronizedAuthority(t *testing.T) {
	for checkpoint := 0; checkpoint <= 11; checkpoint++ {
		t.Run(fmt.Sprint(checkpoint), func(t *testing.T) {
			host := acceptedHost()
			lifecycle := &controlledRemovalLifecycle{ready: true}
			installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
			setup := installation.Review(t.Context(), StartSetupAction)
			installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
			host.lateRemovalPublish = map[int]bool{checkpoint: true}
			host.failLateSync = true
			removal := installation.Review(t.Context(), CompleteRemovalAction)
			result := installation.Execute(t.Context(), *removal.Prepared, Approved, nil)
			if result.Code == CompleteRemovalCompleted {
				t.Fatal("unsynchronized authority permitted further effects")
			}
			before := len(host.operations)
			restarted := newInstalledInterface(lifecycle, host, acceptedSingBox{})
			finish := restarted.Review(t.Context(), FinishRemovalAction)
			if finish.Prepared == nil {
				t.Fatalf("finish = %#v", finish)
			}
			result = restarted.Execute(t.Context(), *finish.Prepared, Approved, nil)
			if len(host.operations) != before || result.Code == CompleteRemovalCompleted {
				t.Fatal("restart guessed durability")
			}
			host.failOwnershipSync = false
			finish = restarted.Review(t.Context(), FinishRemovalAction)
			if result = restarted.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted {
				t.Fatalf("durable finishing = %#v", result)
			}
		})
	}
}

func (host *controlledHost) SyncOwnership(_ string, expected []byte) error {
	if host.failOwnershipSync || !bytes.Equal(expected, host.ownership) {
		return errors.New("ownership sync failed")
	}
	return nil
}

func TestFinalizationRemovesRestoredFinisherWithoutRecreatingProxy(t *testing.T) {
	host := acceptedHost()
	host.finalRemovalFails = 1
	lifecycle := &controlledRemovalLifecycle{ready: true}
	installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	removal := installation.Review(t.Context(), CompleteRemovalAction)
	installation.Execute(t.Context(), *removal.Prepared, Approved, nil)
	if !host.finalizing {
		t.Fatal("did not reach finalization")
	}
	before := len(host.operations)
	lifecycle.ready = true // Pasteable Install Command restored the exact finishing pair.
	restarted := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	finish := restarted.Review(t.Context(), FinishRemovalAction)
	if finish.Prepared == nil {
		t.Fatalf("finish = %#v", finish)
	}
	result := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil)
	if result.Code != CompleteRemovalCompleted || lifecycle.executable || lifecycle.installedRecord || len(host.operations) != before {
		t.Fatalf("restored finish = %#v", result)
	}
}

func TestLegacyCommittedRemovalRetainsExactCreatingReleaseRule(t *testing.T) {
	host := acceptedHost()
	record := newRemovalOwnershipRecord(testInstalledIdentity())
	host.ownership = ownershipBytes(record)
	lifecycle := &controlledRemovalLifecycle{ready: true}
	installation := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	before := bytes.Clone(host.ownership)
	review := installation.Review(t.Context(), FinishRemovalAction)
	if review.Prepared == nil || !bytes.Equal(before, host.ownership) {
		t.Fatalf("legacy review = %#v", review)
	}
	record.Release = legacyProxyCreator
	host.ownership = ownershipBytes(record)
	review = installation.Review(t.Context(), FinishRemovalAction)
	if review.Prepared != nil || review.Status != ProblemDetected {
		t.Fatal("legacy commitment was reinterpreted as compatible")
	}
}

func TestUnknownStagedAuthorityDoesNotProveSubscriptionAbsent(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	host.stagedOwnership = []byte(`{"schema":2,"operation":{"kind":"enable"}}`)
	review := installation.Review(t.Context(), CompleteRemovalAction)
	if review.SubscriptionStatus != SubscriptionProblemDetected || review.Prepared != nil {
		t.Fatalf("unknown staging = %#v", review)
	}
}

func TestSharedSchema2FixtureIsSupportedThroughReview(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, acceptedSingBox{})
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	body, err := os.ReadFile("testdata/subscription-absent-schema2.json")
	if err != nil {
		t.Fatal(err)
	}
	host.ownership = body
	review := installation.Review(t.Context(), CompleteRemovalAction)
	if review.Status != Running || review.SubscriptionStatus != SubscriptionNotEnabled || review.Prepared == nil {
		t.Fatalf("shared schema-2 fixture = %#v", review)
	}
}

func TestSoftwareUpdateAdmissionUsesExactIdleProxyAuthorityAndBothReleases(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, singboxadapter.New())
	setup := installation.Review(t.Context(), StartSetupAction)
	installation.Execute(t.Context(), *setup.Prepared, Approved, nil)
	rotate := installation.Review(t.Context(), RotateClientIdentityAction)
	installation.Execute(t.Context(), *rotate.Prepared, Approved, nil)
	source := testInstalledIdentity()
	support := &softwarelifecycle.ReleaseSupport{Scope: softwarelifecycle.RecurringSubscriptionUpgrade, Contract: softwarelifecycle.SubscriptionUpdateContract, Sources: []softwarelifecycle.ReleaseIdentity{source}}
	compatible := softwarelifecycle.UpdateTarget{Support: support, Identity: source, Executable: []byte(expandedProxyAuthorityCapability)}
	if !AdmitSoftwareUpdate(host.ownership, source, nil) || !AdmitSoftwareUpdate(host.ownership, source, &compatible) {
		t.Fatal("compatible source was refused")
	}
	target := source
	target.Tag, target.Commit = "v3.0.1", strings.Repeat("c", 40)
	unsupported := softwarelifecycle.UpdateTarget{Support: support, Identity: target, Executable: []byte("no declared capability")}
	if AdmitSoftwareUpdate(host.ownership, source, &unsupported) {
		t.Fatal("candidate without expanded-authority compatibility was admitted")
	}
	supported := softwarelifecycle.UpdateTarget{Support: support, Identity: target, Executable: []byte("prefix " + expandedProxyAuthorityCapability + " suffix")}
	if !AdmitSoftwareUpdate(host.ownership, source, &supported) {
		t.Fatal("candidate with expanded-authority compatibility was refused")
	}
	record, _ := decodeOwnership(host.ownership)
	if !compatibleOwnership(record, target) {
		t.Fatal("compatible installed target could not consume preserved authority")
	}
	targetLifecycle := &mutableLifecycle{result: softwarelifecycle.Result{State: softwarelifecycle.Ready, Installed: &target, Code: softwarelifecycle.StatusReady}}
	if review := newInstalledInterface(targetLifecycle, host, singboxadapter.New()).Review(t.Context(), StatusAction); review.Status != Running || !authorizeProxyStart(t.Context(), targetLifecycle, host) {
		t.Fatalf("post-update preserved authority was unusable: %#v", review)
	}
	legacyRecord := record
	legacyRecord.Release = legacyProxyCreator
	for index := range legacyRecord.ResourceCreatingReleases {
		legacyRecord.ResourceCreatingReleases[index] = legacyProxyCreator
	}
	if AdmitSoftwareUpdate(ownershipBytes(legacyRecord), legacyProxyCreator, &unsupported) {
		t.Fatal("arbitrary candidate was admitted through legacy compatibility")
	}
	record.ClientRotation = &clientIdentityRotation{}
	if AdmitSoftwareUpdate(ownershipBytes(record), source, nil) {
		t.Fatal("pending proxy work was admitted")
	}
}
