// Package proxyinstallation owns the installed V3 proxy journey.
package proxyinstallation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"sync"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type Status string

const (
	NotSetUp          Status = "Not set up"
	Running           Status = "Running"
	ChangeInProgress  Status = "Change in progress"
	ChangeIncomplete  Status = "Change incomplete"
	SetupIncomplete   Status = "Setup incomplete"
	ProblemDetected   Status = "Problem detected"
	RemovalIncomplete Status = "Removal incomplete"
)

type SubscriptionStatus string

const (
	SubscriptionNotEnabled       SubscriptionStatus = "Not enabled"
	SubscriptionAvailable        SubscriptionStatus = "Available"
	SubscriptionChangeInProgress SubscriptionStatus = "Change in progress"
	SubscriptionChangeIncomplete SubscriptionStatus = "Change incomplete"
	SubscriptionProblemDetected  SubscriptionStatus = "Problem detected"
)

type Availability string

const (
	ProvedWorking    Availability = "proved working"
	ProvedStopped    Availability = "proved stopped"
	CannotBeVerified Availability = "cannot be verified"
)

type Action string

const (
	StatusAction                         Action = "Status"
	ViewDetailsAction                    Action = "View details"
	StartSetupAction                     Action = "Start setup"
	FinishCleanupAction                  Action = "Finish cleanup"
	FinishSetupAction                    Action = "Finish setup"
	ShowClientConfigurationAction        Action = "Show client configuration"
	CompleteRemovalAction                Action = "Complete removal"
	FinishRemovalAction                  Action = "Finish removal"
	EnableSubscriptionAction             Action = "Enable subscription"
	RotateSubscriptionLinkAction         Action = "Rotate subscription link"
	ReplaceSubscriptionCertificateAction Action = "Replace subscription certificate"
	RepairSubscriptionAction             Action = "Repair subscription"
	FinishSubscriptionChangeAction       Action = "Finish subscription change"
	RotateClientIdentityAction           Action = "Rotate Client Identity"
	FinishClientIdentityAction           Action = "Finish Client Identity rotation"
)

type Confirmation uint8

const (
	Declined Confirmation = iota + 1
	Approved
)

type ResultCode string

const (
	StatusNotSetUp                          ResultCode = "PROXY-INSTALLATION-STATUS-NOT-SET-UP"
	StatusProblemDetected                   ResultCode = "PROXY-INSTALLATION-STATUS-PROBLEM-DETECTED"
	StatusChangeInProgress                  ResultCode = "PROXY-INSTALLATION-STATUS-CHANGE-IN-PROGRESS"
	StatusChangeIncomplete                  ResultCode = "PROXY-INSTALLATION-STATUS-CHANGE-INCOMPLETE"
	ActionCancelled                         ResultCode = "PROXY-INSTALLATION-ACTION-CANCELLED"
	ActionRefused                           ResultCode = "PROXY-INSTALLATION-ACTION-REFUSED"
	SetupComplete                           ResultCode = "PROXY-INSTALLATION-SETUP-COMPLETE"
	SetupNeedsCleanup                       ResultCode = "PROXY-INSTALLATION-SETUP-CLEANUP-REQUIRED"
	SetupNeedsCompletion                    ResultCode = "PROXY-INSTALLATION-SETUP-COMPLETION-REQUIRED"
	SetupCleanedUp                          ResultCode = "PROXY-INSTALLATION-SETUP-CLEANED-UP"
	ClientConfigurationDisclosed            ResultCode = "PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED"
	RemovalNeedsCompletion                  ResultCode = "PROXY-INSTALLATION-REMOVAL-COMPLETION-REQUIRED"
	CompleteRemovalCompleted                ResultCode = "SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED"
	SubscriptionStatusNotEnabled            ResultCode = "PROXY-INSTALLATION-SUBSCRIPTION-STATUS-NOT-ENABLED"
	SubscriptionStatusAvailable             ResultCode = "PROXY-INSTALLATION-SUBSCRIPTION-STATUS-AVAILABLE"
	SubscriptionStatusChangeIncomplete      ResultCode = "PROXY-INSTALLATION-SUBSCRIPTION-STATUS-CHANGE-INCOMPLETE"
	SubscriptionStatusProblemDetected       ResultCode = "PROXY-INSTALLATION-SUBSCRIPTION-STATUS-PROBLEM-DETECTED"
	SubscriptionChangeFinished              ResultCode = "PROXY-INSTALLATION-SUBSCRIPTION-CHANGE-FINISHED"
	SubscriptionChangeNeedsCompletion       ResultCode = "PROXY-INSTALLATION-SUBSCRIPTION-CHANGE-INCOMPLETE"
	SubscriptionEnabled                     ResultCode = "PROXY-INSTALLATION-SUBSCRIPTION-ENABLED"
	SubscriptionLinkRotated                 ResultCode = "PROXY-INSTALLATION-SUBSCRIPTION-LINK-ROTATED"
	SubscriptionCertificateReplaced         ResultCode = "PROXY-INSTALLATION-SUBSCRIPTION-CERTIFICATE-REPLACED"
	SubscriptionRepaired                    ResultCode = "PROXY-INSTALLATION-SUBSCRIPTION-REPAIRED"
	SubscriptionChangeCleanedUp             ResultCode = "PROXY-INSTALLATION-SUBSCRIPTION-CHANGE-CLEANED-UP"
	SubscriptionLinkDisplayIncomplete       ResultCode = "PROXY-INSTALLATION-SUBSCRIPTION-LINK-DISPLAY-INCOMPLETE"
	SubscriptionLinkDisclosed               ResultCode = "PROXY-INSTALLATION-SUBSCRIPTION-LINK-DISCLOSED"
	ClientIdentityRotated                   ResultCode = "PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATED"
	ClientIdentityRotationNeedsFinish       ResultCode = "PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATION-INCOMPLETE"
	ClientIdentityRotationFailed            ResultCode = "PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATION-FAILED"
	ClientIdentityRotationFinished          ResultCode = "PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATION-FINISHED"
	ClientIdentityRotationCleanedUp         ResultCode = "PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATION-CLEANED-UP"
	ClientIdentityRotationDisplayIncomplete ResultCode = "PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATION-DISPLAY-INCOMPLETE"
)

type Result struct {
	SubscriptionStatus  SubscriptionStatus
	ProxyTraffic        Availability
	SubscriptionServing Availability
	Status              Status
	Message             string
	Code                ResultCode
	FailedCheck         string
	Correction          string
}

type PreparedAction struct{ token [32]byte }

type UnavailableAction struct {
	Action                  Action
	FailedCheck, Correction string
}

type Review struct {
	SubscriptionStatus  SubscriptionStatus
	ProxyTraffic        Availability
	SubscriptionServing Availability
	Version             string
	Status              Status
	LegalActions        []Action
	UnavailableActions  []UnavailableAction
	Details             []string
	Plan                []string
	Result              Result
	Prepared            *PreparedAction
	SubscriptionLink    []byte
}

type Progress struct {
	Phase               string
	ClientConfiguration []byte
	SubscriptionLink    []byte
}

type ProgressReporter func(Progress)

type Interface interface {
	Review(context.Context, Action) Review
	Execute(context.Context, PreparedAction, Confirmation, ProgressReporter) Result
}

type hostInterface interface {
	PreflightSubscription(context.Context, string) hostadapter.SubscriptionPreflight
	AcquireSubscriptionReviewLock(string) (*hostadapter.MutationLock, bool, error)
	InspectSubscriptionAbsence(context.Context) hostadapter.Observation
	Inspect(context.Context, []hostadapter.Resource) hostadapter.Inspection
	Preflight(context.Context, []hostadapter.Resource, []hostadapter.Destination) hostadapter.Preflight
	ReadOwnership(string) ([]byte, error)
	SyncOwnership(string, []byte) error
	ReadConfiguration(context.Context, hostadapter.SetupSpec, string) ([]byte, error)
	MutationInProgress(string) (bool, bool)
	PublishOwnership(string, string, []byte, []byte) error
	RemoveOwnership(string, string, []byte) error
	RemoveFinalOwnership(string, string, string, []byte) error
	AcquireMutationLock(string) (*hostadapter.MutationLock, bool, error)
	AcquirePackageLocks() (*hostadapter.PackageLocks, bool, error)
	Apply(context.Context, hostadapter.OperationInput) hostadapter.OperationResult
	InspectActivation(context.Context, hostadapter.SetupSpec, []byte, []byte, string, string, hostadapter.Destination) hostadapter.ActivationInspection
	InspectRunning(context.Context, hostadapter.SetupSpec, []byte, []byte, string, string) hostadapter.RunningInspection
	InspectRemoval(context.Context, hostadapter.SetupSpec, []byte, []byte, string, string) hostadapter.RemovalInspection
}

type removalLifecycle interface {
	softwarelifecycle.Interface
	InspectCompleteRemoval(context.Context, softwarelifecycle.ReleaseIdentity) softwarelifecycle.CompleteRemovalInspection
	RemoveCompleteRemovalExecutable(context.Context, softwarelifecycle.ReleaseIdentity) bool
	RemoveCompleteRemovalInstalledRecord(context.Context, softwarelifecycle.ReleaseIdentity) bool
}

type mutationLifecycle interface {
	softwarelifecycle.Interface
	StatusUnderMutationLock(context.Context, *softwarelifecycle.MutationLockAuthority) softwarelifecycle.Result
}

type singboxInterface interface {
	PrepareIdentity() (singboxadapter.Identity, error)
	ValidIdentity(singboxadapter.Identity) bool
	EncodeServerConfiguration(singboxadapter.Identity, string, string) ([]byte, error)
	EncodeClientConfiguration([]byte, string) ([]byte, error)
	ReplaceClientIdentity([]byte) ([]byte, error)
}

type installedInterface struct {
	lifecycle  softwarelifecycle.Interface
	host       hostInterface
	singbox    singboxInterface
	mu         sync.Mutex
	generation uint64
	prepared   map[[32]byte]preparedReview
}

type preparedReview struct {
	subscription hostadapter.SubscriptionPreflight
	generation   uint64
	action       Action
	status       Status
	release      softwarelifecycle.ReleaseIdentity
	facts        hostadapter.Preflight
	identity     singboxadapter.Identity
	record       []byte
	inspection   hostadapter.Inspection
	running      hostadapter.RunningInspection
	removal      hostadapter.RemovalInspection
	activation   hostadapter.CertificateActivationInspection
	servingState hostadapter.ServingAuthority
	renewal      hostadapter.RenewalInspection
	repair       subscriptionRepairCorrection
	target       []byte
	startup      *hostadapter.ProxyStartupAuthority
}

var clientIdentityRotationEffects = []string{"prepare target", "publish startup integration", "reload systemd", "verify startup route", "establish cutover gate", "stop source", "prove source quiescence", "revoke source", "publish target", "start target", "verify target", "clean staging"}

var clientIdentityCheckpointPolicies = []clientIdentityCheckpointPolicy{
	{checkpoint: clientRotationAuthorized, ordinaryStart: true},
	{checkpoint: clientRotationTargetPrepared, effect: "prepare target", targetRequired: true, ordinaryStart: true},
	{checkpoint: clientRotationIntegrationPublished, effect: "publish startup integration", targetRequired: true, startupRequired: true, ordinaryStart: true},
	{checkpoint: clientRotationReloaded, effect: "reload systemd", targetRequired: true, startupRequired: true, ordinaryStart: true},
	{checkpoint: clientRotationRouteVerified, effect: "verify startup route", targetRequired: true, startupRequired: true, ordinaryStart: true, verifyRoute: true},
	{checkpoint: clientRotationGated, effect: "establish cutover gate", targetRequired: true, startupRequired: true, verifyRoute: true},
	{checkpoint: clientRotationStopped, effect: "stop source", targetRequired: true, startupRequired: true, verifyRoute: true},
	{checkpoint: clientRotationQuiescent, effect: "prove source quiescence", targetRequired: true, startupRequired: true, verifyRoute: true},
	{checkpoint: clientRotationRevoked, effect: "revoke source", targetRequired: true, startupRequired: true, forward: true, verifyRoute: true},
	{checkpoint: clientRotationTargetPublished, effect: "publish target", targetRequired: true, startupRequired: true, forward: true, targetCanonical: true, verifyRoute: true},
	{checkpoint: clientRotationTargetStarted, effect: "start target", startupRequired: true, forward: true, targetCanonical: true, verifyRoute: true},
}

var subscriptionRotationEffects = []string{"prepare target", "stop source", "publish target", "activate target"}

var destinations = []hostadapter.Destination{
	{Address: "google.com:443", ServerName: "google.com"},
}

var aptSourceBody = []byte("Types: deb\nURIs: https://deb.sagernet.org/\nSuites: *\nComponents: *\nSigned-By: /etc/apt/keyrings/sagernet.asc\n")

var hostSetupSpec = hostadapter.SetupSpec{
	OwnershipPath: "/var/lib/sbxr/proxy-ownership.json", OwnershipNextPath: "/var/lib/sbxr/.proxy-ownership.json.next", LockPath: "/run/lock/sbxr.lock",
	PackageArtifactPath: "/var/lib/sbxr/sing-box_1.13.19_amd64.deb",
	APTKeyPath:          "/etc/apt/keyrings/sagernet.asc", APTKeyURL: "https://sing-box.app/gpg.key", APTKeySHA256: "803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1",
	APTSourcePath: "/etc/apt/sources.list.d/sagernet.sources",
	PackageName:   "sing-box", PackageVersion: "1.13.19", Architecture: "amd64", PackageSize: 24597120, PackageSHA256: "fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf",
	ConfigurationPath: "/etc/sing-box/config.json", StatePath: "/var/lib/sing-box", Service: "sing-box.service", ServiceUnitPath: "/usr/lib/systemd/system/sing-box.service",
	User: "sing-box", Group: "sing-box", ListenerPort: "443",
}

const finalOwnershipPath = "/var/lib/.sbxr-removal.json"

var footprint = []hostadapter.Resource{
	{Kind: hostadapter.PathResource, Name: "/var/lib/sbxr/proxy-ownership.json"},
	{Kind: hostadapter.PathResource, Name: finalOwnershipPath},
	{Kind: hostadapter.PathResource, Name: "/var/lib/sbxr/.proxy-ownership.json.next"},
	{Kind: hostadapter.PathResource, Name: "/var/lib/sbxr/sing-box_1.13.19_amd64.deb"},
	{Kind: hostadapter.PathResource, Name: "/etc/apt/sources.list.d/sagernet.sources"},
	{Kind: hostadapter.PathResource, Name: "/etc/apt/sources.list.d/sagernet.sources.sbxr-next"},
	{Kind: hostadapter.PathResource, Name: "/etc/apt/keyrings/sagernet.asc"},
	{Kind: hostadapter.PathResource, Name: "/etc/apt/keyrings/sagernet.asc.sbxr-next"},
	{Kind: hostadapter.PathResource, Name: "/etc/sing-box"},
	{Kind: hostadapter.PathResource, Name: hostadapter.ClientIdentityTargetPath},
	{Kind: hostadapter.PathResource, Name: hostadapter.ProxyStartupDropInPath},
	{Kind: hostadapter.PathResource, Name: hostadapter.MutationLockProvisionUnitPath},
	{Kind: hostadapter.PathResource, Name: hostadapter.MutationLockProvisionUnitPath + ".sbxr-next"},
	{Kind: hostadapter.PathResource, Name: hostadapter.MutationLockProvisionWantsPath},
	{Kind: hostadapter.PathResource, Name: "/var/lib/sing-box"},
	{Kind: hostadapter.PathResource, Name: "/usr/bin/sing-box"},
	{Kind: hostadapter.PathResource, Name: "/etc/systemd/system/sing-box.service"},
	{Kind: hostadapter.PathResource, Name: "/etc/systemd/system/multi-user.target.wants/sing-box.service"},
	{Kind: hostadapter.PathResource, Name: "/lib/systemd/system/sing-box.service"},
	{Kind: hostadapter.PathResource, Name: "/usr/lib/systemd/system/sing-box.service"},
	{Kind: hostadapter.PackageResource, Name: "sing-box"},
	{Kind: hostadapter.UserResource, Name: "sing-box"},
	{Kind: hostadapter.GroupResource, Name: "sing-box"},
	{Kind: hostadapter.ProcessResource, Name: "sing-box"},
	{Kind: hostadapter.TCPListenerResource, Name: "443"},
}

var nonPublicIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func newInstalledInterface(lifecycle softwarelifecycle.Interface, host hostInterface, singbox singboxInterface) Interface {
	return &installedInterface{lifecycle: lifecycle, host: host, singbox: singbox, prepared: make(map[[32]byte]preparedReview)}
}

// NewInstalled constructs Proxy Installation with its production private Adapters.
func NewInstalled(lifecycle softwarelifecycle.Interface) Interface {
	return newInstalledInterface(lifecycle, hostadapter.New(), singboxadapter.New())
}

func (module *installedInterface) Review(ctx context.Context, action Action) Review {
	module.mu.Lock()
	defer module.mu.Unlock()
	review := module.review(ctx, action)
	identityLegal := slices.Contains(review.LegalActions, RotateClientIdentityAction)
	if action == EnableSubscriptionAction && review.Prepared == nil && review.Result.Code != ActionRefused {
		failed, correction := "Compatible idle installation", "Use View details to restore a compatible installed release, supported idle Ownership Record, and locally Running proxy before enabling a subscription."
		if review.Status == ChangeInProgress {
			failed, correction = "Whole-host mutation", "Wait for the active SBXR change to finish, then review Enable subscription again."
		}
		review.Result = refused(review.Status, failed, correction)
	}
	status, activation := module.inspectSubscription(ctx)
	if review.Status == ChangeInProgress && status != SubscriptionNotEnabled {
		status = SubscriptionChangeInProgress
	}
	review.SubscriptionStatus = status
	if status != SubscriptionNotEnabled {
		review.UnavailableActions = slices.DeleteFunc(review.UnavailableActions, func(unavailable UnavailableAction) bool { return unavailable.Action == EnableSubscriptionAction })
	}
	if review.ProxyTraffic == "" {
		review.ProxyTraffic = CannotBeVerified
	}
	review.SubscriptionServing = CannotBeVerified
	if review.Status == Running {
		review.ProxyTraffic = ProvedWorking
	}
	if review.SubscriptionStatus == SubscriptionNotEnabled {
		review.SubscriptionServing = ProvedStopped
	} else if activation.Loaded.Valid() {
		review.SubscriptionServing = ProvedWorking
	} else if activation.Observed && activation.Accepted {
		review.SubscriptionServing = ProvedStopped
	}
	review.Details = append(review.Details, "Subscription Capability Status: "+string(review.SubscriptionStatus))
	if body, err := module.readOwnership(); err == nil {
		if record, ok := decodeOwnership(body); ok && record.Renewal != nil {
			if host, ok := module.host.(renewalHost); ok {
				inspection := host.InspectRenewal(*record.Renewal)
				review.Details = append(review.Details, "Renewal Attempt Evidence: "+string(inspection.State))
				review.Details = append(review.Details, renewalFailureDetails(inspection)...)
			}
		}
	}
	if review.Status == Running && review.SubscriptionStatus == SubscriptionProblemDetected && action != RotateClientIdentityAction {
		compromised, rotationCandidate := false, false
		if body, err := module.readOwnership(); err == nil {
			if record, ok := decodeOwnership(body); ok {
				compromised = record.SubscriptionCompromised && record.Rotation == nil && record.Serving != nil
				rotationCandidate = record.Rotation == nil && record.Serving != nil && record.Renewal != nil && activation.Observed && activation.Published == *record.Serving
			}
		}
		repairCandidate := false
		if body, err := module.readOwnership(); err == nil {
			if record, ok := decodeOwnership(body); ok {
				_, _, repairCandidate = module.repairDiagnosis(ctx, record, activation)
			}
		}
		if rotationCandidate || repairCandidate {
			review.LegalActions = []Action{ViewDetailsAction, ShowClientConfigurationAction, CompleteRemovalAction}
			if repairCandidate {
				review.LegalActions = append([]Action{RepairSubscriptionAction}, review.LegalActions...)
			}
			if rotationCandidate {
				review.LegalActions = append(review.LegalActions, RotateSubscriptionLinkAction)
			}
			if compromised {
				review.Details = append(review.Details, "Subscription security problem: the old link remains authoritative after a failed replacement attempt.")
			}
			if action == RotateSubscriptionLinkAction {
				review = module.prepareSubscriptionRotationReview(ctx, review, activation)
			} else if action == RepairSubscriptionAction && repairCandidate {
				review = module.prepareSubscriptionRepairReview(ctx, review, activation)
			} else if action != StatusAction && action != ViewDetailsAction && action != ShowClientConfigurationAction && action != CompleteRemovalAction {
				clear(module.prepared)
				review.Prepared = nil
				review.Result = refused(review.Status, "Legal action", "Choose one displayed exact subscription action, inspect details, use the confirmed client fallback, or complete removal.")
			}
		} else {
			servingSafe := module.servingSurfaceSafe()
			showFallback := slices.Contains(review.LegalActions, ShowClientConfigurationAction) && servingSafe
			showSelected := showFallback && action == ShowClientConfigurationAction
			removalSafe := servingSafe && action == CompleteRemovalAction && review.Prepared != nil
			if !removalSafe {
				if !showSelected {
					clear(module.prepared)
					review.Prepared = nil
				}
				review.LegalActions = []Action{ViewDetailsAction}
				if showFallback {
					review.LegalActions = append(review.LegalActions, ShowClientConfigurationAction)
				}
				if action != StatusAction && action != ViewDetailsAction && !showSelected && review.Result.Code != ActionRefused {
					review.Result = refused(review.Status, "Subscription authority", "Restore one consistent published, accepted, and loaded certificate generation, then inspect again.")
				}
			}
		}
	}
	if review.Status == Running && review.SubscriptionStatus == SubscriptionAvailable {
		review.LegalActions = slices.DeleteFunc(review.LegalActions, func(a Action) bool { return a == EnableSubscriptionAction })
		review.LegalActions = append(review.LegalActions, RotateSubscriptionLinkAction)
		replacementCandidate := false
		if body, err := module.readOwnership(); err == nil {
			if record, valid := decodeOwnership(body); valid {
				_, replacementCandidate = module.certificateReplacementDiagnosis(ctx, record, activation)
			}
		}
		if replacementCandidate {
			review.LegalActions = append(review.LegalActions, ReplaceSubscriptionCertificateAction)
			if action == ReplaceSubscriptionCertificateAction {
				review = module.prepareSubscriptionCertificateReplacementReview(ctx, review, activation)
			}
		} else if action == ReplaceSubscriptionCertificateAction {
			clear(module.prepared)
			review.Prepared = nil
			review.Result = refused(review.Status, "Healthy subscription certificate authority", "Restore one accepted, loaded owned certificate generation and healthy managed renewal evidence, then review Replace subscription certificate again.")
		}
		if action == EnableSubscriptionAction {
			clear(module.prepared)
			review.Prepared = nil
			review.Result = refused(review.Status, "Existing serving authority", "Complete removal is supported; subscription enablement remains unavailable.")
		}
		review.Details = append(review.Details, "Subscription passed local checks. Karing reachability is not verified.")
		if action == RotateSubscriptionLinkAction {
			review = module.prepareSubscriptionRotationReview(ctx, review, activation)
		}
	}
	if review.Status == Running && review.SubscriptionStatus == SubscriptionChangeIncomplete && !(identityLegal && action == RotateClientIdentityAction) {
		review.LegalActions = []Action{FinishSubscriptionChangeAction, ViewDetailsAction, CompleteRemovalAction}
		if action != CompleteRemovalAction {
			review.Result = Result{Status: review.Status, SubscriptionStatus: review.SubscriptionStatus, Message: "A subscription change needs safe cleanup or completion.", Code: SubscriptionStatusChangeIncomplete}
		}
		if action == FinishSubscriptionChangeAction {
			if body, err := module.readOwnership(); err == nil {
				if record, ok := decodeOwnership(body); ok && record.Enablement != nil {
					review = module.prepareEnablementCleanupReview(ctx, review, record, body)
				} else if ok && record.Rotation != nil {
					review = module.prepareSubscriptionRotationFinishReview(ctx, review, record, body)
				} else if ok && record.Repair != nil {
					review = module.prepareSubscriptionRepairFinishReview(ctx, review, record, body)
				} else {
					review = module.prepareCertificateActivationReview(ctx, review, activation)
				}
			} else {
				review.Result = refused(review.Status, "Subscription authority", "Restore the exact durable Ownership Record, then inspect again.")
			}
		} else if action != StatusAction && action != ViewDetailsAction && action != CompleteRemovalAction {
			review.Result = refused(review.Status, "Legal action", "Choose Finish subscription change for the proved certificate activation direction.")
		}
	} else if review.Status == Running && action == FinishSubscriptionChangeAction {
		review.Result = refused(review.Status, "Certificate activation direction", "Review View details and restore one proved published certificate generation before finishing.")
	}
	review.Result.SubscriptionStatus = review.SubscriptionStatus
	if identityLegal && !slices.Contains(review.LegalActions, RotateClientIdentityAction) {
		review.LegalActions = append(review.LegalActions, RotateClientIdentityAction)
	}
	review.Result.ProxyTraffic, review.Result.SubscriptionServing = review.ProxyTraffic, review.SubscriptionServing
	if action == ViewDetailsAction {
		if body, err := module.readOwnership(); err == nil {
			if record, ok := decodeOwnership(body); ok && record.Serving != nil {
				if host, ok := module.host.(interface {
					ReadSubscriptionLink(hostadapter.ServingAuthority, string) ([]byte, bool)
				}); ok {
					review.SubscriptionLink, _ = host.ReadSubscriptionLink(*record.Serving, record.PublicIPv4)
				}
			}
		}
	}
	return review
}

func (module *installedInterface) subscriptionStatus(ctx context.Context) SubscriptionStatus {
	status, _ := module.inspectSubscription(ctx)
	return status
}

func (module *installedInterface) review(ctx context.Context, action Action) Review {
	module.generation++
	clear(module.prepared)

	result := Result{Status: NotSetUp, Message: "Proxy setup has not started.", Code: StatusNotSetUp}
	review := Review{Status: NotSetUp, LegalActions: []Action{StartSetupAction, ViewDetailsAction, CompleteRemovalAction}, Result: result}
	var installed softwarelifecycle.ReleaseIdentity
	installedReady := false
	if module.lifecycle != nil {
		status := module.lifecycle.Status(ctx)
		if status.State == softwarelifecycle.Ready && status.Installed != nil {
			installed, installedReady = *status.Installed, true
			review.Version = status.Installed.Tag
		}
	}
	if module.host != nil {
		if held, valid := module.host.MutationInProgress(hostSetupSpec.LockPath); held || !valid {
			if held {
				review.Status = ChangeInProgress
				review.LegalActions = []Action{ViewDetailsAction}
				review.Result = Result{Status: ChangeInProgress, Message: "Another Proxy Installation change is in progress.", Code: StatusChangeInProgress}
				review.Details = []string{"Proxy Installation Status: Change in progress", "Safe correction: Wait for the current atomic mutation and checkpoint to finish."}
				if action == ViewDetailsAction {
					body, err := module.readOwnership()
					if err == nil {
						if record, ok := decodeOwnership(body); ok {
							facts := module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
							review.Details = ownedDetails(installed, installedReady, ChangeInProgress, record, facts, "In use")
							if !installedReady || !compatibleOwnership(record, installed) {
								review.Details = append(review.Details, "Detected mismatch: the Ownership Record does not match the active SBXR Release Identity", "Safe correction: Wait for the active atomic mutation and checkpoint to finish, then inspect again.")
							}
						} else {
							review.Details = module.problemDetails(ctx, installed, installedReady, ChangeInProgress, "In use", "Invalid or unsafe; checkpoint unavailable", "the Ownership Record is invalid or unsafe during the active mutation", "Wait for the active atomic mutation and checkpoint to finish, then inspect again.")
						}
					} else {
						ownership := "Unavailable; checkpoint unavailable"
						if errors.Is(err, os.ErrNotExist) {
							ownership = "Absent before the first durable checkpoint"
						}
						review.Details = module.problemDetails(ctx, installed, installedReady, ChangeInProgress, "In use", ownership, "the Ownership Record checkpoint is not available during the active mutation", "Wait for the active atomic mutation and checkpoint to finish, then inspect again.")
					}
				}
				return review
			}
			return module.ownershipProblem(ctx, review, installed, installedReady, "Invalid or unsafe", "Unavailable while the mutation lock is unsafe", "the shared mutation lock is invalid or unsafe", "Replace /run/lock/sbxr.lock with a root-owned mode-0600 regular file, then inspect again.")
		}
		body, err := module.readOwnership()
		if err == nil {
			record, ok := decodeOwnership(body)
			if !ok {
				return module.ownershipProblem(ctx, review, installed, installedReady, "Available", "Invalid or unsafe; checkpoint unavailable", "the Ownership Record is invalid or unsafe", "Restore the exact supported root-owned Ownership Record and its original provenance, then inspect again.")
			}
			return module.reviewOwned(ctx, action, review, record, body, installed, installedReady)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return module.ownershipProblem(ctx, review, installed, installedReady, "Available", "Unavailable; checkpoint unavailable", "the Ownership Record cannot be safely inspected", "Restore read-only root access to /var/lib/sbxr/proxy-ownership.json, then inspect again.")
		}
	}
	inspection := hostadapter.Inspection{}
	var unownedFacts *hostadapter.RunningInspection
	if module.host != nil {
		inspection = module.host.Inspect(ctx, slices.Clone(footprint))
		if action == ViewDetailsAction {
			facts := module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, nil, "", "")
			unownedFacts = &facts
		}
	}
	review.Details = inspectionDetails(installed, installedReady, NotSetUp, inspection, unownedFacts, nil, true)
	if module.host == nil || module.singbox == nil || !inspectionAccepted(inspection) || resourcesPresent(inspection.Resources) {
		review.Status = ProblemDetected
		review.LegalActions = []Action{ViewDetailsAction, CompleteRemovalAction}
		if inspectionAccepted(inspection) && resourcesPresent(inspection.Resources) {
			review.LegalActions = []Action{StartSetupAction, ViewDetailsAction, CompleteRemovalAction}
		}
		review.Result = Result{Status: ProblemDetected, Message: "A proxy problem was detected. View details before continuing.", Code: StatusProblemDetected}
		review.Details = inspectionDetails(installed, installedReady, ProblemDetected, inspection, unownedFacts, nil, true)
		switch action {
		case StatusAction, ViewDetailsAction:
			return review
		case CompleteRemovalAction:
			review.Result = refused(ProblemDetected, "Complete removal preflight", "Remove only the unowned or conflicting resource named in View details, then review Complete removal again.")
		default:
			review.Result = refused(ProblemDetected, "Legal action", "Choose one of the actions legal for the freshly inspected Proxy Installation Status.")
		}
		return review
	}
	switch action {
	case StatusAction, ViewDetailsAction:
		return review
	case CompleteRemovalAction:
		if !installedReady {
			review.Result = refused(NotSetUp, "Installed SBXR", "Restore SBXR to a verified Ready Software Lifecycle state before Complete removal.")
			return review
		}
		return module.prepareRemoval(review, installed, nil, nil, inspection, hostadapter.RemovalInspection{})
	case StartSetupAction:
	default:
		review.Result = refused(NotSetUp, "Legal action", "Choose one of the actions legal for the freshly inspected Proxy Installation Status.")
		return review
	}
	if !installedReady {
		review.Result = refused(NotSetUp, "Installed SBXR", "Restore SBXR to a verified Ready Software Lifecycle state before setup.")
		return review
	}
	facts := module.host.Preflight(ctx, slices.Clone(footprint), slices.Clone(destinations))
	selected, failed, correction := acceptedPreflight(facts)
	if failed != "" {
		review.Result = refused(NotSetUp, failed, correction)
		return review
	}
	identity, err := module.singbox.PrepareIdentity()
	if err != nil || !module.singbox.ValidIdentity(identity) {
		review.Result = refused(NotSetUp, "Client Identity generation", "Run Start setup again. If generation still fails, replace the SBXR executable with the qualified release.")
		return review
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		review.Result = refused(NotSetUp, "Prepared Action generation", "Run Start setup again.")
		return review
	}
	module.prepared[token] = preparedReview{generation: module.generation, action: StartSetupAction, status: NotSetUp, release: installed, facts: facts, identity: identity}
	review.Prepared = &PreparedAction{token: token}
	review.Plan = setupPlan(facts, selected)
	return review
}

func (module *installedInterface) reviewOwned(ctx context.Context, action Action, review Review, record ownershipRecord, body []byte, installed softwarelifecycle.ReleaseIdentity, installedReady bool) Review {
	if record.Direction == removalRequired {
		return module.reviewCommittedRemoval(ctx, action, review, record, body)
	}
	if !installedReady || !compatibleOwnership(record, installed) {
		facts := module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
		review.Status = ProblemDetected
		review.LegalActions = []Action{ViewDetailsAction}
		review.Result = Result{Status: ProblemDetected, Message: "A proxy problem was detected. View details before continuing.", Code: StatusProblemDetected}
		review.Details = append(ownedDetails(installed, installedReady, ProblemDetected, record, facts, "Available"), "Detected mismatch: the Ownership Record does not match the active SBXR Release Identity", "Safe correction: Restore the exact installed SBXR Release Identity recorded by the valid Ownership Record, then inspect again.")
		return review
	}
	if record.ClientRotation != nil {
		return module.prepareClientIdentityFinishReview(ctx, action, review, record, body, installed)
	}
	review.Status = SetupIncomplete
	review.Result = Result{Status: SetupIncomplete, Message: "Proxy setup was interrupted and must be finished safely.", Code: SetupNeedsCleanup}
	review.LegalActions = []Action{FinishCleanupAction, ViewDetailsAction}
	if phaseAtOrAfter(record.Phase, activationCommitted) {
		review.Result.Code = SetupNeedsCompletion
		review.LegalActions = []Action{FinishSetupAction, ViewDetailsAction}
	}
	inspection := hostadapter.Inspection{}
	facts := hostadapter.RunningInspection{}
	if record.Phase == runningPhase || action == ViewDetailsAction {
		facts = module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
	}
	if record.Phase == runningPhase {
		if runningAccepted(facts) {
			review.Status = Running
			review.Result = Result{Status: Running, Message: "Proxy setup is complete and locally verified.", Code: SetupComplete}
			review.LegalActions = []Action{ViewDetailsAction, ShowClientConfigurationAction, CompleteRemovalAction, EnableSubscriptionAction}
		} else {
			review.Status = ProblemDetected
			review.Result = Result{Status: ProblemDetected, Message: "A proxy problem was detected. View details before continuing.", Code: StatusProblemDetected}
			review.LegalActions = []Action{ViewDetailsAction, CompleteRemovalAction}
		}
	} else {
		inspection = module.host.Inspect(ctx, slices.Clone(footprint))
		if !inspectionAccepted(inspection) {
			return module.ownershipProblem(ctx, review, installed, installedReady, "Available", fmt.Sprintf("Valid; phase %s; cleanup checkpoint %d", record.Phase, record.CleanupCheckpoint), "the owned proxy footprint could not be freshly inspected", "Restore read-only inspection of every fixed V3 proxy resource, then inspect again.")
		}
	}
	review.Details = ownedDetails(installed, installedReady, review.Status, record, facts, "Available")
	subscription := hostadapter.SubscriptionPreflight{}
	if review.Status == Running {
		subscription = module.host.PreflightSubscription(ctx, record.PublicIPv4)
		certbotFailed, certbotCorrection := certbotAdmission(subscription)
		if certbotFailed != "" {
			for _, unavailable := range []Action{EnableSubscriptionAction, RotateClientIdentityAction} {
				review.UnavailableActions = append(review.UnavailableActions, UnavailableAction{Action: unavailable, FailedCheck: certbotFailed, Correction: certbotCorrection})
				review.Details = append(review.Details, string(unavailable)+" unavailable: "+certbotFailed, "Safe correction: "+certbotCorrection)
			}
		}
		failed, correction := module.subscriptionAdmission(ctx, subscription)
		if failed != "" {
			review.LegalActions = slices.DeleteFunc(review.LegalActions, func(a Action) bool { return a == EnableSubscriptionAction })
			review.Details = append(review.Details, "Subscription enablement check: "+failed, "Safe correction: "+correction)
			if action == EnableSubscriptionAction {
				review.Result = refused(Running, failed, correction)
				return review
			}
		}
		subscriptionSafe := module.clientIdentitySubscriptionAdmitted(ctx, record)
		clientHost, clientSupported := module.host.(clientIdentityHost)
		startup := hostadapter.Observation{}
		var startupAuthority hostadapter.ProxyStartupAuthority
		if clientSupported {
			if record.Startup != nil {
				startupAuthority, startup = *record.Startup, hostadapter.Observation{Observed: true, Accepted: clientHost.VerifyProxyStartupIntegration(ctx, *record.Startup)}
			} else {
				startupAuthority, startup = clientHost.PlanProxyStartupIntegration()
			}
			idle := clientHost.ClientIdentityPreparationIdle()
			startup.Observed = startup.Observed && idle.Observed
			startup.Accepted = startup.Accepted && idle.Accepted
		}
		if subscriptionSafe && subscription.PackageLocks.Observed && subscription.PackageLocks.Accepted && subscription.RenewalIdle.Observed && subscription.RenewalIdle.Accepted && startup.Observed && startup.Accepted {
			review.LegalActions = append(review.LegalActions, RotateClientIdentityAction)
			if action == RotateClientIdentityAction {
				configuration, err := module.host.ReadConfiguration(ctx, hostSetupSpec, record.ConfigurationSHA256)
				target, replaceErr := module.singbox.ReplaceClientIdentity(configuration)
				if err != nil || replaceErr != nil || len(target) == 0 {
					review.Result = refused(Running, "Client Identity preparation", "Restore the proved current configuration, then review Rotate Client Identity again.")
					return review
				}
				var token [32]byte
				if _, err := rand.Read(token[:]); err != nil {
					review.Result = refused(Running, "Prepared Action generation", "Review Rotate Client Identity again.")
					return review
				}
				module.prepared[token] = preparedReview{generation: module.generation, action: action, status: Running, release: installed, record: slices.Clone(body), running: facts, subscription: subscription, target: slices.Clone(target), startup: &startupAuthority}
				review.Prepared = &PreparedAction{token: token}
				review.Plan = clientIdentityRotationPlan()
				if record.Serving != nil {
					review.Plan[3] = "Preserve the same Subscription Link, its credential and Link ID, node name, and all non-UUID connection fields. Pause Subscription Serving during cutover; an independent availability fault does not require repair first."
					review.Plan[5] = "Refresh the unchanged Subscription Link after completion, or use separately confirmed Show client configuration. If the revoked proxy blocks refresh, temporarily stop using that proxy and fetch through a working direct connection. Do not change persistent Karing DNS, routing, TUN, or settings."
					review.Plan = append(review.Plan, "Active Certbot or managed writers require a retry; the official renewal schedule and unresolved renewal failures remain unchanged.")
				}
				return review
			}
		} else if action == RotateClientIdentityAction {
			if certbotFailed != "" {
				review.Result = refused(Running, certbotFailed, certbotCorrection)
				return review
			}
			review.Result = refused(Running, "Client Identity rotation admission", "Restore proved subscription material or absence and idle package, Certbot, and managed-writer facts, then review again.")
			return review
		}
	}
	if action == CompleteRemovalAction {
		surface := module.host.Inspect(ctx, slices.Clone(footprint))
		removal := module.inspectOwnedRemoval(ctx, record, body)
		review.Details = append(review.Details, removalMismatchDetails(removal)...)
		if !inspectionAccepted(surface) || !removalAccepted(removal) {
			review.Result = refused(review.Status, "Complete removal preflight", removalCorrection(removal))
			return review
		}
		return module.prepareRemoval(review, installed, &record, body, surface, removal)
	}
	if action == ViewDetailsAction && record.Phase == runningPhase {
		removal := module.inspectOwnedRemoval(ctx, record, body)
		review.Details = append(review.Details, removalMismatchDetails(removal)...)
	}
	if action == StatusAction || action == ViewDetailsAction {
		return review
	}
	if (action == ShowClientConfigurationAction || action == EnableSubscriptionAction) && review.Status == Running {
		var token [32]byte
		if _, err := rand.Read(token[:]); err != nil {
			review.Result = refused(Running, "Prepared Action generation", "Review Show client configuration again.")
			return review
		}
		module.prepared[token] = preparedReview{generation: module.generation, action: action, status: Running, release: installed, record: slices.Clone(body), running: facts, subscription: subscription}
		review.Prepared = &PreparedAction{token: token}
		review.Plan = []string{
			"Warning: this Client Configuration contains a credential.",
			"Anyone with a copy can use the proxy while this Client Identity remains active.",
			"Terminal history or recording can retain the complete Client Configuration.",
			"SBXR creates no client file on this VPS.",
			"Outside copies survive Complete removal and must be deleted separately.",
		}
		if action == EnableSubscriptionAction {
			review.Plan = subscriptionPlan(record.PublicIPv4, subscription)
		}
		return review
	}
	legal := action == FinishCleanupAction && record.Direction == cleanupRequired || action == FinishSetupAction && record.Direction == setupRequired
	if !legal {
		review.Result = refused(review.Status, "Legal action", "Choose one of the actions legal for the freshly inspected Proxy Installation Status.")
		return review
	}
	if !inspectionAccepted(inspection) || action == FinishSetupAction && !module.setupFactsFresh(ctx, record, body) {
		review.Result = refused(review.Status, "Finishing preflight", "Restore every required local proxy fact, then review the finishing action again.")
		return review
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		review.Result = refused(review.Status, "Prepared Action generation", "Review the finishing action again.")
		return review
	}
	module.prepared[token] = preparedReview{generation: module.generation, action: action, status: review.Status, release: installed, record: slices.Clone(body), inspection: inspection}
	review.Prepared = &PreparedAction{token: token}
	return review
}

func (module *installedInterface) reviewCommittedRemoval(ctx context.Context, action Action, review Review, record ownershipRecord, body []byte) Review {
	review.Version = finishingRelease(record).Tag
	review.Status = RemovalIncomplete
	review.Result = Result{Status: RemovalIncomplete, Message: "Complete removal was interrupted and must continue forward.", Code: RemovalNeedsCompletion}
	review.LegalActions = []Action{FinishRemovalAction, ViewDetailsAction}
	lifecycle, ok := module.lifecycle.(removalLifecycle)
	if !ok {
		review.Status = ProblemDetected
		review.LegalActions = []Action{ViewDetailsAction}
		review.Result = refused(ProblemDetected, "Exact executable restoration", "Restore the exact committed SBXR executable with the Pasteable Install Command, then inspect again.")
		return review
	}
	facts := lifecycle.InspectCompleteRemoval(ctx, finishingRelease(record))
	if !facts.Valid {
		review.Status = ProblemDetected
		review.LegalActions = []Action{ViewDetailsAction}
		review.Result = refused(ProblemDetected, "Removal commitment", "Restore the exact committed Release Identity, then inspect again.")
		return review
	}
	review.Details = []string{
		"SBXR version: " + finishingRelease(record).Tag,
		"Proxy Installation Status: Removal incomplete",
		"Required unfinished direction: removal required",
		fmt.Sprintf("Ownership Record: Valid; phase %s; removal checkpoint %d", record.Phase, record.RemovalCheckpoint),
		"Only Finish removal is permitted. Rollback, cancellation, setup, installation, update, and Latest selection are forbidden.",
	}
	if action == StatusAction || action == ViewDetailsAction {
		return review
	}
	if action != FinishRemovalAction {
		review.Result = refused(RemovalIncomplete, "Legal action", "Choose Finish removal.")
		return review
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		review.Result = refused(RemovalIncomplete, "Prepared Action generation", "Review Finish removal again.")
		return review
	}
	module.prepared[token] = preparedReview{generation: module.generation, action: FinishRemovalAction, status: RemovalIncomplete, release: finishingRelease(record), record: slices.Clone(body)}
	review.Prepared = &PreparedAction{token: token}
	return review
}

func (module *installedInterface) prepareRemoval(review Review, installed softwarelifecycle.ReleaseIdentity, record *ownershipRecord, body []byte, inspection hostadapter.Inspection, removal hostadapter.RemovalInspection) Review {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		review.Result = refused(review.Status, "Prepared Action generation", "Review Complete removal again.")
		return review
	}
	module.prepared[token] = preparedReview{generation: module.generation, action: CompleteRemovalAction, status: review.Status, release: installed, record: slices.Clone(body), inspection: inspection, removal: removal}
	review.Prepared = &PreparedAction{token: token}
	review.Plan = completeRemovalPlan(record)
	review.Plan = append(review.Plan, fmt.Sprintf("Finishing Release Identity: %s %s %s %s", installed.Repository, installed.Tag, installed.Commit, installed.IndexSHA256), "After Removal committed, only forward removal is legal; no proxy availability or network access is required.")
	if record != nil {
		review.Plan = append(review.Plan, fmt.Sprintf("Creating Release Identity (preserved): %s %s %s %s", record.Release.Repository, record.Release.Tag, record.Release.Commit, record.Release.IndexSHA256))
	}
	return review
}

func (module *installedInterface) Execute(ctx context.Context, prepared PreparedAction, confirmation Confirmation, progress ProgressReporter) (result Result) {
	module.mu.Lock()
	defer module.mu.Unlock()
	authority, ok := module.prepared[prepared.token]
	delete(module.prepared, prepared.token)
	defer func() {
		if result.Code != SubscriptionStatusProblemDetected && result.Code != SubscriptionEnabled {
			result.SubscriptionStatus = module.subscriptionStatus(context.WithoutCancel(ctx))
			result.ProxyTraffic, result.SubscriptionServing = CannotBeVerified, CannotBeVerified
		}
		if authority.action == EnableSubscriptionAction {
			fresh := module.review(context.WithoutCancel(ctx), StatusAction)
			result.Status = fresh.Status
			if fresh.Status == Running {
				result.ProxyTraffic = ProvedWorking
			}
		}
		if result.Code == SetupComplete || result.Code == ClientConfigurationDisclosed {
			result.ProxyTraffic = ProvedWorking
		}
		if result.Code == SubscriptionChangeFinished || result.Code == SubscriptionEnabled || result.Code == SubscriptionLinkRotated || result.Code == SubscriptionCertificateReplaced || result.Code == SubscriptionRepaired {
			result.ProxyTraffic, result.SubscriptionServing = ProvedWorking, ProvedWorking
		}
		if result.Code == ClientIdentityRotated || result.Code == ClientIdentityRotationFinished || result.Code == ClientIdentityRotationCleanedUp {
			result.Status, result.ProxyTraffic = Running, ProvedWorking
			_, inspection := module.inspectSubscription(context.WithoutCancel(ctx))
			if inspection.Loaded.Valid() {
				result.SubscriptionServing = ProvedWorking
			} else if inspection.Observed {
				result.SubscriptionServing = ProvedStopped
			}
		}
		if result.Code == SubscriptionChangeNeedsCompletion && authority.repair != "" {
			result.ProxyTraffic = ProvedWorking
		}
		if result.Code == CompleteRemovalCompleted {
			result.ProxyTraffic = ProvedStopped
		}
		if result.SubscriptionStatus == SubscriptionNotEnabled {
			result.SubscriptionServing = ProvedStopped
		}
		if result.Code == ClientIdentityRotationNeedsFinish {
			body, err := module.readOwnership()
			if record, ok := decodeOwnership(body); err == nil && ok {
				facts := module.host.InspectRunning(context.WithoutCancel(ctx), hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
				if runningAccepted(facts) {
					result.ProxyTraffic = ProvedWorking
				}
			}
		}
	}()
	if !ok || authority.generation != module.generation {
		return refused(NotSetUp, "Prepared Action", "Review the action again and use only the new Prepared Action.")
	}
	if confirmation == Declined {
		return Result{Status: authority.status, Message: "No changes were made.", Code: ActionCancelled}
	}
	if confirmation != Approved || module.lifecycle == nil || module.host == nil || module.singbox == nil {
		return refused(authority.status, "Prepared Action", "Review the action again and use only the new Prepared Action.")
	}
	if authority.action == EnableSubscriptionAction {
		return module.enableSubscription(ctx, authority, progress)
	}
	if authority.action == RotateClientIdentityAction {
		return module.rotateClientIdentity(ctx, authority, progress)
	}
	if authority.action == FinishClientIdentityAction {
		return module.finishClientIdentityRotation(ctx, authority, progress)
	}
	if authority.action == RotateSubscriptionLinkAction {
		return module.rotateSubscriptionLink(ctx, authority, progress)
	}
	if authority.action == RepairSubscriptionAction {
		return module.executeSubscriptionRepair(ctx, authority, progress)
	}
	if authority.action == ReplaceSubscriptionCertificateAction {
		return module.executeSubscriptionRepair(ctx, authority, progress)
	}
	if authority.action == FinishSubscriptionChangeAction {
		if record, body, ok := module.currentSubscriptionRotation(authority); ok {
			return module.finishSubscriptionRotation(ctx, authority, record, body, progress)
		}
		if record, body, ok := module.currentEnablement(authority); ok {
			return module.executeEnablementCleanup(ctx, authority, record, body, progress)
		}
		if _, _, ok := module.currentRepair(authority); ok {
			return module.executeSubscriptionRepair(ctx, authority, progress)
		}
		return module.executeCertificateActivation(ctx, authority, progress)
	}
	if authority.action == CompleteRemovalAction {
		if ctx.Err() != nil {
			return refused(authority.status, "Managed termination", "Review Complete removal again after the current process stops.")
		}
		lock, busy, err := module.host.AcquireMutationLock(hostSetupSpec.LockPath)
		if err != nil || busy {
			return refused(authority.status, "SBXR mutation lock", "Wait for the active SBXR change to finish, then review Complete removal again.")
		}
		defer lock.Release()
		if module.subscriptionStatus(context.WithoutCancel(ctx)) != SubscriptionNotEnabled && !module.subscriptionRemovalSurfaceSafe() {
			return refused(authority.status, "Subscription absence", "Inspect subscription material before retrying.")
		}
		packageLocks, packageBusy, err := module.host.AcquirePackageLocks()
		if err != nil || packageBusy {
			return refused(authority.status, "Ubuntu package locks", "Wait for APT and dpkg to finish, then review Complete removal again.")
		}
		defer packageLocks.Release()
		inspection := module.host.Inspect(context.WithoutCancel(ctx), slices.Clone(footprint))
		if !reflect.DeepEqual(inspection, authority.inspection) {
			return refused(ProblemDetected, "Prepared Action facts", "View details, restore every changed SBXR identity or host resource, then review Complete removal again.")
		}
		if len(authority.record) > 0 {
			current, err := module.readOwnership()
			record, valid := decodeOwnership(current)
			if err != nil || !valid || !bytes.Equal(current, authority.record) {
				return refused(ProblemDetected, "Prepared Action facts", "Restore the exact reviewed Ownership Record, then review Complete removal again.")
			}
			removal := module.inspectOwnedRemoval(context.WithoutCancel(ctx), record, current)
			if !removalAccepted(removal) || !reflect.DeepEqual(removal, authority.removal) {
				return refused(ProblemDetected, "Prepared Action facts", removalCorrection(removal))
			}
		}
		lifecycle, ok := module.lifecycle.(removalLifecycle)
		if !ok {
			return refused(authority.status, "Complete removal commitment", "Use an SBXR release that implements committed V3 Complete removal.")
		}
		installed := lifecycle.InspectCompleteRemoval(context.WithoutCancel(ctx), authority.release)
		if !installed.Valid || !installed.ExecutablePresent || !installed.InstalledRecordPresent {
			return refused(ProblemDetected, "Prepared Action facts", "Restore the exact reviewed SBXR Release Identity, then review Complete removal again.")
		}
		record := newRemovalOwnershipRecord(authority.release)
		current := authority.record
		if len(current) > 0 {
			var valid bool
			record, valid = decodeOwnership(current)
			if !valid {
				return refused(ProblemDetected, "Removal commitment", "Restore the exact reviewed Ownership Record, then review Complete removal again.")
			}
			record.Phase, record.Direction, record.RemovalCheckpoint, record.CleanupCheckpoint = removalCommitted, removalRequired, 0, 0
		}
		record = removalAuthority(record, authority.release)
		var exclusion *subscriptionExclusion
		if record.Serving != nil {
			var acquired bool
			exclusion, acquired = module.acquireSubscriptionExclusion(record)
			if !acquired {
				return refused(authority.status, "Certbot exclusion", "Wait for Certbot to finish or restore its protected lock files, then review Complete removal again.")
			}
			defer exclusion.Release()
		}
		next := ownershipBytes(record)
		if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, current, next); err != nil {
			if committed, readErr := module.readOwnership(); readErr == nil {
				if committedRecord, ok := decodeOwnership(committed); ok && bytes.Equal(committed, next) && committedRecord.Direction == removalRequired && finishingRelease(committedRecord) == authority.release {
					return module.finishRemoval(ctx, committedRecord, committed, progress, exclusion)
				}
			}
			return refused(authority.status, "Removal commitment", "Review Complete removal again.")
		}
		report(progress, string(removalCommitted))
		packageLocks.Release()
		return module.finishRemoval(ctx, record, next, progress, exclusion)
	}
	lock, busy, err := module.host.AcquireMutationLock(hostSetupSpec.LockPath)
	if err != nil || busy {
		return refused(authority.status, "SBXR mutation lock", "Wait for the active SBXR change to finish, then review the action again.")
	}
	defer lock.Release()
	if authority.action == FinishCleanupAction {
		var recovered bool
		authority.record, recovered = module.recoverStagedCleanupCheckpoint(authority.record)
		if !recovered {
			return refused(ProblemDetected, "Prepared Action facts", "Review Finish cleanup again after restoring every changed authority fact.")
		}
	}
	if module.subscriptionStatus(context.WithoutCancel(ctx)) != SubscriptionNotEnabled && authority.action != FinishRemovalAction && !(module.servingSurfaceSafe() && authority.action == ShowClientConfigurationAction) {
		return refused(authority.status, "Subscription absence", "Inspect subscription material before retrying.")
	}
	if ctx.Err() != nil {
		return refused(authority.status, "Managed termination", "Review the action again after the current process stops.")
	}
	if authority.action == FinishRemovalAction {
		packageLocks, packageBusy, packageErr := module.host.AcquirePackageLocks()
		if packageErr != nil || packageBusy {
			return refused(RemovalIncomplete, "Ubuntu package locks", "Wait for APT and dpkg to finish, then review Finish removal again.")
		}
		defer packageLocks.Release()
		current, err := module.readOwnership()
		record, valid := decodeOwnership(current)
		if err != nil || !valid || !bytes.Equal(current, authority.record) || record.Direction != removalRequired || finishingRelease(record) != authority.release {
			return refused(ProblemDetected, "Prepared Action facts", "Restore the exact committed Ownership Record, then review Finish removal again.")
		}
		if record.Package != "" && record.RemovalCheckpoint == 0 {
			facts := module.inspectOwnedRemoval(context.WithoutCancel(ctx), record, current)
			if !removalAccepted(facts) {
				return refused(RemovalIncomplete, "Committed removal facts", removalCorrection(facts))
			}
		}
		packageLocks.Release()
		return module.finishRemoval(ctx, record, current, progress, nil)
	}
	if authority.action == FinishCleanupAction {
		record, current, ok := module.revalidateFinishingAuthority(context.WithoutCancel(ctx), authority, lock)
		inspection := module.host.Inspect(context.WithoutCancel(ctx), slices.Clone(footprint))
		if !ok || !inspectionAccepted(inspection) || !reflect.DeepEqual(inspection, authority.inspection) {
			return refused(ProblemDetected, "Prepared Action facts", "Review Finish cleanup again after restoring every changed authority fact.")
		}
		return module.cleanup(ctx, record, current, progress)
	}
	if authority.action == FinishSetupAction {
		record, current, ok := module.revalidateFinishingAuthority(context.WithoutCancel(ctx), authority, lock)
		if !ok || !module.setupFactsFresh(context.WithoutCancel(ctx), record, current) {
			return refused(ProblemDetected, "Prepared Action facts", "Review Finish setup again after restoring every changed safety fact.")
		}
		return module.finishSetup(ctx, record, current, progress)
	}
	if authority.action == ShowClientConfigurationAction {
		if progress == nil {
			return refused(Running, "Presentation boundary", "Review Show client configuration again from the SBXR numbered menu.")
		}
		current, err := module.readOwnership()
		record, valid := decodeOwnership(current)
		if err != nil || !valid || !bytes.Equal(current, authority.record) {
			return refused(ProblemDetected, "Prepared Action facts", "Restore complete locally Running proxy facts, then review Show client configuration again.")
		}
		installed := module.statusUnderMutationLock(context.WithoutCancel(ctx), lock)
		facts := module.host.InspectRunning(context.WithoutCancel(ctx), hostSetupSpec, aptSourceBody, current, record.ConfigurationSHA256, record.PublicIPv4)
		if installed.State != softwarelifecycle.Ready || installed.Installed == nil || *installed.Installed != authority.release || !compatibleOwnership(record, authority.release) || !runningAccepted(facts) || !reflect.DeepEqual(facts, authority.running) {
			return refused(ProblemDetected, "Prepared Action facts", "Restore complete locally Running proxy facts, then review Show client configuration again.")
		}
		if ctx.Err() != nil {
			return refused(Running, "Managed termination", "Review Show client configuration again after the current process stops.")
		}
		serverConfiguration, err := module.host.ReadConfiguration(context.WithoutCancel(ctx), hostSetupSpec, record.ConfigurationSHA256)
		if err != nil {
			return refused(ProblemDetected, "Protected configuration", "Restore the exact protected server configuration, then review Show client configuration again.")
		}
		clientConfiguration, err := module.singbox.EncodeClientConfiguration(serverConfiguration, record.PublicIPv4)
		if err != nil {
			return refused(ProblemDetected, "Client Configuration", "Restore the exact official server configuration, then review Show client configuration again.")
		}
		if ctx.Err() != nil {
			return refused(Running, "Managed termination", "Review Show client configuration again after the current process stops.")
		}
		progress(Progress{ClientConfiguration: slices.Clone(clientConfiguration)})
		return Result{Status: Running, Message: "Client Configuration was disclosed.", Code: ClientConfigurationDisclosed}
	}
	installed := module.statusUnderMutationLock(ctx, lock)
	currentFacts := module.host.Preflight(ctx, slices.Clone(footprint), slices.Clone(destinations))
	currentFacts.MutationLockAvailable = authority.facts.MutationLockAvailable
	selected, failed, _ := acceptedPreflight(currentFacts)
	if installed.State != softwarelifecycle.Ready || installed.Installed == nil || *installed.Installed != authority.release || failed != "" || !samePreflight(authority.facts, currentFacts) || !module.singbox.ValidIdentity(authority.identity) {
		return refused(authority.status, "Prepared Action facts", "Review the action again after restoring every changed safety fact.")
	}
	configuration, err := module.singbox.EncodeServerConfiguration(authority.identity, selected.Address, selected.ServerName)
	if err != nil {
		return refused(authority.status, "Server configuration", "Review Start setup again with a qualified SBXR executable.")
	}
	record := newOwnershipRecord(authority.release, currentFacts, selected, configuration)
	body := ownershipBytes(record)
	if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, nil, body); err != nil {
		if current, readErr := module.readOwnership(); readErr == nil {
			if currentRecord, ok := decodeOwnership(current); ok && reflect.DeepEqual(currentRecord, record) {
				return module.cleanup(ctx, currentRecord, current, progress)
			}
		}
		return refused(NotSetUp, "Ownership Record", "Inspect the VPS and finish cleanup if an Ownership Record was created.")
	}
	report(progress, "Ownership Record recorded")
	if ctx.Err() != nil {
		return interruptedCleanup()
	}
	return module.runPreCommit(ctx, record, body, configuration, progress)
}

func (module *installedInterface) statusUnderMutationLock(ctx context.Context, lock *softwarelifecycle.MutationLockAuthority) softwarelifecycle.Result {
	lifecycle, ok := module.lifecycle.(mutationLifecycle)
	if !ok {
		return softwarelifecycle.Result{}
	}
	return lifecycle.StatusUnderMutationLock(ctx, lock)
}

func (module *installedInterface) revalidateFinishingAuthority(ctx context.Context, authority preparedReview, lock *softwarelifecycle.MutationLockAuthority) (ownershipRecord, []byte, bool) {
	current, err := module.readOwnership()
	if err != nil || !bytes.Equal(current, authority.record) {
		return ownershipRecord{}, nil, false
	}
	record, ok := decodeOwnership(current)
	installed := module.statusUnderMutationLock(ctx, lock)
	return record, current, ok && installed.State == softwarelifecycle.Ready && installed.Installed != nil && *installed.Installed == authority.release && compatibleOwnership(record, authority.release)
}

func (module *installedInterface) recoverStagedCleanupCheckpoint(current []byte) ([]byte, bool) {
	record, valid := decodeOwnership(current)
	if !valid || record.Direction != cleanupRequired {
		return nil, false
	}
	staged, err := module.host.ReadOwnership(hostSetupSpec.OwnershipNextPath)
	if errors.Is(err, os.ErrNotExist) {
		return current, true
	}
	stagedRecord, stagedValid := decodeOwnership(staged)
	index := slices.Index(setupPhaseOrder, record.Phase)
	if err != nil || !stagedValid || index < 0 || index+1 >= len(setupPhaseOrder) || setupPhaseOrder[index+1] != stagedRecord.Phase || phaseAtOrAfter(stagedRecord.Phase, activationCommitted) {
		return nil, false
	}
	record.Phase = stagedRecord.Phase
	if !bytes.Equal(ownershipBytes(record), staged) || module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, current, staged) != nil {
		return nil, false
	}
	return staged, true
}

func (module *installedInterface) setupFactsFresh(ctx context.Context, record ownershipRecord, body []byte) bool {
	if record.Phase == serviceStarted {
		return runningAccepted(module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4))
	}
	destination, _ := acceptedDestination(record.DestinationAddress, record.DestinationName)
	facts := module.host.InspectActivation(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4, destination)
	if !ownedFactsAccepted(facts.RunningInspection) || !facts.DestinationCompatible {
		return false
	}
	inactive := facts.ServiceActive.Observed && !facts.ServiceActive.Accepted && facts.Listener.Observed && !facts.Listener.Accepted && facts.ListenerAvailable
	running := facts.ServiceEnabled.Accepted && facts.ServiceActive.Accepted && facts.Listener.Accepted
	return record.Phase == activationCommitted && (inactive || running) || record.Phase == serviceEnabled && facts.ServiceEnabled.Accepted && (inactive || running)
}

func (module *installedInterface) runPreCommit(ctx context.Context, record ownershipRecord, body, configuration []byte, progress ProgressReporter) Result {
	steps := []struct {
		operation hostadapter.Operation
		phase     setupPhase
		payload   []byte
	}{
		{hostadapter.InstallAPTKey, aptKeyInstalled, nil},
		{hostadapter.InstallAPTSource, aptSourceInstalled, aptSourceBody},
		{hostadapter.MaskService, serviceMasked, nil},
		{hostadapter.InstallPackage, packageInstalled, nil},
		{hostadapter.HoldPackage, packageHeld, nil},
		{hostadapter.CreateStateDirectory, stateDirectoryCreated, nil},
		{hostadapter.InstallConfiguration, configurationInstalled, configuration},
		{hostadapter.ValidateConfiguration, configurationValidated, nil},
		{hostadapter.UnmaskService, serviceUnmasked, nil},
	}
	for _, step := range steps {
		if result := module.host.Apply(ctx, hostadapter.OperationInput{Operation: step.operation, Spec: hostSetupSpec, Body: step.payload, LockProvisioning: record.LockProvisioning}); !result.OK {
			return module.cleanup(ctx, record, body, progress)
		}
		report(progress, string(step.operation))
		record.Phase = step.phase
		next := ownershipBytes(record)
		if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, body, next); err != nil {
			if current, readErr := module.readOwnership(); readErr == nil {
				body = current
				if decoded, ok := decodeOwnership(current); ok {
					record = decoded
				}
			}
			return module.cleanup(ctx, record, body, progress)
		}
		body = next
		if ctx.Err() != nil {
			return interruptedCleanup()
		}
	}
	destination, _ := acceptedDestination(record.DestinationAddress, record.DestinationName)
	if facts := module.host.InspectActivation(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4, destination); !ownedFactsAccepted(facts.RunningInspection) || facts.ServiceEnabled.Accepted || facts.ServiceActive.Accepted || facts.Listener.Accepted || !facts.DestinationCompatible || !facts.ListenerAvailable {
		if ctx.Err() != nil {
			return interruptedCleanup()
		}
		return module.cleanup(ctx, record, body, progress)
	}
	record.Phase, record.Direction = activationCommitted, setupRequired
	next := ownershipBytes(record)
	if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, body, next); err != nil {
		if current, readErr := module.readOwnership(); readErr == nil {
			if currentRecord, ok := decodeOwnership(current); ok && phaseAtOrAfter(currentRecord.Phase, activationCommitted) {
				return module.finishSetup(ctx, currentRecord, current, progress)
			}
		}
		return module.cleanup(ctx, record, body, progress)
	}
	report(progress, string(activationCommitted))
	if ctx.Err() != nil {
		return interruptedSetup()
	}
	return module.finishSetup(ctx, record, next, progress)
}

func (module *installedInterface) finishSetup(ctx context.Context, record ownershipRecord, body []byte, progress ProgressReporter) Result {
	steps := []struct {
		operation hostadapter.Operation
		phase     setupPhase
	}{{hostadapter.EnableService, serviceEnabled}, {hostadapter.StartService, serviceStarted}}
	for _, step := range steps {
		if phaseAtOrAfter(record.Phase, step.phase) {
			continue
		}
		if result := module.host.Apply(ctx, hostadapter.OperationInput{Operation: step.operation, Spec: hostSetupSpec}); !result.OK {
			return Result{Status: SetupIncomplete, Message: "Proxy setup needs forward completion.", Code: SetupNeedsCompletion, FailedCheck: string(step.operation), Correction: "Choose Finish setup again after correcting the reported local service problem."}
		}
		record.Phase = step.phase
		next := ownershipBytes(record)
		if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, body, next); err != nil {
			if current, readErr := module.readOwnership(); readErr == nil {
				if currentRecord, ok := decodeOwnership(current); ok && phaseAtOrAfter(currentRecord.Phase, step.phase) {
					record, body = currentRecord, current
					continue
				}
			}
			return Result{Status: SetupIncomplete, Message: "Proxy setup needs forward completion.", Code: SetupNeedsCompletion, FailedCheck: "Ownership Record checkpoint", Correction: "Choose Finish setup again."}
		}
		body = next
		report(progress, string(step.operation))
		if ctx.Err() != nil {
			return interruptedSetup()
		}
	}
	facts := module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
	if !runningAccepted(facts) {
		return Result{Status: SetupIncomplete, Message: "Proxy setup needs forward completion.", Code: SetupNeedsCompletion, FailedCheck: "Locally Running verification", Correction: "Correct the local package, configuration, service, or listener fact, then choose Finish setup."}
	}
	record.Phase, record.Direction = runningPhase, noDirection
	next := ownershipBytes(record)
	if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, body, next); err != nil {
		if current, readErr := module.readOwnership(); readErr == nil {
			if currentRecord, ok := decodeOwnership(current); ok && currentRecord.Phase == runningPhase && runningAccepted(module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, current, currentRecord.ConfigurationSHA256, currentRecord.PublicIPv4)) {
				return Result{Status: Running, Message: "Proxy setup is complete and locally verified.", Code: SetupComplete}
			}
		}
		return Result{Status: SetupIncomplete, Message: "Proxy setup needs forward completion.", Code: SetupNeedsCompletion, FailedCheck: "Running checkpoint", Correction: "Choose Finish setup again."}
	}
	report(progress, "Locally verified Running")
	return Result{Status: Running, Message: "Proxy setup is complete and locally verified.", Code: SetupComplete}
}

func (module *installedInterface) cleanup(ctx context.Context, record ownershipRecord, body []byte, progress ProgressReporter) Result {
	for index, operation := range []hostadapter.Operation{hostadapter.StopDisableService, hostadapter.UnmaskService, hostadapter.RemovePackageArtifact, hostadapter.RemovePackage, hostadapter.RemoveConfigurationState, hostadapter.RemovePackageIdentity, hostadapter.RemoveAPTSource, hostadapter.RemoveAPTKey} {
		if record.CleanupCheckpoint > index {
			continue
		}
		if result := module.host.Apply(ctx, cleanupInput(operation, record)); !result.OK {
			return Result{Status: SetupIncomplete, Message: "Proxy setup cleanup is incomplete.", Code: SetupNeedsCleanup, FailedCheck: string(operation), Correction: "Correct the local cleanup problem, then choose Finish cleanup."}
		}
		record.CleanupCheckpoint = index + 1
		next := ownershipBytes(record)
		if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, body, next); err != nil {
			if current, readErr := module.readOwnership(); readErr == nil {
				if currentRecord, ok := decodeOwnership(current); ok && currentRecord.CleanupCheckpoint >= record.CleanupCheckpoint {
					record, body = currentRecord, current
					continue
				}
			}
			return Result{Status: SetupIncomplete, Message: "Proxy setup cleanup is incomplete.", Code: SetupNeedsCleanup, FailedCheck: "Cleanup checkpoint", Correction: "Choose Finish cleanup again."}
		}
		body = next
		report(progress, string(operation))
		if ctx.Err() != nil {
			return interruptedCleanup()
		}
	}
	if inspection := module.host.Inspect(context.WithoutCancel(ctx), slices.Clone(footprint)); !cleanupSurfaceAccepted(inspection, true) {
		return Result{Status: SetupIncomplete, Message: "Proxy setup cleanup is incomplete.", Code: SetupNeedsCleanup, FailedCheck: "Final cleanup inspection", Correction: "Correct the remaining or uninspectable proxy resource, then choose Finish cleanup."}
	}
	if err := module.host.RemoveOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, body); err != nil {
		return Result{Status: SetupIncomplete, Message: "Proxy setup cleanup is incomplete.", Code: SetupNeedsCleanup, FailedCheck: "Ownership Record cleanup", Correction: "Choose Finish cleanup again."}
	}
	report(progress, "Cleanup complete")
	if inspection := module.host.Inspect(context.WithoutCancel(ctx), slices.Clone(footprint)); !cleanupSurfaceAccepted(inspection, false) {
		return Result{Status: ProblemDetected, Message: "Cleanup finished, but the empty proxy footprint could not be freshly proved.", Code: StatusProblemDetected, FailedCheck: "Empty proxy footprint", Correction: "Inspect every fixed V3 proxy resource before continuing."}
	}
	return Result{Status: NotSetUp, Message: "Setup was safely cleaned up. No proxy resources remain.", Code: SetupCleanedUp}
}

func (module *installedInterface) finishRemoval(ctx context.Context, record ownershipRecord, body []byte, progress ProgressReporter, exclusion *subscriptionExclusion) Result {
	lifecycle, ok := module.lifecycle.(removalLifecycle)
	if !ok || record.Direction != removalRequired || record.Phase != removalCommitted {
		return removalInterrupted("Removal authority")
	}
	if !module.syncRemovalAuthority(body) {
		return removalInterrupted("Removal authority synchronization")
	}
	repairServingRemoved := false
	if record.ClientRotation != nil {
		if sub := record.ClientRotation.Subscription; sub != nil {
			host, supported := module.host.(clientIdentitySubscriptionHost)
			remover, removalSupported := module.host.(subscriptionRepairRemovalHost)
			if !supported || !removalSupported {
				return removalInterrupted("Client Identity subscription removal")
			}
			if exclusion == nil {
				var acquired bool
				exclusion, acquired = module.acquireSubscriptionExclusion(record)
				if !acquired {
					return removalInterrupted("Client Identity subscription exclusion")
				}
				defer exclusion.Release()
			}
			if !host.RemoveClientIdentitySubscription(*sub) || !remover.RemoveSubscriptionRepair(context.WithoutCancel(ctx), sub.Source, sub.Target, exclusion.serving) {
				return removalInterrupted("Client Identity subscription removal")
			}
			repairServingRemoved = true
		}
		host, ok := module.host.(clientIdentityHost)
		if !ok || !host.RemoveClientIdentityTarget(record.ClientRotation.Source, record.ClientRotation.Target) {
			return removalInterrupted("Interrupted Client Identity rotation removal")
		}
		report(progress, "Client Identity rotation target removed")
	}
	if record.Enablement != nil {
		host, ok := module.host.(subscriptionEnablementHost)
		if !ok || !host.CleanupPreparedSubscription(context.WithoutCancel(ctx), hostadapter.SubscriptionCleanupInput{Checkpoint: record.Enablement.Checkpoint, LinkID: record.Enablement.LinkID, CredentialSHA256: record.Enablement.CredentialSHA256, RecorderID: record.Enablement.RecorderID, Serving: record.Enablement.Serving, Renewal: record.Enablement.Renewal, Resources: record.Enablement.Resources}) {
			return removalInterrupted("Interrupted subscription enablement removal")
		}
		report(progress, "Cleaning up subscription change")
	}
	if record.Rotation != nil {
		host, ok := module.host.(subscriptionRotationHost)
		if !ok || record.Renewal == nil {
			return removalInterrupted("Interrupted Subscription Link rotation removal")
		}
		if exclusion == nil {
			var acquired bool
			exclusion, acquired = module.acquireSubscriptionExclusion(record)
			if !acquired {
				return removalInterrupted("Subscription rotation exclusion")
			}
			defer exclusion.Release()
		}
		if !host.RemoveSubscriptionRotation(context.WithoutCancel(ctx), hostadapter.SubscriptionRotationInput{Source: record.Rotation.Source, Target: record.Rotation.Target, Renewal: *record.Renewal}, exclusion.serving) {
			return removalInterrupted("Interrupted Subscription Link rotation removal")
		}
		report(progress, "Cleaning up subscription change")
	}
	if record.Repair != nil && record.Repair.Target != nil {
		host, ok := module.host.(subscriptionRepairRemovalHost)
		if !ok {
			return removalInterrupted("Interrupted subscription repair removal")
		}
		if exclusion == nil {
			var acquired bool
			exclusion, acquired = module.acquireSubscriptionExclusion(record)
			if !acquired {
				return removalInterrupted("Subscription repair exclusion")
			}
			defer exclusion.Release()
		}
		if !host.RemoveSubscriptionRepair(context.WithoutCancel(ctx), record.Repair.Source, *record.Repair.Target, exclusion.serving) {
			return removalInterrupted("Interrupted subscription repair removal")
		}
		repairServingRemoved = true
		report(progress, "Cleaning up subscription change")
	}
	if record.Serving != nil && !repairServingRemoved {
		host, ok := module.host.(servingRemovalHost)
		if !ok {
			return removalInterrupted("Subscription Serving exclusion")
		}
		if host.ServingRuntimeAbsent(*record.Serving) {
			report(progress, "Subscription Serving removed")
		} else {
			if exclusion == nil {
				var acquired bool
				exclusion, acquired = module.acquireSubscriptionExclusion(record)
				if !acquired {
					return removalInterrupted("Subscription Serving exclusion")
				}
				defer exclusion.Release()
			}
			if !host.RemoveServingRuntime(context.WithoutCancel(ctx), *record.Serving, exclusion.serving) || !host.ServingRuntimeAbsent(*record.Serving) {
				return removalInterrupted("Subscription Serving removal")
			}
			report(progress, "Subscription Serving removed")
		}
		if ctx.Err() != nil {
			return removalInterrupted("Managed termination")
		}
	}
	if record.Renewal != nil {
		host, ok := module.host.(renewalHost)
		if !ok {
			return removalInterrupted("Renewal recorder removal")
		}
		if !host.RenewalIntegrationAbsent(*record.Renewal) {
			if exclusion == nil {
				var acquired bool
				exclusion, acquired = module.acquireSubscriptionExclusion(record)
				if !acquired {
					return removalInterrupted("Renewal recorder exclusion")
				}
				defer exclusion.Release()
			}
			if exclusion == nil || exclusion.renewal == nil || !host.RemoveRenewalIntegration(context.WithoutCancel(ctx), *record.Renewal, exclusion.renewal) || !host.RenewalIntegrationAbsent(*record.Renewal) {
				return removalInterrupted("Renewal recorder removal")
			}
		}
		report(progress, "Renewal recorder removed")
	}
	if record.SubscriptionResources != nil {
		host, ok := module.host.(subscriptionResourceRemovalHost)
		if !ok {
			return removalInterrupted("Subscription owned-resource removal")
		}
		if exclusion == nil {
			servingHost, ok := module.host.(servingRemovalHost)
			if !ok {
				return removalInterrupted("Subscription resource exclusion")
			}
			servingExclusion, acquired := servingHost.AcquireServingExclusion()
			if !acquired {
				return removalInterrupted("Subscription resource exclusion")
			}
			exclusion = &subscriptionExclusion{serving: servingExclusion}
			defer exclusion.Release()
		}
		removalServing := record.Serving
		if record.Repair != nil && record.Repair.Target != nil {
			removalServing = record.Repair.Target
		}
		if !host.RemoveSubscriptionResources(context.WithoutCancel(ctx), *record.SubscriptionResources, removalServing) {
			return removalInterrupted("Subscription owned-resource removal")
		}
		report(progress, "Subscription owned resources removed")
	}
	operations := []hostadapter.Operation{}
	if record.Package != "" {
		operations = []hostadapter.Operation{
			hostadapter.StopDisableService,
			hostadapter.RemovePackageArtifact,
			hostadapter.RemovePackageHold,
			hostadapter.RemovePackage,
			hostadapter.RemoveConfigurationState,
			hostadapter.RemovePackageIdentity,
			hostadapter.RemoveAPTSource,
			hostadapter.RemoveAPTKey,
		}
	}
	removeStartup := func() bool {
		if record.Startup == nil {
			return true
		}
		host, ok := module.host.(clientIdentityHost)
		return ok && host.RemoveProxyStartupIntegration(context.WithoutCancel(ctx), *record.Startup)
	}
	if record.RemovalCheckpoint > 0 && !removeStartup() {
		return removalInterrupted("Proxy startup integration removal")
	}
	for index, operation := range operations {
		if record.RemovalCheckpoint > index {
			continue
		}
		if result := module.host.Apply(context.WithoutCancel(ctx), cleanupInput(operation, record)); !result.OK {
			return removalInterrupted(string(operation))
		}
		record.RemovalCheckpoint = index + 1
		var checkpointed bool
		body, checkpointed = module.publishRemovalCheckpoint(record, body)
		if !checkpointed {
			return removalInterrupted("Removal checkpoint")
		}
		report(progress, string(operation))
		if operation == hostadapter.StopDisableService {
			if !removeStartup() {
				return removalInterrupted("Proxy startup integration removal")
			}
			report(progress, "Proxy startup integration removed")
		}
		if ctx.Err() != nil {
			return removalInterrupted("Managed termination")
		}
	}
	proxyCheckpoint := len(operations)
	if record.RemovalCheckpoint <= proxyCheckpoint {
		if inspection := module.host.Inspect(context.WithoutCancel(ctx), slices.Clone(footprint)); !cleanupSurfaceAccepted(inspection, true) {
			return removalInterrupted("Final proxy absence inspection")
		}
		record.RemovalCheckpoint = proxyCheckpoint + 1
		var checkpointed bool
		body, checkpointed = module.publishRemovalCheckpoint(record, body)
		if !checkpointed {
			return removalInterrupted("Proxy absence checkpoint")
		}
	}
	lifecycleFacts := lifecycle.InspectCompleteRemoval(context.WithoutCancel(ctx), finishingRelease(record))
	if !lifecycleFacts.Valid || !lifecycleFacts.StateDirectoryEmpty {
		return removalInterrupted("SBXR state directory inspection")
	}
	executableCheckpoint := proxyCheckpoint + 1
	if lifecycleFacts.ExecutablePresent || record.RemovalCheckpoint <= executableCheckpoint {
		if !lifecycle.RemoveCompleteRemovalExecutable(context.WithoutCancel(ctx), finishingRelease(record)) {
			return removalInterrupted("SBXR executable removal")
		}
	}
	if record.RemovalCheckpoint <= executableCheckpoint {
		record.RemovalCheckpoint = executableCheckpoint + 1
		var checkpointed bool
		body, checkpointed = module.publishRemovalCheckpoint(record, body)
		if !checkpointed {
			return removalInterrupted("Executable removal checkpoint")
		}
	}
	installedCheckpoint := executableCheckpoint + 1
	if lifecycleFacts.InstalledRecordPresent || record.RemovalCheckpoint <= installedCheckpoint {
		if !lifecycle.RemoveCompleteRemovalInstalledRecord(context.WithoutCancel(ctx), finishingRelease(record)) {
			return removalInterrupted("Installed Record removal")
		}
	}
	if record.RemovalCheckpoint <= installedCheckpoint {
		record.RemovalCheckpoint = installedCheckpoint + 1
		var checkpointed bool
		body, checkpointed = module.publishRemovalCheckpoint(record, body)
		if !checkpointed {
			return removalInterrupted("Installed Record removal checkpoint")
		}
	}
	if inspection := module.host.Inspect(context.WithoutCancel(ctx), slices.Clone(footprint)); !cleanupSurfaceAccepted(inspection, true) {
		return removalInterrupted("Final proxy absence inspection")
	}
	finalLifecycle := lifecycle.InspectCompleteRemoval(context.WithoutCancel(ctx), finishingRelease(record))
	if !finalLifecycle.Valid || finalLifecycle.ExecutablePresent || finalLifecycle.InstalledRecordPresent || !finalLifecycle.StateDirectoryEmpty {
		return removalInterrupted("Final installed-product absence inspection")
	}
	if err := module.host.RemoveFinalOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, finalOwnershipPath, body); err != nil {
		if errors.Is(err, hostadapter.ErrFinalRemovalSync) {
			return Result{Status: ProblemDetected, Code: RemovalNeedsCompletion, Message: "All owned resources were removed, but final removal synchronization could not be verified.", FailedCheck: "Final removal synchronization", Correction: "Restore reliable storage access, then inspect the installation again. Do not assume Finish removal is available."}
		}
		return removalInterrupted("Ownership Record finalization")
	}
	return Result{Message: "SBXR is not installed.", Code: CompleteRemovalCompleted}
}

func (module *installedInterface) publishRemovalCheckpoint(record ownershipRecord, current []byte) ([]byte, bool) {
	next := ownershipBytes(record)
	if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, current, next); err == nil {
		return next, true
	}
	committed, err := module.readOwnership()
	committedRecord, ok := decodeOwnership(committed)
	return committed, err == nil && ok && committedRecord.Direction == removalRequired && bytes.Equal(committed, next) && module.syncRemovalAuthority(committed)
}

func (module *installedInterface) syncRemovalAuthority(body []byte) bool {
	current, err := module.readOwnership()
	if err != nil || !bytes.Equal(current, body) {
		return false
	}
	name := hostSetupSpec.OwnershipPath
	if _, err := module.host.ReadOwnership(name); errors.Is(err, os.ErrNotExist) {
		name = finalOwnershipPath
	}
	return module.host.SyncOwnership(name, body) == nil
}

func removalInterrupted(failed string) Result {
	return Result{Status: RemovalIncomplete, Message: "Complete removal must continue forward.", Code: RemovalNeedsCompletion, FailedCheck: failed, Correction: "Start SBXR again and choose Finish removal."}
}

func (module *installedInterface) readOwnership() ([]byte, error) {
	body, err := module.host.ReadOwnership(hostSetupSpec.OwnershipPath)
	final, finalErr := module.host.ReadOwnership(finalOwnershipPath)
	if err == nil {
		if !errors.Is(finalErr, os.ErrNotExist) {
			return nil, errors.New("conflicting ownership authority")
		}
		return body, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if finalErr == nil {
		record, valid := decodeOwnership(final)
		if !valid || record.Direction != removalRequired || record.RemovalCheckpoint != removalCheckpointLimit(record) {
			return nil, errors.New("invalid finalization authority")
		}
	}
	return final, finalErr
}

func cleanupSurfaceAccepted(inspection hostadapter.Inspection, ownershipPresent bool) bool {
	if !inspectionAccepted(inspection) {
		return false
	}
	authorityCount := 0
	for _, resource := range inspection.Resources {
		if resource.Name == hostSetupSpec.OwnershipPath || resource.Name == finalOwnershipPath {
			if resource.Present {
				authorityCount++
			}
			continue
		}
		if resource.Present {
			return false
		}
	}
	return ownershipPresent && authorityCount == 1 || !ownershipPresent && authorityCount == 0
}

func cleanupInput(operation hostadapter.Operation, record ownershipRecord) hostadapter.OperationInput {
	input := hostadapter.OperationInput{Operation: operation, Spec: hostSetupSpec, LockProvisioning: record.LockProvisioning}
	switch operation {
	case hostadapter.RemoveConfigurationState:
		input.SHA256 = record.ConfigurationSHA256
	case hostadapter.RemoveAPTSource:
		digest := sha256.Sum256(aptSourceBody)
		input.SHA256 = hex.EncodeToString(digest[:])
	}
	return input
}

func interruptedCleanup() Result {
	return Result{Status: SetupIncomplete, Message: "Proxy setup cleanup must be finished after managed termination.", Code: SetupNeedsCleanup, FailedCheck: "Managed termination", Correction: "Start SBXR again and choose Finish cleanup."}
}

func interruptedSetup() Result {
	return Result{Status: SetupIncomplete, Message: "Proxy setup must continue forward after managed termination.", Code: SetupNeedsCompletion, FailedCheck: "Managed termination", Correction: "Start SBXR again and choose Finish setup."}
}

func resourcesPresent(resources []hostadapter.Resource) bool {
	return slices.ContainsFunc(resources, func(resource hostadapter.Resource) bool { return resource.Present })
}

func inspectionAccepted(inspection hostadapter.Inspection) bool {
	return inspection.Complete && resourcesObserved(inspection.Resources)
}

func resourcesObserved(resources []hostadapter.Resource) bool {
	if len(resources) != len(footprint) {
		return false
	}
	for index, expected := range footprint {
		if resources[index].Kind != expected.Kind || resources[index].Name != expected.Name || !resources[index].Observed {
			return false
		}
	}
	return true
}

func acceptedPreflight(facts hostadapter.Preflight) (hostadapter.Destination, string, string) {
	if !resourcesObserved(facts.Resources) {
		return hostadapter.Destination{}, "Proxy footprint inspection", "Restore complete read-only access to every fixed V3 proxy resource, then review setup again."
	}
	if resourcesPresent(facts.Resources) {
		return hostadapter.Destination{}, "Clean proxy footprint", "Remove every conflicting sing-box or V3 resource, then review setup again."
	}
	if facts.OSID != "ubuntu" || facts.OSVersion != "24.04" {
		return hostadapter.Destination{}, "Ubuntu version", "Use a clean Ubuntu Server 24.04 VPS."
	}
	if facts.Architecture != "amd64" {
		return hostadapter.Destination{}, "Architecture", "Use an Ubuntu Server 24.04 amd64 VPS."
	}
	ip, err := netip.ParseAddr(facts.PublicIPv4)
	if err != nil || !isPublicIPv4(ip) {
		return hostadapter.Destination{}, "Public IPv4", "Give the VPS one public IPv4 address and make https://api.ipify.org return it."
	}
	if !facts.ClockSynchronized {
		return hostadapter.Destination{}, "Synchronized clock", "Synchronize the VPS clock, then review setup again."
	}
	if !facts.TCP443Available {
		return hostadapter.Destination{}, "Public TCP port 443", "Free TCP port 443 on the VPS and in host or provider policy without changing SSH."
	}
	if !facts.MutationLockAvailable {
		return hostadapter.Destination{}, "SBXR mutation lock", "Wait for the active SBXR change to finish, then review setup again."
	}
	if !facts.PackageLocksAvailable {
		return hostadapter.Destination{}, "Ubuntu package locks", "Wait for APT and dpkg to finish, then review setup again."
	}
	for _, candidate := range destinations {
		for _, observation := range facts.Destinations {
			if observation.Destination == candidate && observation.Compatible() {
				return candidate, "", ""
			}
		}
	}
	return hostadapter.Destination{}, "REALITY destination", "Restore DNS and outbound TCP/TLS access to at least one accepted REALITY destination."
}

func isPublicIPv4(address netip.Addr) bool {
	address = address.Unmap()
	return address.Is4() && address.IsGlobalUnicast() && !slices.ContainsFunc(nonPublicIPv4, func(prefix netip.Prefix) bool { return prefix.Contains(address) })
}

func removalAccepted(facts hostadapter.RemovalInspection) bool {
	required := []hostadapter.Observation{
		facts.Host, facts.PublicIPv4Matches, facts.Ownership, facts.TransactionFilesAbsent,
		facts.APTKey, facts.APTSource, facts.Package, facts.Hold, facts.PackageIdentity,
		facts.Configuration, facts.State, facts.Validation, facts.ServiceProvenance,
		facts.PackageLocks, facts.ConfigurationEntries, facts.StateEntries,
		facts.IdentityExclusive, facts.ProcessExclusive,
		facts.ServiceSafe,
	}
	return !slices.ContainsFunc(required, func(fact hostadapter.Observation) bool { return !fact.Observed || !fact.Accepted })
}

func refused(status Status, failed, correction string) Result {
	return Result{Status: status, Message: "The requested action was refused. View details for the failed check and correction.", Code: ActionRefused, FailedCheck: failed, Correction: correction}
}

func samePreflight(left, right hostadapter.Preflight) bool {
	return reflect.DeepEqual(left, right)
}

// This exact prior creator is supported only for its validated original proxy
// contract. This is not update-source qualification or arbitrary V3 admission.
var legacyProxyCreator = softwarelifecycle.ReleaseIdentity{
	Repository: softwarelifecycle.Repository, Tag: "v3.0.21",
	Commit:      "989094b9766f02bf17510a71753c6a5c736bf120",
	IndexSHA256: "90463aa73a2c81542b44ea833c762bb2cd44d2d585fb7bd322279f678feea331",
}

var setupPhaseOrder = []setupPhase{ownershipRecorded, aptKeyInstalled, aptSourceInstalled, serviceMasked, packageInstalled, packageHeld, stateDirectoryCreated, configurationInstalled, configurationValidated, serviceUnmasked, activationCommitted, serviceEnabled, serviceStarted, runningPhase}

func runningAccepted(facts hostadapter.RunningInspection) bool {
	return all(facts.Host, facts.PublicIPv4Matches, facts.ServiceEnabled, facts.ServiceActive, facts.Listener).Accepted && ownedFactsAccepted(facts)
}

func ownedFactsAccepted(facts hostadapter.RunningInspection) bool {
	return all(facts.Ownership, facts.TransactionFilesAbsent, facts.APTKey, facts.APTSource, facts.Package, facts.Hold, facts.PackageIdentity, facts.Configuration, facts.State, facts.Validation, facts.ServiceProvenance, facts.LockProvisioning).Accepted
}

func report(progress ProgressReporter, phase string) {
	if progress != nil {
		progress(Progress{Phase: phase})
	}
}
