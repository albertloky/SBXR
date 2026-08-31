// Package proxyinstallation owns the installed V3 proxy journey.
package proxyinstallation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"reflect"
	"regexp"
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
	SetupIncomplete   Status = "Setup incomplete"
	ProblemDetected   Status = "Problem detected"
	RemovalIncomplete Status = "Removal incomplete"
)

type SubscriptionStatus string

const (
	SubscriptionNotEnabled      SubscriptionStatus = "Not enabled"
	SubscriptionProblemDetected SubscriptionStatus = "Problem detected"
)

type Availability string

const (
	ProvedWorking    Availability = "proved working"
	ProvedStopped    Availability = "proved stopped"
	CannotBeVerified Availability = "cannot be verified"
)

type Action string

const (
	StatusAction                  Action = "Status"
	ViewDetailsAction             Action = "View details"
	StartSetupAction              Action = "Start setup"
	FinishCleanupAction           Action = "Finish cleanup"
	FinishSetupAction             Action = "Finish setup"
	ShowClientConfigurationAction Action = "Show client configuration"
	CompleteRemovalAction         Action = "Complete removal"
	FinishRemovalAction           Action = "Finish removal"
	EnableSubscriptionAction      Action = "Enable subscription"
)

type Confirmation uint8

const (
	Declined Confirmation = iota + 1
	Approved
)

type ResultCode string

const (
	StatusNotSetUp               ResultCode = "PROXY-INSTALLATION-STATUS-NOT-SET-UP"
	StatusProblemDetected        ResultCode = "PROXY-INSTALLATION-STATUS-PROBLEM-DETECTED"
	StatusChangeInProgress       ResultCode = "PROXY-INSTALLATION-STATUS-CHANGE-IN-PROGRESS"
	ActionCancelled              ResultCode = "PROXY-INSTALLATION-ACTION-CANCELLED"
	ActionRefused                ResultCode = "PROXY-INSTALLATION-ACTION-REFUSED"
	SetupComplete                ResultCode = "PROXY-INSTALLATION-SETUP-COMPLETE"
	SetupNeedsCleanup            ResultCode = "PROXY-INSTALLATION-SETUP-CLEANUP-REQUIRED"
	SetupNeedsCompletion         ResultCode = "PROXY-INSTALLATION-SETUP-COMPLETION-REQUIRED"
	SetupCleanedUp               ResultCode = "PROXY-INSTALLATION-SETUP-CLEANED-UP"
	ClientConfigurationDisclosed ResultCode = "PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED"
	RemovalNeedsCompletion       ResultCode = "PROXY-INSTALLATION-REMOVAL-COMPLETION-REQUIRED"
	CompleteRemovalCompleted     ResultCode = "SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED"
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

type Review struct {
	SubscriptionStatus  SubscriptionStatus
	ProxyTraffic        Availability
	SubscriptionServing Availability
	Version             string
	Status              Status
	LegalActions        []Action
	Details             []string
	Plan                []string
	Result              Result
	Prepared            *PreparedAction
}

type Progress struct {
	Phase               string
	ClientConfiguration []byte
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
}

type unfinishedDirection string

const (
	cleanupRequired unfinishedDirection = "cleanup required"
	setupRequired   unfinishedDirection = "setup required"
	noDirection     unfinishedDirection = "none"
	removalRequired unfinishedDirection = "removal required"
)

type setupPhase string

const (
	ownershipRecorded      setupPhase = "Ownership recorded"
	aptKeyInstalled        setupPhase = "APT key installed"
	aptSourceInstalled     setupPhase = "APT source installed"
	serviceMasked          setupPhase = "Service masked"
	packageInstalled       setupPhase = "Package installed"
	packageHeld            setupPhase = "Package held"
	stateDirectoryCreated  setupPhase = "State directory created"
	configurationInstalled setupPhase = "Configuration installed"
	configurationValidated setupPhase = "Configuration validated"
	serviceUnmasked        setupPhase = "Service unmasked"
	activationCommitted    setupPhase = "Activation committed"
	serviceEnabled         setupPhase = "Service enabled"
	serviceStarted         setupPhase = "Service started"
	runningPhase           setupPhase = "Running"
	removalCommitted       setupPhase = "Removal committed"
)

type ownershipRecord struct {
	Schema                   int                                 `json:"schema"`
	Phase                    setupPhase                          `json:"phase"`
	Direction                unfinishedDirection                 `json:"unfinished_direction"`
	Release                  softwarelifecycle.ReleaseIdentity   `json:"release_identity"`
	Package                  string                              `json:"proxy_package_identity"`
	PublicIPv4               string                              `json:"public_ipv4"`
	DestinationAddress       string                              `json:"destination_address"`
	DestinationName          string                              `json:"destination_server_name"`
	ConfigurationSHA256      string                              `json:"configuration_sha256"`
	Resources                []string                            `json:"permitted_resources"`
	CleanupCheckpoint        int                                 `json:"cleanup_checkpoint"`
	RemovalCheckpoint        int                                 `json:"removal_checkpoint"`
	ResourceCreatingReleases []softwarelifecycle.ReleaseIdentity `json:"resource_creating_releases,omitempty"`
	FinishingRelease         *softwarelifecycle.ReleaseIdentity  `json:"finishing_release_identity,omitempty"`
	Serving                  *hostadapter.ServingAuthority       `json:"serving,omitempty"`
}

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
	if action == EnableSubscriptionAction && review.Prepared == nil && review.Result.Code != ActionRefused {
		failed, correction := "Compatible idle installation", "Use View details to restore a compatible installed release, supported idle Ownership Record, and locally Running proxy before enabling a subscription."
		if review.Status == ChangeInProgress {
			failed, correction = "Whole-host mutation", "Wait for the active SBXR change to finish, then review Enable subscription again."
		}
		review.Result = refused(review.Status, failed, correction)
	}
	review.SubscriptionStatus = module.subscriptionStatus(ctx)
	review.ProxyTraffic, review.SubscriptionServing = CannotBeVerified, CannotBeVerified
	if review.Status == Running {
		review.ProxyTraffic = ProvedWorking
	}
	if review.SubscriptionStatus == SubscriptionNotEnabled {
		review.SubscriptionServing = ProvedStopped
	}
	review.Result.SubscriptionStatus = review.SubscriptionStatus
	review.Result.ProxyTraffic, review.Result.SubscriptionServing = review.ProxyTraffic, review.SubscriptionServing
	review.Details = append(review.Details, "Subscription Capability Status: "+string(review.SubscriptionStatus))
	if review.SubscriptionStatus != SubscriptionNotEnabled && !module.servingSurfaceSafe() {
		clear(module.prepared)
		review.Prepared = nil
		review.LegalActions = []Action{ViewDetailsAction}
		if action != StatusAction && action != ViewDetailsAction && review.Result.Code != ActionRefused {
			review.Result.Code, review.Result.FailedCheck, review.Result.Correction = ActionRefused, "Subscription absence", "Restore safe, supported authority and prove subscription material absent before retrying."
		}
	}
	if module.servingSurfaceSafe() {
		review.LegalActions = slices.DeleteFunc(review.LegalActions, func(a Action) bool { return a == EnableSubscriptionAction })
		if action == EnableSubscriptionAction {
			clear(module.prepared)
			review.Prepared = nil
			review.Result = refused(review.Status, "Existing serving authority", "Complete removal is supported; subscription enablement remains unavailable.")
		}
		review.Details = append(review.Details, "Subscription runtime authority is supported. Managed renewal and Owner enablement are not available in this slice.")
	}
	return review
}

func (module *installedInterface) subscriptionStatus(ctx context.Context) SubscriptionStatus {
	if module.host == nil {
		return SubscriptionProblemDetected
	}
	body, err := module.readOwnership()
	if err == nil {
		if record, valid := decodeOwnership(body); !valid || record.Serving != nil {
			return SubscriptionProblemDetected
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return SubscriptionProblemDetected
	}
	staged, stagedErr := module.host.ReadOwnership(hostSetupSpec.OwnershipNextPath)
	if stagedErr == nil {
		if _, valid := decodeOwnership(staged); !valid {
			return SubscriptionProblemDetected
		}
	} else if !errors.Is(stagedErr, os.ErrNotExist) {
		return SubscriptionProblemDetected
	}
	fact := module.host.InspectSubscriptionAbsence(ctx)
	if fact.Observed && fact.Accepted {
		return SubscriptionNotEnabled
	}
	return SubscriptionProblemDetected
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
		failed, correction := module.subscriptionAdmission(ctx, subscription)
		if failed != "" {
			review.LegalActions = slices.DeleteFunc(review.LegalActions, func(a Action) bool { return a == EnableSubscriptionAction })
			review.Details = append(review.Details, "Subscription enablement check: "+failed, "Safe correction: "+correction)
			if action == EnableSubscriptionAction {
				review.Result = refused(Running, failed, correction)
				return review
			}
		}
	}
	if action == CompleteRemovalAction {
		surface := module.host.Inspect(ctx, slices.Clone(footprint))
		removal := module.host.InspectRemoval(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
		review.Details = append(review.Details, removalMismatchDetails(removal)...)
		if !inspectionAccepted(surface) || !removalAccepted(removal) {
			review.Result = refused(review.Status, "Complete removal preflight", removalCorrection(removal))
			return review
		}
		return module.prepareRemoval(review, installed, &record, body, surface, removal)
	}
	if action == ViewDetailsAction && record.Phase == runningPhase {
		removal := module.host.InspectRemoval(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
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

func (module *installedInterface) ownershipProblem(ctx context.Context, review Review, installed softwarelifecycle.ReleaseIdentity, installedReady bool, lock, ownership, detail, correction string) Review {
	review.Status = ProblemDetected
	review.LegalActions = []Action{ViewDetailsAction}
	review.Result = Result{Status: ProblemDetected, Message: "A proxy problem was detected. View details before continuing.", Code: StatusProblemDetected}
	review.Details = module.problemDetails(ctx, installed, installedReady, ProblemDetected, lock, ownership, detail, correction)
	if installedReady {
		review.Version = installed.Tag
	}
	return review
}

func (module *installedInterface) problemDetails(ctx context.Context, installed softwarelifecycle.ReleaseIdentity, installedReady bool, status Status, lock, ownership, detail, correction string) []string {
	inspection := module.host.Inspect(ctx, slices.Clone(footprint))
	facts := module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, nil, "", "")
	configurationPresent := resourcePresent(inspection.Resources, "/etc/sing-box")
	overrides := &detailOverrides{
		direction: "Unavailable", lock: lock, ownership: ownership,
		clientIdentity: present(configurationPresent), publicEndpoint: "Unavailable",
		destination: "Unavailable", serverName: "Unavailable",
	}
	details := inspectionDetails(installed, installedReady, status, inspection, &facts, overrides, false)
	return append(details, "Detected mismatch: "+detail, "Safe correction: "+correction)
}

func ownedDetails(installed softwarelifecycle.ReleaseIdentity, installedReady bool, status Status, record ownershipRecord, facts hostadapter.RunningInspection, lock string) []string {
	version, release := "Unavailable", "Unavailable"
	if installedReady {
		version = installed.Tag
		release = fmt.Sprintf("%s %s %s %s", installed.Repository, installed.Tag, installed.Commit, installed.IndexSHA256)
	}
	details := []string{
		"SBXR version: " + version,
		"Release Identity: " + release,
		"Ubuntu: " + ubuntu(facts),
		"Proxy Installation Status: " + string(status),
		"Required unfinished direction: " + string(record.Direction),
		"Mutation lock: " + lock,
		fmt.Sprintf("Ownership Record: Valid; phase %s; cleanup checkpoint %d", record.Phase, record.CleanupCheckpoint),
		"Proxy Package Identity: " + proxyPackageIdentity() + "; " + observationMatch(all(facts.APTKey, facts.APTSource, facts.Package)),
		"Package hold: " + observationPresence(facts.Hold),
		"Protected configuration identity: /etc/sing-box/config.json SHA-256 " + record.ConfigurationSHA256 + "; " + observationMatch(facts.Configuration),
		"Packaged validation result: " + observationAcceptance(facts.Validation),
		"systemd unit provenance: /usr/lib/systemd/system/sing-box.service from sing-box; " + observationMatch(facts.ServiceProvenance),
		"Service enabled: " + observationYesNo(facts.ServiceEnabled),
		"Service active: " + observationYesNo(facts.ServiceActive),
		"Expected public listener ownership: sing-box on TCP " + record.PublicIPv4 + ":443; " + observationMatch(facts.Listener),
		"Public endpoint: " + record.PublicIPv4 + ":443",
		"Selected destination: " + record.DestinationAddress,
		"Server name: " + record.DestinationName,
		"Client Identity: " + present(facts.Configuration.Accepted),
		"Running is local VPS truth only; outside-client traffic is not claimed.",
	}
	if status != ProblemDetected {
		return details
	}
	checks := []struct {
		fact        hostadapter.Observation
		unavailable string
		accepted    bool
		mismatch    string
		correction  string
		observe     string
	}{
		{facts.Host, "Ubuntu version and architecture", facts.Host.Accepted, "the host is not Ubuntu 24.04 amd64", "Use the V3 installation only on Ubuntu Server 24.04 amd64, then inspect again.", "Restore read-only access to /etc/os-release, then inspect again."},
		{facts.PublicIPv4Matches, "public IPv4", facts.PublicIPv4Matches.Accepted, "the current public IPv4 does not match the Ownership Record", "Restore the recorded public IPv4 to this VPS, then inspect again.", "Restore HTTPS access to https://api.ipify.org, then inspect again."},
		{facts.Ownership, "Ownership Record", facts.Ownership.Accepted, "the Ownership Record changed during inspection", "Restore the exact valid Ownership Record checkpoint, then inspect again.", "Restore read-only access to /var/lib/sbxr/proxy-ownership.json, then inspect again."},
		{facts.TransactionFilesAbsent, "transaction files", facts.TransactionFilesAbsent.Accepted, "unfinished transaction material is present after Running", "Remove only the proved V3 transaction files, then inspect again.", "Restore read-only access to the four fixed V3 transaction paths, then inspect again."},
		{facts.APTKey, "APT signing key", facts.APTKey.Accepted, "the SagerNet signing key identity does not match", "Restore /etc/apt/keyrings/sagernet.asc from the qualified package identity, then inspect again.", "Restore read-only access to /etc/apt/keyrings/sagernet.asc, then inspect again."},
		{facts.APTSource, "APT source", facts.APTSource.Accepted, "the SagerNet APT source identity does not match", "Restore /etc/apt/sources.list.d/sagernet.sources to the exact qualified source, then inspect again.", "Restore read-only access to /etc/apt/sources.list.d/sagernet.sources, then inspect again."},
		{facts.Package, "proxy package", facts.Package.Accepted, "the sing-box package identity does not match", "Restore sing-box 1.13.19 amd64 from the qualified DEB, then inspect again.", "Restore working dpkg-query inspection for sing-box, then inspect again."},
		{facts.Hold, "package hold", facts.Hold.Accepted, "the sing-box package hold is absent", "Apply the package hold to sing-box 1.13.19, then inspect again.", "Restore working apt-mark inspection for sing-box, then inspect again."},
		{facts.PackageIdentity, "package user and group", facts.PackageIdentity.Accepted, "the sing-box user or group identity does not match", "Restore the package-created sing-box user and group ownership, then inspect again.", "Restore working getent inspection for the sing-box user and group, then inspect again."},
		{facts.Configuration, "protected configuration", facts.Configuration.Accepted, "the protected configuration identity does not match", "Restore /etc/sing-box/config.json with the recorded SHA-256 and protected ownership, then inspect again.", "Restore read-only access to /etc/sing-box/config.json, then inspect again."},
		{facts.State, "protected state", facts.State.Accepted, "the protected sing-box state identity does not match", "Restore /var/lib/sing-box with the package-created sing-box ownership and native systemd mode 0755, then inspect again.", "Restore read-only access to /var/lib/sing-box, then inspect again."},
		{facts.Validation, "packaged validation", facts.Validation.Accepted, "the packaged configuration validation was refused", "Restore the recorded protected configuration until packaged sing-box check accepts it, then inspect again.", "Restore execution of the packaged sing-box check command, then inspect again."},
		{facts.ServiceProvenance, "systemd unit provenance", facts.ServiceProvenance.Accepted, "sing-box.service does not have package provenance", "Restore /usr/lib/systemd/system/sing-box.service from sing-box 1.13.19, then inspect again.", "Restore working dpkg-query provenance inspection for sing-box.service, then inspect again."},
		{facts.ServiceEnabled, "service enabled state", facts.ServiceEnabled.Accepted, "sing-box.service is not enabled", "Enable the package-owned sing-box.service, then inspect again.", "Restore working systemctl enabled-state inspection for sing-box.service, then inspect again."},
		{facts.ServiceActive, "service active state", facts.ServiceActive.Accepted, "sing-box.service is not active", "Start sing-box.service from the exact installed package, then inspect again.", "Restore working systemctl active-state inspection for sing-box.service, then inspect again."},
		{facts.Listener, "public listener ownership", facts.Listener.Accepted, "TCP port 443 is not owned by the expected sing-box service", "Restore the sing-box listener on the recorded public endpoint, then inspect again.", "Restore working ss inspection for TCP port 443, then inspect again."},
	}
	for _, check := range checks {
		if !check.fact.Observed {
			details = append(details, "Detected mismatch: "+check.unavailable+" could not be inspected", "Safe correction: "+check.observe)
		} else if !check.accepted {
			details = append(details, "Detected mismatch: "+check.mismatch, "Safe correction: "+check.correction)
		}
	}
	return details
}

func match(ok bool) string {
	if ok {
		return "Matches"
	}
	return "Mismatch"
}

func present(ok bool) string {
	if ok {
		return "Present"
	}
	return "Absent"
}

func accepted(ok bool) string {
	if ok {
		return "Accepted"
	}
	return "Refused"
}

func yesNo(ok bool) string {
	if ok {
		return "Yes"
	}
	return "No"
}

type detailOverrides struct {
	direction, lock, ownership, clientIdentity string
	publicEndpoint, destination, serverName    string
}

func inspectionDetails(installed softwarelifecycle.ReleaseIdentity, installedReady bool, status Status, inspection hostadapter.Inspection, facts *hostadapter.RunningInspection, overrides *detailOverrides, reportResourceMismatches bool) []string {
	version, identity := "Unavailable", "Unavailable"
	if installedReady {
		version = installed.Tag
		identity = fmt.Sprintf("%s %s %s %s", installed.Repository, installed.Tag, installed.Commit, installed.IndexSHA256)
	}
	ownership := "Absent"
	if slices.ContainsFunc(inspection.Resources, func(resource hostadapter.Resource) bool {
		return resource.Name == "/var/lib/sbxr/proxy-ownership.json" && resource.Present
	}) {
		ownership = "Present"
	}
	direction, lock := "none", "Available"
	clientIdentity, publicEndpoint := "Absent", "Absent"
	destination, serverName := "Absent", "Absent"
	if overrides != nil {
		direction, lock, ownership = overrides.direction, overrides.lock, overrides.ownership
		clientIdentity, publicEndpoint = overrides.clientIdentity, overrides.publicEndpoint
		destination, serverName = overrides.destination, overrides.serverName
	}
	details := []string{
		"SBXR version: " + version,
		"Release Identity: " + identity,
		"Proxy Installation Status: " + string(status),
		"Required unfinished direction: " + direction,
		"Mutation lock: " + lock,
		"Ownership Record: " + ownership,
		"Client Identity: " + clientIdentity,
	}
	if facts != nil {
		configuration := resourcePresent(inspection.Resources, "/etc/sing-box")
		listener := resourcePresent(inspection.Resources, "443")
		packagePresent := resourcePresent(inspection.Resources, hostSetupSpec.PackageName)
		details = slices.Insert(details, 2,
			"Ubuntu: "+ubuntu(*facts),
		)
		details = append(details,
			"Proxy Package Identity: "+proxyPackageIdentity()+"; "+present(packagePresent),
			"Package hold: "+observationPresence(facts.Hold),
			"Protected configuration identity: "+present(configuration),
			"Packaged validation result: "+validationState(facts, configuration),
			"systemd unit provenance: "+observationPresence(facts.ServiceProvenance),
			"Service enabled: "+observationYesNo(facts.ServiceEnabled),
			"Service active: "+observationYesNo(facts.ServiceActive),
			"Expected public listener ownership: "+listenerState(facts, listener),
			"Public endpoint: "+publicEndpoint,
			"Selected destination: "+destination,
			"Server name: "+serverName,
		)
	}
	if !reportResourceMismatches {
		return details
	}
	for _, resource := range inspection.Resources {
		if !resource.Observed {
			details = append(details, "Detected mismatch: "+resource.Name+" could not be inspected", "Safe correction: Restore read-only inspection of "+resource.Name+", then inspect again.")
		} else if resource.Present {
			details = append(details, "Detected mismatch: "+resource.Name+" is present", "Safe correction: Remove only the conflicting "+resource.Name+" resource after proving it is not Owner data, then inspect again.")
		}
	}
	return details
}

func resourcePresent(resources []hostadapter.Resource, name string) bool {
	return slices.ContainsFunc(resources, func(resource hostadapter.Resource) bool { return resource.Name == name && resource.Present })
}

func validationState(facts *hostadapter.RunningInspection, applicable bool) string {
	if !applicable {
		return "Not applicable"
	}
	return observationAcceptance(facts.Validation)
}

func listenerState(facts *hostadapter.RunningInspection, present bool) string {
	if !facts.Listener.Observed {
		return "Unavailable"
	}
	if !present {
		return "Absent"
	}
	return match(facts.Listener.Accepted)
}

func observationPresence(fact hostadapter.Observation) string {
	if !fact.Observed {
		return "Unavailable"
	}
	return present(fact.Accepted)
}

func ubuntu(facts hostadapter.RunningInspection) string {
	if !facts.Host.Observed {
		return "Unavailable"
	}
	return facts.OSVersion + " " + facts.Architecture
}

func observationYesNo(fact hostadapter.Observation) string {
	if !fact.Observed {
		return "Unavailable"
	}
	return yesNo(fact.Accepted)
}

func observationMatch(fact hostadapter.Observation) string {
	if !fact.Observed {
		return "Unavailable"
	}
	return match(fact.Accepted)
}

func observationAcceptance(fact hostadapter.Observation) string {
	if !fact.Observed {
		return "Unavailable"
	}
	return accepted(fact.Accepted)
}

func all(facts ...hostadapter.Observation) hostadapter.Observation {
	combined := hostadapter.Observation{Observed: true, Accepted: true}
	for _, fact := range facts {
		combined.Observed = combined.Observed && fact.Observed
		combined.Accepted = combined.Accepted && fact.Accepted
	}
	return combined
}

func (module *installedInterface) Execute(ctx context.Context, prepared PreparedAction, confirmation Confirmation, progress ProgressReporter) (result Result) {
	module.mu.Lock()
	defer module.mu.Unlock()
	authority, ok := module.prepared[prepared.token]
	delete(module.prepared, prepared.token)
	defer func() {
		result.SubscriptionStatus = module.subscriptionStatus(context.WithoutCancel(ctx))
		result.ProxyTraffic, result.SubscriptionServing = CannotBeVerified, CannotBeVerified
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
		if result.Code == CompleteRemovalCompleted {
			result.ProxyTraffic = ProvedStopped
		}
		if result.SubscriptionStatus == SubscriptionNotEnabled {
			result.SubscriptionServing = ProvedStopped
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
		return module.refuseSubscriptionExecution(ctx, authority)
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
		if module.subscriptionStatus(context.WithoutCancel(ctx)) != SubscriptionNotEnabled && !module.servingSurfaceSafe() {
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
			removal := module.host.InspectRemoval(context.WithoutCancel(ctx), hostSetupSpec, aptSourceBody, current, record.ConfigurationSHA256, record.PublicIPv4)
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
		var exclusion *hostadapter.ServingExclusion
		if record.Serving != nil {
			host, ok := module.host.(servingRemovalHost)
			if !ok {
				return refused(authority.status, "Serving exclusion", "Restore supported serving inspection before removal.")
			}
			var acquired bool
			exclusion, acquired = host.AcquireServingExclusion()
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
	if module.subscriptionStatus(context.WithoutCancel(ctx)) != SubscriptionNotEnabled && !(module.servingSurfaceSafe() && (authority.action == FinishRemovalAction || authority.action == ShowClientConfigurationAction)) {
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
			facts := module.host.InspectRemoval(context.WithoutCancel(ctx), hostSetupSpec, aptSourceBody, current, record.ConfigurationSHA256, record.PublicIPv4)
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
		if result := module.host.Apply(ctx, hostadapter.OperationInput{Operation: step.operation, Spec: hostSetupSpec, Body: step.payload}); !result.OK {
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

func (module *installedInterface) finishRemoval(ctx context.Context, record ownershipRecord, body []byte, progress ProgressReporter, exclusion *hostadapter.ServingExclusion) Result {
	lifecycle, ok := module.lifecycle.(removalLifecycle)
	if !ok || record.Direction != removalRequired || record.Phase != removalCommitted {
		return removalInterrupted("Removal authority")
	}
	if !module.syncRemovalAuthority(body) {
		return removalInterrupted("Removal authority synchronization")
	}
	if record.Serving != nil {
		host, ok := module.host.(servingRemovalHost)
		if !ok {
			return removalInterrupted("Subscription Serving exclusion")
		}
		if exclusion == nil {
			var acquired bool
			exclusion, acquired = host.AcquireServingExclusion()
			if !acquired {
				return removalInterrupted("Subscription Serving exclusion")
			}
			defer exclusion.Release()
		}
		if !host.RemoveServingRuntime(context.WithoutCancel(ctx), *record.Serving, exclusion) || !host.ServingRuntimeAbsent(*record.Serving) {
			return removalInterrupted("Subscription Serving removal")
		}
		report(progress, "Subscription Serving removed")
		if ctx.Err() != nil {
			return removalInterrupted("Managed termination")
		}
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
	input := hostadapter.OperationInput{Operation: operation, Spec: hostSetupSpec}
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

func setupPlan(facts hostadapter.Preflight, selected hostadapter.Destination) []string {
	return []string{
		"Host: Ubuntu 24.04 amd64",
		"Public endpoint: " + facts.PublicIPv4 + ":443",
		"Port preflight: " + facts.PublicIPv4 + ":443 accepted a local bind; SBXR does not claim firewall or provider reachability before setup",
		"REALITY destination: " + selected.Address + " with server_name " + selected.ServerName,
		"Proxy Package Identity: " + proxyPackageIdentity(),
		"APT resources: /etc/apt/keyrings/sagernet.asc and /etc/apt/sources.list.d/sagernet.sources",
		"Protected resources: /etc/sing-box/config.json, /var/lib/sing-box, sing-box.service, and the package-created sing-box user and group",
		"Ownership Record: /var/lib/sbxr/proxy-ownership.json",
		"Identity: one generated Client Identity; no Owner-supplied proxy value is accepted",
		"Secret boundary: the VLESS UUID is disclosed only in an explicitly requested Client Configuration; the REALITY private key is an Infrastructure Secret and is never disclosed",
		"Owned resource groups: exact repository key and source, qualified package and hold, protected configuration and state, service state, and package-created identity",
		"SBXR will not change SSH, firewall, routing, or provider settings. It preserves every unrelated host resource.",
	}
}

func completeRemovalPlan(record *ownershipRecord) []string {
	groups := "No V3 proxy resource is present; SBXR executable and Installed Record only"
	if record != nil {
		groups = "Ownership Record; exact proxy package and hold; protected configuration and state; package-owned service, user, and group; APT source and signing key; SBXR executable and Installed Record"
	}
	plan := []string{
		"Complete removal deletes SBXR, proxy credentials, and every proved V3-owned resource from this VPS.",
		"Proved removal inventory: " + groups + ".",
		"Proved SBXR executable: /usr/local/bin/sbxr",
		"Proved Installed Record: /var/lib/sbxr/installed.json",
		"Outside copies of the Client Configuration cannot be deleted by SBXR.",
		"SBXR preserves SSH, firewall, routing, forwarding, provider settings, shared package-manager state, and every unrelated resource.",
		"There is no adoption, repair, recursive deletion, force path, or Owner override.",
		"Exact confirmation required: REMOVE SBXR",
	}
	if record != nil {
		for _, resource := range record.Resources {
			plan = append(plan, "Proved V3-owned resource: "+resource)
		}
	}
	return plan
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

func removalCorrection(facts hostadapter.RemovalInspection) string {
	checks := []struct {
		fact hostadapter.Observation
		name string
	}{
		{facts.PackageLocks, "Ubuntu package locks"},
		{facts.ConfigurationEntries, "/etc/sing-box directory membership"},
		{facts.StateEntries, "/var/lib/sing-box directory membership"},
		{facts.IdentityExclusive, "sing-box user and group ownership"},
		{facts.ProcessExclusive, "sing-box process identity"},
		{facts.ServiceSafe, "sing-box service, process, and listener state"},
	}
	for _, check := range checks {
		if !check.fact.Observed {
			return "Restore read-only inspection of " + check.name + ", then review Complete removal again."
		}
		if !check.fact.Accepted {
			return "Remove the unproved use or restore the exact proved " + check.name + ", then review Complete removal again."
		}
	}
	return "Restore every changed V3 ownership, package, service, process, listener, directory, and system fact, then review Complete removal again."
}

func removalMismatchDetails(facts hostadapter.RemovalInspection) []string {
	checks := []struct {
		fact       hostadapter.Observation
		mismatch   string
		correction string
		observe    string
	}{
		{facts.PackageLocks, "Ubuntu package locks are in use", "Wait for APT and dpkg to finish, then review Complete removal again.", "Restore safe inspection of every Ubuntu package lock, then inspect again."},
		{facts.ConfigurationEntries, "/etc/sing-box has changed metadata or unexpected directory entries", "Restore the exact root-owned mode-0755 directory containing only config.json, then inspect again.", "Restore read-only directory and metadata inspection of /etc/sing-box, then inspect again."},
		{facts.StateEntries, "/var/lib/sing-box has changed metadata or unexpected directory entries", "Remove only unproved entries after preserving Owner data, and restore the exact empty package-owned native systemd mode-0755 state directory, then inspect again.", "Restore read-only directory and metadata inspection of /var/lib/sing-box, then inspect again."},
		{facts.IdentityExclusive, "the sing-box user or group owns resources outside the proved V3 paths", "Reassign or preserve every outside resource before reviewing Complete removal again.", "Restore complete local ownership inspection for the sing-box user and group, then inspect again."},
		{facts.ProcessExclusive, "the sing-box user, group, or process name is used by an outside process", "Stop or reassign only the outside process after proving its ownership, then inspect again.", "Restore complete process inspection for the sing-box user, group, and process name, then inspect again."},
		{facts.ServiceSafe, "the service, process, or TCP 443 listener is neither exact Running state nor a harmless stopped reduction", "Stop the outside process or listener, or restore the exact package-owned sing-box service, then inspect again.", "Restore systemd, process, and TCP 443 listener inspection, then inspect again."},
	}
	var details []string
	for _, check := range checks {
		if !check.fact.Observed {
			details = append(details, "Detected mismatch: the Complete removal fact could not be inspected", "Safe correction: "+check.observe)
		} else if !check.fact.Accepted {
			details = append(details, "Detected mismatch: "+check.mismatch, "Safe correction: "+check.correction)
		}
	}
	return details
}

func proxyPackageIdentity() string {
	return fmt.Sprintf("https://deb.sagernet.org/; signing-key bytes SHA-256 %s; %s %s %s; DEB %d bytes; DEB SHA-256 %s", hostSetupSpec.APTKeySHA256, hostSetupSpec.PackageName, hostSetupSpec.PackageVersion, hostSetupSpec.Architecture, hostSetupSpec.PackageSize, hostSetupSpec.PackageSHA256)
}

func refused(status Status, failed, correction string) Result {
	return Result{Status: status, Message: "The requested action was refused. View details for the failed check and correction.", Code: ActionRefused, FailedCheck: failed, Correction: correction}
}

func samePreflight(left, right hostadapter.Preflight) bool {
	return reflect.DeepEqual(left, right)
}

func newOwnershipRecord(release softwarelifecycle.ReleaseIdentity, facts hostadapter.Preflight, destination hostadapter.Destination, configuration []byte) ownershipRecord {
	digest := sha256.Sum256(configuration)
	return ownershipRecord{
		Schema: 1, Phase: ownershipRecorded, Direction: cleanupRequired, Release: release,
		Package:    "https://deb.sagernet.org/ sing-box 1.13.19 amd64 24597120 fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf",
		PublicIPv4: facts.PublicIPv4, DestinationAddress: destination.Address, DestinationName: destination.ServerName,
		ConfigurationSHA256: hex.EncodeToString(digest[:]),
		Resources:           ownershipResources(hex.EncodeToString(digest[:])),
	}
}

func ownershipBytes(record ownershipRecord) []byte {
	body, _ := json.Marshal(record)
	return append(body, '\n')
}

func newRemovalOwnershipRecord(release softwarelifecycle.ReleaseIdentity) ownershipRecord {
	return ownershipRecord{
		Schema: 1, Phase: removalCommitted, Direction: removalRequired, Release: release,
		Resources: []string{
			"/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-1",
			finalOwnershipPath + " root:root 0600 one-link finalization authority",
			"/usr/local/bin/sbxr exact committed Release Identity",
			"/var/lib/sbxr/installed.json exact committed Release Identity",
		},
	}
}

func decodeOwnership(body []byte) (ownershipRecord, bool) {
	if len(body) > 64<<10 || softwarelifecycle.ValidateUniqueJSON(body) != nil {
		return ownershipRecord{}, false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return ownershipRecord{}, false
	}
	for _, name := range []string{"schema", "phase", "unfinished_direction", "release_identity", "proxy_package_identity", "public_ipv4", "destination_address", "destination_server_name", "configuration_sha256", "permitted_resources", "cleanup_checkpoint", "removal_checkpoint"} {
		if len(fields[name]) == 0 {
			return ownershipRecord{}, false
		}
	}
	for name, value := range fields {
		if !slices.Contains([]string{"schema", "phase", "unfinished_direction", "release_identity", "proxy_package_identity", "public_ipv4", "destination_address", "destination_server_name", "configuration_sha256", "permitted_resources", "cleanup_checkpoint", "removal_checkpoint", "resource_creating_releases", "finishing_release_identity", "serving"}, name) {
			return ownershipRecord{}, false
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ownershipRecord{}, false
		}
	}
	if raw, exists := fields["serving"]; exists {
		var serving map[string]json.RawMessage
		var hashes []string
		if json.Unmarshal(raw, &serving) != nil || len(serving) != 4 || json.Unmarshal(serving["certificate_sha256"], &hashes) != nil || len(hashes) != 4 {
			return ownershipRecord{}, false
		}
		for _, name := range []string{"link_id", "credential_sha256", "certificate_generation", "certificate_sha256"} {
			if len(serving[name]) == 0 || bytes.Equal(bytes.TrimSpace(serving[name]), []byte("null")) {
				return ownershipRecord{}, false
			}
		}
	}
	if !exactIdentityFields(fields["release_identity"]) {
		return ownershipRecord{}, false
	}
	if finishing, exists := fields["finishing_release_identity"]; exists && !exactIdentityFields(finishing) {
		return ownershipRecord{}, false
	}
	if origins, exists := fields["resource_creating_releases"]; exists {
		var identities []json.RawMessage
		if json.Unmarshal(origins, &identities) != nil {
			return ownershipRecord{}, false
		}
		for _, identity := range identities {
			if !exactIdentityFields(identity) {
				return ownershipRecord{}, false
			}
		}
	}
	var record ownershipRecord
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !validOwnership(record) {
		return ownershipRecord{}, false
	}
	return record, true
}

func exactIdentityFields(body []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || len(fields) != 4 {
		return false
	}
	for _, name := range []string{"Repository", "Tag", "Commit", "IndexSHA256"} {
		var value string
		if json.Unmarshal(fields[name], &value) != nil || value == "" {
			return false
		}
	}
	return true
}

func validOwnership(record ownershipRecord) bool {
	if record.Schema != 1 && record.Schema != 2 || !validReleaseIdentity(record.Release) {
		return false
	}
	if record.Schema == 1 {
		if record.ResourceCreatingReleases != nil || record.FinishingRelease != nil || record.Serving != nil {
			return false
		}
	} else {
		if len(record.ResourceCreatingReleases) != len(record.Resources) {
			return false
		}
		for _, release := range record.ResourceCreatingReleases {
			if !validReleaseIdentity(release) {
				return false
			}
		}
		if record.Direction == removalRequired {
			if record.FinishingRelease == nil || !validReleaseIdentity(*record.FinishingRelease) {
				return false
			}
		} else if record.Phase != runningPhase || record.Direction != noDirection || record.FinishingRelease != nil {
			return false
		}
	}
	if record.Serving != nil && (!record.Serving.Valid() || record.Package == "" || record.Phase != runningPhase && record.Phase != removalCommitted) {
		return false
	}
	if record.Direction == removalRequired {
		if record.Phase != removalCommitted || record.CleanupCheckpoint != 0 || record.RemovalCheckpoint < 0 || record.RemovalCheckpoint > removalCheckpointLimit(record) {
			return false
		}
		if record.Package == "" {
			return record.PublicIPv4 == "" && record.DestinationAddress == "" && record.DestinationName == "" && record.ConfigurationSHA256 == "" && slices.Equal(record.Resources, recordResources(record, true))
		}
		return validOwnedProxyFields(record)
	}
	if !validPhase(record.Phase) || record.Direction != cleanupRequired && record.Direction != setupRequired && record.Direction != noDirection || record.CleanupCheckpoint < 0 || record.CleanupCheckpoint > 8 || record.RemovalCheckpoint != 0 || record.Direction != cleanupRequired && record.CleanupCheckpoint != 0 || !validOwnedProxyFields(record) {
		return false
	}
	if record.Phase == runningPhase && record.Direction != noDirection || phaseAtOrAfter(record.Phase, activationCommitted) && record.Phase != runningPhase && record.Direction != setupRequired || !phaseAtOrAfter(record.Phase, activationCommitted) && record.Direction != cleanupRequired {
		return false
	}
	return true
}

// Schema 2 supports the original proxy footprint and the fixed serving-only
// footprint. Pending capability operations remain unsupported.
func recordResources(record ownershipRecord, softwareOnly bool) []string {
	resources := ownershipResources(record.ConfigurationSHA256)
	if softwareOnly {
		resources = newRemovalOwnershipRecord(record.Release).Resources
	}
	if record.Schema == 2 {
		resources[0] = "/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-2"
	}
	if record.Serving != nil {
		resources = append(resources, record.Serving.Resources()...)
	}
	return resources
}

// This exact prior creator is supported only for its validated original proxy
// contract. This is not update-source qualification or arbitrary V3 admission.
var legacyProxyCreator = softwarelifecycle.ReleaseIdentity{
	Repository: softwarelifecycle.Repository, Tag: "v3.0.21",
	Commit:      "989094b9766f02bf17510a71753c6a5c736bf120",
	IndexSHA256: "90463aa73a2c81542b44ea833c762bb2cd44d2d585fb7bd322279f678feea331",
}

func compatibleOwnership(record ownershipRecord, installed softwarelifecycle.ReleaseIdentity) bool {
	if !validOwnership(record) || !validReleaseIdentity(installed) {
		return false
	}
	if record.Direction == removalRequired {
		return finishingRelease(record) == installed
	}
	if record.Phase != runningPhase {
		return record.Schema == 1 && record.Release == installed
	}
	if record.Release != installed && record.Release != legacyProxyCreator {
		return false
	}
	for _, creator := range record.ResourceCreatingReleases {
		if creator != installed && creator != legacyProxyCreator {
			return false
		}
	}
	return true
}

func finishingRelease(record ownershipRecord) softwarelifecycle.ReleaseIdentity {
	if record.Schema == 2 && record.FinishingRelease != nil {
		return *record.FinishingRelease
	}
	return record.Release
}

func removalAuthority(record ownershipRecord, installed softwarelifecycle.ReleaseIdentity) ownershipRecord {
	if record.Schema == 1 {
		record.Schema = 2
		record.Resources = recordResources(record, record.Package == "")
		record.ResourceCreatingReleases = make([]softwarelifecycle.ReleaseIdentity, len(record.Resources))
		for i := range record.ResourceCreatingReleases {
			record.ResourceCreatingReleases[i] = record.Release
		}
	}
	record.FinishingRelease = &installed
	return record
}

func removalCheckpointLimit(record ownershipRecord) int {
	if record.Package == "" {
		return 3
	}
	return 11
}

func validOwnedProxyFields(record ownershipRecord) bool {
	if record.Package != "https://deb.sagernet.org/ sing-box 1.13.19 amd64 24597120 fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf" || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(record.ConfigurationSHA256) || !slices.Equal(record.Resources, recordResources(record, false)) {
		return false
	}
	_, acceptedDestination := acceptedDestination(record.DestinationAddress, record.DestinationName)
	ip, ipErr := netip.ParseAddr(record.PublicIPv4)
	return ipErr == nil && isPublicIPv4(ip) && acceptedDestination
}

func validReleaseIdentity(release softwarelifecycle.ReleaseIdentity) bool {
	return release.Repository == softwarelifecycle.Repository && regexp.MustCompile(`^v[1-9][0-9]*\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`).MatchString(release.Tag) && regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(release.Commit) && regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(release.IndexSHA256)
}

func ownershipResources(configurationDigest string) []string {
	return []string{
		"/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-1",
		finalOwnershipPath + " root:root 0600 one-link finalization authority",
		"/var/lib/sbxr/.proxy-ownership.json.next root:root 0600 one-link transaction material",
		"/var/lib/sbxr/sing-box_1.13.19_amd64.deb root-owned one-link verified package artifact",
		"/etc/apt/keyrings/sagernet.asc sha256:803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1",
		"/etc/apt/keyrings/sagernet.asc.sbxr-next root-owned transaction material",
		"/etc/apt/sources.list.d/sagernet.sources https://deb.sagernet.org/ signed-by sagernet.asc",
		"/etc/apt/sources.list.d/sagernet.sources.sbxr-next root-owned transaction material",
		"sing-box package 1.13.19 amd64 deb-sha256:fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf",
		"sing-box package hold",
		"/etc/sing-box/config.json sha256:" + configurationDigest,
		"/var/lib/sing-box package state",
		"sing-box.service package provenance stopped-disabled-before-commit",
		"sing-box package-created user and group",
		"tcp/443 local listener",
	}
}

func acceptedDestination(address, name string) (hostadapter.Destination, bool) {
	for _, destination := range destinations {
		if destination.Address == address && destination.ServerName == name {
			return destination, true
		}
	}
	return hostadapter.Destination{}, false
}

func validPhase(phase setupPhase) bool {
	return slices.Contains([]setupPhase{ownershipRecorded, aptKeyInstalled, aptSourceInstalled, serviceMasked, packageInstalled, packageHeld, stateDirectoryCreated, configurationInstalled, configurationValidated, serviceUnmasked, activationCommitted, serviceEnabled, serviceStarted, runningPhase}, phase)
}

func phaseAtOrAfter(phase, boundary setupPhase) bool {
	order := []setupPhase{ownershipRecorded, aptKeyInstalled, aptSourceInstalled, serviceMasked, packageInstalled, packageHeld, stateDirectoryCreated, configurationInstalled, configurationValidated, serviceUnmasked, activationCommitted, serviceEnabled, serviceStarted, runningPhase}
	return slices.Index(order, phase) >= slices.Index(order, boundary)
}

func runningAccepted(facts hostadapter.RunningInspection) bool {
	return all(facts.Host, facts.PublicIPv4Matches, facts.ServiceEnabled, facts.ServiceActive, facts.Listener).Accepted && ownedFactsAccepted(facts)
}

func ownedFactsAccepted(facts hostadapter.RunningInspection) bool {
	return all(facts.Ownership, facts.TransactionFilesAbsent, facts.APTKey, facts.APTSource, facts.Package, facts.Hold, facts.PackageIdentity, facts.Configuration, facts.State, facts.Validation, facts.ServiceProvenance).Accepted
}

func report(progress ProgressReporter, phase string) {
	if progress != nil {
		progress(Progress{Phase: phase})
	}
}
