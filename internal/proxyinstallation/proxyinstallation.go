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
	NotSetUp         Status = "Not set up"
	Running          Status = "Running"
	ChangeInProgress Status = "Change in progress"
	SetupIncomplete  Status = "Setup incomplete"
	ProblemDetected  Status = "Problem detected"
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
)

type Confirmation uint8

const (
	Declined Confirmation = iota + 1
	Approved
)

type ResultCode string

const (
	StatusNotSetUp         ResultCode = "PROXY-INSTALLATION-STATUS-NOT-SET-UP"
	StatusProblemDetected  ResultCode = "PROXY-INSTALLATION-STATUS-PROBLEM-DETECTED"
	StatusChangeInProgress ResultCode = "PROXY-INSTALLATION-STATUS-CHANGE-IN-PROGRESS"
	ActionCancelled        ResultCode = "PROXY-INSTALLATION-ACTION-CANCELLED"
	ActionRefused          ResultCode = "PROXY-INSTALLATION-ACTION-REFUSED"
	SetupComplete          ResultCode = "PROXY-INSTALLATION-SETUP-COMPLETE"
	SetupNeedsCleanup      ResultCode = "PROXY-INSTALLATION-SETUP-CLEANUP-REQUIRED"
	SetupNeedsCompletion   ResultCode = "PROXY-INSTALLATION-SETUP-COMPLETION-REQUIRED"
	SetupCleanedUp         ResultCode = "PROXY-INSTALLATION-SETUP-CLEANED-UP"
)

type Result struct {
	Status      Status
	Message     string
	Code        ResultCode
	FailedCheck string
	Correction  string
}

type PreparedAction struct{ token [32]byte }

type Review struct {
	Version      string
	Status       Status
	LegalActions []Action
	Details      []string
	Plan         []string
	Result       Result
	Prepared     *PreparedAction
}

type Progress struct {
	Phase string
}

type ProgressReporter func(Progress)

type Interface interface {
	Review(context.Context, Action) Review
	Execute(context.Context, PreparedAction, Confirmation, ProgressReporter) Result
}

type hostInterface interface {
	Inspect(context.Context, []hostadapter.Resource) hostadapter.Inspection
	Preflight(context.Context, []hostadapter.Resource, []hostadapter.Destination) hostadapter.Preflight
	ReadOwnership(string) ([]byte, error)
	MutationInProgress(string) (bool, bool)
	PublishOwnership(string, string, []byte, []byte) error
	RemoveOwnership(string, string, []byte) error
	AcquireMutationLock(string) (*hostadapter.MutationLock, bool, error)
	Apply(context.Context, hostadapter.OperationInput) hostadapter.OperationResult
	InspectActivation(context.Context, hostadapter.SetupSpec, []byte, []byte, string, string, hostadapter.Destination) hostadapter.ActivationInspection
	InspectRunning(context.Context, hostadapter.SetupSpec, []byte, []byte, string, string) hostadapter.RunningInspection
}

type singboxInterface interface {
	PrepareIdentity() (singboxadapter.Identity, error)
	ValidIdentity(singboxadapter.Identity) bool
	EncodeServerConfiguration(singboxadapter.Identity, string, string) ([]byte, error)
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
	generation uint64
	action     Action
	status     Status
	release    softwarelifecycle.ReleaseIdentity
	facts      hostadapter.Preflight
	identity   singboxadapter.Identity
	record     []byte
	inspection hostadapter.Inspection
}

type unfinishedDirection string

const (
	cleanupRequired unfinishedDirection = "cleanup required"
	setupRequired   unfinishedDirection = "setup required"
	noDirection     unfinishedDirection = "none"
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
)

type ownershipRecord struct {
	Schema              int                               `json:"schema"`
	Phase               setupPhase                        `json:"phase"`
	Direction           unfinishedDirection               `json:"unfinished_direction"`
	Release             softwarelifecycle.ReleaseIdentity `json:"release_identity"`
	Package             string                            `json:"proxy_package_identity"`
	PublicIPv4          string                            `json:"public_ipv4"`
	DestinationAddress  string                            `json:"destination_address"`
	DestinationName     string                            `json:"destination_server_name"`
	ConfigurationSHA256 string                            `json:"configuration_sha256"`
	Resources           []string                          `json:"permitted_resources"`
	CleanupCheckpoint   int                               `json:"cleanup_checkpoint"`
}

var destinations = []hostadapter.Destination{
	{Address: "microsoft.com:443", ServerName: "microsoft.com"},
	{Address: "www.apple.com:443", ServerName: "www.apple.com"},
	{Address: "cloudflare.com:443", ServerName: "cloudflare.com"},
}

var aptSourceBody = []byte("Types: deb\nURIs: https://deb.sagernet.org/\nSuites: *\nComponents: *\nSigned-By: /etc/apt/keyrings/sagernet.asc\n")

var hostSetupSpec = hostadapter.SetupSpec{
	OwnershipPath: "/var/lib/sbxr/proxy-ownership.json", OwnershipNextPath: "/var/lib/sbxr/.proxy-ownership.json.next", LockPath: "/run/lock/sbxr.lock",
	PackageArtifactPath: "/var/lib/sbxr/sing-box_1.13.19_amd64.deb",
	APTKeyPath:          "/etc/apt/keyrings/sagernet.asc", APTKeyURL: "https://sing-box.app/gpg.key", APTKeySHA256: "803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1",
	APTSourcePath: "/etc/apt/sources.list.d/sagernet.sources",
	PackageName:   "sing-box", PackageVersion: "1.13.19", Architecture: "amd64", PackageSize: 24597120, PackageSHA256: "fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf",
	ConfigurationPath: "/etc/sing-box/config.json", StatePath: "/var/lib/sing-box", Service: "sing-box.service", ServiceUnitPath: "/lib/systemd/system/sing-box.service",
	User: "sing-box", Group: "sing-box", ListenerPort: "443",
}

var footprint = []hostadapter.Resource{
	{Kind: hostadapter.PathResource, Name: "/var/lib/sbxr/proxy-ownership.json"},
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
				return review
			}
			return ownershipProblem(review, installed, installedReady, "The shared mutation lock is invalid or unsafe.")
		}
		body, err := module.host.ReadOwnership(hostSetupSpec.OwnershipPath)
		if err == nil {
			record, ok := decodeOwnership(body)
			if !ok {
				return ownershipProblem(review, installed, installedReady, "The Ownership Record is invalid or unsafe.")
			}
			return module.reviewOwned(ctx, action, review, record, body, installed, installedReady)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return ownershipProblem(review, installed, installedReady, "The Ownership Record cannot be safely inspected.")
		}
	}
	inspection := hostadapter.Inspection{}
	if module.host != nil {
		inspection = module.host.Inspect(ctx, slices.Clone(footprint))
	}
	review.Details = inspectionDetails(installed, installedReady, NotSetUp, inspection)
	if module.host == nil || module.singbox == nil || !inspectionAccepted(inspection) || resourcesPresent(inspection.Resources) {
		review.Status = ProblemDetected
		review.LegalActions = []Action{ViewDetailsAction, CompleteRemovalAction}
		review.Result = Result{Status: ProblemDetected, Message: "A proxy problem was detected. View details before continuing.", Code: StatusProblemDetected}
		review.Details = inspectionDetails(installed, installedReady, ProblemDetected, inspection)
		switch action {
		case StatusAction, ViewDetailsAction:
			return review
		case CompleteRemovalAction:
			review.Result = refused(ProblemDetected, "Complete removal availability", "Use an SBXR release that implements reviewed V3 Complete removal.")
		default:
			review.Result = refused(ProblemDetected, "Legal action", "Choose one of the actions legal for the freshly inspected Proxy Installation Status.")
		}
		return review
	}
	switch action {
	case StatusAction, ViewDetailsAction:
		return review
	case CompleteRemovalAction:
		review.Result = refused(NotSetUp, "Complete removal availability", "Use an SBXR release that implements reviewed V3 Complete removal.")
		return review
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
	if !installedReady || record.Release != installed {
		return ownershipProblem(review, installed, installedReady, "The Ownership Record does not match the active SBXR Release Identity.")
	}
	review.Status = SetupIncomplete
	review.Result = Result{Status: SetupIncomplete, Message: "Proxy setup was interrupted and must be finished safely.", Code: SetupNeedsCleanup}
	review.LegalActions = []Action{FinishCleanupAction, ViewDetailsAction}
	if phaseAtOrAfter(record.Phase, activationCommitted) {
		review.Result.Code = SetupNeedsCompletion
		review.LegalActions = []Action{FinishSetupAction, ViewDetailsAction}
	}
	inspection := hostadapter.Inspection{}
	if record.Phase == runningPhase {
		facts := module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
		if runningAccepted(facts) {
			review.Status = Running
			review.Result = Result{Status: Running, Message: "Proxy setup is complete and locally verified.", Code: SetupComplete}
			review.LegalActions = []Action{ViewDetailsAction, CompleteRemovalAction}
		} else {
			return ownershipProblem(review, installed, installedReady, "The locally Running facts no longer match the Ownership Record.")
		}
	} else {
		inspection = module.host.Inspect(ctx, slices.Clone(footprint))
		if !inspectionAccepted(inspection) {
			return ownershipProblem(review, installed, installedReady, "The owned proxy footprint could not be freshly inspected.")
		}
	}
	review.Details = ownedDetails(installed, installedReady, review.Status, record)
	if action == StatusAction || action == ViewDetailsAction {
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

func ownershipProblem(review Review, installed softwarelifecycle.ReleaseIdentity, installedReady bool, detail string) Review {
	review.Status = ProblemDetected
	review.LegalActions = []Action{ViewDetailsAction}
	review.Result = Result{Status: ProblemDetected, Message: "A proxy problem was detected. View details before continuing.", Code: StatusProblemDetected}
	review.Details = []string{detail, "Safe correction: Restore the exact root-owned Ownership Record or use a qualified recovery procedure."}
	if installedReady {
		review.Version = installed.Tag
	}
	return review
}

func ownedDetails(installed softwarelifecycle.ReleaseIdentity, installedReady bool, status Status, record ownershipRecord) []string {
	version, release := "Unavailable", "Unavailable"
	if installedReady {
		version = installed.Tag
		release = fmt.Sprintf("%s %s %s %s", installed.Repository, installed.Tag, installed.Commit, installed.IndexSHA256)
	}
	return []string{
		"SBXR version: " + version,
		"Release Identity: " + release,
		"Proxy Installation Status: " + string(status),
		"Current setup phase: " + string(record.Phase),
		"Required unfinished direction: " + string(record.Direction),
		"Ownership Record: Present and verified",
		"Running is local VPS truth only; outside-client traffic is not claimed.",
	}
}

func inspectionDetails(installed softwarelifecycle.ReleaseIdentity, installedReady bool, status Status, inspection hostadapter.Inspection) []string {
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
	details := []string{
		"SBXR version: " + version,
		"Release Identity: " + identity,
		"Proxy Installation Status: " + string(status),
		"Required unfinished direction: None",
		"Ownership Record: " + ownership,
		"Client Identity: Absent",
	}
	for _, resource := range inspection.Resources {
		if !resource.Observed {
			details = append(details, "Detected mismatch: "+resource.Name+" could not be inspected")
		} else if resource.Present {
			details = append(details, "Detected mismatch: "+resource.Name+" is present")
		}
	}
	if status == ProblemDetected {
		return append(details, "Safe correction: Remove or restore every conflicting proxy resource, then inspect again.")
	}
	return append(details, "Safe correction: None")
}

func (module *installedInterface) Execute(ctx context.Context, prepared PreparedAction, confirmation Confirmation, progress ProgressReporter) Result {
	module.mu.Lock()
	defer module.mu.Unlock()
	authority, ok := module.prepared[prepared.token]
	delete(module.prepared, prepared.token)
	if !ok || authority.generation != module.generation {
		return refused(NotSetUp, "Prepared Action", "Review the action again and use only the new Prepared Action.")
	}
	if confirmation == Declined {
		return Result{Status: authority.status, Message: "No changes were made.", Code: ActionCancelled}
	}
	if confirmation != Approved || module.lifecycle == nil || module.host == nil || module.singbox == nil {
		return refused(authority.status, "Prepared Action", "Review the action again and use only the new Prepared Action.")
	}
	lock, busy, err := module.host.AcquireMutationLock(hostSetupSpec.LockPath)
	if err != nil || busy {
		return refused(authority.status, "SBXR mutation lock", "Wait for the active SBXR change to finish, then review the action again.")
	}
	defer lock.Release()
	if ctx.Err() != nil {
		return refused(authority.status, "Managed termination", "Review the action again after the current process stops.")
	}
	if authority.action == FinishCleanupAction {
		record, current, ok := module.revalidateFinishingAuthority(context.WithoutCancel(ctx), authority)
		inspection := module.host.Inspect(context.WithoutCancel(ctx), slices.Clone(footprint))
		if !ok || !inspectionAccepted(inspection) || !reflect.DeepEqual(inspection, authority.inspection) {
			return refused(ProblemDetected, "Prepared Action facts", "Review Finish cleanup again after restoring every changed authority fact.")
		}
		return module.cleanup(ctx, record, current, progress)
	}
	if authority.action == FinishSetupAction {
		record, current, ok := module.revalidateFinishingAuthority(context.WithoutCancel(ctx), authority)
		if !ok || !module.setupFactsFresh(context.WithoutCancel(ctx), record, current) {
			return refused(ProblemDetected, "Prepared Action facts", "Review Finish setup again after restoring every changed safety fact.")
		}
		return module.finishSetup(ctx, record, current, progress)
	}
	installed := module.lifecycle.Status(ctx)
	currentFacts := module.host.Preflight(ctx, slices.Clone(footprint), slices.Clone(destinations))
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
		if current, readErr := module.host.ReadOwnership(hostSetupSpec.OwnershipPath); readErr == nil {
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

func (module *installedInterface) revalidateFinishingAuthority(ctx context.Context, authority preparedReview) (ownershipRecord, []byte, bool) {
	current, err := module.host.ReadOwnership(hostSetupSpec.OwnershipPath)
	if err != nil || !bytes.Equal(current, authority.record) {
		return ownershipRecord{}, nil, false
	}
	record, ok := decodeOwnership(current)
	installed := module.lifecycle.Status(ctx)
	return record, current, ok && installed.State == softwarelifecycle.Ready && installed.Installed != nil && *installed.Installed == authority.release && record.Release == authority.release
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
	inactive := !facts.ServiceActive && !facts.Listener && facts.ListenerAvailable
	running := facts.ServiceEnabled && facts.ServiceActive && facts.Listener
	return record.Phase == activationCommitted && (inactive || running) || record.Phase == serviceEnabled && facts.ServiceEnabled && (inactive || running)
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
			if current, readErr := module.host.ReadOwnership(hostSetupSpec.OwnershipPath); readErr == nil {
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
	if facts := module.host.InspectActivation(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4, destination); !ownedFactsAccepted(facts.RunningInspection) || facts.ServiceEnabled || facts.ServiceActive || facts.Listener || !facts.DestinationCompatible || !facts.ListenerAvailable {
		if ctx.Err() != nil {
			return interruptedCleanup()
		}
		return module.cleanup(ctx, record, body, progress)
	}
	record.Phase, record.Direction = activationCommitted, setupRequired
	next := ownershipBytes(record)
	if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, body, next); err != nil {
		if current, readErr := module.host.ReadOwnership(hostSetupSpec.OwnershipPath); readErr == nil {
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
			if current, readErr := module.host.ReadOwnership(hostSetupSpec.OwnershipPath); readErr == nil {
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
		if current, readErr := module.host.ReadOwnership(hostSetupSpec.OwnershipPath); readErr == nil {
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
			if current, readErr := module.host.ReadOwnership(hostSetupSpec.OwnershipPath); readErr == nil {
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

func cleanupSurfaceAccepted(inspection hostadapter.Inspection, ownershipPresent bool) bool {
	if !inspectionAccepted(inspection) {
		return false
	}
	for _, resource := range inspection.Resources {
		expected := ownershipPresent && resource.Name == "/var/lib/sbxr/proxy-ownership.json"
		if resource.Present != expected {
			return false
		}
	}
	return true
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
		"Proxy Package Identity: https://deb.sagernet.org/; signing-key bytes SHA-256 803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1; sing-box 1.13.19 amd64; DEB 24597120 bytes; DEB SHA-256 fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf",
		"APT resources: /etc/apt/keyrings/sagernet.asc and /etc/apt/sources.list.d/sagernet.sources",
		"Protected resources: /etc/sing-box/config.json, /var/lib/sing-box, sing-box.service, and the package-created sing-box user and group",
		"Ownership Record: /var/lib/sbxr/proxy-ownership.json",
		"Identity: one generated Client Identity; no Owner-supplied proxy value is accepted",
		"Secret boundary: the VLESS UUID is disclosed only in an explicitly requested Client Configuration; the REALITY private key is an Infrastructure Secret and is never disclosed",
		"Owned resource groups: exact repository key and source, qualified package and hold, protected configuration and state, service state, and package-created identity",
		"SBXR will not change SSH, firewall, routing, or provider settings. It preserves every unrelated host resource.",
	}
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

func decodeOwnership(body []byte) (ownershipRecord, bool) {
	var record ownershipRecord
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !validOwnership(record) {
		return ownershipRecord{}, false
	}
	return record, true
}

func validOwnership(record ownershipRecord) bool {
	if record.Schema != 1 || !validPhase(record.Phase) || record.Direction != cleanupRequired && record.Direction != setupRequired && record.Direction != noDirection || record.CleanupCheckpoint < 0 || record.CleanupCheckpoint > 8 || record.Direction != cleanupRequired && record.CleanupCheckpoint != 0 || record.Package != "https://deb.sagernet.org/ sing-box 1.13.19 amd64 24597120 fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf" || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(record.ConfigurationSHA256) || !slices.Equal(record.Resources, ownershipResources(record.ConfigurationSHA256)) {
		return false
	}
	if record.Phase == runningPhase && record.Direction != noDirection || phaseAtOrAfter(record.Phase, activationCommitted) && record.Phase != runningPhase && record.Direction != setupRequired || !phaseAtOrAfter(record.Phase, activationCommitted) && record.Direction != cleanupRequired {
		return false
	}
	_, acceptedDestination := acceptedDestination(record.DestinationAddress, record.DestinationName)
	ip, ipErr := netip.ParseAddr(record.PublicIPv4)
	return record.Release.Repository == softwarelifecycle.Repository && regexp.MustCompile(`^v[1-9][0-9]*\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`).MatchString(record.Release.Tag) && regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(record.Release.Commit) && regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(record.Release.IndexSHA256) && ipErr == nil && isPublicIPv4(ip) && acceptedDestination
}

func ownershipResources(configurationDigest string) []string {
	return []string{
		"/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-1",
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
	return ownedFactsAccepted(facts) && facts.ServiceEnabled && facts.ServiceActive && facts.Listener
}

func ownedFactsAccepted(facts hostadapter.RunningInspection) bool {
	return facts.Ownership && facts.TransactionFilesAbsent && facts.APTKey && facts.APTSource && facts.Package && facts.Hold && facts.PackageIdentity && facts.Configuration && facts.State && facts.Validation && facts.ServiceProvenance
}

func report(progress ProgressReporter, phase string) {
	if progress != nil {
		progress(Progress{Phase: phase})
	}
}
