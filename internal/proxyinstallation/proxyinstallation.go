// Package proxyinstallation owns the installed V3 proxy journey.
package proxyinstallation

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sync"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type Status string

const (
	NotSetUp        Status = "Not set up"
	ProblemDetected Status = "Problem detected"
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
	StatusNotSetUp        ResultCode = "PROXY-INSTALLATION-STATUS-NOT-SET-UP"
	StatusProblemDetected ResultCode = "PROXY-INSTALLATION-STATUS-PROBLEM-DETECTED"
	ActionCancelled       ResultCode = "PROXY-INSTALLATION-ACTION-CANCELLED"
	ActionRefused         ResultCode = "PROXY-INSTALLATION-ACTION-REFUSED"
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
}

type singboxInterface interface {
	PrepareIdentity() (singboxadapter.Identity, error)
	ValidIdentity(singboxadapter.Identity) bool
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
	status     Status
	release    softwarelifecycle.ReleaseIdentity
	facts      hostadapter.Preflight
	identity   singboxadapter.Identity
}

var destinations = []hostadapter.Destination{
	{Address: "microsoft.com:443", ServerName: "microsoft.com"},
	{Address: "www.apple.com:443", ServerName: "www.apple.com"},
	{Address: "cloudflare.com:443", ServerName: "cloudflare.com"},
}

var footprint = []hostadapter.Resource{
	{Kind: hostadapter.PathResource, Name: "/var/lib/sbxr/proxy-ownership.json"},
	{Kind: hostadapter.PathResource, Name: "/etc/apt/sources.list.d/sagernet.sources"},
	{Kind: hostadapter.PathResource, Name: "/etc/apt/keyrings/sagernet.asc"},
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
	module.prepared[token] = preparedReview{generation: module.generation, status: NotSetUp, release: installed, facts: facts, identity: identity}
	review.Prepared = &PreparedAction{token: token}
	review.Plan = setupPlan(facts, selected)
	return review
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

func (module *installedInterface) Execute(ctx context.Context, prepared PreparedAction, confirmation Confirmation, _ ProgressReporter) Result {
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
	installed := module.lifecycle.Status(ctx)
	currentFacts := module.host.Preflight(ctx, slices.Clone(footprint), slices.Clone(destinations))
	if installed.State != softwarelifecycle.Ready || installed.Installed == nil || *installed.Installed != authority.release || !samePreflight(authority.facts, currentFacts) || !module.singbox.ValidIdentity(authority.identity) {
		return refused(authority.status, "Prepared Action facts", "Review the action again after restoring every changed safety fact.")
	}
	// ponytail: issue #298 stops before mutation; issue #299 replaces this refusal with the approved setup path.
	return refused(authority.status, "Approved setup", "Use an SBXR release that implements approved V3 setup.")
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
