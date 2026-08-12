// Package networkpolicy evaluates one complete network baseline without changing the host.
package networkpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
)

type Baseline string

const (
	Clean   Baseline = "Clean VPS"
	Managed Baseline = "Managed"
)

type Stage string

const (
	PreApproval  Stage = "pre-approval"
	PostApproval Stage = "post-approval"
)

type Classification string

const (
	Required Classification = "Required"
	Advisory Classification = "Advisory"
)

type Outcome string

const (
	Healthy        Outcome = "Healthy"
	NeedsAttention Outcome = "Needs attention"
	Failed         Outcome = "Failed"
	Unknown        Outcome = "Unknown"
)

type Protocol string

const (
	TCP Protocol = "TCP"
	UDP Protocol = "UDP"
)

type Intent struct {
	Revision                   uint64
	Baseline                   Baseline
	PublicIPv4                 string
	PublicIPv6                 string
	PrimarySubscriptionAddress string
	CertificateHostname        string
	SSHPort                    uint16
	Profiles                   Profiles
	SubscriptionPort           uint16
	TemporaryHTTP              bool
	Disk                       DiskRequirement
}

func (i Intent) SelectedPorts() []uint16 {
	ports := []uint16{i.SSHPort}
	for _, profile := range profileDefinitions(i) {
		ports = append(ports, profile.profile.Port)
	}
	return ports
}

type Profiles struct {
	VLESSRealityVision Profile
	VLESSXHTTP         Profile
	VLESSWebSocket     Profile
	Hysteria2          Profile
	TUIC               Profile
	AnyTLS             Profile
}

type Profile struct {
	Enabled bool
	Address string
	Port    uint16
}

type DiskRequirement struct {
	PreparationBytes uint64
	TemporaryBytes   uint64
	SnapshotBytes    uint64
	JournalBytes     uint64
	RollbackBytes    uint64
	OverheadBytes    uint64
}

func (d DiskRequirement) Total() uint64 {
	return d.PreparationBytes + d.TemporaryBytes + d.SnapshotBytes + d.JournalBytes + d.RollbackBytes + d.OverheadBytes
}

type ObservationRequest struct {
	Intent            Intent
	Stage             Stage
	Scope             ObservationScope
	ReclamationReview bool
}

type ObservationScope string

const (
	LocalObservations    ObservationScope = "local"
	ExternalObservations ObservationScope = "external"
)

type Adapter interface {
	Observe(ObservationRequest) (Observations, error)
}

type Observations struct {
	Host                HostFacts
	Lineage             LineageState
	PublicIPv4          []string
	PublicIPv6          []string
	Listeners           []Listener
	ServiceIdentities   []string
	ResourcePaths       []string
	SSH                 SSHFacts
	Firewall            FirewallFacts
	Routes              RouteFacts
	Outbound            OutboundFacts
	Disk                DiskFacts
	Time                TimeFacts
	OwnerFacts          OwnerFacts
	Certificate         CertificateFacts
	LocalProofs         []LocalProof
	Checksums           map[string]string
	Ephemeral           PortRange
	PortCandidates      []PortCandidate
	Reclamation         ReclamationFacts
	ReclamationComplete bool
}

type InstallationClass string

const (
	CleanVPS         InstallationClass = "Clean VPS"
	ReclaimableVPS   InstallationClass = "Reclaimable VPS"
	ContradictoryVPS InstallationClass = "contradictory lineage"
	UnsupportedHost  InstallationClass = "unsupported host"
)

type ReclamationFacts struct {
	Packages       []PackageConflict
	Identities     []IdentityConflict
	Executables    []FileConflict
	Scripts        []ScriptConflict
	UnsafePaths    []string
	ProtectedPaths []string
	Docker         *DockerConflict
}

type PackageConflict struct {
	Name, Version, Owns string
	OwnedPaths          []string
}
type IdentityConflict struct {
	Name, Kind string
	Exclusive  bool
}
type FileConflict struct {
	Path, SHA256, Process, Service, Package string
	OwnerUID                                uint32
	Mode                                    uint32
	Links                                   uint64
	Mount                                   bool
}
type ScriptConflict struct {
	Interpreter, Path, SHA256, Process, Service string
	Links                                       uint64
	Mount                                       bool
}
type DockerConflict struct {
	Service, Status         string
	Packages, PreservedData []string
}

type ProtectedHostFoundation struct {
	Version uint16
	Paths   []string
}

type ReclamationPlan struct {
	Digest, Classification                   string
	Targets, Preservation, PermanentWarnings []string
	Interruption, Cancellation, Rollback     string
}

type PortRange struct {
	First uint16
	Last  uint16
}

type PortCandidate struct {
	Port          uint16
	Protocol      Protocol
	Address       string
	BindProven    bool
	Cryptographic bool
}

type LineageState string

const (
	ProvenLineage        LineageState = "proven"
	ContradictoryLineage LineageState = "contradictory"
)

type HostFacts struct {
	UbuntuVersion  string
	UbuntuServer   bool
	Architecture   string
	Systemd        bool
	LogicalCPUs    int
	PhysicalRAM    uint64
	Virtualization string
}

type Listener struct {
	Address    string
	Port       uint16
	Protocol   Protocol
	Process    string
	Service    string
	Ownership  Ownership
	Executable string
}

type Ownership string

const (
	Unproved  Ownership = "unproved"
	SBXROwned Ownership = "SBXR-owned"
)

type SSHFacts struct {
	DetectedPort    uint16
	ServerAddress   string
	CurrentSessions []string
}

type FirewallFacts struct {
	ActiveManager  string
	UnexpectedRule string
	SBXRTableState string
	RootVerified   bool
}

type RouteFacts struct {
	IPv4 string
	IPv6 string
}

type OutboundFacts struct {
	DNS                       bool
	GitHubHTTPS               bool
	GitHubAttestationHTTPS    bool
	CloudflareHTTPS           bool
	ACMEHTTPS                 bool
	CertificateEndpointsHTTPS bool
	TimeService               bool
	TunnelTCP7844             bool
	TunnelUDP7844             bool
}

type DiskFacts struct {
	FilesystemBytes uint64
	AvailableBytes  uint64
}

type TimeFacts struct {
	Synchronized bool
	Owner        string
}

type OwnerFacts struct {
	DNS       string
	Tunnel    string
	Routes    []CloudflareRoute
	Conflicts []CloudflareConflict
}

type CloudflareConflict struct{ Kind, ID, Name string }

type CloudflareRoute struct {
	Profile       string
	OriginAddress string
	OriginPort    uint16
	Protocol      Protocol
	Connected     bool
}

const UnprovedResource = "unproved"

type Request struct {
	Intent            Intent
	Stage             Stage
	Managed           ManagedProof
	OwnerFacts        OwnerFacts
	Certificate       CertificateFacts
	Outside           OutsideFacts
	RelevantChecksums map[string]string
	ReclamationReview bool
}

type ProofStatus string

const (
	ProofPassed  ProofStatus = "Passed"
	ProofFailed  ProofStatus = "Failed"
	ProofPending ProofStatus = "Pending"
)

type OutsideProof struct {
	Purpose  string
	Address  string
	Port     uint16
	Protocol Protocol
	Status   ProofStatus
}

type LocalProof struct {
	Purpose              string
	Address              string
	Port                 uint16
	Protocol             Protocol
	RouteMatches         bool
	ConfigurationMatches bool
}

type OutsideFacts struct {
	HTTP01 ProofStatus
	Direct []OutsideProof
}

type DNSRecordType string

const (
	CNAME DNSRecordType = "CNAME"
	NS    DNSRecordType = "NS"
	TXT   DNSRecordType = "TXT"
)

type DNSRecord struct {
	Name string
	Type DNSRecordType
}

type DNSFacts struct {
	Hostname         string
	IPv4             []string
	IPv6             []string
	ChallengeRecords []DNSRecord
}

type CAAFacts struct {
	Issuer        string
	HTTP01Allowed bool
}

type CertificateFacts struct {
	DNS DNSFacts
	CAA CAAFacts
}

type ManagedProof struct {
	Lineage        LineageState
	Listeners      []ListenerProof
	NftablesSHA256 string
}

type ListenerProof struct {
	Address  string
	Port     uint16
	Protocol Protocol
	Process  string
	Service  string
}

type Result struct {
	Baseline              Baseline
	InstallationClass     InstallationClass
	Reclamation           *ReclamationPlan
	ProtectedFoundation   ProtectedHostFoundation
	Outcome               Outcome
	Findings              []Finding
	Policy                Policy
	SystemChanges         SystemChangesRequirements
	SSHSafety             SSHSafety
	CompleteRemoval       CompleteRemoval
	Certificate           CertificatePolicy
	CertificateRetry      *CertificateRetryHandoff
	Reachability          []ReachabilityProof
	ProviderGuidance      []ProviderGuidance
	SameVPSProvesOutside  bool
	Renewal               RenewalFreshness
	Binding               Binding
	PreApplyGates         []Gate
	PostApplyGates        []Gate
	Bounds                CheckBounds
	CloudflareTunnelPath  CloudflareTunnelPath
	portCorrection        *portCorrectionCell
	portCorrectionBinding Binding
	freshInstallation     *freshInstallationProofCell
	freshDNSHostname      string
	intent                Intent
}

// FreshInstallationProof is a one-use, non-renderable Clean VPS proof for
// System Changes. It re-runs the exact Network Policy request when consumed.
type FreshInstallationProof struct{ cell *freshInstallationProofCell }

type freshInstallationProofCell struct {
	evaluate func() Result
	digest   string
	used     atomic.Bool
}

func (FreshInstallationProof) String() string   { return "Network Policy Clean VPS proof: redacted" }
func (FreshInstallationProof) GoString() string { return "Network Policy Clean VPS proof: redacted" }
func (FreshInstallationProof) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("Network Policy Clean VPS proof cannot be rendered")
}

func (result Result) FreshInstallationProof() FreshInstallationProof {
	if result.freshInstallation == nil {
		return FreshInstallationProof{}
	}
	return FreshInstallationProof{cell: &freshInstallationProofCell{evaluate: result.freshInstallation.evaluate, digest: result.freshInstallation.digest}}
}

// CertificateLifecycleFreshDNSPrerequisites exposes only the exact Clean VPS
// hostname, addresses, and already-approved CAA method awaiting Cloudflare.
func (result Result) CertificateLifecycleFreshDNSPrerequisites() (string, []string, bool) {
	if result.freshDNSHostname == "" || !cleanVPSAuthorityEligible(result) {
		return "", nil, false
	}
	addresses := make([]string, 0, 2)
	if result.Policy.PublicIPv4 != "" {
		addresses = append(addresses, result.Policy.PublicIPv4)
	}
	if result.Policy.PublicIPv6 != "" {
		addresses = append(addresses, result.Policy.PublicIPv6)
	}
	return result.freshDNSHostname, addresses, len(addresses) > 0
}

func (result Result) MatchesDesiredState(sshPort uint16, publicIPv4, publicIPv6, primaryAddress string) bool {
	if result.Binding.Digest == "" || result.Outcome == Failed {
		return false
	}
	var observedSSH uint16
	for _, exposure := range result.Policy.Exposures {
		if exposure.Purpose == "SSH preservation" && exposure.Protocol == TCP {
			observedSSH = exposure.Port
		}
	}
	return observedSSH == sshPort && result.Policy.PublicIPv4 == publicIPv4 && result.Policy.PublicIPv6 == publicIPv6 && result.Policy.PrimaryAddress == primaryAddress
}

func (proof FreshInstallationProof) SystemChangesFreshInstallation() bool {
	if proof.cell == nil || proof.cell.evaluate == nil || !proof.cell.used.CompareAndSwap(false, true) {
		return false
	}
	result := proof.cell.evaluate()
	return cleanVPSAuthorityEligible(result) && result.Binding.Digest == proof.cell.digest
}

type PortCorrectionAuthority struct{ cell *portCorrectionCell }

type portCorrectionCell struct {
	purpose, protocol string
	port, candidate   uint16
	used              atomic.Bool
}

func (PortCorrectionAuthority) String() string   { return "Network Policy port correction: redacted" }
func (PortCorrectionAuthority) GoString() string { return "Network Policy port correction: redacted" }
func (PortCorrectionAuthority) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("Network Policy port correction cannot be rendered")
}
func (result Result) PortCorrectionAuthority() PortCorrectionAuthority {
	return PortCorrectionAuthority{cell: result.portCorrection}
}
func (authority PortCorrectionAuthority) ConnectionProfilesPortCorrection() (string, uint16, uint16, string, bool) {
	if authority.cell == nil || !authority.cell.used.CompareAndSwap(false, true) {
		return "", 0, 0, "", false
	}
	return authority.cell.purpose, authority.cell.port, authority.cell.candidate, authority.cell.protocol, true
}
func (result Result) PortCorrectionCandidate() ListenerContribution {
	return listenerContribution(result.portCorrectionBinding)
}

// ListenerContribution is the narrow protocol-aware listener fact consumed by
// Connection Profiles without granting it a dependency on Network Policy.
type ListenerContribution struct {
	realityPort, hysteria2Port, tuicPort, anyTLSPort                 uint16
	realityProtocol, hysteria2Protocol, tuicProtocol, anyTLSProtocol string
	valid, tuicValid, anyTLSValid                                    bool
	registryHealthy                                                  bool
	exposures                                                        []Exposure
	registryRevision                                                 uint64
	registryDigest                                                   string
	freshSelection                                                   bool
}

func NewListenerContribution(result Result) ListenerContribution {
	return listenerContribution(result.Binding)
}

// PrepareProfileEnablement derives one candidate listener authority from a
// freshly healthy Managed result. Only one enablement bit may change; ports,
// addresses, SSH preservation, certificates, and every other intent stay fixed.
func PrepareProfileEnablement(current Result, currentIntent, candidateIntent Intent) (ListenerContribution, string, error) {
	if current.Outcome != Healthy || !current.Binding.approved || currentIntent.Baseline != Managed || candidateIntent.Baseline != Managed || currentIntent.Revision == 0 || candidateIntent.Revision != currentIntent.Revision || !reflect.DeepEqual(current.intent, currentIntent) {
		return ListenerContribution{}, "", fmt.Errorf("current Managed Network Policy is unavailable")
	}
	currentEnabled := []bool{currentIntent.Profiles.VLESSRealityVision.Enabled, currentIntent.Profiles.VLESSXHTTP.Enabled, currentIntent.Profiles.VLESSWebSocket.Enabled, currentIntent.Profiles.Hysteria2.Enabled, currentIntent.Profiles.TUIC.Enabled, currentIntent.Profiles.AnyTLS.Enabled}
	candidateEnabled := []bool{candidateIntent.Profiles.VLESSRealityVision.Enabled, candidateIntent.Profiles.VLESSXHTTP.Enabled, candidateIntent.Profiles.VLESSWebSocket.Enabled, candidateIntent.Profiles.Hysteria2.Enabled, candidateIntent.Profiles.TUIC.Enabled, candidateIntent.Profiles.AnyTLS.Enabled}
	changes := 0
	for index := range currentEnabled {
		if currentEnabled[index] != candidateEnabled[index] {
			changes++
		}
	}
	normalized := candidateIntent
	normalized.Profiles.VLESSRealityVision.Enabled = currentIntent.Profiles.VLESSRealityVision.Enabled
	normalized.Profiles.VLESSXHTTP.Enabled = currentIntent.Profiles.VLESSXHTTP.Enabled
	normalized.Profiles.VLESSWebSocket.Enabled = currentIntent.Profiles.VLESSWebSocket.Enabled
	normalized.Profiles.Hysteria2.Enabled = currentIntent.Profiles.Hysteria2.Enabled
	normalized.Profiles.TUIC.Enabled = currentIntent.Profiles.TUIC.Enabled
	normalized.Profiles.AnyTLS.Enabled = currentIntent.Profiles.AnyTLS.Enabled
	if changes != 1 || !reflect.DeepEqual(normalized, currentIntent) {
		return ListenerContribution{}, "", fmt.Errorf("exactly one Connection Profile enablement may change")
	}
	policy := candidatePolicy(candidateIntent)
	encoded, _ := json.Marshal(struct {
		CurrentDigest string
		Candidate     Intent
		Policy        Policy
	}{current.Binding.digest, candidateIntent, policy})
	digest := sha256.Sum256(encoded)
	checksum := hex.EncodeToString(digest[:])
	binding := Binding{Digest: checksum, policy: policy, baseline: Managed, revision: candidateIntent.Revision, digest: checksum, approved: true}
	return listenerContribution(binding), policy.Nftables, nil
}

func listenerContribution(binding Binding) ListenerContribution {
	contribution := ListenerContribution{registryHealthy: binding.approved, exposures: append([]Exposure(nil), binding.policy.Exposures...), registryRevision: binding.revision, registryDigest: binding.digest, freshSelection: binding.baseline == Clean}
	if !binding.approved {
		return contribution
	}
	for _, exposure := range binding.policy.Exposures {
		switch exposure.Purpose {
		case "VLESS REALITY Vision":
			if exposure.Address == "public" {
				contribution.realityPort, contribution.realityProtocol = exposure.Port, string(exposure.Protocol)
			}
		case "Hysteria2":
			if exposure.Address == "public" {
				contribution.hysteria2Port, contribution.hysteria2Protocol = exposure.Port, string(exposure.Protocol)
			}
		case "TUIC":
			if exposure.Address == "public" {
				contribution.tuicPort, contribution.tuicProtocol = exposure.Port, string(exposure.Protocol)
			}
		case "AnyTLS":
			if exposure.Address == "public" {
				contribution.anyTLSPort, contribution.anyTLSProtocol = exposure.Port, string(exposure.Protocol)
			}
		}
	}
	contribution.valid = contribution.realityPort > 0 && contribution.realityProtocol == "TCP" && contribution.hysteria2Port > 0 && contribution.hysteria2Protocol == "UDP"
	contribution.tuicValid = contribution.valid && contribution.tuicPort > 0 && contribution.tuicProtocol == "UDP"
	contribution.anyTLSValid = contribution.tuicValid && contribution.anyTLSPort > 0 && contribution.anyTLSProtocol == "TCP"
	return contribution
}

func (contribution ListenerContribution) ConnectionProfilesFreshPortSelection() bool {
	return contribution.registryHealthy && contribution.freshSelection
}

func (contribution ListenerContribution) ConnectionProfilesManagedPortSelection() bool {
	return contribution.registryHealthy && !contribution.freshSelection
}

func (contribution ListenerContribution) ConnectionProfilesRegistryBinding() (uint64, string, bool) {
	return contribution.registryRevision, contribution.registryDigest, contribution.registryHealthy && contribution.registryRevision > 0 && len(contribution.registryDigest) == 64
}

func (contribution ListenerContribution) registryExposure(purpose string) (string, uint16, string, bool, bool) {
	for _, exposure := range contribution.exposures {
		if exposure.Purpose == purpose {
			return exposure.Address, exposure.Port, string(exposure.Protocol), true, contribution.registryHealthy
		}
	}
	return "", 0, "", false, contribution.registryHealthy
}

func (contribution ListenerContribution) ConnectionProfilesRealityExposure() (string, uint16, string, bool, bool) {
	return contribution.registryExposure("VLESS REALITY Vision")
}

func (contribution ListenerContribution) ConnectionProfilesXHTTPExposure() (string, uint16, string, bool, bool) {
	return contribution.registryExposure("VLESS XHTTP origin")
}

func (contribution ListenerContribution) ConnectionProfilesWebSocketExposure() (string, uint16, string, bool, bool) {
	return contribution.registryExposure("VLESS WebSocket origin")
}

func (contribution ListenerContribution) ConnectionProfilesHysteria2Exposure() (string, uint16, string, bool, bool) {
	return contribution.registryExposure("Hysteria2")
}

func (contribution ListenerContribution) ConnectionProfilesTUICExposure() (string, uint16, string, bool, bool) {
	return contribution.registryExposure("TUIC")
}

func (contribution ListenerContribution) ConnectionProfilesAnyTLSExposure() (string, uint16, string, bool, bool) {
	return contribution.registryExposure("AnyTLS")
}

func (contribution ListenerContribution) ConnectionProfilesAnyTLSListener() (uint16, string, bool) {
	return contribution.anyTLSPort, contribution.anyTLSProtocol, contribution.anyTLSValid
}

func (contribution ListenerContribution) ConnectionProfilesTUICListener() (uint16, string, bool) {
	return contribution.tuicPort, contribution.tuicProtocol, contribution.tuicValid
}

func (contribution ListenerContribution) ConnectionProfilesListeners() (uint16, string, uint16, string, bool) {
	return contribution.realityPort, contribution.realityProtocol, contribution.hysteria2Port, contribution.hysteria2Protocol, contribution.valid
}

// CloudflareTunnelPath is the typed outbound proof consumed by Cloudflare Tunnel.
type CloudflareTunnelPath struct {
	HTTPS   ProofStatus
	TCP7844 ProofStatus
	UDP7844 ProofStatus
}

type CertificateRetryHandoff struct {
	Owner                  string
	KeepCurrentCertificate bool
	Until                  string
}

type CertificatePolicy struct {
	HTTP01ForIPAndDomain    bool
	CreatesCAA              bool
	IgnoredChallengeRecords int
}

type ReachabilityProof struct {
	Purpose  string
	Address  string
	Port     uint16
	Protocol Protocol
	Local    ProofStatus
	Outside  ProofStatus
}

type ProviderGuidance struct {
	Address             string
	Port                uint16
	Protocol            Protocol
	RequiredPorts       []Exposure
	SSHWarning          string
	ReconnectionWarning string
	Guidance            string
	Action              string
	ProviderChanged     bool
}

type RenewalFreshness struct {
	ReevaluateAfterGlobalLockWait bool
	RebuildOneUsePlan             bool
}

type Finding struct {
	Classification Classification
	Outcome        Outcome
	Code           string
	Problem        string
	Found          string
	Required       string
	WhyStopped     string
	Fix            Fix
	CheckAgain     string
	Back           string
	Evidence       string
}

type Fix struct {
	SBXROption     string
	OwnerChecklist []string
}

type Policy struct {
	Table              string
	Nftables           string
	FlushRuleset       bool
	SSHAddress         string
	PublicIPv4         string
	PublicIPv6         string
	PrimaryAddress     string
	CertificateAddress string
	Exposures          []Exposure
	Replacements       []PortReplacement
	TemporaryHTTP      *TemporaryHTTPPolicy
}

type CleanupOutcome string

const (
	CleanupSuccess      CleanupOutcome = "success"
	CleanupFailure      CleanupOutcome = "failure"
	CleanupInterruption CleanupOutcome = "interruption"
	CleanupCancellation CleanupOutcome = "cancellation"
	CleanupRollback     CleanupOutcome = "rollback"
)

type TemporaryHTTPPolicy struct {
	Identity            string
	Purpose             string
	Exposure            Exposure
	RecordNativeHandles bool
	RemoveAfter         [5]CleanupOutcome
}

type SystemChangesRequirements struct {
	ValidateCompleteCandidate bool
	AtomicTableApply          bool
	RootOwnedWatchdog         bool
	ProveCurrentSSHResponsive bool
	ProveDetectedSSHAdmitted  bool
	CancelAfterGate           string
	RestoreExactPreviousRules bool
}

type SSHSafety struct {
	SecondConnectionRequired       bool
	EditsSSHConfiguration          bool
	FutureOutsideReconnectUnproved bool
	Warning                        string
	RecoveryPath                   string
}

type CompleteRemoval struct {
	Family                  string
	Table                   string
	PreserveUnrelatedPolicy bool
}

type PortReplacement struct {
	Purpose          string
	Address          string
	Protocol         Protocol
	PreviousPort     uint16
	Port             uint16
	RebuiltArtifacts [7]RebuiltArtifact
}

type RebuiltArtifact string

const (
	ServerConfiguration        RebuiltArtifact = "server configuration"
	SubscriptionRepresentation RebuiltArtifact = "subscription representation"
	ShareURI                   RebuiltArtifact = "share URI"
	QRValue                    RebuiltArtifact = "QR value"
	FirewallRule               RebuiltArtifact = "firewall rule"
	CertificateInput           RebuiltArtifact = "certificate input"
	ReviewPlan                 RebuiltArtifact = "Plan"
)

type Exposure struct {
	Purpose  string
	Address  string
	Port     uint16
	Protocol Protocol
}

type Gate struct {
	Code     string
	Required string
}

type CheckBounds struct {
	DeterministicAttempts  int
	TemporaryAttempts      int
	TemporaryWindowSeconds int
	LocalHealthSeconds     int
	CloudflareOwner        string
	ACMEOwner              string
	InfiniteRetries        bool
}

type Binding struct {
	Digest   string
	policy   Policy
	baseline Baseline
	revision uint64
	digest   string
	approved bool
}

type HTTP01Contribution struct {
	candidate          string
	sshPort            uint16
	revision           uint64
	selectedIP, digest string
}

func (result Result) HTTP01Contribution() (HTTP01Contribution, bool) {
	policy := result.Binding.policy
	if !result.Binding.approved || len(result.Binding.digest) != 64 || policy.TemporaryHTTP == nil || policy.TemporaryHTTP.Identity != "sbxr:acme-http-01" || !policy.TemporaryHTTP.RecordNativeHandles || strings.Count(policy.Nftables, `comment "sbxr:acme-http-01"`) != 1 {
		return HTTP01Contribution{}, false
	}
	var sshPort uint16
	for _, exposure := range policy.Exposures {
		if exposure.Purpose == "SSH preservation" && exposure.Protocol == TCP {
			sshPort = exposure.Port
		}
	}
	if sshPort == 0 || policy.CertificateAddress == "" {
		return HTTP01Contribution{}, false
	}
	return HTTP01Contribution{candidate: policy.Nftables, sshPort: sshPort, revision: result.Binding.revision, selectedIP: policy.CertificateAddress, digest: result.Binding.digest}, true
}

func (contribution HTTP01Contribution) SystemChangesHTTP01() (string, uint16, uint64, string, string, bool) {
	return contribution.candidate, contribution.sshPort, contribution.revision, contribution.selectedIP, contribution.digest, contribution.digest != ""
}

type Interface struct{ adapter Adapter }

func New(adapter Adapter) Interface { return Interface{adapter: adapter} }

func (i Interface) Evaluate(request Request) Result {
	result := Result{Baseline: request.Intent.Baseline, Outcome: Healthy, Bounds: CheckBounds{DeterministicAttempts: 1, TemporaryAttempts: 3, TemporaryWindowSeconds: 60, LocalHealthSeconds: 60, CloudflareOwner: "Cloudflare Tunnel", ACMEOwner: "Certificate Lifecycle"}, Renewal: RenewalFreshness{ReevaluateAfterGlobalLockWait: true, RebuildOneUsePlan: true}, intent: request.Intent}
	if !validRequest(request) {
		result.add(requiredFailure("NETWORK-INTENT-INVALID", "Network Policy intent is incomplete or unsupported", "a missing or invalid typed intent value", "one exact revision, Clean or Managed baseline, approved ports, addresses, profiles, and evaluation stage", "SBXR cannot inspect or adopt ambiguous intent", ownerFix("Return to the previous review and complete the Network Policy inputs.")))
		return result
	}
	if i.adapter == nil {
		result.add(requiredFailure("NETWORK-ADAPTER-UNAVAILABLE", "Ubuntu observations are unavailable", "no Adapter", "one Ubuntu-host Adapter", "SBXR cannot prove the network baseline", Fix{OwnerChecklist: []string{"Restore the Ubuntu-host Adapter."}}))
		return result
	}
	observed, err := i.adapter.Observe(ObservationRequest{Intent: request.Intent, Stage: request.Stage, Scope: LocalObservations, ReclamationReview: request.ReclamationReview})
	if err != nil {
		result.add(requiredFailure("NETWORK-OBSERVATION-FAILED", "Ubuntu observation failed", "typed observation unavailable", "fresh typed Ubuntu facts", "SBXR cannot prove the network baseline", Fix{OwnerChecklist: []string{"Correct the observation failure."}}))
		return result
	}
	if ownerFactsProvided(request.OwnerFacts) {
		observed.OwnerFacts = request.OwnerFacts
	}
	if certificateFactsProvided(request.Certificate) {
		observed.Certificate = request.Certificate
	}
	observed.Outbound = OutboundFacts{}
	applyManagedProof(request.Managed, &observed)
	result.Policy = candidatePolicy(request.Intent)
	reviewInstallation(&result, observed, request.ReclamationReview)
	if result.Outcome == Failed {
		return result
	}
	result.SystemChanges = SystemChangesRequirements{ValidateCompleteCandidate: true, AtomicTableApply: true, RootOwnedWatchdog: true, ProveCurrentSSHResponsive: true, ProveDetectedSSHAdmitted: true, CancelAfterGate: "NETWORK-SSH-RESPONSIVE", RestoreExactPreviousRules: true}
	result.SSHSafety = SSHSafety{FutureOutsideReconnectUnproved: true, Warning: "One existing SSH session cannot prove a future outside reconnection.", RecoveryPath: "VPS provider console"}
	result.CompleteRemoval = CompleteRemoval{Family: "inet", Table: "sbxr", PreserveUnrelatedPolicy: true}
	evaluateSSH(&result, request.Intent, observed.SSH)
	evaluateHost(&result, observed.Host)
	evaluateAddresses(&result, request.Intent, observed)
	evaluateCertificate(&result, request.Intent, observed.Certificate)
	evaluatePrivilege(&result, request.Stage, observed.Firewall)
	evaluateDisk(&result, request.Intent.Disk, observed.Disk)
	evaluateTime(&result, request.Intent.Baseline, observed.Time)
	evaluateOwnership(&result, request.Intent, observed)
	result.Policy.Nftables = renderNftables(result.Policy)
	if result.Outcome == Failed {
		return result
	}
	external, err := i.adapter.Observe(ObservationRequest{Intent: request.Intent, Stage: request.Stage, Scope: ExternalObservations, ReclamationReview: request.ReclamationReview})
	if err != nil {
		result.add(requiredFailure("NETWORK-OBSERVATION-FAILED", "External network observation failed", "typed external observation unavailable", "fresh configured-resolver and verified-protocol facts", "SBXR cannot prove required outbound dependencies", Fix{OwnerChecklist: []string{"Correct the external observation failure."}}))
		return result
	}
	observed.Outbound = external.Outbound
	evaluateOutbound(&result, observed.Outbound)
	evaluateReachability(&result, request, observed)
	result.Binding = bind(request, observed, result.Policy)
	result.Binding.approved = result.Outcome == Healthy || cleanVPSAuthorityEligible(result)
	if result.portCorrection != nil && len(result.Findings) == 1 && result.Findings[0].Code == "NETWORK-MANAGED-DRIFT" {
		candidate := result.Policy
		for index := range candidate.Exposures {
			exposure := &candidate.Exposures[index]
			if exposure.Purpose == result.portCorrection.purpose && exposure.Port == result.portCorrection.port && string(exposure.Protocol) == result.portCorrection.protocol {
				exposure.Port = result.portCorrection.candidate
				candidate.Replacements = append(candidate.Replacements, PortReplacement{Purpose: exposure.Purpose, Address: exposure.Address, Protocol: exposure.Protocol, PreviousPort: result.portCorrection.port, Port: result.portCorrection.candidate, RebuiltArtifacts: rebuiltArtifacts()})
				candidate.Nftables = renderNftables(candidate)
				result.portCorrectionBinding = bind(request, observed, candidate)
				result.portCorrectionBinding.approved = true
				break
			}
		}
	}
	result.PreApplyGates = []Gate{
		{Code: "NETWORK-PREFLIGHT-FRESH", Required: "all bound observations still match"},
		{Code: "NETWORK-CANDIDATE-VALID", Required: "the complete native nftables candidate validates without applying it"},
		{Code: "NETWORK-WATCHDOG-READY", Required: "a root-owned watchdog can restore the exact previous rules on any failure"},
		{Code: "NETWORK-SSH-PRESERVED", Required: "the detected SSH port and current session remain admitted"},
	}
	for _, replacement := range result.Policy.Replacements {
		result.PreApplyGates = append(result.PreApplyGates, Gate{Code: "NETWORK-PORT-STILL-BINDABLE", Required: fmt.Sprintf("bind-prove %s:%d/%s immediately before the first mutation", replacement.Address, replacement.Port, replacement.Protocol)})
	}
	result.PostApplyGates = []Gate{
		{Code: "NETWORK-POLICY-ACTIVE", Required: "only the approved SBXR nftables table and exposure are active"},
		{Code: "NETWORK-SSH-RESPONSIVE", Required: "the current SSH session remains responsive before watchdog cancellation"},
	}
	if cleanVPSAuthorityEligible(result) {
		result.freshInstallation = &freshInstallationProofCell{evaluate: func() Result { return i.Evaluate(request) }, digest: result.Binding.Digest}
	}
	return result
}

func reviewInstallation(result *Result, observed Observations, required bool) {
	result.ProtectedFoundation = ProtectedHostFoundation{Version: 1, Paths: []string{"/bin/sh", "/boot", "/etc/apt", "/etc/passwd", "/etc/sbxr", "/etc/shadow", "/etc/ssh", "/lib", "/lib64", "/proc", "/run", "/sbin/init", "/sys", "/usr/bin/apt", "/usr/bin/apt-get", "/usr/bin/dpkg", "/usr/bin/env", "/usr/bin/sudo", "/usr/bin/systemctl", "/usr/lib", "/usr/local/bin/sbxr", "/usr/sbin/sshd", "/var/lib/dpkg", "/var/lib/sbxr"}}
	result.ProtectedFoundation.Paths = append(result.ProtectedFoundation.Paths, observed.Reclamation.ProtectedPaths...)
	if required && !observed.ReclamationComplete {
		result.add(requiredFailure("NETWORK-RECLAMATION-UNPROVED", "Installation conflict inventory is incomplete", "one or more conflict ownership facts are unavailable", "one complete listener, process, service, package, identity, executable, script, mount, Docker, firewall, SSH, port, and Cloudflare inventory", "SBXR never treats incomplete conflict evidence as a Clean VPS", ownerFix("Restore read access to the host inventory or reimage the VPS.")))
		return
	}
	unsupported := observed.Host.UbuntuVersion != "24.04" && !strings.HasPrefix(observed.Host.UbuntuVersion, "24.04.") || !observed.Host.UbuntuServer || !observed.Host.Systemd || observed.Host.Architecture != "amd64" && observed.Host.Architecture != "arm64"
	switch {
	case unsupported:
		result.InstallationClass = UnsupportedHost
	case observed.Lineage == ContradictoryLineage:
		result.InstallationClass = ContradictoryVPS
	case hasReclamationConflict(observed):
		result.InstallationClass = ReclaimableVPS
	default:
		result.InstallationClass = CleanVPS
		return
	}
	if result.InstallationClass != ReclaimableVPS {
		return
	}
	if !observed.ReclamationComplete {
		result.add(requiredFailure("NETWORK-RECLAMATION-UNPROVED", "Reclaimable VPS facts are incomplete", "one or more conflict ownership facts are unavailable", "one complete listener, process, service, package, identity, executable, script, mount, Docker, firewall, SSH, port, and Cloudflare inventory", "SBXR never treats incomplete conflict evidence as a Clean VPS", ownerFix("Restore read access to the host inventory or reimage the VPS.")))
		return
	}
	if len(observed.Reclamation.UnsafePaths) > 0 {
		result.add(requiredFailure("NETWORK-RECLAMATION-PROTECTED", "A reclamation target is linked, mounted, shared, or otherwise ambiguous", safeFact(observed.Reclamation.UnsafePaths[0]), "only exact unchanged regular unshared targets", "SBXR never guesses through a filesystem boundary", ownerFix("Reimage the VPS or remove the conflict through its proven owner.")))
		return
	}
	for _, identity := range observed.Reclamation.Identities {
		if !identity.Exclusive {
			result.add(requiredFailure("NETWORK-RECLAMATION-UNPROVED", "A conflicting identity is not proven exclusive", safeFact(identity.Name), "one identity used only by the exact conflicting service", "SBXR never deletes a shared or merely name-matched identity", ownerFix("Remove the identity through its proven owner or reimage the VPS.")))
			return
		}
	}
	for _, listener := range observed.Listeners {
		if !reclaimableListener(listener, observed.SSH) {
			continue
		}
		if listener.Executable == "" {
			result.add(requiredFailure("NETWORK-RECLAMATION-UNPROVED", "A conflicting listener has no proven executable", safeFact(listener.Process, listener.Service), "one exact /proc process executable or supported unambiguous script", "SBXR never plans deletion from only a socket or process name", ownerFix("Stop the ambiguous owner outside SBXR or reimage the VPS.")))
			return
		}
		proved := slices.ContainsFunc(observed.Reclamation.Executables, func(file FileConflict) bool { return file.Path == listener.Executable && file.SHA256 != "" }) || slices.ContainsFunc(observed.Reclamation.Scripts, func(script ScriptConflict) bool {
			return script.Process == listener.Process && script.Service == listener.Service && script.SHA256 != ""
		})
		if !proved {
			result.add(requiredFailure("NETWORK-RECLAMATION-UNPROVED", "A conflicting listener lacks an exact executable or script digest", safeFact(listener.Executable, listener.Process), "one exact unchanged executable or supported unambiguous script", "SBXR never plans deletion from only a socket or process name", ownerFix("Stop the ambiguous owner outside SBXR or reimage the VPS.")))
			return
		}
	}
	for _, file := range observed.Reclamation.Executables {
		if protectedPath(file.Path, result.ProtectedFoundation.Paths) || file.Mount || file.Links > 1 {
			if !slices.Contains(result.ProtectedFoundation.Paths, file.Path) {
				result.ProtectedFoundation.Paths = append(result.ProtectedFoundation.Paths, file.Path)
			}
			result.add(requiredFailure("NETWORK-RECLAMATION-PROTECTED", "A reclamation target belongs to the Protected Host Foundation", safeFact(file.Path), "no SSH, current-shell, system, package-tool, shared-library, mount, or recovery dependency target", "SBXR never offers destruction of the host foundation", ownerFix("Reimage the VPS or remove the conflict through its proven owner.")))
			return
		}
	}
	for _, pkg := range observed.Reclamation.Packages {
		if slices.ContainsFunc(pkg.OwnedPaths, func(path string) bool { return protectedPath(path, result.ProtectedFoundation.Paths) }) {
			result.add(requiredFailure("NETWORK-RECLAMATION-PROTECTED", "A package conflict owns part of the Protected Host Foundation", safeFact(pkg.Name, pkg.Owns), "no package owning SSH, system tools, shared libraries, mounts, or recovery dependencies", "SBXR never offers removal of a package that owns the host foundation", ownerFix("Reimage the VPS or remove the conflict through its proven owner.")))
			return
		}
	}
	for _, script := range observed.Reclamation.Scripts {
		if protectedPath(script.Path, result.ProtectedFoundation.Paths) || script.Mount || script.Links > 1 {
			result.add(requiredFailure("NETWORK-RECLAMATION-PROTECTED", "A script target belongs to the Protected Host Foundation", safeFact(script.Path), "no shared, mounted, system, or recovery script target", "SBXR never offers destruction of a protected script", ownerFix("Reimage the VPS or remove the conflict through its proven owner.")))
			return
		}
	}
	plan := ReclamationPlan{Classification: string(ReclaimableVPS), Interruption: "No work starts; an interrupted review changes nothing", Cancellation: "Back or Cancel changes nothing", Rollback: "no rollback exists after future permanent reclamation starts"}
	for _, value := range observed.Reclamation.Executables {
		path := reviewFact(value.Path)
		plan.Targets = append(plan.Targets, fmt.Sprintf("executable %s sha256 %s", path, reviewFact(value.SHA256)), fmt.Sprintf("executable %s process %s service %s package %s", path, reviewFact(value.Process), reviewFact(value.Service), reviewFact(value.Package)))
	}
	for _, value := range observed.Reclamation.Scripts {
		path := reviewFact(value.Path)
		plan.Targets = append(plan.Targets, fmt.Sprintf("script %s sha256 %s", path, reviewFact(value.SHA256)), fmt.Sprintf("script %s via preserved interpreter %s process %s service %s", path, reviewFact(value.Interpreter), reviewFact(value.Process), reviewFact(value.Service)))
	}
	for _, value := range observed.Reclamation.Packages {
		plan.Targets = append(plan.Targets, fmt.Sprintf("package %s %s owns conflict %s; complete owned-path digest %s", reviewFact(value.Name), reviewFact(value.Version), reviewFact(value.Owns), digestStrings(value.OwnedPaths)))
	}
	for _, value := range observed.Reclamation.Identities {
		plan.Targets = append(plan.Targets, fmt.Sprintf("identity %s kind %s exclusive %t", reviewFact(value.Name), reviewFact(value.Kind), value.Exclusive))
	}
	if value := observed.Reclamation.Docker; value != nil {
		plan.Targets = append(plan.Targets, fmt.Sprintf("Docker service %s status %s", reviewFact(value.Service), reviewFact(value.Status)))
		for _, pkg := range value.Packages {
			plan.Targets = append(plan.Targets, "Docker package "+reviewFact(pkg))
		}
		for _, preserved := range value.PreservedData {
			plan.Preservation = append(plan.Preservation, "preserve "+reviewFact(preserved))
		}
	}
	for _, listener := range observed.Listeners {
		if reclaimableListener(listener, observed.SSH) {
			plan.Targets = append(plan.Targets, fmt.Sprintf("listener %s:%d/%s process %s service %s", reviewFact(listener.Address), listener.Port, listener.Protocol, reviewFact(listener.Process), reviewFact(listener.Service)))
		}
	}
	for _, service := range observed.ServiceIdentities {
		plan.Targets = append(plan.Targets, "service identity "+reviewFact(service))
	}
	for _, path := range observed.ResourcePaths {
		plan.Targets = append(plan.Targets, "resource path "+reviewFact(path))
	}
	if observed.Firewall.ActiveManager != "" || observed.Firewall.UnexpectedRule != "" {
		plan.Targets = append(plan.Targets, "firewall owner "+reviewFact(observed.Firewall.ActiveManager)+" rule "+reviewFact(observed.Firewall.UnexpectedRule))
	}
	if observed.OwnerFacts.DNS != "" {
		plan.Targets = append(plan.Targets, "Cloudflare DNS "+reviewFact(observed.OwnerFacts.DNS))
	}
	if observed.OwnerFacts.Tunnel != "" {
		plan.Targets = append(plan.Targets, "Cloudflare Tunnel "+reviewFact(observed.OwnerFacts.Tunnel))
	}
	for _, route := range observed.OwnerFacts.Routes {
		plan.Targets = append(plan.Targets, fmt.Sprintf("Cloudflare route %s to %s:%d/%s connected %t", reviewFact(route.Profile), reviewFact(route.OriginAddress), route.OriginPort, route.Protocol, route.Connected))
	}
	for _, conflict := range observed.OwnerFacts.Conflicts {
		plan.Targets = append(plan.Targets, fmt.Sprintf("Cloudflare %s %s name %s", reviewFact(conflict.Kind), reviewFact(conflict.ID), reviewFact(conflict.Name)))
	}
	plan.PermanentWarnings = []string{"Future reclamation is permanent", "Future interruption may require forward recovery"}
	encoded, _ := json.Marshal(struct {
		Facts      Observations
		Plan       ReclamationPlan
		Foundation ProtectedHostFoundation
	}{observed, plan, result.ProtectedFoundation})
	digest := sha256.Sum256(encoded)
	plan.Digest = hex.EncodeToString(digest[:])
	result.Reclamation = &plan
}

func digestStrings(values []string) string {
	digest := sha256.Sum256([]byte(strings.Join(values, "\n")))
	return hex.EncodeToString(digest[:])
}

func reviewFact(value string) string {
	value = strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(value))
	if value == "" {
		return "none"
	}
	if strings.Contains(value, "INFRASTRUCTURE-SECRET-MARKER") || strings.Contains(value, "-----BEGIN ") || len(value) > 200 {
		return "unsafe fact withheld"
	}
	return value
}

func hasReclamationConflict(observed Observations) bool {
	r := observed.Reclamation
	if len(r.Packages)+len(r.Identities)+len(r.Executables)+len(r.Scripts)+len(r.UnsafePaths) > 0 || r.Docker != nil {
		return true
	}
	if !observed.ReclamationComplete {
		return false
	}
	ownerConflict := func(value string) bool { return value != "" && value != "fresh" }
	return len(observed.ServiceIdentities)+len(observed.ResourcePaths) > 0 || observed.Firewall.ActiveManager != "" || observed.Firewall.UnexpectedRule != "" || observed.Firewall.SBXRTableState != "" && observed.Firewall.SBXRTableState != "absent" || ownerConflict(observed.OwnerFacts.DNS) || ownerConflict(observed.OwnerFacts.Tunnel) || len(observed.OwnerFacts.Routes)+len(observed.OwnerFacts.Conflicts) > 0 || slices.ContainsFunc(observed.Listeners, func(listener Listener) bool { return reclaimableListener(listener, observed.SSH) })
}

func reclaimableListener(listener Listener, ssh SSHFacts) bool {
	return listener.Ownership != SBXROwned && (ssh.DetectedPort == 0 || listener.Port != ssh.DetectedPort || listener.Protocol != TCP)
}

func protectedPath(path string, protected []string) bool {
	for _, root := range protected {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

func cleanVPSAuthorityEligible(result Result) bool {
	if result.Baseline != Clean || result.Binding.Digest == "" || result.Outcome == Failed {
		return false
	}
	for _, finding := range result.Findings {
		if finding.Classification == Advisory && finding.Outcome == NeedsAttention || finding.Code == "NETWORK-PRIVILEGED-PENDING" && finding.Outcome == Unknown {
			continue
		}
		return false
	}
	return true
}

func applyManagedProof(proof ManagedProof, observed *Observations) {
	if proof.Lineage != "" {
		observed.Lineage = proof.Lineage
	}
	for index := range observed.Listeners {
		for _, expected := range proof.Listeners {
			if expected.Process == "" && expected.Service == "" {
				continue
			}
			found := observed.Listeners[index]
			if found.Address == expected.Address && found.Port == expected.Port && found.Protocol == expected.Protocol && (expected.Process == "" || found.Process == expected.Process) && (expected.Service == "" || found.Service == expected.Service) {
				observed.Listeners[index].Ownership = SBXROwned
				break
			}
		}
	}
	if proof.NftablesSHA256 != "" {
		if observed.Checksums["sbxr_nftables"] == proof.NftablesSHA256 {
			observed.Firewall.SBXRTableState = "matches Desired State"
		} else {
			observed.Firewall.SBXRTableState = "different from Desired State"
		}
	}
}

func evaluateSSH(result *Result, intent Intent, facts SSHFacts) {
	if facts.DetectedPort != 0 && len(result.Policy.Exposures) > 0 {
		result.Policy.Exposures[0].Port = facts.DetectedPort
	}
	if address := net.ParseIP(facts.ServerAddress); address != nil {
		result.Policy.SSHAddress = address.String()
	}
	if facts.DetectedPort == intent.SSHPort && result.Policy.SSHAddress != "" && len(facts.CurrentSessions) > 0 {
		return
	}
	result.add(requiredFailure("NETWORK-SSH-DETECTION", "Fresh SSH preservation facts do not match reviewed intent", fmt.Sprintf("detected port %d with %d current sessions", facts.DetectedPort, len(facts.CurrentSessions)), fmt.Sprintf("detected SSH port %d with the current session present", intent.SSHPort), "the candidate policy must preserve the actual SSH port and established session", ownerFix("Reconnect through the intended SSH port or correct the reviewed port, then run the complete preflight again.")))
}

func validRequest(request Request) bool {
	intent := request.Intent
	if intent.Revision == 0 || request.Stage != PreApproval && request.Stage != PostApproval || intent.Baseline != Clean && intent.Baseline != Managed || intent.SSHPort == 0 || intent.SubscriptionPort == 0 || intent.PublicIPv4 == "" && intent.PublicIPv6 == "" || intent.PrimarySubscriptionAddress != intent.PublicIPv4 && intent.PrimarySubscriptionAddress != intent.PublicIPv6 {
		return false
	}
	if intent.PublicIPv4 != "" && (net.ParseIP(intent.PublicIPv4) == nil || net.ParseIP(intent.PublicIPv4).To4() == nil) || intent.PublicIPv6 != "" && (net.ParseIP(intent.PublicIPv6) == nil || net.ParseIP(intent.PublicIPv6).To4() != nil) {
		return false
	}
	for _, port := range intent.SelectedPorts() {
		if port == 0 {
			return false
		}
	}
	if (intent.Profiles.Hysteria2.Enabled || intent.Profiles.TUIC.Enabled || intent.Profiles.AnyTLS.Enabled) && intent.CertificateHostname == "" {
		return false
	}
	return intent.Profiles.VLESSXHTTP.Address != "" && intent.Profiles.VLESSWebSocket.Address != ""
}

func evaluateOwnership(result *Result, intent Intent, observed Observations) {
	if intent.Profiles.VLESSXHTTP.Enabled && intent.Profiles.VLESSXHTTP.Address != "127.0.0.1" || intent.Profiles.VLESSWebSocket.Enabled && intent.Profiles.VLESSWebSocket.Address != "127.0.0.1" {
		result.add(requiredFailure("NETWORK-ORIGIN-LOOPBACK", "A Cloudflare Tunnel origin is not loopback-only", "a selected origin outside 127.0.0.1", "both origins exactly on 127.0.0.1", "a public origin would bypass Cloudflare exposure controls", ownerFix("Restore both approved loopback origins and review again.")))
		return
	}
	if intent.Baseline == Managed && observed.Lineage == ContradictoryLineage {
		result.add(requiredFailure("NETWORK-LINEAGE-RECOVERY", "Managed network lineage is contradictory", "network resources disagree with proven Desired State lineage", "one provable current Managed revision", "SBXR cannot safely adopt or repair contradictory ownership", ownerFix("Use the Recovery Required flow.")))
		return
	}
	if observed.Firewall.ActiveManager != "" || observed.Firewall.UnexpectedRule != "" {
		found := observed.Firewall.UnexpectedRule
		if observed.Firewall.ActiveManager != "" {
			found = fmt.Sprintf("manager %q; service %q; table %q; chain %q; rule %q", strings.TrimSuffix(observed.Firewall.ActiveManager, ".service"), observed.Firewall.ActiveManager, "not found", "not found", "active manager owns firewall behavior")
			if observed.Firewall.UnexpectedRule != "" {
				found += "; competing policy: " + observed.Firewall.UnexpectedRule
			}
		}
		result.add(requiredFailure("NETWORK-FIREWALL-CONFLICT", "A competing firewall owner or unexpected rule is active", found, "no active competing firewall owner and no unexpected base-chain or legacy rule", "SBXR never disables another firewall owner or flushes the host ruleset", ownerFix("Review the named firewall owner and correct it outside SBXR, then check again.")))
		return
	}
	policy := candidatePolicy(intent)
	if intent.Baseline == Clean {
		if observed.Firewall.SBXRTableState != "" && observed.Firewall.SBXRTableState != "absent" {
			result.add(requiredFailure("NETWORK-CLEAN-ADOPTION-REFUSED", "A Clean VPS already has an unproved SBXR nftables table", observed.Firewall.SBXRTableState, "the SBXR nftables table absent before fresh installation", "SBXR never adopts or overwrites an unproved table", ownerFix("Remove the unproved table through its proven owner or reimage, then check again.")))
			return
		}
		if observed.OwnerFacts.DNS == UnprovedResource || observed.OwnerFacts.Tunnel == UnprovedResource || len(observed.OwnerFacts.Routes) > 0 {
			found := fmt.Sprintf("DNS %q; Tunnel %q", observed.OwnerFacts.DNS, observed.OwnerFacts.Tunnel)
			if len(observed.OwnerFacts.Routes) > 0 {
				route := observed.OwnerFacts.Routes[0]
				found += fmt.Sprintf("; Route %q to %s:%d/%s", safeFact(route.Profile), safeFact(route.OriginAddress), route.OriginPort, route.Protocol)
			}
			result.add(requiredFailure("NETWORK-CLEAN-ADOPTION-REFUSED", "A Clean VPS has an unproved DNS route or Tunnel", found, "no unproved DNS route or Tunnel on an SBXR seam", "SBXR never adopts or overwrites an external resource without immutable ownership proof", ownerFix("Remove or rename the conflicting resource through its owning system, then check again.")))
			return
		}
		if len(observed.ServiceIdentities) > 0 || len(observed.ResourcePaths) > 0 {
			found := observed.ServiceIdentities
			if len(found) == 0 {
				found = observed.ResourcePaths
			}
			result.add(requiredFailure("NETWORK-CLEAN-ADOPTION-REFUSED", "A Clean VPS has an unproved proxy or SBXR service identity or path", safeFact(found[0]), "no SBXR, proxy, Tunnel, listener, service-identity, DNS-route, or firewall ownership on an SBXR seam", "SBXR never adopts or overwrites unproved resources", ownerFix("Remove the unproved resource or reimage to a Clean VPS, then check again.")))
			return
		}
		for _, listener := range observed.Listeners {
			service := strings.ToLower(listener.Process + " " + listener.Service)
			if strings.Contains(service, "xray") || strings.Contains(service, "sing-box") || strings.Contains(service, "cloudflared") || strings.Contains(service, "sbxr") || listener.Ownership == SBXROwned {
				result.add(requiredFailure("NETWORK-CLEAN-ADOPTION-REFUSED", "A Clean VPS has unproved proxy or SBXR ownership", safeFact(listener.Service, listener.Process), "no SBXR, proxy, Tunnel, listener, service-identity, DNS-route, or firewall ownership on an SBXR seam", "SBXR never adopts or overwrites unproved resources", ownerFix("Remove the unproved resource or reimage to a Clean VPS, then check again.")))
				return
			}
		}
		for _, listener := range observed.Listeners {
			if listener.Port == intent.SSHPort && listener.Protocol == TCP && addressMatches(listener.Address, "public", policy) && !currentSSHListener(listener, observed.Listeners, observed.SSH) {
				if listener.Process == "" && listener.Service == "" && !observed.Firewall.RootVerified {
					continue
				}
				result.add(requiredFailure("NETWORK-SSH-PORT-CONFLICT", "Detected SSH port has an unrelated holder", listenerFact(listener), fmt.Sprintf("only the detected SSH service on fixed %d/TCP", intent.SSHPort), "SBXR never moves SSH, edits sshd, or stops an unrelated process", ownerFix("Free the detected SSH port on the named address without closing the current SSH session, then check again.")))
				return
			}
		}
		if intent.TemporaryHTTP {
			if listener, ok := conflictingListener(observed.Listeners, Exposure{"ACME HTTP-01", "public", 80, TCP}, policy); ok {
				result.CertificateRetry = &CertificateRetryHandoff{Owner: "Certificate Lifecycle", KeepCurrentCertificate: true, Until: "fresh Network Policy evaluation passes"}
				result.add(requiredFailure("NETWORK-FIXED-PORT-CONFLICT", "Fixed TCP 80 is occupied", listenerFact(listener), "TCP 80 free for one exact temporary HTTP-01 interval; keep the current certificate and let Certificate Lifecycle own bounded retry until a fresh evaluation passes", "SBXR never moves TCP 80, stops its current owner, or discards the current certificate", ownerFix("Stop or reconfigure the named owner outside SBXR, then check again.")))
				return
			}
		}
		for index, exposure := range result.Policy.Exposures {
			if exposure.Purpose == "SSH preservation" || exposure.Purpose == "ACME HTTP-01" {
				continue
			}
			listener, conflict := conflictingListener(observed.Listeners, exposure, policy)
			if !conflict {
				continue
			}
			if !configurableDefault(intent, exposure) {
				result.portCorrection = &portCorrectionCell{purpose: exposure.Purpose, port: exposure.Port, protocol: string(exposure.Protocol)}
				result.add(requiredFailure("NETWORK-PORT-CONFLICT", "A committed port is occupied", listenerFact(listener), fmt.Sprintf("committed %s port %d/%s free", exposure.Purpose, exposure.Port, exposure.Protocol), "a committed replacement remains stable until the Owner reviews another Change Set", ownerFix("Free the committed port or review a new Change Set, then check again.")))
				return
			}
			candidate, ok := availableCandidate(observed, result.Policy, intent.SSHPort, exposure)
			if !ok {
				result.add(requiredFailure("NETWORK-PORT-CONFLICT", "A selected configurable port is occupied", listenerFact(listener), fmt.Sprintf("an available bind-proven replacement for %s", exposure.Purpose), "SBXR never kills an unrelated listener or silently continues", ownerFix("Free the selected port or correct the listener owner, then check again.")))
				return
			}
			result.Policy.Exposures[index].Port = candidate.Port
			result.Policy.Replacements = append(result.Policy.Replacements, PortReplacement{Purpose: exposure.Purpose, Address: exposure.Address, Protocol: exposure.Protocol, PreviousPort: exposure.Port, Port: candidate.Port, RebuiltArtifacts: rebuiltArtifacts()})
			finding := requiredFailure("NETWORK-PORT-ALTERNATIVE", "A configurable default port is occupied", listenerFact(listener), fmt.Sprintf("a fully rebuilt server configuration, subscription representation, share URI, QR value, firewall rule, certificate input, and Plan using bind-proven %d/%s", candidate.Port, candidate.Protocol), "the Owner must review every affected output before Apply", Fix{SBXROption: fmt.Sprintf("Review rebuilt %s exposure on %d/%s.", exposure.Purpose, candidate.Port, candidate.Protocol)})
			finding.Outcome = NeedsAttention
			result.add(finding)
		}
		return
	}

	if observed.Lineage != ProvenLineage {
		result.add(requiredFailure("NETWORK-LINEAGE-RECOVERY", "Managed network lineage is unproved", string(observed.Lineage), "one provable current Managed revision", "SBXR cannot classify discovered resources as current Desired State", ownerFix("Use the Recovery Required flow.")))
		return
	}
	var drift []string
	var correction *portCorrectionCell
	correctionConflicts := 0
	for _, exposure := range policy.Exposures {
		if exposure.Purpose == "SSH preservation" || exposure.Purpose == "ACME HTTP-01" {
			continue
		}
		if !hasOwnedListener(observed.Listeners, exposure, policy) {
			if listener, conflict := conflictingListener(observed.Listeners, exposure, policy); conflict {
				drift = append(drift, exposure.Purpose+" held by "+listenerFact(listener))
				if candidate, ok := availableCandidate(observed, policy, intent.SSHPort, exposure); ok {
					correction = &portCorrectionCell{purpose: exposure.Purpose, port: exposure.Port, candidate: candidate.Port, protocol: string(exposure.Protocol)}
				}
				correctionConflicts++
			} else {
				drift = append(drift, exposure.Purpose+" listener missing or different")
			}
		}
	}
	for _, listener := range observed.Listeners {
		if listener.Ownership == SBXROwned && !matchesAnyExposure(listener, policy) {
			drift = append(drift, fmt.Sprintf("unexpected SBXR-owned %d/%s listener", listener.Port, listener.Protocol))
		}
	}
	if !cloudflareRoutesMatch(observed.OwnerFacts.Routes, expectedCloudflareRoutes(intent)) {
		drift = append(drift, "Cloudflare routes missing or different")
	}
	otherDrift := observed.Firewall.SBXRTableState != "matches Desired State" || observed.OwnerFacts.DNS != "matches Desired State" || observed.OwnerFacts.Tunnel != "matches Desired State"
	if len(drift) > 0 || otherDrift {
		exactCorrection := correctionConflicts == 1 && len(drift) == 1 && !otherDrift && correction != nil
		if exactCorrection {
			result.portCorrection = correction
		}
		found := strings.Join(drift, "; ")
		if found == "" {
			found = "an owned firewall, DNS, or Tunnel fact differs from Desired State"
		}
		fix := Fix{SBXROption: "Review a forward-repair Plan for the current Desired State."}
		if exactCorrection {
			fix = Fix{SBXROption: "Change the SBXR port", OwnerChecklist: []string{"Stop the other service"}}
		}
		finding := requiredFailure("NETWORK-MANAGED-DRIFT", "Managed network resources have proven drift", found, "every SBXR-owned listener, nftables rule, DNS route, and Tunnel fact matching Desired State", "the current proven revision needs forward repair before another change", fix)
		finding.Outcome = NeedsAttention
		result.add(finding)
	}
}

func rebuiltArtifacts() [7]RebuiltArtifact {
	return [7]RebuiltArtifact{ServerConfiguration, SubscriptionRepresentation, ShareURI, QRValue, FirewallRule, CertificateInput, ReviewPlan}
}

func currentSSHListener(listener Listener, listeners []Listener, facts SSHFacts) bool {
	var current Listener
	for _, candidate := range listeners {
		if candidate.Port == facts.DetectedPort && candidate.Protocol == TCP && coversAddress(candidate.Address, facts.ServerAddress) {
			current = candidate
			break
		}
	}
	if current == (Listener{}) {
		return false
	}
	if listener == current {
		return true
	}
	return current.Process != "" && listener.Process == current.Process || current.Service != "" && listener.Service == current.Service
}

func coversAddress(listenerAddress, serverAddress string) bool {
	server := net.ParseIP(serverAddress)
	if server == nil {
		return false
	}
	if listenerAddress == "0.0.0.0" {
		return server.To4() != nil
	}
	if listenerAddress == "::" {
		return server.To4() == nil
	}
	listener := net.ParseIP(listenerAddress)
	return listener != nil && listener.Equal(server)
}

func configurableDefault(intent Intent, exposure Exposure) bool {
	for _, profile := range profileDefinitions(intent) {
		if profile.name == exposure.Purpose {
			return exposure.Port == profile.defaultPort
		}
	}
	return false
}

func conflictingListener(listeners []Listener, exposure Exposure, policy Policy) (Listener, bool) {
	for _, listener := range listeners {
		if listener.Port == exposure.Port && listener.Protocol == exposure.Protocol && addressConflicts(listener.Address, exposure.Address, policy) {
			return listener, true
		}
	}
	return Listener{}, false
}

func addressConflicts(found, required string, policy Policy) bool {
	if required != "public" {
		if found == required || found == "::" {
			return true
		}
		return found == "0.0.0.0" && net.ParseIP(required).To4() != nil
	}
	if found == "::" {
		return policy.PublicIPv4 != "" || policy.PublicIPv6 != ""
	}
	ip := net.ParseIP(found)
	if ip == nil {
		return false
	}
	if ip.To4() != nil {
		return policy.PublicIPv4 != ""
	}
	return policy.PublicIPv6 != ""
}

func availableCandidate(observed Observations, policy Policy, sshPort uint16, exposure Exposure) (PortCandidate, bool) {
	for _, candidate := range observed.PortCandidates {
		if !candidate.BindProven || !candidate.Cryptographic || candidate.Protocol != exposure.Protocol || candidate.Address != exposure.Address || candidate.Port < 1024 || candidate.Port == 80 || candidate.Port == sshPort || observed.Ephemeral.First <= candidate.Port && candidate.Port <= observed.Ephemeral.Last {
			continue
		}
		used := false
		for _, current := range policy.Exposures {
			used = used || current.Port == candidate.Port
		}
		for _, listener := range observed.Listeners {
			used = used || listener.Port == candidate.Port
		}
		if !used {
			return candidate, true
		}
	}
	return PortCandidate{}, false
}

func listenerFact(listener Listener) string {
	return fmt.Sprintf("process %s; service %s; %s:%d/%s", safeFact(listener.Process), safeFact(listener.Service), safeFact(listener.Address), listener.Port, listener.Protocol)
}

func hasOwnedListener(listeners []Listener, exposure Exposure, policy Policy) bool {
	if exposure.Address == "public" {
		ipv4, ipv6 := policy.PublicIPv4 == "", policy.PublicIPv6 == ""
		for _, listener := range listeners {
			if listener.Ownership != SBXROwned || listener.Port != exposure.Port || listener.Protocol != exposure.Protocol {
				continue
			}
			ipv4 = ipv4 || matchesPublicFamily(listener.Address, policy.PublicIPv4, "0.0.0.0")
			ipv6 = ipv6 || matchesPublicFamily(listener.Address, policy.PublicIPv6, "::")
		}
		return ipv4 && ipv6
	}
	for _, listener := range listeners {
		if listener.Ownership == SBXROwned && listener.Port == exposure.Port && listener.Protocol == exposure.Protocol && listener.Address == exposure.Address {
			return true
		}
	}
	return false
}

func matchesAnyExposure(listener Listener, policy Policy) bool {
	for _, exposure := range policy.Exposures {
		if exposure.Purpose != "SSH preservation" && exposure.Purpose != "ACME HTTP-01" && listener.Port == exposure.Port && listener.Protocol == exposure.Protocol && addressMatches(listener.Address, exposure.Address, policy) {
			return true
		}
	}
	return false
}

func addressMatches(found, required string, policy Policy) bool {
	if required == "public" {
		return matchesPublicFamily(found, policy.PublicIPv4, "0.0.0.0") || matchesPublicFamily(found, policy.PublicIPv6, "::")
	}
	return found == required
}

func matchesPublicFamily(found, selected, wildcard string) bool {
	if selected == "" {
		return false
	}
	if found == wildcard {
		return true
	}
	selectedIP, foundIP := net.ParseIP(selected), net.ParseIP(found)
	return selectedIP != nil && foundIP != nil && selectedIP.Equal(foundIP)
}

func expectedCloudflareRoutes(intent Intent) []CloudflareRoute {
	var routes []CloudflareRoute
	if intent.Profiles.VLESSXHTTP.Enabled {
		routes = append(routes, CloudflareRoute{"VLESS XHTTP", intent.Profiles.VLESSXHTTP.Address, intent.Profiles.VLESSXHTTP.Port, TCP, true})
	}
	if intent.Profiles.VLESSWebSocket.Enabled {
		routes = append(routes, CloudflareRoute{"VLESS WebSocket", intent.Profiles.VLESSWebSocket.Address, intent.Profiles.VLESSWebSocket.Port, TCP, true})
	}
	return routes
}

func cloudflareRoutesMatch(found, required []CloudflareRoute) bool {
	if len(found) != len(required) {
		return false
	}
	for _, route := range required {
		if !slices.Contains(found, route) {
			return false
		}
	}
	return true
}

func safeFact(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(value))
		if value != "" {
			if len(value) > 80 {
				return value[:80] + "…"
			}
			return value
		}
	}
	return "an unidentified occupied SBXR seam"
}

func evaluatePrivilege(result *Result, stage Stage, firewall FirewallFacts) {
	if firewall.RootVerified {
		return
	}
	if stage == PreApproval {
		finding := requiredFailure("NETWORK-PRIVILEGED-PENDING", "Privileged nftables facts are pending", "unprivileged review complete; root-only nftables ownership not read", "after approval, read the complete nftables ruleset and verify the candidate before mutation", "SBXR does not guess facts that genuinely require root", ownerFix("Approve the Plan and authenticate sudo so System Changes can obtain fresh root-only facts."))
		finding.Outcome = Unknown
		result.add(finding)
		return
	}
	result.add(requiredFailure("NETWORK-PRIVILEGED-MISSING", "Fresh privileged nftables facts are missing", "post-approval evaluation without root-verified nftables facts", "a fresh root-only nftables observation before the first mutation", "SBXR cannot safely apply or validate the candidate policy", ownerFix("Authenticate sudo, collect the root-only facts, and run Evaluate again.")))
}

func evaluateDisk(result *Result, requirement DiskRequirement, disk DiskFacts) {
	floor := uint64(1 << 30)
	if percent := disk.FilesystemBytes / 10; percent > floor {
		floor = percent
	}
	required := requirement.Total() + floor
	if disk.AvailableBytes < required {
		result.add(requiredFailure("NETWORK-DISK-FLOOR", "Insufficient transaction disk space", fmt.Sprintf("%d bytes available", disk.AvailableBytes), fmt.Sprintf("%d bytes available", required), "the Change Set must reserve every transaction copy and still leave the fixed safety floor", ownerFix("Remove only safe incomplete SBXR temporary files or increase the filesystem, then check again.")))
	}
}

func evaluateTime(result *Result, baseline Baseline, facts TimeFacts) {
	if facts.Synchronized {
		return
	}
	if baseline == Clean && facts.Owner == "" {
		finding := requiredFailure("NETWORK-TIME-CORRECTION", "Wall time is not plausibly synchronized", "no synchronized time owner", "plausibly synchronized wall time before mutation", "TLS, certificates, and signed release checks require sound time", Fix{SBXROption: "Review enabling systemd-timesyncd, then check again."})
		finding.Outcome = NeedsAttention
		result.add(finding)
		return
	}
	owner := facts.Owner
	if owner == "" {
		owner = "no proven time owner"
	}
	result.add(requiredFailure("NETWORK-TIME-OWNER", "Wall time is not plausibly synchronized", owner, "the existing time owner reporting synchronized time", "SBXR never stops or replaces an existing time owner", ownerFix("Correct the existing time service without stopping proven SBXR services, then check again.")))
}

func evaluateHost(result *Result, host HostFacts) {
	if host.UbuntuVersion != "24.04" && !strings.HasPrefix(host.UbuntuVersion, "24.04.") {
		result.add(requiredFailure("NETWORK-HOST-UBUNTU", "Unsupported Ubuntu release", host.UbuntuVersion, "Ubuntu Server 24.04.x", "SBXR supports one tested operating-system baseline", ownerFix("Install Ubuntu Server 24.04.x on a Clean VPS.")))
	}
	if !host.UbuntuServer {
		result.add(requiredFailure("NETWORK-HOST-UBUNTU-SERVER", "Ubuntu Server identity is unproved", "Ubuntu Server package identity absent", "Ubuntu Server 24.04.x", "Ubuntu Desktop and unproved derivatives are outside the qualified baseline", ownerFix("Install an official Ubuntu Server 24.04.x image on a Clean VPS.")))
	}
	if host.Architecture != "amd64" && host.Architecture != "arm64" {
		result.add(requiredFailure("NETWORK-HOST-ARCH", "Unsupported architecture", host.Architecture, "linux/amd64 or linux/arm64", "SBXR cannot run a qualified release on this architecture", ownerFix("Use a VPS with amd64 or arm64 architecture.")))
	}
	if !host.Systemd {
		result.add(requiredFailure("NETWORK-HOST-SYSTEMD", "systemd is not running", "systemd unavailable", "systemd running", "SBXR services require the supported service manager", ownerFix("Use Ubuntu Server with systemd running.")))
	}
	if host.LogicalCPUs < 1 {
		result.add(requiredFailure("NETWORK-HOST-CPU", "No usable logical CPU", fmt.Sprintf("%d logical CPUs", host.LogicalCPUs), "at least 1 logical CPU", "SBXR cannot run its services", ownerFix("Choose a VPS with at least one logical CPU.")))
	}
	if host.PhysicalRAM < 512<<20 {
		result.add(requiredFailure("NETWORK-HOST-RAM", "Insufficient physical RAM", byteCount(host.PhysicalRAM), "at least 512 MiB physical RAM; swap does not count", "SBXR cannot safely run the approved services", ownerFix("Choose a VPS with at least 512 MiB physical RAM.")))
	} else if host.PhysicalRAM < 1<<30 {
		result.add(advisory("NETWORK-HOST-RAM-RECOMMENDED", "Physical RAM is below the recommendation", byteCount(host.PhysicalRAM), "1 GiB physical RAM recommended; 512 MiB required", "The host is supported but has less headroom", ownerFix("Continue with the supported host or choose 1 GiB for more headroom.")))
	}
}

func evaluateAddresses(result *Result, intent Intent, observed Observations) {
	ipv4 := intent.PublicIPv4 != "" && slices.Contains(observed.PublicIPv4, intent.PublicIPv4)
	ipv6 := intent.PublicIPv6 != "" && slices.Contains(observed.PublicIPv6, intent.PublicIPv6)
	if !ipv4 {
		result.Policy.PublicIPv4 = ""
	}
	if !ipv6 {
		result.Policy.PublicIPv6 = ""
	}
	if !ipv4 && !ipv6 {
		result.Policy.PrimaryAddress = ""
		result.Policy.CertificateAddress = ""
		result.Policy.Exposures = nil
		result.add(requiredFailure("NETWORK-PUBLIC-ADDRESS", "No selected public address family is usable", fmt.Sprintf("IPv4 %q; IPv6 %q", intent.PublicIPv4, intent.PublicIPv6), "at least one freshly observed selected public IPv4 or IPv6 address", "SBXR cannot build a reachable exposure policy", ownerFix("Correct the public address selection and check again.")))
		return
	}
	if intent.PublicIPv4 != "" && !ipv4 || intent.PublicIPv6 != "" && !ipv6 {
		if ipv4 {
			result.Policy.PrimaryAddress = intent.PublicIPv4
		} else {
			result.Policy.PrimaryAddress = intent.PublicIPv6
		}
		result.Policy.CertificateAddress = result.Policy.PrimaryAddress
		result.add(advisory("NETWORK-PUBLIC-FAMILY-EXCLUDED", "A selected optional public address family is no longer usable", fmt.Sprintf("IPv4 usable=%t; IPv6 usable=%t", ipv4, ipv6), "publish only freshly qualified address families and review a new single-family Plan", "the failed family cannot remain in certificates, firewall rules, subscriptions, or client output", ownerFix("Review the new single-family Plan or go Back and correct the missing family.")))
		return
	}
	if intent.PrimarySubscriptionAddress != intent.PublicIPv4 && intent.PrimarySubscriptionAddress != intent.PublicIPv6 {
		result.add(requiredFailure("NETWORK-PRIMARY-ADDRESS", "Primary subscription address is not selected", intent.PrimarySubscriptionAddress, "one selected usable public address", "the default subscription URL would name an unapproved family", ownerFix("Choose one qualified selected address as primary.")))
	}
}

func evaluateOutbound(result *Result, facts OutboundFacts) {
	result.CloudflareTunnelPath = CloudflareTunnelPath{HTTPS: boolProofStatus(facts.CloudflareHTTPS), TCP7844: boolProofStatus(facts.TunnelTCP7844), UDP7844: boolProofStatus(facts.TunnelUDP7844)}
	checks := []struct {
		ok   bool
		code string
		name string
	}{
		{facts.DNS, "NETWORK-OUTBOUND-DNS", "Ubuntu configured DNS resolver"},
		{facts.GitHubHTTPS, "NETWORK-OUTBOUND-GITHUB-HTTPS", "verified HTTPS to GitHub release services"},
		{facts.GitHubAttestationHTTPS, "NETWORK-OUTBOUND-GITHUB-ATTESTATION-HTTPS", "verified HTTPS to GitHub attestation services"},
		{facts.CloudflareHTTPS, "NETWORK-OUTBOUND-CLOUDFLARE-HTTPS", "verified HTTPS to the Cloudflare API"},
		{facts.ACMEHTTPS, "NETWORK-OUTBOUND-ACME-HTTPS", "verified HTTPS to the approved ACME issuer"},
		{facts.CertificateEndpointsHTTPS, "NETWORK-OUTBOUND-CERTIFICATE-HTTPS", "verified HTTPS to required certificate chain or revocation endpoints"},
		{facts.TimeService, "NETWORK-OUTBOUND-TIME", "the active time service"},
		{facts.TunnelTCP7844, "NETWORK-OUTBOUND-TUNNEL-TCP", "Cloudflare Tunnel outbound TCP 7844"},
		{facts.TunnelUDP7844, "NETWORK-OUTBOUND-TUNNEL-UDP", "Cloudflare Tunnel outbound UDP 7844"},
	}
	for _, check := range checks {
		if !check.ok {
			result.add(requiredFailure(check.code, "A required outbound check failed", check.name+" unavailable", check.name+" reachable with its native verified protocol", "SBXR never disables TLS verification, substitutes HTTP, changes the resolver, installs a VPN, or edits provider networking", ownerFix("Correct the named outbound path and check again.")))
		}
	}
}

func boolProofStatus(passed bool) ProofStatus {
	if passed {
		return ProofPassed
	}
	return ProofFailed
}

func evaluateCertificate(result *Result, intent Intent, facts CertificateFacts) {
	if intent.CertificateHostname == "" {
		return
	}
	result.Certificate = CertificatePolicy{HTTP01ForIPAndDomain: true, IgnoredChallengeRecords: len(facts.DNS.ChallengeRecords)}
	if intent.Baseline == Clean && facts.DNS.Hostname == intent.CertificateHostname && len(facts.DNS.IPv4) == 0 && len(facts.DNS.IPv6) == 0 && facts.CAA.Issuer == "letsencrypt.org" && facts.CAA.HTTP01Allowed {
		if result.Policy.PrimaryAddress != "" {
			result.freshDNSHostname = intent.CertificateHostname
			result.add(advisory("NETWORK-CERTIFICATE-DNS-PENDING", "Direct TLS DNS will be created by the reviewed Cloudflare install", "no existing Direct TLS DNS record", fmt.Sprintf("the Cloudflare Plan creates %s on only the qualified selected addresses", safeFact(intent.CertificateHostname)), "a Clean VPS has no SBXR-owned DNS to observe before the first Change Set", ownerFix("Continue only with the exact reviewed Cloudflare Plan or go Back.")))
		}
		return
	}
	ipv4Matches := result.Policy.PublicIPv4 == "" && len(facts.DNS.IPv4) == 0 || result.Policy.PublicIPv4 != "" && len(facts.DNS.IPv4) == 1 && facts.DNS.IPv4[0] == result.Policy.PublicIPv4
	ipv6Matches := result.Policy.PublicIPv6 == "" && len(facts.DNS.IPv6) == 0 || result.Policy.PublicIPv6 != "" && len(facts.DNS.IPv6) == 1 && facts.DNS.IPv6[0] == result.Policy.PublicIPv6
	if facts.DNS.Hostname != intent.CertificateHostname || !ipv4Matches || !ipv6Matches {
		result.add(requiredFailure("NETWORK-CERTIFICATE-DNS", "Domain certificate DNS facts do not match qualified addresses", fmt.Sprintf("hostname match=%t; IPv4 match=%t; IPv6 match=%t", facts.DNS.Hostname == intent.CertificateHostname, ipv4Matches, ipv6Matches), fmt.Sprintf("%s on only the qualified selected addresses", safeFact(intent.CertificateHostname)), "Certificate Lifecycle needs exact typed DNS facts; unrelated _acme-challenge records are ignored for HTTP-01", ownerFix("Correct the ordinary DNS A or AAAA records through their owning Module, then check again.")))
		return
	}
	if facts.CAA.Issuer != "letsencrypt.org" || !facts.CAA.HTTP01Allowed {
		result.add(requiredFailure("NETWORK-CERTIFICATE-CAA", "Effective CAA does not permit the approved HTTP-01 issuer", fmt.Sprintf("approved issuer=%t; HTTP-01 allowed=%t", facts.CAA.Issuer == "letsencrypt.org", facts.CAA.HTTP01Allowed), "effective CAA permitting letsencrypt.org and HTTP-01", "SBXR validates effective CAA but never creates or edits CAA in v1", ownerFix("Correct effective CAA through the DNS owner, then check again.")))
	}
}

func evaluateReachability(result *Result, request Request, observed Observations) {
	policy := result.Policy
	for _, definition := range profileDefinitions(request.Intent) {
		if !definition.profile.Enabled || definition.address != "public" || definition.name == "Subscription HTTPS" {
			continue
		}
		for _, address := range []string{policy.PublicIPv4, policy.PublicIPv6} {
			if address == "" {
				continue
			}
			exposure := Exposure{definition.name, "public", definition.profile.Port, definition.protocol}
			local := ProofPending
			if request.Intent.Baseline == Managed && observed.Firewall.SBXRTableState == "matches Desired State" && hasProvenLocalListener(observed.Listeners, exposure, policy) && hasExactLocalProof(observed.LocalProofs, definition.name, address, definition.profile.Port, definition.protocol) {
				local = ProofPassed
			}
			outside := ProofPending
			for _, proof := range request.Outside.Direct {
				if proof.Purpose == definition.name && proof.Address == address && proof.Port == definition.profile.Port && proof.Protocol == definition.protocol {
					if local == ProofPassed {
						outside = proofStatus(proof.Status)
					}
					break
				}
			}
			result.Reachability = append(result.Reachability, ReachabilityProof{definition.name, address, definition.profile.Port, definition.protocol, local, outside})
			if outside == ProofFailed {
				result.ProviderGuidance = append(result.ProviderGuidance, providerGuidance(request.Intent, policy, address, definition.profile.Port, definition.protocol))
				finding := advisory("NETWORK-OUTSIDE-REACHABILITY", "A genuine outside client could not reach a direct profile", fmt.Sprintf("%s:%d/%s outside failure", address, definition.profile.Port, definition.protocol), fmt.Sprintf("%s:%d/%s reachable from a genuine outside client", address, definition.profile.Port, definition.protocol), "Local or same-VPS proof cannot prove provider-level reachability, and SBXR never edits provider networking", ownerFix("Review the typed provider guidance, preserve SSH, correct the provider-owned policy, then Run Live Profile Check again."))
				result.add(finding)
			}
		}
	}
	for _, expected := range expectedCloudflareRoutes(request.Intent) {
		proof := ReachabilityProof{Purpose: expected.Profile, Address: expected.OriginAddress, Port: expected.OriginPort, Protocol: expected.Protocol, Local: ProofPending, Outside: ProofPending}
		for _, route := range observed.OwnerFacts.Routes {
			if route.Profile != expected.Profile || route.OriginAddress != expected.OriginAddress || route.OriginPort != expected.OriginPort || route.Protocol != expected.Protocol {
				continue
			}
			exposure := Exposure{Purpose: expected.Profile + " origin", Address: expected.OriginAddress, Port: expected.OriginPort, Protocol: expected.Protocol}
			if request.Intent.Baseline == Managed && observed.Firewall.SBXRTableState == "matches Desired State" && observed.OwnerFacts.Tunnel == "matches Desired State" && hasProvenLocalListener(observed.Listeners, exposure, policy) && hasExactLocalProof(observed.LocalProofs, expected.Profile, expected.OriginAddress, expected.OriginPort, expected.Protocol) {
				proof.Local = ProofPassed
			}
			if route.Connected {
				proof.Outside = ProofPassed
			}
			break
		}
		result.Reachability = append(result.Reachability, proof)
	}
	if policy.TemporaryHTTP != nil {
		outside := proofStatus(request.Outside.HTTP01)
		result.Reachability = append(result.Reachability, ReachabilityProof{"ACME HTTP-01", policy.PrimaryAddress, 80, TCP, ProofPending, outside})
		if outside == ProofFailed {
			result.ProviderGuidance = append(result.ProviderGuidance, providerGuidance(request.Intent, policy, policy.PrimaryAddress, 80, TCP))
			result.add(requiredFailure("NETWORK-OUTSIDE-HTTP01", "ACME could not reach the exact temporary HTTP-01 exposure", fmt.Sprintf("%s:80/TCP outside failure", policy.PrimaryAddress), fmt.Sprintf("%s:80/TCP reachable during the exact certificate interval", policy.PrimaryAddress), "Same-VPS proof cannot replace ACME outside proof, and SBXR never edits provider networking", ownerFix("Review the typed provider guidance, preserve SSH, correct DNS or provider-owned policy, then check again.")))
		}
	}
}

func hasProvenLocalListener(listeners []Listener, exposure Exposure, policy Policy) bool {
	for _, listener := range listeners {
		if listener.Ownership == SBXROwned && listener.Service != "" && listener.Port == exposure.Port && listener.Protocol == exposure.Protocol && addressMatches(listener.Address, exposure.Address, policy) {
			return true
		}
	}
	return false
}

func hasExactLocalProof(proofs []LocalProof, purpose, address string, port uint16, protocol Protocol) bool {
	for _, proof := range proofs {
		if proof.Purpose == purpose && proof.Address == address && proof.Port == port && proof.Protocol == protocol && proof.RouteMatches && proof.ConfigurationMatches {
			return true
		}
	}
	return false
}

func proofStatus(status ProofStatus) ProofStatus {
	if status == ProofPassed || status == ProofFailed {
		return status
	}
	return ProofPending
}

func providerGuidance(intent Intent, policy Policy, address string, port uint16, protocol Protocol) ProviderGuidance {
	var required []Exposure
	for _, exposure := range policy.Exposures {
		if exposure.Address == "public" {
			required = append(required, exposure)
		}
	}
	return ProviderGuidance{
		Address: address, Port: port, Protocol: protocol, RequiredPorts: required,
		SSHWarning:          fmt.Sprintf("Preserve detected SSH %d/TCP while correcting provider policy.", intent.SSHPort),
		ReconnectionWarning: "One existing SSH session cannot prove a future outside reconnection; use the VPS provider console if SSH is blocked.",
		Guidance:            "Review the VPS provider firewall, security group, and network ACL without giving SBXR provider credentials.",
		Action:              "Run Live Profile Check again",
	}
}

func candidatePolicy(intent Intent) Policy {
	policy := Policy{Table: "inet sbxr", PublicIPv4: intent.PublicIPv4, PublicIPv6: intent.PublicIPv6, PrimaryAddress: intent.PrimarySubscriptionAddress, CertificateAddress: intent.PrimarySubscriptionAddress}
	policy.Exposures = append(policy.Exposures, Exposure{"SSH preservation", "public", intent.SSHPort, TCP})
	if intent.TemporaryHTTP {
		exposure := Exposure{"ACME HTTP-01", "public", 80, TCP}
		policy.Exposures = append(policy.Exposures, exposure)
		policy.TemporaryHTTP = &TemporaryHTTPPolicy{Identity: "sbxr:acme-http-01", Purpose: "ACME HTTP-01 validation for IP and domain certificates", Exposure: exposure, RecordNativeHandles: true, RemoveAfter: [5]CleanupOutcome{CleanupSuccess, CleanupFailure, CleanupInterruption, CleanupCancellation, CleanupRollback}}
	}
	for _, current := range profileDefinitions(intent) {
		if current.profile.Enabled {
			policy.Exposures = append(policy.Exposures, Exposure{current.name, current.address, current.profile.Port, current.protocol})
		}
	}
	return policy
}

func renderNftables(policy Policy) string {
	if policy.Table != "inet sbxr" || len(policy.Exposures) == 0 {
		return ""
	}
	ports := map[Protocol][]uint16{TCP: {}, UDP: {}}
	for _, exposure := range policy.Exposures {
		if exposure.Address == "public" && exposure.Purpose != "ACME HTTP-01" {
			ports[exposure.Protocol] = append(ports[exposure.Protocol], exposure.Port)
		}
	}
	for protocol := range ports {
		slices.Sort(ports[protocol])
		ports[protocol] = slices.Compact(ports[protocol])
	}
	var rules []string
	if policy.SSHAddress != policy.PublicIPv4 && policy.SSHAddress != policy.PublicIPv6 {
		family := "ip6"
		if net.ParseIP(policy.SSHAddress).To4() != nil {
			family = "ip"
		}
		for _, exposure := range policy.Exposures {
			if exposure.Purpose == "SSH preservation" {
				rules = append(rules, fmt.Sprintf("\t\t%s daddr %s tcp dport %d accept", family, policy.SSHAddress, exposure.Port))
				break
			}
		}
	}
	for _, address := range []struct {
		family string
		value  string
	}{{"ip", policy.PublicIPv4}, {"ip6", policy.PublicIPv6}} {
		if address.value == "" {
			continue
		}
		if policy.TemporaryHTTP != nil && address.value == policy.CertificateAddress {
			rules = append(rules, fmt.Sprintf("\t\t%s daddr %s tcp dport 80 accept comment %q", address.family, address.value, policy.TemporaryHTTP.Identity))
		}
		for _, protocol := range []Protocol{TCP, UDP} {
			if len(ports[protocol]) == 0 {
				continue
			}
			values := make([]string, len(ports[protocol]))
			for index, port := range ports[protocol] {
				values[index] = fmt.Sprint(port)
			}
			rules = append(rules, fmt.Sprintf("\t\t%s daddr %s %s dport { %s } accept", address.family, address.value, strings.ToLower(string(protocol)), strings.Join(values, ", ")))
		}
	}
	return "table inet sbxr {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tct state established,related accept\n\t\tiifname \"lo\" accept\n\t\tip protocol icmp accept\n\t\tmeta l4proto ipv6-icmp accept\n" + strings.Join(rules, "\n") + "\n\t}\n}"
}

type profileDefinition struct {
	name        string
	profile     Profile
	protocol    Protocol
	address     string
	defaultPort uint16
}

func profileDefinitions(intent Intent) []profileDefinition {
	return []profileDefinition{
		{"VLESS REALITY Vision", intent.Profiles.VLESSRealityVision, TCP, "public", 443},
		{"Hysteria2", intent.Profiles.Hysteria2, UDP, "public", 443},
		{"TUIC", intent.Profiles.TUIC, UDP, "public", 8443},
		{"AnyTLS", intent.Profiles.AnyTLS, TCP, "public", 9443},
		{"Subscription HTTPS", Profile{Enabled: true, Port: intent.SubscriptionPort}, TCP, "public", 10443},
		{"VLESS XHTTP origin", intent.Profiles.VLESSXHTTP, TCP, intent.Profiles.VLESSXHTTP.Address, 11080},
		{"VLESS WebSocket origin", intent.Profiles.VLESSWebSocket, TCP, intent.Profiles.VLESSWebSocket.Address, 11081},
	}
}

func bind(request Request, observed Observations, policy Policy) Binding {
	observed.PortCandidates = nil
	if ownerFactsProvided(request.OwnerFacts) {
		observed.OwnerFacts = request.OwnerFacts
	}
	if certificateFactsProvided(request.Certificate) {
		observed.Certificate = request.Certificate
	}
	applyManagedProof(request.Managed, &observed)
	data, _ := json.Marshal(struct {
		Request  Request
		Observed Observations
		Policy   Policy
	}{request, observed, policy})
	digest := sha256.Sum256(data)
	encodedDigest := hex.EncodeToString(digest[:])
	return Binding{Digest: encodedDigest, policy: policy, baseline: request.Intent.Baseline, revision: request.Intent.Revision, digest: encodedDigest}
}

func ownerFactsProvided(facts OwnerFacts) bool {
	return facts.DNS != "" || facts.Tunnel != "" || len(facts.Routes) > 0 || len(facts.Conflicts) > 0
}

func certificateFactsProvided(facts CertificateFacts) bool {
	return facts.DNS.Hostname != "" || len(facts.DNS.IPv4) > 0 || len(facts.DNS.IPv6) > 0 || len(facts.DNS.ChallengeRecords) > 0 || facts.CAA.Issuer != "" || facts.CAA.HTTP01Allowed
}

func (b Binding) Stale(request Request, observed Observations) bool {
	return b.digest == "" || b.digest != bind(request, observed, b.policy).digest
}

func (b Binding) StaleAfterGlobalLockWait() bool { return true }

func (r *Result) add(finding Finding) {
	r.Findings = append(r.Findings, finding)
	if outcomeRank(finding.Outcome) > outcomeRank(r.Outcome) {
		r.Outcome = finding.Outcome
	}
}

func outcomeRank(outcome Outcome) int {
	switch outcome {
	case Failed:
		return 3
	case Unknown:
		return 2
	case NeedsAttention:
		return 1
	default:
		return 0
	}
}

func requiredFailure(code, problem, found, required, why string, fix Fix) Finding {
	return Finding{
		Classification: Required,
		Outcome:        Failed,
		Code:           code,
		Problem:        problem,
		Found:          found,
		Required:       required,
		WhyStopped:     why,
		Fix:            fix,
		CheckAgain:     "Repeat this observation, then run the complete preflight again.",
		Back:           "Return to the previous review without changing the host.",
		Evidence:       fmt.Sprintf("%s: found %s; required %s", code, found, required),
	}
}

func advisory(code, problem, found, required, why string, fix Fix) Finding {
	finding := requiredFailure(code, problem, found, required, why, fix)
	finding.Classification = Advisory
	finding.Outcome = NeedsAttention
	return finding
}

func ownerFix(step string) Fix { return Fix{OwnerChecklist: []string{step}} }

func byteCount(value uint64) string {
	const mib = 1 << 20
	return fmt.Sprintf("%d MiB", value/mib)
}
