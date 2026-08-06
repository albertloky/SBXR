// Package networkpolicy evaluates one complete network baseline without changing the host.
package networkpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
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
	Intent Intent
	Stage  Stage
}

type Adapter interface {
	Observe(ObservationRequest) (Observations, error)
}

type Observations struct {
	Host              HostFacts
	Lineage           LineageState
	PublicIPv4        []string
	PublicIPv6        []string
	Listeners         []Listener
	ServiceIdentities []string
	ResourcePaths     []string
	SSH               SSHFacts
	Firewall          FirewallFacts
	Routes            RouteFacts
	Outbound          OutboundFacts
	Disk              DiskFacts
	Time              TimeFacts
	OwnerFacts        OwnerFacts
	Checksums         map[string]string
	Ephemeral         PortRange
	PortCandidates    []PortCandidate
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
	Address   string
	Port      uint16
	Protocol  Protocol
	Process   string
	Service   string
	Ownership Ownership
}

type Ownership string

const (
	Unproved  Ownership = "unproved"
	SBXROwned Ownership = "SBXR-owned"
)

type SSHFacts struct {
	DetectedPort    uint16
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
	DNS             bool
	GitHubHTTPS     bool
	CloudflareHTTPS bool
	ACMEHTTPS       bool
	TimeService     bool
	TunnelTCP7844   bool
	TunnelUDP7844   bool
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
	DNS    string
	Tunnel string
}

const UnprovedResource = "unproved"

type Request struct {
	Intent            Intent
	Stage             Stage
	Managed           ManagedProof
	OwnerFacts        OwnerFacts
	RelevantChecksums map[string]string
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
	Baseline       Baseline
	Outcome        Outcome
	Findings       []Finding
	Policy         Policy
	Binding        Binding
	PreApplyGates  []Gate
	PostApplyGates []Gate
	Bounds         CheckBounds
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
	Table          string
	PublicIPv4     string
	PublicIPv6     string
	PrimaryAddress string
	Exposures      []Exposure
}

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
	TemporaryAttempts      int
	TemporaryWindowSeconds int
	LocalHealthSeconds     int
}

type Binding struct {
	Digest string
	policy Policy
}

type Interface struct{ adapter Adapter }

func New(adapter Adapter) Interface { return Interface{adapter: adapter} }

func (i Interface) Evaluate(request Request) Result {
	result := Result{Baseline: request.Intent.Baseline, Outcome: Healthy, Bounds: CheckBounds{TemporaryAttempts: 3, TemporaryWindowSeconds: 60, LocalHealthSeconds: 60}}
	if !validRequest(request) {
		result.add(requiredFailure("NETWORK-INTENT-INVALID", "Network Policy intent is incomplete or unsupported", "a missing or invalid typed intent value", "one exact revision, Clean or Managed baseline, approved ports, addresses, profiles, and evaluation stage", "SBXR cannot inspect or adopt ambiguous intent", ownerFix("Return to the previous review and complete the Network Policy inputs.")))
		return result
	}
	if i.adapter == nil {
		result.add(requiredFailure("NETWORK-ADAPTER-UNAVAILABLE", "Ubuntu observations are unavailable", "no Adapter", "one Ubuntu-host Adapter", "SBXR cannot prove the network baseline", Fix{OwnerChecklist: []string{"Restore the Ubuntu-host Adapter."}}))
		return result
	}
	observed, err := i.adapter.Observe(ObservationRequest{Intent: request.Intent, Stage: request.Stage})
	if err != nil {
		result.add(requiredFailure("NETWORK-OBSERVATION-FAILED", "Ubuntu observation failed", "typed observation unavailable", "fresh typed Ubuntu facts", "SBXR cannot prove the network baseline", Fix{OwnerChecklist: []string{"Correct the observation failure."}}))
		return result
	}
	if request.OwnerFacts != (OwnerFacts{}) {
		observed.OwnerFacts = request.OwnerFacts
	}
	applyManagedProof(request.Managed, &observed)
	result.Policy = candidatePolicy(request.Intent)
	evaluateSSH(&result, request.Intent, observed.SSH)
	evaluateHost(&result, observed.Host)
	evaluateAddresses(&result, request.Intent, observed)
	evaluatePrivilege(&result, request.Stage, observed.Firewall)
	evaluateDisk(&result, request.Intent.Disk, observed.Disk)
	evaluateTime(&result, request.Intent.Baseline, observed.Time)
	evaluateOutbound(&result, observed.Outbound)
	evaluateOwnership(&result, request.Intent, observed)
	result.Binding = bind(request, observed, result.Policy)
	result.PreApplyGates = []Gate{
		{Code: "NETWORK-PREFLIGHT-FRESH", Required: "all bound observations still match"},
		{Code: "NETWORK-SSH-PRESERVED", Required: "the detected SSH port and current session remain admitted"},
	}
	result.PostApplyGates = []Gate{
		{Code: "NETWORK-POLICY-ACTIVE", Required: "only the approved SBXR nftables table and exposure are active"},
		{Code: "NETWORK-SSH-RESPONSIVE", Required: "the current SSH session remains responsive before watchdog cancellation"},
	}
	return result
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
	if facts.DetectedPort == intent.SSHPort && len(facts.CurrentSessions) > 0 {
		return
	}
	result.add(requiredFailure("NETWORK-SSH-DETECTION", "Fresh SSH preservation facts do not match reviewed intent", fmt.Sprintf("detected port %d with %d current sessions", facts.DetectedPort, len(facts.CurrentSessions)), fmt.Sprintf("detected SSH port %d with the current session present", intent.SSHPort), "the candidate policy must preserve the actual SSH port and established session", ownerFix("Reconnect through the intended SSH port or correct the reviewed port, then run the complete preflight again.")))
}

func validRequest(request Request) bool {
	intent := request.Intent
	if intent.Revision == 0 || request.Stage != PreApproval && request.Stage != PostApproval || intent.Baseline != Clean && intent.Baseline != Managed || intent.SSHPort == 0 || intent.SubscriptionPort == 0 || intent.PublicIPv4 == "" && intent.PublicIPv6 == "" || intent.PrimarySubscriptionAddress != intent.PublicIPv4 && intent.PrimarySubscriptionAddress != intent.PublicIPv6 {
		return false
	}
	for _, port := range intent.SelectedPorts() {
		if port == 0 {
			return false
		}
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
		found := observed.Firewall.ActiveManager
		if found == "" {
			found = observed.Firewall.UnexpectedRule
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
		if observed.OwnerFacts.DNS == UnprovedResource || observed.OwnerFacts.Tunnel == UnprovedResource {
			result.add(requiredFailure("NETWORK-CLEAN-ADOPTION-REFUSED", "A Clean VPS has an unproved DNS route or Tunnel", fmt.Sprintf("DNS %q; Tunnel %q", observed.OwnerFacts.DNS, observed.OwnerFacts.Tunnel), "no unproved DNS route or Tunnel on an SBXR seam", "SBXR never adopts or overwrites an external resource without immutable ownership proof", ownerFix("Remove or rename the conflicting resource through its owning system, then check again.")))
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
		if intent.TemporaryHTTP {
			if listener, ok := conflictingListener(observed.Listeners, Exposure{"ACME HTTP-01", "public", 80, TCP}); ok {
				result.add(requiredFailure("NETWORK-FIXED-PORT-CONFLICT", "Fixed TCP 80 is occupied", listenerFact(listener), "TCP 80 free for one exact temporary HTTP-01 interval", "SBXR never moves TCP 80 or stops its current owner", ownerFix("Stop or reconfigure the named owner outside SBXR, then check again.")))
				return
			}
		}
		for index, exposure := range result.Policy.Exposures {
			if exposure.Purpose == "SSH preservation" || exposure.Purpose == "ACME HTTP-01" {
				continue
			}
			listener, conflict := conflictingListener(observed.Listeners, exposure)
			if !conflict {
				continue
			}
			candidate, ok := availableCandidate(observed, result.Policy, intent.SSHPort, exposure)
			if !ok {
				result.add(requiredFailure("NETWORK-PORT-CONFLICT", "A selected configurable port is occupied", listenerFact(listener), fmt.Sprintf("an available bind-proven replacement for %s", exposure.Purpose), "SBXR never kills an unrelated listener or silently continues", ownerFix("Free the selected port or correct the listener owner, then check again.")))
				return
			}
			result.Policy.Exposures[index].Port = candidate.Port
			finding := requiredFailure("NETWORK-PORT-ALTERNATIVE", "A configurable default port is occupied", listenerFact(listener), fmt.Sprintf("a reviewed bind-proven replacement outside the ephemeral range; candidate %d/%s", candidate.Port, candidate.Protocol), "every affected configuration and Plan must be rebuilt before Apply", Fix{SBXROption: fmt.Sprintf("Review rebuilt %s exposure on %d/%s.", exposure.Purpose, candidate.Port, candidate.Protocol)})
			finding.Outcome = NeedsAttention
			result.add(finding)
			return
		}
		return
	}

	if observed.Lineage != ProvenLineage {
		result.add(requiredFailure("NETWORK-LINEAGE-RECOVERY", "Managed network lineage is unproved", string(observed.Lineage), "one provable current Managed revision", "SBXR cannot classify discovered resources as current Desired State", ownerFix("Use the Recovery Required flow.")))
		return
	}
	var drift []string
	for _, exposure := range policy.Exposures {
		if exposure.Purpose == "SSH preservation" || exposure.Purpose == "ACME HTTP-01" {
			continue
		}
		if !hasOwnedListener(observed.Listeners, exposure) {
			drift = append(drift, exposure.Purpose+" listener missing or different")
		}
	}
	for _, listener := range observed.Listeners {
		if listener.Ownership == SBXROwned && !matchesAnyExposure(listener, policy.Exposures) {
			drift = append(drift, fmt.Sprintf("unexpected SBXR-owned %d/%s listener", listener.Port, listener.Protocol))
		}
	}
	if len(drift) > 0 || observed.Firewall.SBXRTableState != "matches Desired State" || observed.OwnerFacts.DNS != "matches Desired State" || observed.OwnerFacts.Tunnel != "matches Desired State" {
		found := strings.Join(drift, "; ")
		if found == "" {
			found = "an owned firewall, DNS, or Tunnel fact differs from Desired State"
		}
		finding := requiredFailure("NETWORK-MANAGED-DRIFT", "Managed network resources have proven drift", found, "every SBXR-owned listener, nftables rule, DNS route, and Tunnel fact matching Desired State", "the current proven revision needs forward repair before another change", Fix{SBXROption: "Review a forward-repair Plan for the current Desired State."})
		finding.Outcome = NeedsAttention
		result.add(finding)
	}
}

func conflictingListener(listeners []Listener, exposure Exposure) (Listener, bool) {
	for _, listener := range listeners {
		if listener.Port == exposure.Port && listener.Protocol == exposure.Protocol && addressMatches(listener.Address, exposure.Address) {
			return listener, true
		}
	}
	return Listener{}, false
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
	return fmt.Sprintf("%s on %s:%d/%s", safeFact(listener.Service, listener.Process), safeFact(listener.Address), listener.Port, listener.Protocol)
}

func hasOwnedListener(listeners []Listener, exposure Exposure) bool {
	for _, listener := range listeners {
		if listener.Ownership == SBXROwned && listener.Port == exposure.Port && listener.Protocol == exposure.Protocol && addressMatches(listener.Address, exposure.Address) {
			return true
		}
	}
	return false
}

func matchesAnyExposure(listener Listener, exposures []Exposure) bool {
	for _, exposure := range exposures {
		if exposure.Purpose != "SSH preservation" && exposure.Purpose != "ACME HTTP-01" && listener.Port == exposure.Port && listener.Protocol == exposure.Protocol && addressMatches(listener.Address, exposure.Address) {
			return true
		}
	}
	return false
}

func addressMatches(found, required string) bool {
	if required == "public" {
		return found != "" && found != "127.0.0.1" && found != "::1"
	}
	return found == required
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
	if !ipv4 && !ipv6 {
		result.add(requiredFailure("NETWORK-PUBLIC-ADDRESS", "No selected public address family is usable", fmt.Sprintf("IPv4 %q; IPv6 %q", intent.PublicIPv4, intent.PublicIPv6), "at least one freshly observed selected public IPv4 or IPv6 address", "SBXR cannot build a reachable exposure policy", ownerFix("Correct the public address selection and check again.")))
		return
	}
	if intent.PublicIPv4 != "" && !ipv4 || intent.PublicIPv6 != "" && !ipv6 {
		if !ipv4 {
			result.Policy.PublicIPv4 = ""
		}
		if !ipv6 {
			result.Policy.PublicIPv6 = ""
		}
		if ipv4 {
			result.Policy.PrimaryAddress = intent.PublicIPv4
		} else {
			result.Policy.PrimaryAddress = intent.PublicIPv6
		}
		result.add(advisory("NETWORK-PUBLIC-FAMILY-EXCLUDED", "A selected optional public address family is no longer usable", fmt.Sprintf("IPv4 usable=%t; IPv6 usable=%t", ipv4, ipv6), "publish only freshly qualified address families and review a new single-family Plan", "the failed family cannot remain in certificates, firewall rules, subscriptions, or client output", ownerFix("Review the new single-family Plan or go Back and correct the missing family.")))
		return
	}
	if intent.PrimarySubscriptionAddress != intent.PublicIPv4 && intent.PrimarySubscriptionAddress != intent.PublicIPv6 {
		result.add(requiredFailure("NETWORK-PRIMARY-ADDRESS", "Primary subscription address is not selected", intent.PrimarySubscriptionAddress, "one selected usable public address", "the default subscription URL would name an unapproved family", ownerFix("Choose one qualified selected address as primary.")))
	}
}

func evaluateOutbound(result *Result, facts OutboundFacts) {
	checks := []struct {
		ok   bool
		code string
		name string
	}{
		{facts.DNS, "NETWORK-OUTBOUND-DNS", "Ubuntu configured DNS resolver"},
		{facts.GitHubHTTPS, "NETWORK-OUTBOUND-GITHUB-HTTPS", "verified HTTPS to GitHub release and attestation services"},
		{facts.CloudflareHTTPS, "NETWORK-OUTBOUND-CLOUDFLARE-HTTPS", "verified HTTPS to the Cloudflare API"},
		{facts.ACMEHTTPS, "NETWORK-OUTBOUND-ACME-HTTPS", "verified HTTPS to the approved ACME issuer"},
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

func candidatePolicy(intent Intent) Policy {
	policy := Policy{Table: "inet sbxr", PublicIPv4: intent.PublicIPv4, PublicIPv6: intent.PublicIPv6, PrimaryAddress: intent.PrimarySubscriptionAddress}
	policy.Exposures = append(policy.Exposures, Exposure{"SSH preservation", "public", intent.SSHPort, TCP})
	if intent.TemporaryHTTP {
		policy.Exposures = append(policy.Exposures, Exposure{"ACME HTTP-01", "public", 80, TCP})
	}
	for _, current := range profileDefinitions(intent) {
		if current.profile.Enabled {
			policy.Exposures = append(policy.Exposures, Exposure{current.name, current.address, current.profile.Port, current.protocol})
		}
	}
	return policy
}

type profileDefinition struct {
	name     string
	profile  Profile
	protocol Protocol
	address  string
}

func profileDefinitions(intent Intent) []profileDefinition {
	return []profileDefinition{
		{"VLESS REALITY Vision", intent.Profiles.VLESSRealityVision, TCP, "public"},
		{"Hysteria2", intent.Profiles.Hysteria2, UDP, "public"},
		{"TUIC", intent.Profiles.TUIC, UDP, "public"},
		{"AnyTLS", intent.Profiles.AnyTLS, TCP, "public"},
		{"Subscription HTTPS", Profile{Enabled: true, Port: intent.SubscriptionPort}, TCP, "public"},
		{"VLESS XHTTP origin", intent.Profiles.VLESSXHTTP, TCP, intent.Profiles.VLESSXHTTP.Address},
		{"VLESS WebSocket origin", intent.Profiles.VLESSWebSocket, TCP, intent.Profiles.VLESSWebSocket.Address},
	}
}

func bind(request Request, observed Observations, policy Policy) Binding {
	observed.PortCandidates = nil
	if request.OwnerFacts != (OwnerFacts{}) {
		observed.OwnerFacts = request.OwnerFacts
	}
	applyManagedProof(request.Managed, &observed)
	data, _ := json.Marshal(struct {
		Request  Request
		Observed Observations
		Policy   Policy
	}{request, observed, policy})
	digest := sha256.Sum256(data)
	return Binding{Digest: hex.EncodeToString(digest[:]), policy: policy}
}

func (b Binding) Stale(request Request, observed Observations) bool {
	return b.Digest == "" || b.Digest != bind(request, observed, b.policy).Digest
}

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
