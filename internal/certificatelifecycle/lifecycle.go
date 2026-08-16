package certificatelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	lifecyclecontract "github.com/albertloky/SBXR/internal/softwarelifecycle/contract"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

const (
	ipProfile      = "shortlived"
	domainProfile  = "tlsserver"
	ipCertName     = "sbxr-ip"
	domainCertName = "sbxr-domain"
)

type InputGuidance struct {
	Purpose, AcceptedFormat, Recovery, Example, URL string
	Instructions, CommonMistakes                    []string
}

func OwnerEmailInputGuidance() InputGuidance {
	return InputGuidance{
		Purpose:        "Supply one email to Certbot for ACME account registration.",
		Instructions:   []string{"SBXR keeps this Personal Information in protected Desired State; Let's Encrypt ended expiration emails on June 4, 2025."},
		AcceptedFormat: "One exact local-part@domain email address with no display name, spaces, or control data.",
		CommonMistakes: []string{"Display names, two addresses, whitespace, and typing mistakes are refused."},
		Recovery:       "Correct it and submit again; no certificate request or Plan exists yet.",
		Example:        "owner@sbxr.example",
		URL:            "https://letsencrypt.org/docs/expiration-emails/",
	}
}

func SubscriberAgreementInputGuidance() InputGuidance {
	return InputGuidance{
		Purpose:        "Review the current Let's Encrypt Subscriber Agreement before certificate issuance.",
		Instructions:   []string{"Open the current Policy and Legal Repository and read the current Subscriber Agreement.", "Opening Help does not accept the agreement, authorize issuance, or approve a Plan."},
		AcceptedFormat: "Exact uppercase AGREE after review.",
		CommonMistakes: []string{"Lowercase, added spaces, and any other text are refused."},
		Recovery:       "Review the current agreement, then type AGREE; use Back if you do not agree.",
		Example:        "AGREE only after review",
		URL:            "https://letsencrypt.org/repository/",
	}
}

func ValidOwnerEmail(value string) bool {
	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value && address.Name == "" && !strings.ContainsAny(value, "\r\n") && !strings.HasSuffix(strings.ToLower(value), ".example")
}

var (
	stateSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hostname    = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9]?))*$`)
	servingID   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	planName    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$`)
	versionText = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)(?:\.[0-9]+)?$`)
)

type Outcome string

const (
	Healthy        Outcome = "Healthy"
	NeedsAttention Outcome = "Needs attention"
	Failed         Outcome = "Failed"
	Unknown        Outcome = "Unknown"
)

type Clock interface{ Now() time.Time }

type Adapter interface {
	Observe(context.Context) (Observation, error)
}

type Interface struct {
	adapter Adapter
	clock   Clock
}

func New(adapter Adapter, clock Clock) Interface { return Interface{adapter: adapter, clock: clock} }

type CandidateQualification interface {
	CertificateLifecycleQualification() (certbotVersion string, valid bool)
}

type freshDNSPrerequisites interface {
	CertificateLifecycleFreshDNSPrerequisites() (hostname string, addresses []string, valid bool)
}

type freshDNSPlan interface {
	CertificateLifecycleFreshDNSPlan() (hostname, ipv4, ipv6, desiredStateSHA256 string, valid bool)
}

type freshDNSCell struct {
	hostname, ipv4, ipv6, desiredStateSHA256 string
}

// FreshDNSAuthority binds Network Policy's exact absent-DNS observation to the
// reviewed Cloudflare records that will be created before certificate steps.
type FreshDNSAuthority struct{ cell *freshDNSCell }

func (FreshDNSAuthority) String() string   { return "fresh certificate DNS Plan: redacted" }
func (FreshDNSAuthority) GoString() string { return "fresh certificate DNS Plan: redacted" }
func (FreshDNSAuthority) MarshalJSON() ([]byte, error) {
	return nil, errors.New("fresh certificate DNS Plan cannot be rendered")
}

func NewFreshDNSAuthority(network freshDNSPrerequisites, cloudflare freshDNSPlan) FreshDNSAuthority {
	networkType, cloudflareType := reflect.TypeOf(network), reflect.TypeOf(cloudflare)
	if networkType == nil || networkType.Kind() != reflect.Struct || networkType.PkgPath() != "github.com/albertloky/SBXR/internal/networkpolicy" || networkType.Name() != "Result" || cloudflareType == nil || cloudflareType.Kind() != reflect.Pointer || cloudflareType.Elem().PkgPath() != "github.com/albertloky/SBXR/internal/cloudflaretunnel" || cloudflareType.Elem().Name() != "Plan" {
		return FreshDNSAuthority{}
	}
	hostname, addresses, networkValid := network.CertificateLifecycleFreshDNSPrerequisites()
	plannedHostname, ipv4, ipv6, desired, planValid := cloudflare.CertificateLifecycleFreshDNSPlan()
	want := make([]string, 0, 2)
	if ipv4 != "" {
		want = append(want, ipv4)
	}
	if ipv6 != "" {
		want = append(want, ipv6)
	}
	if !networkValid || !planValid || hostname != plannedHostname || !slices.Equal(addresses, want) {
		return FreshDNSAuthority{}
	}
	return FreshDNSAuthority{cell: &freshDNSCell{hostname: hostname, ipv4: ipv4, ipv6: ipv6, desiredStateSHA256: desired}}
}

func (authority FreshDNSAuthority) apply(desiredStateSHA256 string, request ViewRequest) (ViewRequest, bool) {
	if authority.cell == nil || authority.cell.desiredStateSHA256 != desiredStateSHA256 || request.DirectHostname != authority.cell.hostname {
		return ViewRequest{}, false
	}
	request.DNS = DNSFacts{Status: DNSAvailable, Hostname: authority.cell.hostname, DNSOnly: true}
	if authority.cell.ipv4 != "" {
		request.DNS.Addresses = append(request.DNS.Addresses, authority.cell.ipv4)
	}
	if authority.cell.ipv6 != "" {
		request.DNS.Addresses = append(request.DNS.Addresses, authority.cell.ipv6)
	}
	request.CAA = CAAFacts{Status: CAAAvailable}
	return request, true
}

type candidateAdapter struct{ certbotVersion string }

// NewForFreshInstallation uses only the capability proof carried by an exact
// staged Software Lifecycle candidate. Issuance and activation still happen
// later through Certificate Lifecycle's normal Change Set steps.
func NewForFreshInstallation(candidate CandidateQualification, clock Clock) Interface {
	typeOf := reflect.TypeOf(candidate)
	if typeOf == nil || typeOf.Kind() != reflect.Struct || typeOf.PkgPath() != "github.com/albertloky/SBXR/internal/softwarelifecycle" || typeOf.Name() != "InstallCandidate" {
		return Interface{clock: clock}
	}
	version, valid := candidate.CertificateLifecycleQualification()
	if !valid || !versionAtLeast(version, 5, 4) {
		return Interface{clock: clock}
	}
	return New(candidateAdapter{certbotVersion: version}, clock)
}

func (adapter candidateAdapter) Observe(context.Context) (Observation, error) {
	return Observation{
		Issuer:    IssuerObservation{Name: "Let's Encrypt", CertbotVersion: adapter.certbotVersion, Distribution: "pip-venv", SupportedDistribution: true, RequiredProfile: true, IPAddress: true, Staging: true},
		Scheduler: SchedulerObservation{Enabled: true, Persistent: true, Serial: true, ExactUnitPair: true, Randomized: true, NoCompetingScheduler: true, RunsPerDay: 2},
	}, nil
}

type IssuerObservation struct {
	Name, CertbotVersion, Distribution                         string
	SupportedDistribution, RequiredProfile, IPAddress, Staging bool
}

type CertificateObservation struct {
	Identity, Profile, ActiveServingID string
	NotBefore, NotAfter                time.Time
	RenewalInformation                 RenewalInformation
}

type SchedulerObservation struct {
	Enabled, Persistent, Serial, ExactUnitPair, Randomized, NoCompetingScheduler bool
	RunsPerDay                                                                   int
}

type Observation struct {
	Issuer    IssuerObservation
	IP        CertificateObservation
	Domain    CertificateObservation
	Scheduler SchedulerObservation
}

type DNSStatus string

const (
	DNSAvailable     DNSStatus = "available"
	DNSSERVFAIL      DNSStatus = "SERVFAIL"
	DNSTimeout       DNSStatus = "timeout"
	DNSUnavailable   DNSStatus = "unavailable"
	DNSContradictory DNSStatus = "contradictory"
)

type DNSRecord struct{ Name, Type string }

type DNSFacts struct {
	Status           DNSStatus
	Hostname         string
	Addresses        []string
	DNSOnly          bool
	ChallengeRecords []DNSRecord
}

type CAAStatus string

const (
	CAAAvailable     CAAStatus = "available"
	CAASERVFAIL      CAAStatus = "SERVFAIL"
	CAATimeout       CAAStatus = "timeout"
	CAAUnavailable   CAAStatus = "unavailable"
	CAAContradictory CAAStatus = "contradictory"
)

type CAARecord struct {
	Flags uint8
	Tag   string
	Value string
}

type CAAFacts struct {
	Status  CAAStatus
	Records []CAARecord
}

type HTTP01Prerequisites struct {
	AddressQualified, RouteReachable, Port80Available, TimeSynchronized, FirewallOwned bool
}

type ViewRequest struct {
	SelectedIP, DirectHostname string
	QualifiedAddresses         []string
	HTTP01                     HTTP01Prerequisites
	DNS                        DNSFacts
	CAA                        CAAFacts
}

type Health struct {
	Time                                       time.Time
	Module                                     string
	Outcome                                    Outcome
	Code, Problem, Found, Required, WhyStopped string
	NextActions                                []string
	Evidence                                   string
}

type IssuerStatus struct {
	Name, CertbotVersion, Distribution string
	Qualified                          bool
}

type LineageStatus struct {
	Lineage                   Lineage
	Identity, RequiredProfile string
	NotBefore, NotAfter       time.Time
	Valid, Due                bool
	ActiveServingID           string
}

type SchedulerStatus struct {
	Enabled, Persistent, Serial, ExactUnitPair, Randomized, NoCompetingScheduler bool
	RunsPerDay                                                                   int
	Qualified                                                                    bool
}

type PrerequisiteStatus struct {
	SelectedIP, DirectHostname string
	HTTP01                     HTTP01Prerequisites
	DNS, CAA                   bool
	IgnoredChallengeRecords    int
}

type ViewResult struct {
	Issuer        IssuerStatus
	IP, Domain    LineageStatus
	Scheduler     SchedulerStatus
	Prerequisites PrerequisiteStatus
	Health        Health
	observation   Observation
}

func (result ViewResult) String() string {
	return fmt.Sprintf("Certificate Lifecycle View: issuer=%s IP=%s domain=%s health=%s code=%s", result.Issuer.Name, result.IP.Identity, result.Domain.Identity, result.Health.Outcome, result.Health.Code)
}
func (result ViewResult) GoString() string { return result.String() }

func (module Interface) View(ctx context.Context, request ViewRequest) ViewResult {
	now := time.Time{}
	if module.clock != nil {
		now = module.clock.Now().UTC()
	}
	result := ViewResult{Health: health(now, Failed, "CERTIFICATE-VIEW-INVALID", "Certificate prerequisites are incomplete", "an unavailable Adapter or clock, invalid selected IP, or invalid Direct TLS Hostname", "one typed complete Certificate Lifecycle observation")}
	if module.adapter == nil || module.clock == nil {
		result.Health.Code = "CERTIFICATE-VIEW-UNAVAILABLE"
		result.Health.NextActions = []string{"Back"}
		return result
	}
	address, addressErr := netip.ParseAddr(request.SelectedIP)
	if addressErr != nil || !address.IsGlobalUnicast() {
		result.Health = health(now, Failed, "CERTIFICATE-IP-IDENTITY", "The selected subscription IP is invalid", "the selected value is not one global unicast IP address", "one qualified selected IPv4 or IPv6 address")
		result.Health.NextActions = []string{"Choose one qualified subscription IP", "Check again", "Back"}
		return result
	}
	if len(request.DirectHostname) > 253 || !hostname.MatchString(request.DirectHostname) {
		result.Health = health(now, Failed, "CERTIFICATE-DOMAIN-IDENTITY", "The Direct TLS Hostname is invalid", "the committed value is not one supported DNS hostname", "the exact committed Direct TLS Hostname")
		result.Health.NextActions = []string{"Correct the Direct TLS Hostname through Cloudflare Tunnel", "Check again", "Back"}
		return result
	}
	observed, err := module.adapter.Observe(ctx)
	if err != nil {
		result.Health = health(now, Unknown, "CERTIFICATE-ISSUER-UNAVAILABLE", "The issuer capability check is unavailable", "no supported typed issuer observation", "a bounded successful Certbot capability check")
		result.Health.NextActions = []string{"Check the Certbot installation", "Check again", "Back"}
		return result
	}
	result.observation = observed
	result.Issuer = IssuerStatus{Name: "unsupported", CertbotVersion: "unsupported", Distribution: "unsupported"}
	if observed.Issuer.Name == "Let's Encrypt" {
		result.Issuer.Name = observed.Issuer.Name
	}
	if versionAtLeast(observed.Issuer.CertbotVersion, 0, 0) {
		result.Issuer.CertbotVersion = observed.Issuer.CertbotVersion
	}
	if observed.Issuer.Distribution == "snap" || observed.Issuer.Distribution == "pip-venv" {
		result.Issuer.Distribution = observed.Issuer.Distribution
	}
	result.Issuer.Qualified = observed.Issuer.Name == "Let's Encrypt" && versionAtLeast(observed.Issuer.CertbotVersion, 5, 4) && observed.Issuer.SupportedDistribution && observed.Issuer.RequiredProfile && observed.Issuer.IPAddress && observed.Issuer.Staging
	result.IP = lineageStatus(IPLineage, request.SelectedIP, ipProfile, observed.IP, now)
	result.Domain = lineageStatus(DomainLineage, request.DirectHostname, domainProfile, observed.Domain, now)
	result.Scheduler = SchedulerStatus{Enabled: observed.Scheduler.Enabled, Persistent: observed.Scheduler.Persistent, Serial: observed.Scheduler.Serial, ExactUnitPair: observed.Scheduler.ExactUnitPair, Randomized: observed.Scheduler.Randomized, NoCompetingScheduler: observed.Scheduler.NoCompetingScheduler, RunsPerDay: observed.Scheduler.RunsPerDay}
	result.Scheduler.Qualified = result.Scheduler.Enabled && result.Scheduler.Persistent && result.Scheduler.Serial && result.Scheduler.ExactUnitPair && result.Scheduler.Randomized && result.Scheduler.NoCompetingScheduler && result.Scheduler.RunsPerDay >= 2
	dns := assessDNS(request)
	caa := assessCAA(request.CAA)
	result.Prerequisites = PrerequisiteStatus{SelectedIP: request.SelectedIP, DirectHostname: request.DirectHostname, HTTP01: request.HTTP01, DNS: dns.allowed, CAA: caa.allowed, IgnoredChallengeRecords: len(request.DNS.ChallengeRecords)}

	switch {
	case !result.Issuer.Qualified:
		result.Health = health(now, Failed, "CERTIFICATE-ISSUER-CAPABILITY", "The required issuer capability is not proved", fmt.Sprintf("distribution=%s version=%s required-profile=%t ip-address=%t staging=%t", result.Issuer.Distribution, result.Issuer.CertbotVersion, observed.Issuer.RequiredProfile, observed.Issuer.IPAddress, observed.Issuer.Staging), "Certbot >=5.4 from a supported distribution with --required-profile, --ip-address, and --staging")
		switch {
		case !observed.Issuer.SupportedDistribution:
			result.Health.NextActions = []string{"Install Certbot through supported Snap or pip virtual-environment instructions", "Check again", "Back"}
		case !versionAtLeast(observed.Issuer.CertbotVersion, 5, 4):
			result.Health.NextActions = []string{"Install supported Certbot 5.4 or newer", "Check again", "Back"}
		default:
			result.Health.NextActions = []string{"Install a supported Certbot build with required profile, IP address, and staging flags", "Check again", "Back"}
		}
	case !result.Scheduler.Qualified:
		result.Health = health(now, Failed, "CERTIFICATE-RENEWAL-SCHEDULER", "The one renewal scheduler is not proved", fmt.Sprintf("enabled=%t persistent=%t serial=%t exact_units=%t randomized=%t no_competitor=%t runs_per_day=%d", result.Scheduler.Enabled, result.Scheduler.Persistent, result.Scheduler.Serial, result.Scheduler.ExactUnitPair, result.Scheduler.Randomized, result.Scheduler.NoCompetingScheduler, result.Scheduler.RunsPerDay), "one enabled persistent randomized serial scheduler evaluating at least twice daily with no competing owner")
		result.Health.NextActions = []string{"Restore sbxr-cert-renew.timer and remove competing renewal timers", "Check again", "Back"}
	case !observed.IP.NotAfter.IsZero() && !now.Before(observed.IP.NotAfter):
		result.Health = health(now, Failed, "CERTIFICATE-IP-EXPIRED", "The Subscription Serving certificate is expired", "Subscription Serving cannot prove a current IP certificate", "a current publicly trusted IP certificate with normal HTTPS validation")
		result.Health.NextActions = []string{"Renew sbxr-ip without weakening HTTPS", "Check again", "Back"}
	case !validCertificate(observed.IP, request.SelectedIP, ipProfile, now, 150*time.Hour, 170*time.Hour):
		result.Health = health(now, Failed, "CERTIFICATE-IP-LINEAGE", "The IP certificate lineage is implausible", "the typed IP identity, profile, validity, or serving identifier disagrees", "the exact selected IP with the shortlived profile and a roughly 160-hour lifetime")
		result.Health.NextActions = []string{"Keep the current serving certificate and inspect sbxr-ip", "Check again", "Back"}
	case !observed.Domain.NotAfter.IsZero() && !now.Before(observed.Domain.NotAfter):
		result.Health = health(now, Failed, "CERTIFICATE-DOMAIN-EXPIRED", "The Direct TLS certificate is expired", "Hysteria2, TUIC, and AnyTLS cannot prove a current shared domain certificate", "a current publicly trusted domain certificate with normal name and chain validation")
		result.Health.NextActions = []string{"Renew sbxr-domain without weakening TLS verification", "Check again", "Back"}
	case !observed.Domain.NotAfter.IsZero() && !validDomainRenewalInformation(observed.Domain.RenewalInformation):
		result.Health = health(now, Unknown, "CERTIFICATE-DOMAIN-ARI", "ACME Renewal Information is malformed or unavailable to prove", "the suggested domain renewal window is missing, contradictory, or incomplete", "one valid suggested window, or an explicit unavailable result for the 15-day fallback")
		result.Health.NextActions = []string{"Check ACME Renewal Information again", "Back"}
	case !validCertificate(observed.Domain, request.DirectHostname, domainProfile, now, 40*24*time.Hour, 50*24*time.Hour):
		result.Health = health(now, Failed, "CERTIFICATE-DOMAIN-LINEAGE", "The domain certificate lineage is implausible", "the typed DNS identity, profile, validity, or serving identifier disagrees", "the exact Direct TLS Hostname with the tlsserver profile and an approximately 45-day lifetime")
		result.Health.NextActions = []string{"Keep the current serving certificate and inspect sbxr-domain", "Check again", "Back"}
	case !allHTTP01(request.HTTP01):
		result.Health = health(now, Failed, "CERTIFICATE-HTTP01-PREREQUISITES", "HTTP-01 prerequisites are not proved", fmt.Sprintf("address=%t route=%t port80=%t time=%t firewall=%t", request.HTTP01.AddressQualified, request.HTTP01.RouteReachable, request.HTTP01.Port80Available, request.HTTP01.TimeSynchronized, request.HTTP01.FirewallOwned), "qualified address, route, free port 80, synchronized time, and SBXR-owned temporary firewall authority")
		result.Health.NextActions = []string{http01Correction(request.HTTP01), "Check again", "Back"}
	case !dns.allowed:
		result.Health = health(now, Failed, dns.code, "Direct TLS DNS is not proved", dns.found, "available DNS-only A or AAAA facts for exactly the qualified committed addresses")
		result.Health.NextActions = dns.actions
	case !caa.allowed:
		result.Health = health(now, Failed, caa.code, "Effective CAA does not permit the approved issuer and method", caa.found, "effective CAA allowing letsencrypt.org without a method restriction or with validationmethods=http-01")
		result.Health.NextActions = caa.actions
	default:
		result.Health = Health{Time: now, Module: "Certificate Lifecycle", Outcome: Healthy, Code: "CERTIFICATE-PREREQUISITES-VERIFIED", NextActions: []string{"Create Plan", "Check again", "Back"}}
	}
	return result
}

func health(now time.Time, outcome Outcome, code, problem, found, required string) Health {
	return Health{Time: now, Module: "Certificate Lifecycle", Outcome: outcome, Code: code, Problem: problem, Found: found, Required: required, WhyStopped: "SBXR never orders a certificate from unproved issuer, identity, DNS, CAA, or scheduler facts", NextActions: []string{"Check again", "Back"}, Evidence: "copyable redacted " + code + " result"}
}

func lineageStatus(lineage Lineage, identity, profile string, observed CertificateObservation, now time.Time) LineageStatus {
	status := LineageStatus{Lineage: lineage, Identity: identity, RequiredProfile: profile, NotBefore: observed.NotBefore, NotAfter: observed.NotAfter}
	if servingID.MatchString(observed.ActiveServingID) {
		status.ActiveServingID = observed.ActiveServingID
	}
	if observed.NotBefore.IsZero() && observed.NotAfter.IsZero() {
		status.Due = true
		return status
	}
	status.Valid = !now.Before(observed.NotBefore) && now.Before(observed.NotAfter)
	if lineage == IPLineage {
		status.Due = ipRenewalDue(now, observed.NotAfter)
	} else {
		information := observed.RenewalInformation
		if validDomainRenewalInformation(information) {
			if information.Status == RenewalInformationAvailable {
				status.Due = !now.Before(information.WindowStart)
			} else {
				status.Due = observed.NotAfter.Sub(now) <= 15*24*time.Hour
			}
		}
	}
	return status
}

func validDomainRenewalInformation(information RenewalInformation) bool {
	switch information.Status {
	case RenewalInformationUnavailable:
		return information.WindowStart.IsZero() && information.WindowEnd.IsZero()
	case RenewalInformationAvailable:
		return !information.WindowStart.IsZero() && !information.WindowEnd.IsZero() && information.WindowStart.Before(information.WindowEnd)
	default:
		return false
	}
}

func validCertificate(observed CertificateObservation, identity, profile string, now time.Time, minimum, maximum time.Duration) bool {
	if observed.NotBefore.IsZero() && observed.NotAfter.IsZero() {
		return observed.Identity == "" && observed.Profile == "" && observed.ActiveServingID == ""
	}
	return observed.Identity == identity && observed.Profile == profile && !observed.NotBefore.After(now) && observed.NotAfter.After(now) && observed.NotAfter.Sub(observed.NotBefore) >= minimum && observed.NotAfter.Sub(observed.NotBefore) <= maximum && servingID.MatchString(observed.ActiveServingID)
}

func allHTTP01(facts HTTP01Prerequisites) bool {
	return facts.AddressQualified && facts.RouteReachable && facts.Port80Available && facts.TimeSynchronized && facts.FirewallOwned
}

func http01Correction(facts HTTP01Prerequisites) string {
	switch {
	case !facts.AddressQualified:
		return "Re-run Network Policy for the selected address"
	case !facts.RouteReachable:
		return "Correct the public route through Network Policy"
	case !facts.Port80Available:
		return "Resolve the unrelated port 80 listener through Network Policy"
	case !facts.TimeSynchronized:
		return "Correct VPS time synchronization"
	default:
		return "Restore SBXR-owned temporary firewall authority through Network Policy"
	}
}

type dnsAssessment struct {
	allowed bool
	code    string
	found   string
	actions []string
}

func assessDNS(request ViewRequest) dnsAssessment {
	blocked := func(code, found string, ownerCorrection bool) dnsAssessment {
		actions := []string{"Check DNS again", "Back"}
		if ownerCorrection {
			actions = []string{"Correct Direct TLS DNS through Cloudflare Tunnel", "Check again", "Back"}
		}
		return dnsAssessment{code: code, found: found, actions: actions}
	}
	switch request.DNS.Status {
	case DNSSERVFAIL:
		return blocked("CERTIFICATE-DNS-SERVFAIL", "Direct TLS DNS returned SERVFAIL", false)
	case DNSTimeout:
		return blocked("CERTIFICATE-DNS-TIMEOUT", "Direct TLS DNS timed out", false)
	case DNSUnavailable:
		return blocked("CERTIFICATE-DNS-UNAVAILABLE", "Direct TLS DNS is unavailable", false)
	case DNSContradictory:
		return blocked("CERTIFICATE-DNS-CONTRADICTORY", "Direct TLS DNS results contradict each other", true)
	case DNSAvailable:
	default:
		return blocked("CERTIFICATE-DNS-UNSUPPORTED", "Direct TLS DNS status is unsupported", false)
	}
	if request.DNS.Hostname != request.DirectHostname {
		return blocked("CERTIFICATE-DNS-IDENTITY", "Direct TLS DNS does not name the committed hostname", true)
	}
	if !request.DNS.DNSOnly {
		return blocked("CERTIFICATE-DNS-PROXY", "the committed Direct TLS Hostname is proxied", true)
	}
	if len(request.DNS.Addresses) == 0 || len(request.QualifiedAddresses) == 0 {
		return blocked("CERTIFICATE-DNS-ADDRESSES", "Direct TLS DNS or qualified address facts are empty", true)
	}
	parse := func(values []string) ([]string, bool) {
		parsed := make([]string, 0, len(values))
		seen := map[string]bool{}
		for _, text := range values {
			address, err := netip.ParseAddr(text)
			if err != nil || !address.IsGlobalUnicast() || seen[address.String()] {
				return nil, false
			}
			seen[address.String()] = true
			parsed = append(parsed, address.String())
		}
		slices.Sort(parsed)
		return parsed, true
	}
	dns, dnsOK := parse(request.DNS.Addresses)
	qualified, qualifiedOK := parse(request.QualifiedAddresses)
	if !dnsOK || !qualifiedOK || !slices.Equal(dns, qualified) {
		return blocked("CERTIFICATE-DNS-ADDRESSES", "Direct TLS DNS does not exactly match the qualified committed addresses", true)
	}
	selected := false
	for _, text := range qualified {
		address, err := netip.ParseAddr(text)
		selected = selected || err == nil && address.String() == request.SelectedIP
	}
	if !selected {
		return blocked("CERTIFICATE-DNS-ADDRESSES", "the selected subscription IP is not one of the qualified committed addresses", true)
	}
	return dnsAssessment{allowed: true}
}

type caaAssessment struct {
	allowed bool
	code    string
	found   string
	actions []string
}

func assessCAA(facts CAAFacts) caaAssessment {
	blocked := func(code, found string, ownerCorrection bool) caaAssessment {
		actions := []string{"Check DNS again", "Back"}
		if ownerCorrection {
			actions = []string{"Correct CAA through the DNS owner", "Check again", "Back"}
		}
		return caaAssessment{code: code, found: found, actions: actions}
	}
	switch facts.Status {
	case CAASERVFAIL:
		return blocked("CERTIFICATE-CAA-SERVFAIL", "effective CAA returned SERVFAIL", false)
	case CAATimeout:
		return blocked("CERTIFICATE-CAA-TIMEOUT", "effective CAA timed out", false)
	case CAAUnavailable:
		return blocked("CERTIFICATE-CAA-UNAVAILABLE", "effective CAA is unavailable", false)
	case CAAContradictory:
		return blocked("CERTIFICATE-CAA-CONTRADICTORY", "effective CAA results contradict each other", true)
	case CAAAvailable:
	default:
		return blocked("CERTIFICATE-CAA-UNSUPPORTED", "effective CAA status is unsupported", false)
	}
	var issueRecords int
	letsencryptSeen := false
	for _, record := range facts.Records {
		tag := strings.ToLower(strings.TrimSpace(record.Tag))
		if record.Flags&^uint8(128) != 0 || record.Flags&128 != 0 && tag != "issue" && tag != "issuewild" && tag != "iodef" {
			return blocked("CERTIFICATE-CAA-CRITICAL", "effective CAA contains a critical unknown property or unsupported flags", true)
		}
		if tag != "issue" {
			continue
		}
		issueRecords++
		parts := strings.Split(record.Value, ";")
		if !strings.EqualFold(strings.TrimSpace(parts[0]), "letsencrypt.org") {
			continue
		}
		letsencryptSeen = true
		methodOK := true
		methodSeen := false
		for _, parameter := range parts[1:] {
			key, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if !ok || !strings.EqualFold(key, "validationmethods") || methodSeen {
				return blocked("CERTIFICATE-CAA-PARAMETER", "effective CAA contains an unsupported or malformed issuer parameter", true)
			}
			methodSeen = true
			methods := strings.Split(strings.ToLower(value), ",")
			for index := range methods {
				methods[index] = strings.TrimSpace(methods[index])
			}
			methodOK = slices.Contains(methods, "http-01")
		}
		if methodOK {
			return caaAssessment{allowed: true}
		}
	}
	if issueRecords == 0 {
		return caaAssessment{allowed: true}
	}
	if letsencryptSeen {
		return blocked("CERTIFICATE-CAA-METHOD", "effective CAA permits letsencrypt.org only with another validation method", true)
	}
	return blocked("CERTIFICATE-CAA-ISSUER", "effective CAA excludes letsencrypt.org", true)
}

func versionAtLeast(version string, major, minor int) bool {
	parts := versionText.FindStringSubmatch(version)
	if parts == nil {
		return false
	}
	gotMajor, majorErr := strconv.Atoi(parts[1])
	gotMinor, minorErr := strconv.Atoi(parts[2])
	return majorErr == nil && minorErr == nil && (gotMajor > major || gotMajor == major && gotMinor >= minor)
}

type PlanRequest struct {
	View                        ViewRequest
	Lineage                     Lineage
	ChangeSet                   string
	StartingRevision            uint64
	StartingStateSHA256         string
	DesiredStateSHA256          string
	HTTP01                      systemchanges.HTTP01Authority
	DirectTLS                   systemchanges.DirectTLSAuthority
	OwnerEmail                  string
	SubscriberAgreementReviewed bool
	StandingRenewal             bool
	RenewalPolicyApproved       bool
	FreshInstallation           systemchanges.FreshInstallationAuthority
	FreshDNS                    FreshDNSAuthority
}

type OrderContract struct {
	Lineage         Lineage
	RequiredProfile string
	Identity        string
	CertName        string
	OwnerEmail      string
	Staging         bool
	ConfigDirectory string
	Account         string
}

type Plan struct {
	identity, sha256 string
	request          PlanRequest
	orders           []OrderContract
	steps            []systemchanges.Step
	checks           []systemchanges.Check
	used             *atomic.Bool
	stateUsed        *atomic.Bool
}

func (plan *Plan) Identity() string {
	if plan == nil {
		return ""
	}
	return plan.identity
}
func (plan *Plan) SHA256() string {
	if plan == nil {
		return ""
	}
	return plan.sha256
}
func (plan *Plan) Orders() []OrderContract {
	if plan == nil {
		return nil
	}
	return append([]OrderContract(nil), plan.orders...)
}
func (plan *Plan) Steps() []systemchanges.Step {
	if plan == nil {
		return nil
	}
	return append([]systemchanges.Step(nil), plan.steps...)
}
func (plan *Plan) Checks() []systemchanges.Check {
	if plan == nil {
		return nil
	}
	return append([]systemchanges.Check(nil), plan.checks...)
}

func (plan *Plan) MatchesDesiredState(renewalPolicy bool, ownerEmail, acmeAccountID, ipCertificateID, ipServingPointer, domainCertificateID, domainServingPointer, domainHostname string) bool {
	if plan == nil {
		return false
	}
	return renewalPolicy && ownerEmail == plan.request.OwnerEmail && acmeAccountID == "letsencrypt" && ipCertificateID == ipCertName && ipServingPointer == "/var/lib/sbxr/certificates/ip/current" && domainCertificateID == domainCertName && domainServingPointer == "/var/lib/sbxr/certificates/domain/current" && domainHostname == plan.request.View.DirectHostname
}

// StateProfileSetupCertificate binds the domain-certificate contribution to
// one exact staged setup lineage without exposing certificate material.
func (plan *Plan) StateProfileSetupCertificate() (startingRevision, candidateRevision uint64, startingStateSHA256, desiredStateSHA256, changeSet string, valid bool) {
	if plan == nil || plan.request.Lineage != DomainLineage || plan.request.StandingRenewal || plan.identity == "" || plan.sha256 == "" || plan.stateUsed == nil || !plan.stateUsed.CompareAndSwap(false, true) {
		return 0, 0, "", "", "", false
	}
	return plan.request.StartingRevision, plan.request.StartingRevision + 1, plan.request.StartingStateSHA256, plan.request.DesiredStateSHA256, plan.request.ChangeSet, true
}

func (plan *Plan) SoftwareLifecycleInstallContribution() lifecyclecontract.InstallContribution {
	if plan == nil || plan.request.StartingRevision != 1 || plan.request.StartingStateSHA256 != "" || plan.request.StandingRenewal {
		return lifecyclecontract.InstallContribution{}
	}
	name := "Certificate Lifecycle IP"
	if plan.request.Lineage == DomainLineage {
		name = "Certificate Lifecycle domain"
	} else if plan.request.Lineage != IPLineage {
		return lifecyclecontract.InstallContribution{}
	}
	return lifecyclecontract.InstallContribution{Name: name, Owner: systemchanges.CertificateModule, Identity: plan.identity, SHA256: plan.sha256, StableSHA256: plan.sha256, ChangeSet: plan.request.ChangeSet, DesiredStateSHA256: plan.request.DesiredStateSHA256, Steps: plan.Steps(), Checks: plan.Checks(), Details: []string{plan.String()}}
}

type FreshInstallContribution struct {
	proof lifecyclecontract.InstallContribution
}

func NewFreshInstallContribution(ip, domain *Plan) (FreshInstallContribution, bool) {
	ipProof, domainProof := ip.SoftwareLifecycleInstallContribution(), domain.SoftwareLifecycleInstallContribution()
	if ipProof.Name != "Certificate Lifecycle IP" || domainProof.Name != "Certificate Lifecycle domain" || ipProof.ChangeSet != domainProof.ChangeSet || ipProof.DesiredStateSHA256 != domainProof.DesiredStateSHA256 {
		return FreshInstallContribution{}, false
	}
	digest := sha256.Sum256([]byte(ipProof.SHA256 + domainProof.SHA256))
	checksum := hex.EncodeToString(digest[:])
	return FreshInstallContribution{proof: lifecyclecontract.InstallContribution{
		Name: "Certificate Lifecycle", Owner: systemchanges.CertificateModule, Identity: "certificate-install-" + checksum[:12], SHA256: checksum, StableSHA256: checksum,
		ChangeSet: ipProof.ChangeSet, DesiredStateSHA256: ipProof.DesiredStateSHA256,
		Steps: append(append([]systemchanges.Step(nil), ipProof.Steps...), domainProof.Steps...), Checks: append(append([]systemchanges.Check(nil), ipProof.Checks...), domainProof.Checks...), Details: append(append([]string(nil), ipProof.Details...), domainProof.Details...),
	}}, true
}

func (value FreshInstallContribution) SoftwareLifecycleInstallContribution() lifecyclecontract.InstallContribution {
	return value.proof
}
func (plan *Plan) Consume() bool {
	return plan != nil && plan.used != nil && plan.used.CompareAndSwap(false, true)
}
func (plan *Plan) String() string {
	if plan == nil {
		return "Certificate Lifecycle Plan: unavailable"
	}
	if plan.request.Lineage == DomainLineage {
		return fmt.Sprintf("Certificate Lifecycle Plan %s: open one reviewed HTTP-01 rule, prove isolated staging, order and activate only %s for the Direct TLS Hostname, restart sing-box, prove Hysteria2, TUIC, and AnyTLS separately, then close the recorded rule", plan.identity, domainCertName)
	}
	return fmt.Sprintf("Certificate Lifecycle Plan %s: open one reviewed HTTP-01 rule, prove isolated staging, order and activate only %s for the selected IP, then close the recorded rule; %s remains planned separately", plan.identity, ipCertName, domainCertName)
}
func (plan *Plan) GoString() string { return plan.String() }

type PlanResult struct {
	Plan   *Plan
	Health Health
}

func (module Interface) Plan(ctx context.Context, request PlanRequest) PlanResult {
	if request.FreshDNS.cell != nil {
		view, valid := request.FreshDNS.apply(request.DesiredStateSHA256, request.View)
		if !valid {
			return PlanResult{Health: health(time.Time{}, Failed, "CERTIFICATE-PLAN-FRESH-DNS", "The fresh Direct DNS Plan is stale", "Network Policy and Cloudflare Tunnel do not agree", "one exact reviewed fresh-install DNS authority")}
		}
		request.View = view
	}
	view := module.View(ctx, request.View)
	if view.Health.Outcome != Healthy {
		return PlanResult{Health: view.Health}
	}
	if !ValidOwnerEmail(request.OwnerEmail) {
		finding := health(view.Health.Time, Failed, "CERTIFICATE-PLAN-OWNER-EMAIL", "The reviewed registration identity is invalid", "the Owner email is missing, malformed, named, or contains control data", "one exact reviewed Owner contact email")
		finding.NextActions = []string{"Enter and review one Owner contact email", "Back"}
		return PlanResult{Health: finding}
	}
	if !request.SubscriberAgreementReviewed {
		finding := health(view.Health.Time, Failed, "CERTIFICATE-PLAN-AGREEMENT", "Subscriber agreement approval is missing", "the Owner has not reviewed and approved the subscriber agreement", "explicit Owner approval for Certbot --agree-tos")
		finding.NextActions = []string{"Review and approve the subscriber agreement", "Back"}
		return PlanResult{Health: finding}
	}
	freshInstallation := request.FreshInstallation.CertificateLifecycleFreshInstallation()
	validStartingState := freshInstallation && request.StartingRevision == 1 && request.StartingStateSHA256 == "" || !freshInstallation && request.StartingRevision > 0 && stateSHA256.MatchString(request.StartingStateSHA256)
	if !planName.MatchString(request.ChangeSet) || !validStartingState || !stateSHA256.MatchString(request.DesiredStateSHA256) {
		finding := health(view.Health.Time, Failed, "CERTIFICATE-PLAN-STATE", "The starting State lineage is invalid", "the starting revision or State checksum is missing or malformed", "one exact current State revision and SHA-256")
		finding.NextActions = []string{"Reload current State and build a fresh Plan", "Back"}
		return PlanResult{Health: finding}
	}
	lineage := request.Lineage
	if lineage == "" {
		lineage = IPLineage
	}
	request.Lineage = lineage
	due := lineage == IPLineage && view.IP.Valid && view.IP.Due || lineage == DomainLineage && view.Domain.Valid && view.Domain.Due
	if request.StandingRenewal && (!request.RenewalPolicyApproved || !due) {
		finding := health(view.Health.Time, Failed, "CERTIFICATE-RENEWAL-POLICY", "The unattended renewal is outside the standing policy", "the policy is absent or the requested fixed lineage is not valid and due", "one approved due sbxr-ip or sbxr-domain renewal branch")
		finding.NextActions = []string{"Create a fresh reviewed Plan", "Back"}
		return PlanResult{Health: finding}
	}
	open, close, selectedIP, http01Digest, networkRevision, http01Err := systemchanges.NewHTTP01Steps(request.HTTP01)
	if http01Err != nil || selectedIP != request.View.SelectedIP || networkRevision != request.StartingRevision {
		finding := health(view.Health.Time, Failed, "CERTIFICATE-PLAN-NETWORK-POLICY", "The HTTP-01 Network Policy contribution is invalid", "no exact fresh Network Policy authority for the selected IP", "one Network Policy-produced temporary port-80 contribution")
		return PlanResult{Health: finding}
	}
	orders := []OrderContract{
		stagingOrder(IPLineage, ipProfile, request.View.SelectedIP, ipCertName, request.OwnerEmail),
		{Lineage: IPLineage, RequiredProfile: ipProfile, Identity: request.View.SelectedIP, CertName: ipCertName, OwnerEmail: request.OwnerEmail, ConfigDirectory: "/var/lib/sbxr/certbot/production", Account: "production"},
		stagingOrder(DomainLineage, domainProfile, request.View.DirectHostname, domainCertName, request.OwnerEmail),
		{Lineage: DomainLineage, RequiredProfile: domainProfile, Identity: request.View.DirectHostname, CertName: domainCertName, OwnerEmail: request.OwnerEmail, ConfigDirectory: "/var/lib/sbxr/certbot/production", Account: "production"},
	}
	var steps []systemchanges.Step
	var stepErr error
	directTLSDigest := ""
	checks := []systemchanges.Check{
		{Owner: systemchanges.CertificateModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CERTIFICATE-IP-CANDIDATE"},
		{Owner: systemchanges.CertificateModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CERTIFICATE-IP-HTTPS"},
	}
	identityPrefix := "certificate-ip-"
	if lineage == IPLineage {
		steps, stepErr = certificateTransactionSteps(open, close, orders[:2], request.View.SelectedIP, 0, "")
	} else if lineage == DomainLineage {
		var directTLSRevision uint64
		var destinationIP, hostname string
		var directTLSChecks []systemchanges.Check
		directTLSRevision, destinationIP, hostname, directTLSDigest, directTLSChecks, stepErr = systemchanges.NewDirectTLSChecks(request.DirectTLS)
		if stepErr == nil && (directTLSRevision != request.StartingRevision || destinationIP != request.View.SelectedIP || hostname != request.View.DirectHostname) {
			stepErr = errors.New("stale Connection Profiles Direct TLS contribution")
		}
		if stepErr == nil {
			steps, stepErr = certificateTransactionSteps(open, close, orders[2:], destinationIP, directTLSRevision, directTLSDigest)
		}
		identityPrefix = "certificate-domain-"
		checks = append([]systemchanges.Check{
			{Owner: systemchanges.CertificateModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CERTIFICATE-DOMAIN-CANDIDATE"},
		}, directTLSChecks...)
	} else {
		stepErr = errors.New("unsupported certificate lineage")
	}
	if stepErr != nil {
		finding := health(view.Health.Time, Failed, "CERTIFICATE-PLAN-TRANSACTION", "The certificate transaction is invalid", "the reviewed lineage, firewall, or certificate step contract is incomplete", "one exact reversible HTTP-01 fixed-lineage transaction")
		return PlanResult{Health: finding}
	}
	binding := struct {
		View                                      ViewRequest
		ChangeSet                                 string
		Revision                                  uint64
		StartingSHA256, DesiredSHA256, OwnerEmail string
		Agreement                                 bool
		StandingRenewal                           bool
		RenewalPolicyApproved                     bool
		HTTP01Digest                              string
		DirectTLSDigest                           string
		Observation                               Observation
		Orders                                    []OrderContract
	}{request.View, request.ChangeSet, request.StartingRevision, request.StartingStateSHA256, request.DesiredStateSHA256, request.OwnerEmail, request.SubscriberAgreementReviewed, request.StandingRenewal, request.RenewalPolicyApproved, http01Digest, directTLSDigest, view.observation, orders}
	encoded, _ := json.Marshal(binding)
	digest := sha256.Sum256(encoded)
	sha := hex.EncodeToString(digest[:])
	plan := &Plan{identity: identityPrefix + sha[:12], sha256: sha, request: request, orders: orders, steps: steps, checks: checks, used: &atomic.Bool{}, stateUsed: &atomic.Bool{}}
	return PlanResult{Plan: plan, Health: Health{Time: view.Health.Time, Module: "Certificate Lifecycle", Outcome: Healthy, Code: "CERTIFICATE-PLAN-READY", NextActions: []string{"Review Plan", "Back"}}}
}

func (plan *Plan) Apply(module systemchanges.Interface, prepared systemchanges.PreparedStateCommit, starting systemchanges.StateLineage, volatileSHA256 string, disk systemchanges.DiskRequirement) systemchanges.ApplyResult {
	if plan != nil && plan.request.StandingRenewal {
		return module.Apply(nil)
	}
	change, err := plan.buildChangeSet(prepared, starting, volatileSHA256, disk, false)
	if err != nil {
		return module.Apply(nil)
	}
	return module.Apply(change)
}

// RenewalChangeSet consumes a standing renewal Plan and returns its exact
// typed Change Set. Callers build the Plan and invoke this method only inside
// System Changes' ApplyFreshCertificateRenewal callback after lock acquisition.
func (plan *Plan) RenewalChangeSet(prepared systemchanges.PreparedStateCommit, starting systemchanges.StateLineage, volatileSHA256 string, disk systemchanges.DiskRequirement) (*systemchanges.ChangeSet, error) {
	return plan.buildChangeSet(prepared, starting, volatileSHA256, disk, true)
}

func (plan *Plan) buildChangeSet(prepared systemchanges.PreparedStateCommit, starting systemchanges.StateLineage, volatileSHA256 string, disk systemchanges.DiskRequirement, renewalOnly bool) (*systemchanges.ChangeSet, error) {
	if plan == nil || plan.used == nil || !plan.used.CompareAndSwap(false, true) || prepared == nil || !stateSHA256.MatchString(volatileSHA256) || starting.Status != systemchanges.Managed || starting.Revision != plan.request.StartingRevision || starting.SHA256 != plan.request.StartingStateSHA256 {
		return nil, errors.New("certificate Plan authority invalid")
	}
	changeSet, revision, startingSHA256, candidateSHA256, planIdentity, planSHA256, valid := prepared.SystemChangesPreparedState()
	if !valid || changeSet != plan.request.ChangeSet || revision != starting.Revision+1 || startingSHA256 != starting.SHA256 || candidateSHA256 != plan.request.DesiredStateSHA256 || planIdentity != plan.identity || planSHA256 != plan.sha256 {
		return nil, errors.New("prepared State does not match certificate Plan")
	}
	mutation := systemchanges.CertificateChangeMutation
	if plan.request.StandingRenewal {
		renewal, ok := prepared.(systemchanges.CertificateRenewalPreparedState)
		if !ok || renewal == nil {
			return nil, errors.New("standing certificate renewal scope unavailable")
		}
		ip, domain := renewal.SystemChangesIPCertificateRenewal(), renewal.SystemChangesDomainCertificateRenewal()
		if ip == domain || plan.request.Lineage == IPLineage && !ip || plan.request.Lineage == DomainLineage && !domain {
			return nil, errors.New("standing certificate renewal scope unavailable")
		}
		mutation = systemchanges.CertificateRenewalMutation
	} else if renewalOnly {
		return nil, errors.New("standing renewal Plan required")
	}
	change, err := systemchanges.NewChangeSet(systemchanges.ChangeSetSpec{
		Identity: plan.request.ChangeSet, Mutation: mutation, OutcomeOwner: systemchanges.CertificateModule,
		StartingState: starting, TargetStateSHA256: candidateSHA256,
		Plan: systemchanges.PlanBinding{Identity: plan.identity, SHA256: plan.sha256, VolatileSHA256: volatileSHA256}, PreparedState: prepared,
		Steps: plan.steps, Checks: plan.checks, Timeouts: systemchanges.Timeouts{Step: 5 * time.Minute, Check: 5 * time.Minute}, Disk: disk,
	})
	if err != nil {
		return nil, errors.New("certificate Change Set invalid")
	}
	return change, nil
}

func certificateTransactionSteps(open, close systemchanges.Step, orders []OrderContract, destinationIP string, directTLSRevision uint64, directTLSDigest string) ([]systemchanges.Step, error) {
	steps := []systemchanges.Step{open}
	for index, order := range orders {
		action := systemchanges.CertificateIPStage
		if order.Lineage == DomainLineage {
			action = systemchanges.CertificateDomainStage
		}
		if index == 1 && order.Lineage == IPLineage {
			action = systemchanges.CertificateIPOrder
		} else if index == 1 {
			action = systemchanges.CertificateDomainOrder
		}
		change := systemchanges.CertificateChange{Action: action, Identity: order.Identity, RequiredProfile: order.RequiredProfile, CertName: order.CertName, OwnerEmail: order.OwnerEmail, ConfigDirectory: order.ConfigDirectory, Account: order.Account}
		if order.Lineage == DomainLineage {
			change.DestinationIP = destinationIP
		}
		step, err := systemchanges.NewCertificateStep(change)
		if err != nil {
			return nil, err
		}
		steps = append(steps, step)
	}
	activateChange := systemchanges.CertificateChange{Action: systemchanges.CertificateIPActivate, Identity: orders[1].Identity, RequiredProfile: orders[1].RequiredProfile, CertName: orders[1].CertName, SubscriptionUnit: "sbxr-subscription.service"}
	if orders[1].Lineage == DomainLineage {
		activateChange.Action = systemchanges.CertificateDomainActivate
		activateChange.DestinationIP = destinationIP
		activateChange.SubscriptionUnit = ""
		activateChange.DirectTLSRevision = directTLSRevision
		activateChange.DirectTLSSHA256 = directTLSDigest
	}
	activate, err := systemchanges.NewCertificateStep(activateChange)
	if err != nil {
		return nil, err
	}
	return append(steps, activate, close), nil
}

func stagingOrder(lineage Lineage, profile, identity, certName, email string) OrderContract {
	return OrderContract{Lineage: lineage, RequiredProfile: profile, Identity: identity, CertName: certName, OwnerEmail: email, Staging: true, ConfigDirectory: "/var/lib/sbxr/certbot/staging/" + certName, Account: "disposable-staging-" + certName}
}
