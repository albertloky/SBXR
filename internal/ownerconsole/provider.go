package ownerconsole

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// CloudflareModule is the presentation-safe Owner Console seam for the
// Cloudflare Tunnel Module. Provider authority and mutations remain outside
// Owner Console.
type CloudflareModule interface {
	ViewCloudflare(context.Context) CloudflarePresentation
	ActOnCloudflare(context.Context, CloudflareRequest) CloudflareResponse
}

// CertificatesModule is the presentation-safe Owner Console seam for the
// Certificate Lifecycle Module.
type CertificatesModule interface {
	ViewCertificates(context.Context) CertificatesPresentation
	ReviewCertificateChange(context.Context, CertificateChange) ChangeReview
}

type CertificateStatus uint8

const (
	CertificateMissing CertificateStatus = iota + 1
	CertificateHealthy
	CertificateNeedsAttention
	CertificateFailed
	CertificateUnknown
)

func (status CertificateStatus) String() string {
	names := [...]string{"", "MISSING", "HEALTHY", "NEEDS ATTENTION", "FAILED", "UNKNOWN"}
	if int(status) >= len(names) {
		return ""
	}
	return names[status]
}

type CertificateLineage struct {
	Status                      CertificateStatus
	Identity, Profile, NotAfter string
	Due                         bool
	ActiveServingID             string
}

type CertificateScheduler struct {
	Service, Timer                                         string
	Enabled, Persistent, Serial, Randomized, ExactUnitPair bool
	NoCompetingScheduler                                   bool
	RunsPerDay                                             int
	Policy                                                 CertificateRenewalPolicy
}

type CertificateRenewalPolicy struct {
	Approved                                           bool
	IPDueWithin, IPFailureRetry, BusyLockRetry         time.Duration
	UrgentAt, UrgentBusyLockRetry, DomainFallbackAfter time.Duration
	DomainUsesARI                                      bool
}

type CertificateOutcome uint8

const (
	NoCertificateOutcome CertificateOutcome = iota
	CertificateActivated
	CertificateRolledBack
)

func (outcome CertificateOutcome) String() string {
	switch outcome {
	case CertificateActivated:
		return "ACTIVATED"
	case CertificateRolledBack:
		return "ROLLED BACK"
	default:
		return ""
	}
}

type CertificatesPresentation struct {
	IP, DirectTLS CertificateLineage
	Scheduler     CertificateScheduler
	LastOutcome   CertificateOutcome
}

type CertificateChange uint8

const (
	IssueIPCertificate CertificateChange = iota + 1
	RenewIPCertificate
	IssueDirectTLSCertificate
	RenewDirectTLSCertificate
)

func validatedCertificates(presentation CertificatesPresentation) (CertificatesPresentation, bool) {
	if !validCertificateLineage(presentation.IP, "shortlived") || !validCertificateLineage(presentation.DirectTLS, "tlsserver") {
		return CertificatesPresentation{}, false
	}
	scheduler := presentation.Scheduler
	if scheduler.Service != "sbxr-cert-renew.service" || scheduler.Timer != "sbxr-cert-renew.timer" || !scheduler.Enabled || !scheduler.Persistent || !scheduler.Serial || !scheduler.Randomized || !scheduler.ExactUnitPair || !scheduler.NoCompetingScheduler || scheduler.RunsPerDay < 2 || scheduler.RunsPerDay > 24 || !validCertificateRenewalPolicy(scheduler.Policy) || presentation.LastOutcome > CertificateRolledBack {
		return CertificatesPresentation{}, false
	}
	return presentation, true
}

func validCertificateRenewalPolicy(policy CertificateRenewalPolicy) bool {
	return policy.Approved && policy.IPDueWithin == 72*time.Hour && policy.IPFailureRetry == 6*time.Hour && policy.BusyLockRetry == time.Hour && policy.UrgentAt == 24*time.Hour && policy.UrgentBusyLockRetry == 15*time.Minute && policy.DomainUsesARI && policy.DomainFallbackAfter == 15*24*time.Hour
}

func validCertificateLineage(lineage CertificateLineage, profile string) bool {
	if lineage.Status.String() == "" || !safeLine(lineage.Identity) || lineage.Profile != profile || !safeOptionalLine(lineage.NotAfter) || !safeOptionalLine(lineage.ActiveServingID) {
		return false
	}
	if lineage.Status == CertificateMissing {
		return !lineage.Due && lineage.NotAfter == "" && lineage.ActiveServingID == ""
	}
	return safeLine(lineage.NotAfter) && lineage.ActiveServingID != ""
}

type certificateActionDefinition struct {
	label  string
	kind   certificateActionKind
	change CertificateChange
}

type certificateActionKind uint8

const (
	certificateReviewChange certificateActionKind = iota + 1
	certificateBack
)

func certificateActions(presentation CertificatesPresentation) []certificateActionDefinition {
	ipLabel, ipChange := "Review IP certificate issuance", IssueIPCertificate
	if presentation.IP.Status != CertificateMissing {
		ipLabel, ipChange = "Review IP certificate renewal", RenewIPCertificate
	}
	domainLabel, domainChange := "Review Direct TLS certificate issuance", IssueDirectTLSCertificate
	if presentation.DirectTLS.Status != CertificateMissing {
		domainLabel, domainChange = "Review Direct TLS certificate renewal", RenewDirectTLSCertificate
	}
	return []certificateActionDefinition{
		{label: ipLabel, kind: certificateReviewChange, change: ipChange},
		{label: domainLabel, kind: certificateReviewChange, change: domainChange},
		{label: "Back", kind: certificateBack},
	}
}

func certificateLines(presentation CertificatesPresentation, valid bool, selected int) []string {
	if !valid {
		return []string{"Certificate facts are unavailable.", "", "No lineage, scheduler, activation, rollback, or action was inferred.", "", "> Back"}
	}
	lines := []string{
		fmt.Sprintf("IP certificate - %s - %s - %s", presentation.IP.Identity, presentation.IP.Profile, presentation.IP.Status),
		"IP expiry " + shownOrUnavailable(presentation.IP.NotAfter),
		fmt.Sprintf("IP renewal due - %t - at 72 hours or less", presentation.IP.Due),
		fmt.Sprintf("Direct TLS certificate - %s - %s - %s", presentation.DirectTLS.Identity, presentation.DirectTLS.Profile, presentation.DirectTLS.Status),
		"Direct TLS expiry " + shownOrUnavailable(presentation.DirectTLS.NotAfter),
		fmt.Sprintf("Direct TLS renewal due - %t - ACME Renewal Information, fallback 15 days", presentation.DirectTLS.Due),
		"Scheduler " + presentation.Scheduler.Service,
		"Timer " + presentation.Scheduler.Timer,
		fmt.Sprintf("serial - persistent - randomized - %d runs/day", presentation.Scheduler.RunsPerDay),
		"Standing Certificate Renewal Policy - global mutation lock per due Change Set",
		"IP failure retry 6 hours; busy lock 1 hour, or 15 minutes below 24 hours",
	}
	if outcome := presentation.LastOutcome.String(); outcome != "" {
		lines = append(lines, "Last typed outcome "+outcome)
	}
	lines = append(lines, "Certificate Lifecycle receives no Cloudflare token.", "No Cloudflare DNS-01 or CAA creation.", "Certificate private keys and ACME account material never render.", "")
	actions := certificateActions(presentation)
	labels := make([]string, len(actions))
	for index, action := range actions {
		labels[index] = action.label
	}
	return append(lines, selectedLines(labels, selected)...)
}

func shownOrUnavailable(value string) string {
	if value == "" {
		return "not issued"
	}
	return value
}

type CloudflarePresentationKind uint8

const (
	CloudflareWalkthroughPresentation CloudflarePresentationKind = iota + 1
	CloudflareCredentialPresentation
	CloudflareMissingPermissionPresentation
	CloudflarePendingZonePresentation
)

type CloudflarePresentation struct {
	Kind              CloudflarePresentationKind
	Walkthrough       CloudflareWalkthroughFacts
	Credential        CloudflareCredential
	MissingPermission CloudflareMissingPermission
	PendingZone       CloudflarePendingZone
}

type CloudflareWalkthroughFacts struct {
	DashboardURL, AccountTokensPage, CreateControl, TokenName string
	DNSRecordsPage, TunnelsPage                               string
	AccountControl, ZoneControl                               string
	AccountResource, ZoneResource, SummaryControl             string
	RejectsGlobalAPIKey, RejectsBroadAuthority                bool
	RejectsAPITokensWrite                                     bool
}

type CloudflareCredential struct {
	Status                   CloudflareCredentialStatus
	FirstFour, LastFour      string
	Account, Zone            string
	LastVerification, Expiry string
	Uses                     []string
	Guidance                 []string
	HelpURL                  string
}

type CloudflareCredentialStatus uint8

const (
	CloudflareTokenActive CloudflareCredentialStatus = iota + 1
	CloudflareTokenNeedsAttention
	CloudflareTokenUnknown
)

func (status CloudflareCredentialStatus) String() string {
	switch status {
	case CloudflareTokenActive:
		return "active"
	case CloudflareTokenNeedsAttention:
		return "needs attention"
	case CloudflareTokenUnknown:
		return "unknown"
	default:
		return ""
	}
}

type CloudflareMissingPermission struct {
	Capability, Account, Zone, Found, Required, WhyStopped, Evidence string
	DashboardSteps                                                   []string
	HelpURL                                                          string
}

type CloudflarePendingZone struct {
	Zone                                string
	AssignedNameServers                 []string
	ObservedNameServers, RegistrarSteps []string
	Evidence                            string
}

type CloudflareAction uint8

const (
	VerifyInitialManagementToken CloudflareAction = iota + 1
	CheckCurrentManagementToken
	VerifyReplacementManagementToken
	ReviewManagementTokenRemoval
	ReviewTunnelRunTokenRotation
	WaitAnotherTenMinutes
)

type CloudflareRequest struct {
	Action CloudflareAction
	Token  string
}

type CloudflareResponse struct {
	Presentation *CloudflarePresentation
	Review       *ChangeReview
}

func validatedCloudflarePresentation(presentation CloudflarePresentation) (CloudflarePresentation, bool) {
	definition, ok := cloudflarePresentationDefinitions[presentation.Kind]
	if !ok {
		return CloudflarePresentation{}, false
	}
	return definition.validate(presentation)
}

func validateCloudflareWalkthrough(presentation CloudflarePresentation) (CloudflarePresentation, bool) {
	facts := presentation.Walkthrough
	valid := facts.DashboardURL == "https://dash.cloudflare.com/" &&
		facts.AccountTokensPage == "Manage Account > Account API Tokens" &&
		facts.CreateControl == "Create Token" &&
		facts.TokenName == "SBXR - selected account / selected zone" &&
		facts.DNSRecordsPage == "selected domain > DNS > Records" &&
		facts.TunnelsPage == "Cloudflare One > Networks > Tunnels & Mesh" &&
		facts.AccountControl == "Permissions > Account > Account API Tokens > Read; Cloudflare Tunnel > Edit" &&
		facts.ZoneControl == "Permissions > Zone > DNS > Edit" &&
		facts.AccountResource == "Account Resources > Include > Specific account > selected account" &&
		facts.ZoneResource == "Zone Resources > Include > Specific zone > selected zone" &&
		facts.SummaryControl == "Continue to summary > Create Token > copy once" &&
		facts.RejectsGlobalAPIKey && facts.RejectsBroadAuthority && facts.RejectsAPITokensWrite && emptyCloudflareCredential(presentation.Credential) && emptyMissingPermission(presentation.MissingPermission) && emptyPendingZone(presentation.PendingZone)
	return presentation, valid
}

func validateCloudflareCredential(presentation CloudflarePresentation) (CloudflarePresentation, bool) {
	credential := presentation.Credential
	valid := credential.Status.String() != "" && safeProviderLines([]string{credential.FirstFour, credential.LastFour, credential.Account, credential.Zone, credential.LastVerification}, 5) &&
		len([]rune(credential.FirstFour)) == 4 && len([]rune(credential.LastFour)) == 4 && safeOptionalLine(credential.Expiry) && completeStrings(credential.Uses, 16) && completeStrings(credential.Guidance, 8) && credential.HelpURL == "https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/" && presentation.Walkthrough == (CloudflareWalkthroughFacts{}) && emptyMissingPermission(presentation.MissingPermission) && emptyPendingZone(presentation.PendingZone)
	if !valid {
		return CloudflarePresentation{}, false
	}
	presentation.Credential.Uses = append([]string(nil), credential.Uses...)
	presentation.Credential.Guidance = append([]string(nil), credential.Guidance...)
	return presentation, true
}

func validateCloudflareMissingPermission(presentation CloudflarePresentation) (CloudflarePresentation, bool) {
	missing := presentation.MissingPermission
	valid := safeProviderLines([]string{missing.Capability, missing.Account, missing.Zone, missing.Found, missing.Required, missing.WhyStopped, missing.Evidence}, 7) && completeStrings(missing.DashboardSteps, 8) && missing.HelpURL == "https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/" && presentation.Walkthrough == (CloudflareWalkthroughFacts{}) && emptyCloudflareCredential(presentation.Credential) && emptyPendingZone(presentation.PendingZone)
	if !valid {
		return CloudflarePresentation{}, false
	}
	presentation.MissingPermission.DashboardSteps = append([]string(nil), missing.DashboardSteps...)
	return presentation, true
}

func validateCloudflarePendingZone(presentation CloudflarePresentation) (CloudflarePresentation, bool) {
	pending := presentation.PendingZone
	valid := safeLine(pending.Zone) && completeStrings(pending.AssignedNameServers, 4) && safeStrings(pending.ObservedNameServers, 4) && completeStrings(pending.RegistrarSteps, 8) && safeLine(pending.Evidence) && presentation.Walkthrough == (CloudflareWalkthroughFacts{}) && emptyCloudflareCredential(presentation.Credential) && emptyMissingPermission(presentation.MissingPermission)
	if !valid {
		return CloudflarePresentation{}, false
	}
	presentation.PendingZone.AssignedNameServers = append([]string(nil), pending.AssignedNameServers...)
	presentation.PendingZone.ObservedNameServers = append([]string(nil), pending.ObservedNameServers...)
	presentation.PendingZone.RegistrarSteps = append([]string(nil), pending.RegistrarSteps...)
	return presentation, true
}

func safeProviderLines(values []string, count int) bool {
	return len(values) == count && safeStrings(values, count)
}

func emptyPendingZone(pending CloudflarePendingZone) bool {
	return pending.Zone == "" && len(pending.AssignedNameServers) == 0 && len(pending.ObservedNameServers) == 0 && len(pending.RegistrarSteps) == 0 && pending.Evidence == ""
}

func emptyMissingPermission(missing CloudflareMissingPermission) bool {
	return missing.Capability == "" && missing.Account == "" && missing.Zone == "" && missing.Found == "" && missing.Required == "" && missing.WhyStopped == "" && missing.Evidence == "" && len(missing.DashboardSteps) == 0 && missing.HelpURL == ""
}

func emptyCloudflareCredential(credential CloudflareCredential) bool {
	return credential.Status == 0 && credential.FirstFour == "" && credential.LastFour == "" && credential.Account == "" && credential.Zone == "" && credential.LastVerification == "" && credential.Expiry == "" && len(credential.Uses) == 0 && len(credential.Guidance) == 0 && credential.HelpURL == ""
}

type cloudflareActionKind uint8

const (
	cloudflareModuleAction cloudflareActionKind = iota + 1
	cloudflareBeginReplacement
	cloudflareBack
)

type cloudflareActionDefinition struct {
	label   string
	kind    cloudflareActionKind
	request CloudflareAction
}

type cloudflarePresentationDefinition struct {
	validate func(CloudflarePresentation) (CloudflarePresentation, bool)
	actions  func(bool) []cloudflareActionDefinition
	lines    func(CloudflarePresentation, string, bool) []string
}

var cloudflarePresentationDefinitions = map[CloudflarePresentationKind]cloudflarePresentationDefinition{
	CloudflareWalkthroughPresentation: {
		validate: validateCloudflareWalkthrough,
		actions: func(bool) []cloudflareActionDefinition {
			return []cloudflareActionDefinition{
				{label: "Verify token", kind: cloudflareModuleAction, request: VerifyInitialManagementToken},
				{label: "Back and continue later", kind: cloudflareBack},
			}
		},
		lines: cloudflareWalkthroughLines,
	},
	CloudflareCredentialPresentation: {
		validate: validateCloudflareCredential,
		actions: func(replacing bool) []cloudflareActionDefinition {
			if replacing {
				return []cloudflareActionDefinition{
					{label: "Verify replacement", kind: cloudflareModuleAction, request: VerifyReplacementManagementToken},
					{label: "Back", kind: cloudflareBack},
				}
			}
			return []cloudflareActionDefinition{
				{label: "Check now", kind: cloudflareModuleAction, request: CheckCurrentManagementToken},
				{label: "Replace token", kind: cloudflareBeginReplacement},
				{label: "Remove from SBXR", kind: cloudflareModuleAction, request: ReviewManagementTokenRemoval},
				{label: "Rotate genuine Tunnel run token", kind: cloudflareModuleAction, request: ReviewTunnelRunTokenRotation},
			}
		},
		lines: cloudflareCredentialLines,
	},
	CloudflareMissingPermissionPresentation: {
		validate: validateCloudflareMissingPermission,
		actions: func(bool) []cloudflareActionDefinition {
			return []cloudflareActionDefinition{
				{label: "Check current token again", kind: cloudflareModuleAction, request: CheckCurrentManagementToken},
				{label: "Enter replacement token", kind: cloudflareBeginReplacement},
				{label: "Verify replacement", kind: cloudflareModuleAction, request: VerifyReplacementManagementToken},
				{label: "Back", kind: cloudflareBack},
			}
		},
		lines: cloudflareMissingPermissionLines,
	},
	CloudflarePendingZonePresentation: {
		validate: validateCloudflarePendingZone,
		actions: func(bool) []cloudflareActionDefinition {
			return []cloudflareActionDefinition{
				{label: "Check again", kind: cloudflareModuleAction, request: CheckCurrentManagementToken},
				{label: "Wait another 10 minutes", kind: cloudflareModuleAction, request: WaitAnotherTenMinutes},
				{label: "Back and continue later", kind: cloudflareBack},
			}
		},
		lines: cloudflarePendingZoneLines,
	},
}

func cloudflareActions(kind CloudflarePresentationKind, replacing bool) []cloudflareActionDefinition {
	definition, ok := cloudflarePresentationDefinitions[kind]
	if !ok {
		return []cloudflareActionDefinition{{label: "Back", kind: cloudflareBack}}
	}
	return definition.actions(replacing)
}

func cloudflareLines(presentation CloudflarePresentation, valid bool, input string, selected int, replacing, revealed bool) []string {
	if !valid {
		return []string{"Cloudflare facts are unavailable.", "", "No provider authority, health, token state, or action was inferred.", "", "> Back"}
	}
	definition, ok := cloudflarePresentationDefinitions[presentation.Kind]
	if !ok {
		return []string{"Cloudflare facts are unavailable."}
	}
	visibleInput := maskedTokenInput(input)
	if revealed && input != "" {
		visibleInput = strconv.QuoteToGraphic(input)
	}
	lines := definition.lines(presentation, visibleInput, replacing)
	if revealed && input != "" {
		lines = append(lines, "TOKEN REVEALED — screenshots and recordings can capture it.", "")
	}
	return append(lines, selectedCloudflareLines(definition.actions(replacing), selected)...)
}

func cloudflareWalkthroughLines(presentation CloudflarePresentation, input string, _ bool) []string {
	facts := presentation.Walkthrough
	lines := []string{
		facts.DashboardURL,
		facts.AccountTokensPage,
		facts.CreateControl,
		"Name - " + facts.TokenName,
		facts.DNSRecordsPage,
		facts.TunnelsPage,
		facts.AccountControl,
		facts.ZoneControl,
		facts.AccountResource,
		facts.ZoneResource,
		facts.SummaryControl,
		"Do not use a Global API Key.",
		"Account API Tokens Write is not requested.",
		"Broad unrelated authority is rejected.",
		"Scoped token - masked and memory-only: " + input,
		"",
	}
	return lines
}

func cloudflareCredentialLines(presentation CloudflarePresentation, input string, replacing bool) []string {
	credential := presentation.Credential
	lines := []string{
		"Token " + credential.Status.String() + " - " + credential.FirstFour + "..." + credential.LastFour,
		"Bound account " + credential.Account,
		"Bound zone " + credential.Zone,
		"Last verification " + credential.LastVerification,
	}
	if credential.Expiry != "" {
		lines = append(lines, "Expiry "+credential.Expiry)
	}
	lines = append(lines, "Current uses")
	for _, use := range credential.Uses {
		lines = append(lines, "- "+use)
	}
	lines = append(lines, "")
	if replacing {
		lines = append(lines, "Create the replacement Account API Token")
		lines = append(lines, credential.Guidance...)
		lines = append(lines, terminalHyperlinkLines(credential.HelpURL, 58)...)
		lines = append(lines, "Current token stays active until the candidate verifies and its exact Plan is approved.", "Replacement token - masked and memory-only: "+input, "")
	}
	return lines
}

func cloudflareMissingPermissionLines(presentation CloudflarePresentation, input string, _ bool) []string {
	missing := presentation.MissingPermission
	lines := []string{"MISSING PERMISSION CORRECTION", "Problem: " + missing.Capability + " is unavailable", "Account: " + missing.Account, "Zone: " + missing.Zone, "Found: " + missing.Found, "Required: " + missing.Required, "Why SBXR stopped: " + missing.WhyStopped, "Current dashboard steps"}
	for _, step := range missing.DashboardSteps {
		lines = append(lines, "- "+step)
	}
	lines = append(lines, terminalHyperlinkLines(missing.HelpURL, 58)...)
	lines = append(lines, "Replacement token - masked and memory-only: "+input, "Redacted evidence: "+missing.Evidence, "")
	return lines
}

func cloudflarePendingZoneLines(presentation CloudflarePresentation, _ string, _ bool) []string {
	pending := presentation.PendingZone
	lines := []string{"PENDING ZONE CORRECTION", "Zone " + pending.Zone, "Assigned nameservers"}
	for _, server := range pending.AssignedNameServers {
		lines = append(lines, "- "+server)
	}
	lines = append(lines, "Publicly observed nameservers")
	for _, server := range pending.ObservedNameServers {
		lines = append(lines, "- "+server)
	}
	for _, step := range pending.RegistrarSteps {
		lines = append(lines, "Owner step: "+step)
	}
	lines = append(lines, "Redacted evidence: "+pending.Evidence, "")
	return lines
}

func maskedTokenInput(input string) string {
	if input == "" {
		return "******** [empty  ]"
	}
	return "******** [entered]"
}

func selectedLines(labels []string, selected int) []string {
	lines := make([]string, len(labels))
	for index, label := range labels {
		prefix := "  "
		if index == selected {
			prefix = "> "
		}
		lines[index] = prefix + label
	}
	return lines
}

func selectedCloudflareLines(actions []cloudflareActionDefinition, selected int) []string {
	labels := make([]string, len(actions))
	for index, action := range actions {
		labels[index] = action.label
	}
	return selectedLines(labels, selected)
}

func providerPage(lines []string, actionCount, width, height, page int) []string {
	pages := providerPages(lines, actionCount, width, height)
	page = min(max(page, 0), len(pages)-1)
	result := append([]string{fmt.Sprintf("SECTION %d OF %d", page+1, len(pages))}, pages[page]...)
	if page+1 < len(pages) {
		return append(result, "", "> Enter Next section", "  Esc Previous section or Back")
	}
	actions := lines[len(lines)-actionCount:]
	return append(result, append([]string{""}, actions...)...)
}

func providerPageCount(lines []string, actionCount, width, height int) int {
	return len(providerPages(lines, actionCount, width, height))
}

func providerPages(lines []string, actionCount, width, height int) [][]string {
	facts := append([]string(nil), lines[:len(lines)-actionCount]...)
	for len(facts) > 0 && facts[len(facts)-1] == "" {
		facts = facts[:len(facts)-1]
	}
	// Reserve the frame, screen title, section heading, blank separator, and
	// every final action at every supported height.
	return minimumPages(facts, width, max(1, height-9-actionCount))
}
