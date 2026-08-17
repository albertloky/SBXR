package cloudflaretunnel

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/albertloky/SBXR/internal/networkpolicy"
)

const qualifiedOn = "2026-08-15"

var (
	immutableID  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	accountToken = regexp.MustCompile(`^cfat_[A-Za-z0-9_-]{35,75}$`)
	zoneName     = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

type Outcome string

const (
	Healthy        Outcome = "Healthy"
	NeedsAttention Outcome = "Needs attention"
	Failed         Outcome = "Failed"
	Unknown        Outcome = "Unknown"
)

type ManagementToken struct{ value string }

func NewManagementToken(value string) (ManagementToken, error) {
	lower := strings.ToLower(value)
	if !accountToken.MatchString(value) || strings.Contains(lower, "placeholder") || strings.Contains(lower, "your_token") {
		return ManagementToken{}, errors.New("Cloudflare account API token required")
	}
	return ManagementToken{value: value}, nil
}

func (ManagementToken) String() string   { return "Cloudflare management token: masked" }
func (ManagementToken) GoString() string { return "Cloudflare management token: masked" }

type VerifiedManagementToken struct {
	value string
	used  *atomic.Bool
}

func (VerifiedManagementToken) String() string {
	return "Verified Cloudflare management token: redacted"
}
func (VerifiedManagementToken) GoString() string {
	return "Verified Cloudflare management token: redacted"
}

// ConsumeInfrastructureSecret is the one-use handoff consumed only by State.
func (token VerifiedManagementToken) ConsumeInfrastructureSecret() (string, bool) {
	if token.used == nil || !token.used.CompareAndSwap(false, true) {
		return "", false
	}
	return token.value, true
}

type Clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
}

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

func (SystemClock) Sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type API interface {
	Observe(context.Context, ObservationRequest) (Observation, error)
}

type APIErrorKind string

const (
	APITemporary    APIErrorKind = "temporary"
	APIUnauthorized APIErrorKind = "unauthorized"
	APIForbidden    APIErrorKind = "forbidden"
	APINotFound     APIErrorKind = "not-found"
	APIMalformed    APIErrorKind = "malformed"
	APIAmbiguous    APIErrorKind = "ambiguous"
	APIPermanent    APIErrorKind = "permanent"
)

// APIError deliberately drops provider text at the Module boundary.
type APIError struct {
	Kind               APIErrorKind
	RequiredPermission PermissionKind
}

func (e APIError) Error() string { return "Cloudflare API " + string(e.Kind) + " failure" }

type Interface struct {
	api           API
	clock         Clock
	nativeIngress NativeIngressValidator
}

type NativeIngressValidator func(context.Context, []byte) error

func New(api API, clock Clock, validators ...NativeIngressValidator) Interface {
	validator := validateNativeIngress
	if len(validators) == 1 && validators[0] != nil {
		validator = validators[0]
	}
	return Interface{api: api, clock: clock, nativeIngress: validator}
}

func NewProduction() Interface { return New(NewProductionAPI(), SystemClock{}) }

func (i Interface) ObserveManagementTokenID(ctx context.Context, request ObservationRequest) (string, error) {
	if i.api == nil {
		return "", errors.New("Cloudflare token observer unavailable")
	}
	observed, err := i.api.Observe(ctx, request)
	if err != nil || observed.Account.ID != request.AccountID || observed.Zone.ID != request.ZoneID || !immutableID.MatchString(observed.Token.ID) || observed.Token.Status != "active" {
		return "", errors.New("Cloudflare token identity is unproved")
	}
	return observed.Token.ID, nil
}

func (i Interface) DeleteAndVerifyManagementToken(ctx context.Context, request ObservationRequest, tokenID string) error {
	api, ok := i.api.(interface {
		DeleteManagementToken(context.Context, DeleteManagementTokenRequest) error
	})
	if !ok || !immutableID.MatchString(tokenID) {
		return errors.New("Cloudflare token deletion unavailable")
	}
	observed, err := i.api.Observe(ctx, request)
	if apiErrorIs(err, APIUnauthorized) {
		return nil
	}
	if err != nil || observed.Account.ID != request.AccountID || observed.Zone.ID != request.ZoneID || observed.Token.ID != tokenID || observed.Token.Status != "active" {
		return errors.New("Cloudflare token identity is unproved")
	}
	if err := api.DeleteManagementToken(ctx, DeleteManagementTokenRequest{AccountID: request.AccountID, ID: tokenID, Token: request.Token}); err != nil {
		return errors.New("Cloudflare token deletion failed")
	}
	if _, err := i.api.Observe(ctx, request); !apiErrorIs(err, APIUnauthorized) {
		return errors.New("Cloudflare token deletion is unproved")
	}
	return nil
}

type ObservationRequest struct {
	AccountID string
	ZoneID    string
	ZoneName  string
	Token     ManagementToken
}

func (request ObservationRequest) String() string {
	return fmt.Sprintf("Cloudflare observation: account=%s zone=%s name=%s token=masked", request.AccountID, request.ZoneID, request.ZoneName)
}

func (request ObservationRequest) GoString() string { return request.String() }

type Observation struct {
	Account  AccountObservation
	Zone     ZoneObservation
	Token    TokenObservation
	Policies []TokenPolicy
}

type AccountObservation struct {
	ID   string
	Name string
}

type ZoneObservation struct {
	ID                  string
	AccountID           string
	Name                string
	Status              string
	AssignedNameServers []string
	ObservedNameServers []string
}

type TokenObservation struct {
	ID        string
	Status    string
	ExpiresOn *time.Time
}

type TokenPolicy struct {
	Effect           string
	PermissionGroups []string
	Resources        map[string]string
}

type ViewRequest struct {
	AccountID        string
	ZoneID           string
	ZoneName         string
	Token            ManagementToken
	TokenRemoved     bool
	NetworkPath      networkpolicy.CloudflareTunnelPath
	CredentialDetail bool
}

func (request ViewRequest) String() string {
	return fmt.Sprintf("Cloudflare View request: account=%s zone=%s name=%s token=masked", request.AccountID, request.ZoneID, request.ZoneName)
}

func (request ViewRequest) GoString() string { return request.String() }

type ViewResult struct {
	Account                 AccountStatus
	Zone                    ZoneStatus
	Credential              CredentialStatus
	Capability              CapabilityStatus
	NetworkPath             networkpolicy.CloudflareTunnelPath
	Walkthrough             Walkthrough
	PermissionCorrection    PermissionCorrection
	Health                  Health
	LastCheck               time.Time
	verifiedManagementToken VerifiedManagementToken
	tokenVerified           bool
}

type PermissionCorrection struct {
	Capability, AccountID, ZoneID, ZoneName, Found, Required, WhyStopped, Evidence string
	DashboardSteps                                                                 []string
	URL                                                                            string
}

type PermissionKind uint8

const (
	AccountAPITokensReadPermission PermissionKind = iota + 1
	CloudflareTunnelEditPermission
	DNSWritePermission
)

func (result ViewResult) String() string {
	return fmt.Sprintf("Cloudflare View: account=%s zone=%s token=%s health=%s code=%s", result.Account.ID, result.Zone.ID, result.Credential.Status, result.Health.Outcome, result.Health.Code)
}

func (result ViewResult) GoString() string { return result.String() }

// VerifiedManagementToken is an opaque State handoff available only after a Healthy View.
func (result ViewResult) VerifiedManagementToken() (VerifiedManagementToken, bool) {
	return result.verifiedManagementToken, result.tokenVerified
}

type AccountStatus struct {
	ID   string
	Name string
}

type ZoneStatus struct {
	ID                    string
	Name                  string
	Active                bool
	Delegated             bool
	AssignedNameServers   []string
	ObservedNameServers   []string
	ActivationCheckWindow time.Duration
	RegistrarGuidance     string
}

type CredentialStatus struct {
	ID        string
	Status    string
	FirstFour string
	LastFour  string
	ExpiresOn *time.Time
	Uses      []string
}

type CapabilityStatus struct {
	RequiredPermissions   []string
	EffectivePermissions  []string
	UnapprovedPermissions int
	AccountID             string
	ZoneID                string
	ReadsVerified         bool
	WritesProven          bool
	Exact                 bool
}

type Walkthrough struct {
	QualifiedOn   string
	DashboardURL  string
	AccountTokens string
	DNSRecords    string
	Tunnels       string
	Permissions   []string
	Resources     []string
}

type CredentialInput string

const (
	AccountIDInput    CredentialInput = "account-id"
	ZoneIDInput       CredentialInput = "zone-id"
	AccountTokenInput CredentialInput = "account-token"
)

type CredentialHelp struct {
	Purpose, AcceptedFormat, Recovery, Example, URL string
	Instructions, CommonMistakes                    []string
	InfrastructureSecret                            bool
}

func CredentialGuidance(input CredentialInput) (CredentialHelp, bool) {
	switch input {
	case AccountIDInput:
		return CredentialHelp{
			Purpose:        "Bind SBXR to one Cloudflare account.",
			Instructions:   []string{"Open Account home; use Search or CMD/CTRL+K, find the account, and select Copy account ID."},
			AcceptedFormat: "Exactly 32 lowercase hexadecimal characters.",
			CommonMistakes: []string{"Do not use a zone ID or account name."},
			Recovery:       "Copy the selected account ID again.",
			Example:        "11111111111111111111111111111111",
			URL:            "https://developers.cloudflare.com/fundamentals/account/find-account-and-zone-ids/",
		}, true
	case ZoneIDInput:
		return CredentialHelp{
			Purpose:        "Bind SBXR to the selected Cloudflare domain.",
			Instructions:   []string{"Select the domain; open domain Overview; in API, copy the Zone ID."},
			AcceptedFormat: "Exactly 32 lowercase hexadecimal characters.",
			CommonMistakes: []string{"Do not use an account ID or domain name."},
			Recovery:       "Copy the selected domain's Zone ID again.",
			Example:        "22222222222222222222222222222222",
			URL:            "https://developers.cloudflare.com/fundamentals/account/find-account-and-zone-ids/",
		}, true
	case AccountTokenInput:
		return CredentialHelp{
			Purpose: "Authorize only SBXR's Cloudflare work.",
			Instructions: []string{
				"Open Manage Account > Account API Tokens; Create Token.",
				"Add Account > Account API Tokens > Read and Account > Cloudflare Tunnel > Edit for the selected account; add Zone > DNS > Edit for the selected zone.",
			},
			AcceptedFormat:       "cfat_ plus 35 to 75 letters, digits, _ or -.",
			CommonMistakes:       []string{"No Global API Key, user API token, Write, wildcard, or unrelated permission."},
			Recovery:             "Create or correct the exact scoped Account API Token.",
			URL:                  "https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/",
			InfrastructureSecret: true,
		}, true
	default:
		return CredentialHelp{}, false
	}
}

type ExternalCorrection uint8

const (
	NameserverCorrection ExternalCorrection = iota + 1
	ManagementTokenRevocation
	TunnelRunTokenRotation
)

type ExternalCorrectionHelp struct {
	Instructions []string
	URL          string
}

func ExternalCorrectionGuidance(correction ExternalCorrection) (ExternalCorrectionHelp, bool) {
	var help ExternalCorrectionHelp
	switch correction {
	case NameserverCorrection:
		help = ExternalCorrectionHelp{
			Instructions: []string{
				"In Cloudflare, select the domain; open domain Overview; copy both assigned Cloudflare nameservers exactly.",
				"At the registrar or reseller that controls the domain, remove every old authoritative nameserver and add exactly both assigned Cloudflare nameservers.",
				"Do not use a guessed registrar URL; use that provider's nameserver controls. Wait for public delegation, then select Check again in SBXR.",
			},
			URL: "https://developers.cloudflare.com/dns/nameservers/update-nameservers/",
		}
	case ManagementTokenRevocation:
		help = ExternalCorrectionHelp{
			Instructions: []string{
				"Open Manage Account > Account API Tokens in the selected account.",
				"Find the Account API Token named SBXR - selected account / selected zone and revoke only that Account API Token.",
				"Do not revoke a Global API Key, user API token, Tunnel run token, or any unrelated account token. Return to SBXR and select Check again.",
			},
			URL: "https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/",
		}
	case TunnelRunTokenRotation:
		help = ExternalCorrectionHelp{
			Instructions: []string{
				"Open the Cloudflare dashboard > Networking > Tunnels and select the committed SBXR Tunnel.",
				"Select Rotate token for only that Tunnel run token, then return to SBXR forward recovery.",
				"Do not rotate another Tunnel or the management Account API Token.",
			},
			URL: "https://developers.cloudflare.com/tunnel/advanced/tunnel-tokens/",
		}
	default:
		return ExternalCorrectionHelp{}, false
	}
	return help, true
}

type Health struct {
	Time        time.Time
	Module      string
	Outcome     Outcome
	Code        string
	Problem     string
	Found       string
	Required    string
	WhyStopped  string
	Explanation string
	NextActions []string
	NextAction  string
	Evidence    string
}

func (i Interface) View(ctx context.Context, request ViewRequest) ViewResult {
	result := ViewResult{NetworkPath: request.NetworkPath, Walkthrough: walkthrough(request), Health: Health{Outcome: Failed, Code: "CLOUDFLARE-AUTHORITY-UNPROVED"}}
	if i.clock != nil {
		result.LastCheck = i.clock.Now().UTC()
	}
	if i.clock == nil || !validViewRequest(request) || !request.TokenRemoved && i.api == nil {
		result.Health = Health{Outcome: Failed, Code: "CLOUDFLARE-VIEW-INVALID", Found: "an unavailable Adapter or clock, malformed immutable ID, invalid zone name, or missing token", Explanation: "The selected Cloudflare authority is incomplete.", NextActions: []string{"Back"}}
		return finish(result)
	}
	result.Account = AccountStatus{ID: request.AccountID}
	result.Zone = ZoneStatus{ID: request.ZoneID, Name: request.ZoneName}
	if request.TokenRemoved {
		result.Credential = CredentialStatus{Status: "removed"}
		result.Capability = CapabilityStatus{RequiredPermissions: requiredPermissions(), AccountID: request.AccountID, ZoneID: request.ZoneID}
		result.Health = Health{Outcome: Unknown, Code: "CLOUDFLARE-MANAGEMENT-TOKEN-REMOVED", Explanation: "The management token was deliberately removed, so provider authority and dependent provider health cannot be checked.", NextActions: []string{"Check now", "Replace token", "Remove from SBXR"}}
		return finish(result)
	}
	if request.NetworkPath.HTTPS != networkpolicy.ProofPassed || request.NetworkPath.TCP7844 != networkpolicy.ProofPassed || request.NetworkPath.UDP7844 != networkpolicy.ProofPassed {
		result.Health = Health{Outcome: Failed, Code: "CLOUDFLARE-NETWORK-PATH", Found: fmt.Sprintf("HTTPS=%s TCP7844=%s UDP7844=%s", request.NetworkPath.HTTPS, request.NetworkPath.TCP7844, request.NetworkPath.UDP7844), Explanation: "Network Policy has not proved Cloudflare HTTPS and outbound TCP and UDP 7844.", NextActions: []string{"Check Network Policy again", "Back"}}
		return finish(result)
	}

	observed, err := i.observe(ctx, ObservationRequest{AccountID: request.AccountID, ZoneID: request.ZoneID, ZoneName: request.ZoneName, Token: request.Token})
	if err != nil {
		result.Health = safeAPIHealth(err)
		if result.Health.Code == "CLOUDFLARE-TOKEN-PERMISSION" {
			result.PermissionCorrection = permissionCorrection(request, result.Health.Found, apiRequiredPermission(err))
		}
		return finish(result)
	}
	result.Account = AccountStatus{ID: observed.Account.ID, Name: observed.Account.Name}
	result.Zone = ZoneStatus{ID: observed.Zone.ID, Name: observed.Zone.Name, Active: observed.Zone.Status == "active", Delegated: sameNameservers(observed.Zone.AssignedNameServers, observed.Zone.ObservedNameServers), AssignedNameServers: append([]string(nil), observed.Zone.AssignedNameServers...), ObservedNameServers: append([]string(nil), observed.Zone.ObservedNameServers...), ActivationCheckWindow: 10 * time.Minute, RegistrarGuidance: "At the registrar, replace the current authoritative nameservers with exactly the assigned Cloudflare nameservers, wait for public delegation, then Check again."}
	result.Credential = CredentialStatus{ID: observed.Token.ID, Status: observed.Token.Status, ExpiresOn: observed.Token.ExpiresOn, Uses: []string{"verify this account and zone", "manage the one Cloudflare Tunnel", "manage SBXR-owned DNS records"}}
	if request.CredentialDetail {
		result.Credential.FirstFour = request.Token.value[:4]
		result.Credential.LastFour = request.Token.value[len(request.Token.value)-4:]
	}
	valid, found, effective, unapproved := validAuthority(request, observed)
	if valid && observed.Token.ExpiresOn != nil && !observed.Token.ExpiresOn.After(result.LastCheck) {
		valid = false
		found = "token expiry is not after the last check"
	}
	result.Capability = CapabilityStatus{RequiredPermissions: requiredPermissions(), EffectivePermissions: effective, UnapprovedPermissions: unapproved, AccountID: request.AccountID, ZoneID: request.ZoneID, ReadsVerified: valid, Exact: valid}
	if !result.Capability.ReadsVerified {
		result.Health = missingPermissionHealth(found)
		result.PermissionCorrection = permissionCorrection(request, found, permissionFromFinding(found))
		return finish(result)
	}
	if !result.Zone.Active || !result.Zone.Delegated {
		result.Health = Health{Outcome: NeedsAttention, Code: "CLOUDFLARE-ZONE-PENDING", Found: fmt.Sprintf("zone status=%s delegated=%t", safeZoneStatus(observed.Zone.Status), result.Zone.Delegated), Explanation: "The selected zone is not yet active and publicly delegated to its assigned Cloudflare nameservers.", NextActions: []string{"Check again", "Wait another 10 minutes", "Back and continue later"}}
		return finish(result)
	}
	result.verifiedManagementToken = VerifiedManagementToken{value: request.Token.value, used: &atomic.Bool{}}
	result.tokenVerified = true
	result.Health = Health{Outcome: Healthy, Code: "CLOUDFLARE-AUTHORITY-VERIFIED", Explanation: "The scoped account, zone, token capability, delegation, and Network Policy path are verified.", NextActions: []string{"Check now", "Replace token", "Remove from SBXR"}}
	return finish(result)
}

func finish(result ViewResult) ViewResult {
	result.Health.Time = result.LastCheck
	result.Health.Module = "Cloudflare Tunnel"
	if len(result.Health.NextActions) > 0 {
		result.Health.NextAction = result.Health.NextActions[0]
	}
	if result.Health.Outcome != Healthy {
		if result.Health.Problem == "" {
			result.Health.Problem = result.Health.Explanation
		}
		if result.Health.Found == "" {
			result.Health.Found = "the typed check did not pass"
		}
		if result.Health.Required == "" {
			result.Health.Required = "the check identified by " + result.Health.Code + " to pass"
		}
		if result.Health.WhyStopped == "" {
			result.Health.WhyStopped = "SBXR does not bypass required Cloudflare authority"
		}
		if result.Health.Evidence == "" {
			result.Health.Evidence = "copyable redacted " + result.Health.Code + " result"
		}
	}
	return result
}

func (i Interface) observe(ctx context.Context, request ObservationRequest) (Observation, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	var observed Observation
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		observed, err = i.api.Observe(ctx, request)
		if !apiErrorIs(err, APITemporary) || attempt == 2 {
			return observed, err
		}
		if err = i.clock.Sleep(ctx, 30*time.Second); err != nil {
			return Observation{}, APIError{Kind: APITemporary}
		}
	}
	return observed, err
}

func validViewRequest(request ViewRequest) bool {
	tokenValid := request.TokenRemoved && request.Token.value == "" && !request.CredentialDetail || !request.TokenRemoved && request.Token.value != ""
	return immutableID.MatchString(request.AccountID) && immutableID.MatchString(request.ZoneID) && validZoneName(request.ZoneName) && tokenValid
}

func validZoneName(name string) bool { return len(name) <= 253 && zoneName.MatchString(name) }

func validAuthority(request ViewRequest, observed Observation) (bool, string, []string, int) {
	effective, unapproved, policyProblem := assessPolicies(request, observed.Policies)
	if observed.Account.ID != request.AccountID {
		return false, "account ID does not match the selected account", effective, unapproved
	}
	if observed.Zone.ID != request.ZoneID || observed.Zone.Name != request.ZoneName {
		return false, "zone identity does not match the selected zone", effective, unapproved
	}
	if observed.Zone.AccountID != request.AccountID {
		return false, "zone account does not match the selected account", effective, unapproved
	}
	if observed.Token.Status != "active" {
		if observed.Token.Status == "disabled" || observed.Token.Status == "expired" {
			return false, "token status is " + observed.Token.Status, effective, unapproved
		}
		return false, "token status is unsupported", effective, unapproved
	}
	if !immutableID.MatchString(observed.Token.ID) {
		return false, "token identifier is malformed", effective, unapproved
	}
	if policyProblem != "" {
		return false, policyProblem, effective, unapproved
	}
	return true, "exact selected account, zone, permissions, and resources", effective, unapproved
}

func assessPolicies(request ViewRequest, policies []TokenPolicy) ([]string, int, string) {
	want := map[string]string{
		"Account API Tokens Read": "com.cloudflare.api.account." + request.AccountID,
		"Cloudflare Tunnel Edit":  "com.cloudflare.api.account." + request.AccountID,
		"DNS Write":               "com.cloudflare.api.account.zone." + request.ZoneID,
	}
	seen := make(map[string]bool, len(want))
	unapproved := 0
	problem := ""
	for _, policy := range policies {
		if policy.Effect != "allow" {
			if problem == "" {
				if policy.Effect == "deny" {
					problem = "policy effect is deny"
				} else {
					problem = "policy effect is unsupported"
				}
			}
		}
		if len(policy.Resources) != 1 && problem == "" {
			problem = fmt.Sprintf("policy has %d resources", len(policy.Resources))
		}
		if len(policy.PermissionGroups) == 0 && problem == "" {
			problem = "policy has no permission group"
		}
		for _, permission := range policy.PermissionGroups {
			resource, known := want[permission]
			if !known {
				unapproved++
				if problem == "" {
					problem = "token includes an unapproved permission"
				}
				continue
			}
			if seen[permission] {
				if problem == "" {
					problem = "token repeats " + permission
				}
				continue
			}
			if policy.Effect != "allow" || len(policy.Resources) != 1 || policy.Resources[resource] != "*" {
				if problem == "" {
					problem = "token has an unexpected resource for " + permission
				}
				continue
			}
			seen[permission] = true
		}
	}
	effective := make([]string, 0, len(seen))
	for _, permission := range requiredPermissions() {
		if seen[permission] {
			effective = append(effective, permission)
		} else if problem == "" {
			problem = "token is missing " + permission
		}
	}
	return effective, unapproved, problem
}

func safeZoneStatus(status string) string {
	if validZoneStatus(status) {
		return status
	}
	return "unsupported"
}

func sameNameservers(assigned, observed []string) bool {
	clean := func(values []string) []string {
		copy := make([]string, len(values))
		for index, value := range values {
			copy[index] = strings.TrimSuffix(strings.ToLower(value), ".")
		}
		slices.Sort(copy)
		return copy
	}
	return len(assigned) > 0 && slices.Equal(clean(assigned), clean(observed))
}

func requiredPermissions() []string {
	return []string{"Account API Tokens Read", "Cloudflare Tunnel Edit", "DNS Write"}
}

func walkthrough(request ViewRequest) Walkthrough {
	return Walkthrough{
		QualifiedOn:   qualifiedOn,
		DashboardURL:  "https://dash.cloudflare.com/",
		AccountTokens: "Manage Account > Account API Tokens",
		DNSRecords:    "selected domain > DNS > Records",
		Tunnels:       "Cloudflare One > Networks > Tunnels & Mesh",
		Permissions:   []string{"Account > Account API Tokens > Read", "Account > Cloudflare Tunnel > Edit", "Zone > DNS > Edit"},
		Resources:     []string{"only account " + request.AccountID, "only zone " + request.ZoneID},
	}
}

func missingPermissionHealth(found ...string) Health {
	fact := "authorization was refused"
	if len(found) > 0 && found[0] != "" {
		fact = found[0]
	}
	return Health{Outcome: Failed, Code: "CLOUDFLARE-TOKEN-PERMISSION", Found: fact, Explanation: "The token's active status, selected binding, exact capabilities, or resource scope could not be proved.", NextActions: []string{"Check current token again", "Enter replacement token", "Verify replacement", "Back"}}
}

func permissionCorrection(request ViewRequest, found string, permission PermissionKind) PermissionCorrection {
	label := permission.dashboardLabel()
	if label == "" {
		label = "exact selected Cloudflare Account API Token authority"
	}
	scope := "selected account " + request.AccountID
	if permission == DNSWritePermission {
		scope = "selected zone " + request.ZoneID
	}
	required := label + " on " + scope
	return PermissionCorrection{
		Capability: "Required Cloudflare Account API Token authority", AccountID: request.AccountID, ZoneID: request.ZoneID, ZoneName: request.ZoneName,
		Found: found, Required: required, WhyStopped: "SBXR does not bypass required Cloudflare authority", Evidence: "copyable redacted CLOUDFLARE-TOKEN-PERMISSION result",
		DashboardSteps: []string{"Open Manage Account > Account API Tokens in the selected account.", "Edit the SBXR - selected account / selected zone token; require " + required + ".", "Save the token, return to SBXR, and select Check current token again."},
		URL:            "https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/",
	}
}

func permissionFromFinding(found string) PermissionKind {
	for _, permission := range []PermissionKind{AccountAPITokensReadPermission, CloudflareTunnelEditPermission, DNSWritePermission} {
		if strings.Contains(found, permission.apiName()) {
			return permission
		}
	}
	return 0
}

func apiRequiredPermission(err error) PermissionKind {
	var apiError APIError
	if errors.As(err, &apiError) {
		return apiError.RequiredPermission
	}
	return 0
}

func (permission PermissionKind) apiName() string {
	switch permission {
	case AccountAPITokensReadPermission:
		return "Account API Tokens Read"
	case CloudflareTunnelEditPermission:
		return "Cloudflare Tunnel Edit"
	case DNSWritePermission:
		return "DNS Write"
	default:
		return ""
	}
}

func (permission PermissionKind) dashboardLabel() string {
	switch permission {
	case AccountAPITokensReadPermission:
		return "Account > Account API Tokens > Read"
	case CloudflareTunnelEditPermission:
		return "Account > Cloudflare Tunnel > Edit"
	case DNSWritePermission:
		return "Zone > DNS > Edit"
	default:
		return ""
	}
}

func safeAPIHealth(err error) Health {
	switch {
	case apiErrorIs(err, APIUnauthorized), apiErrorIs(err, APIForbidden):
		return missingPermissionHealth("Cloudflare refused authorization")
	case apiErrorIs(err, APIMalformed), apiErrorIs(err, APIAmbiguous), apiErrorIs(err, APIPermanent):
		return Health{Outcome: Failed, Code: "CLOUDFLARE-API-REFUSED", Explanation: "Cloudflare returned no unambiguous supported observation.", NextActions: []string{"Check again", "Back"}}
	default:
		return Health{Outcome: Unknown, Code: "CLOUDFLARE-API-TEMPORARY", Explanation: "Cloudflare is temporarily unavailable or the check was interrupted.", NextActions: []string{"Check again", "Back"}}
	}
}

func apiErrorIs(err error, kind APIErrorKind) bool {
	var apiError APIError
	return errors.As(err, &apiError) && apiError.Kind == kind
}

// IsNotFound reports the one provider response that proves an immutable ID is absent.
func IsNotFound(err error) bool { return apiErrorIs(err, APINotFound) }
