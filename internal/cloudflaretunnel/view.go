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

const qualifiedOn = "2026-08-17"

var (
	immutableID = regexp.MustCompile(`^[0-9a-f]{32}$`)
	userToken   = regexp.MustCompile(`^[A-Za-z0-9_-]{40,80}$`)
	zoneName    = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
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
	if !userToken.MatchString(value) || strings.HasPrefix(value, "cfat_") || strings.Contains(lower, "placeholder") || strings.Contains(lower, "your_token") {
		return ManagementToken{}, errors.New("Dedicated Broad Cloudflare User API Token required")
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
	APILimit        APIErrorKind = "limit"
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
	if err := api.DeleteManagementToken(ctx, DeleteManagementTokenRequest{ID: tokenID, Token: request.Token}); err != nil {
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
	Account          AccountObservation
	Zone             ZoneObservation
	Token            TokenObservation
	DNSListProven    bool
	TunnelListProven bool
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

type ViewRequest struct {
	AccountID                     string
	ZoneID                        string
	ZoneName                      string
	Token                         ManagementToken
	TokenRemoved                  bool
	NetworkPath                   networkpolicy.CloudflareTunnelPath
	CredentialDetail              bool
	DedicatedBroadPolicyConfirmed bool
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
	UserAPITokensEditPermission PermissionKind = iota + 1
	CloudflareTunnelEditPermission
	DNSEditPermission
	ZoneReadPermission
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
	AccountIDInput CredentialInput = "account-id"
	ZoneIDInput    CredentialInput = "zone-id"
	UserTokenInput CredentialInput = "user-token"
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
	case UserTokenInput:
		return CredentialHelp{
			Purpose: "Authorize only SBXR's Cloudflare work.",
			Instructions: []string{
				"Open My Profile > API Tokens; Create Token.",
				"Add User > API Tokens > Edit, Account > Cloudflare Tunnel > Edit for all accounts, Zone > DNS > Edit for all zones, and Zone > Zone > Read for all zones.",
				"Set no expiry and no client-IP restriction. Confirm that SBXR will restrict use to the selected account, selected zone, current and candidate token IDs, and exact immutable-ID-owned resources.",
			},
			AcceptedFormat:       "40 to 80 letters, digits, _ or -; no cfat_ prefix.",
			CommonMistakes:       []string{"No Global API Key, Account API Token, expiry, client-IP restriction, narrow account scope, or narrow zone scope."},
			Recovery:             "Create or correct the Dedicated Broad Cloudflare User API Token.",
			URL:                  "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
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
				"Open My Profile > API Tokens.",
				"Find the exact Dedicated Broad Cloudflare User API Token ID recorded by SBXR and revoke only that token.",
				"Do not revoke a Global API Key, Account API Token, Tunnel run token, or any unrelated user token. Return to SBXR and select Check again.",
			},
			URL: "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
		}
	case TunnelRunTokenRotation:
		help = ExternalCorrectionHelp{
			Instructions: []string{
				"Open the Cloudflare dashboard > Networking > Tunnels and select the committed SBXR Tunnel.",
				"Select Rotate token for only that Tunnel run token, then return to SBXR forward recovery.",
				"Do not rotate another Tunnel or the Dedicated Broad Cloudflare User API Token.",
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
	valid, found := validAuthority(request, observed)
	effective := []string(nil)
	if request.DedicatedBroadPolicyConfirmed {
		effective = requiredPermissions()
	}
	result.Capability = CapabilityStatus{RequiredPermissions: requiredPermissions(), EffectivePermissions: effective, AccountID: request.AccountID, ZoneID: request.ZoneID, ReadsVerified: valid, Exact: valid}
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
	result.Health = Health{Outcome: Healthy, Code: "CLOUDFLARE-AUTHORITY-VERIFIED", Explanation: "The Owner-confirmed broad policy, active token, selected account and zone, exact read probes, delegation, and Network Policy path are verified. Provider reads do not prove write authority.", NextActions: []string{"Check now", "Replace token", "Remove from SBXR", "Rotate genuine Tunnel run token", "Rotate management token"}}
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
	return immutableID.MatchString(request.AccountID) && immutableID.MatchString(request.ZoneID) && validZoneName(request.ZoneName) && tokenValid && (request.TokenRemoved || request.DedicatedBroadPolicyConfirmed)
}

func validZoneName(name string) bool { return len(name) <= 253 && zoneName.MatchString(name) }

func validAuthority(request ViewRequest, observed Observation) (bool, string) {
	if observed.Account.ID != request.AccountID {
		return false, "account ID does not match the selected account"
	}
	if observed.Zone.ID != request.ZoneID || observed.Zone.Name != request.ZoneName {
		return false, "zone identity does not match the selected zone"
	}
	if observed.Zone.AccountID != request.AccountID {
		return false, "zone account does not match the selected account"
	}
	if observed.Token.Status != "active" {
		if observed.Token.Status == "disabled" || observed.Token.Status == "expired" {
			return false, "token status is " + observed.Token.Status
		}
		return false, "token status is unsupported"
	}
	if !immutableID.MatchString(observed.Token.ID) {
		return false, "token identifier is malformed"
	}
	if observed.Token.ExpiresOn != nil {
		return false, "token has an expiry"
	}
	if !observed.DNSListProven || !observed.TunnelListProven {
		return false, "selected DNS and Tunnel probes are unproved"
	}
	return true, "Owner-confirmed broad policy and exact selected provider probes"
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
	return []string{"User API Tokens Edit", "Cloudflare Tunnel Edit", "DNS Edit", "Zone Read"}
}

func walkthrough(request ViewRequest) Walkthrough {
	return Walkthrough{
		QualifiedOn:   qualifiedOn,
		DashboardURL:  "https://dash.cloudflare.com/",
		AccountTokens: "My Profile > API Tokens",
		DNSRecords:    "selected domain > DNS > Records",
		Tunnels:       "Cloudflare One > Networks > Tunnels & Mesh",
		Permissions:   []string{"User > API Tokens > Edit", "Account > Cloudflare Tunnel > Edit", "Zone > DNS > Edit", "Zone > Zone > Read"},
		Resources:     []string{"all accounts and all zones at the provider", "SBXR use restricted to account " + request.AccountID, "SBXR use restricted to zone " + request.ZoneID},
	}
}

func missingPermissionHealth(found ...string) Health {
	fact := "authorization was refused"
	if len(found) > 0 && found[0] != "" {
		fact = found[0]
	}
	return Health{Outcome: NeedsAttention, Code: "CLOUDFLARE-TOKEN-PERMISSION", Found: fact, Explanation: "The active Dedicated Broad Cloudflare User API Token or one selected-resource probe could not be proved.", NextActions: []string{"Check current token again", "Enter replacement token", "Verify replacement", "Back"}}
}

func permissionCorrection(request ViewRequest, found string, permission PermissionKind) PermissionCorrection {
	label := permission.dashboardLabel()
	if label == "" {
		label = "exact Dedicated Broad Cloudflare User API Token authority"
	}
	scope := "selected account " + request.AccountID
	if permission == DNSEditPermission || permission == ZoneReadPermission {
		scope = "selected zone " + request.ZoneID
	}
	required := label + " on " + scope
	return PermissionCorrection{
		Capability: "Required Dedicated Broad Cloudflare User API Token authority", AccountID: request.AccountID, ZoneID: request.ZoneID, ZoneName: request.ZoneName,
		Found: found, Required: required, WhyStopped: "SBXR does not bypass required Cloudflare authority", Evidence: "copyable redacted CLOUDFLARE-TOKEN-PERMISSION result",
		DashboardSteps: []string{"Open My Profile > API Tokens.", "Edit the SBXR Dedicated Broad Cloudflare User API Token; require " + required + ".", "Keep all-account and all-zone scopes, no expiry, and no client-IP restriction; return to SBXR and select Check current token again."},
		URL:            "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
	}
}

func permissionFromFinding(found string) PermissionKind {
	for _, permission := range []PermissionKind{UserAPITokensEditPermission, CloudflareTunnelEditPermission, DNSEditPermission, ZoneReadPermission} {
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
	case UserAPITokensEditPermission:
		return "User API Tokens Edit"
	case CloudflareTunnelEditPermission:
		return "Cloudflare Tunnel Edit"
	case DNSEditPermission:
		return "DNS Edit"
	case ZoneReadPermission:
		return "Zone Read"
	default:
		return ""
	}
}

func (permission PermissionKind) dashboardLabel() string {
	switch permission {
	case UserAPITokensEditPermission:
		return "User > API Tokens > Edit"
	case CloudflareTunnelEditPermission:
		return "Account > Cloudflare Tunnel > Edit"
	case DNSEditPermission:
		return "Zone > DNS > Edit"
	case ZoneReadPermission:
		return "Zone > Zone > Read"
	default:
		return ""
	}
}

func safeAPIHealth(err error) Health {
	switch {
	case apiErrorIs(err, APIUnauthorized), apiErrorIs(err, APIForbidden):
		return missingPermissionHealth("Cloudflare refused authorization")
	case apiErrorIs(err, APILimit):
		return Health{Outcome: NeedsAttention, Code: "CLOUDFLARE-ZONE-LIST-LIMIT", Found: "more than 500 active zones are visible to the token", Required: "at most 500 active zones for bounded discovery", Explanation: "Cloudflare active-zone discovery exceeded the documented safe bound.", NextActions: []string{"Reduce the visible active-zone set", "Check again", "Back"}}
	case apiErrorIs(err, APIMalformed), apiErrorIs(err, APIAmbiguous), apiErrorIs(err, APIPermanent):
		return Health{Outcome: Unknown, Code: "CLOUDFLARE-API-REFUSED", Explanation: "Cloudflare returned no unambiguous supported observation.", NextActions: []string{"Check again", "Back"}}
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
