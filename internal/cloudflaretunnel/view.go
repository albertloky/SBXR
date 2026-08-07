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

const qualifiedOn = "2026-08-07"

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
	if !accountToken.MatchString(value) {
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
	APIMalformed    APIErrorKind = "malformed"
	APIAmbiguous    APIErrorKind = "ambiguous"
	APIPermanent    APIErrorKind = "permanent"
)

// APIError deliberately drops provider text at the Module boundary.
type APIError struct {
	Kind APIErrorKind
}

func (e APIError) Error() string { return "Cloudflare API " + string(e.Kind) + " failure" }

type Interface struct {
	api   API
	clock Clock
}

func New(api API, clock Clock) Interface { return Interface{api: api, clock: clock} }

func NewProduction() Interface { return New(NewProductionAPI(), SystemClock{}) }

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
	Health                  Health
	LastCheck               time.Time
	verifiedManagementToken VerifiedManagementToken
	tokenVerified           bool
}

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
	if request.TokenRemoved {
		result.Account = AccountStatus{ID: request.AccountID}
		result.Zone = ZoneStatus{ID: request.ZoneID, Name: request.ZoneName}
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
