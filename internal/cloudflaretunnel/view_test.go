package cloudflaretunnel_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/state"
)

const (
	accountID = "11111111111111111111111111111111"
	zoneID    = "22222222222222222222222222222222"
	tokenID   = "33333333333333333333333333333333"
	token     = "cfat_MANAGEMENT-TOKEN-MARKER-00000000abcd"
)

type staticAPI struct {
	observation cloudflaretunnel.Observation
	err         error
	errors      []error
	calls       int
}

func (api *staticAPI) Observe(context.Context, cloudflaretunnel.ObservationRequest) (cloudflaretunnel.Observation, error) {
	api.calls++
	if len(api.errors) > 0 {
		err := api.errors[0]
		api.errors = api.errors[1:]
		return api.observation, err
	}
	return api.observation, api.err
}

type controlledClock struct {
	now    time.Time
	sleeps []time.Duration
}

func (clock *controlledClock) Now() time.Time { return clock.now }

func (clock *controlledClock) Sleep(_ context.Context, duration time.Duration) error {
	clock.sleeps = append(clock.sleeps, duration)
	return nil
}

func TestRevocationProofAcceptsOnlyExplicitUnauthorized(t *testing.T) {
	for _, test := range []struct {
		name    string
		err     error
		revoked bool
		wantErr bool
	}{
		{"unauthorized", cloudflaretunnel.APIError{Kind: cloudflaretunnel.APIUnauthorized}, true, false},
		{"forbidden", cloudflaretunnel.APIError{Kind: cloudflaretunnel.APIForbidden}, false, true},
		{"temporary", cloudflaretunnel.APIError{Kind: cloudflaretunnel.APITemporary}, false, true},
		{"still active", nil, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := cloudflaretunnel.New(&staticAPI{err: test.err}, &controlledClock{}).VerifyManagementTokenRevoked(context.Background(), cloudflaretunnel.ObservationRequest{})
			if got != test.revoked || (err != nil) != test.wantErr {
				t.Fatalf("VerifyManagementTokenRevoked() = (%t, %v)", got, err)
			}
		})
	}
}

func TestViewVerifiesOneScopedCloudflareAuthority(t *testing.T) {
	managementToken, err := cloudflaretunnel.NewManagementToken(token)
	if err != nil {
		t.Fatal(err)
	}
	checkedAt := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	api := &staticAPI{observation: completeObservation()}
	result := cloudflaretunnel.New(api, &controlledClock{now: checkedAt}).View(context.Background(), cloudflaretunnel.ViewRequest{
		AccountID:        accountID,
		ZoneID:           zoneID,
		ZoneName:         "example.com",
		Token:            managementToken,
		NetworkPath:      networkpolicy.CloudflareTunnelPath{HTTPS: networkpolicy.ProofPassed, TCP7844: networkpolicy.ProofPassed, UDP7844: networkpolicy.ProofPassed},
		CredentialDetail: true,
	})

	if result.Health.Outcome != cloudflaretunnel.Healthy || result.Health.Code != "CLOUDFLARE-AUTHORITY-VERIFIED" {
		t.Fatalf("View() health = %+v", result.Health)
	}
	if result.Health.Module != "Cloudflare Tunnel" || result.Health.Time != checkedAt || result.Health.Explanation == "" || result.Health.NextAction == "" {
		t.Fatalf("View() omitted typed health facts: %+v", result.Health)
	}
	if result.Account.ID != accountID || result.Account.Name != "Selected account" || result.Zone.ID != zoneID || result.Zone.Name != "example.com" || !result.Zone.Active || !result.Zone.Delegated {
		t.Fatalf("View() binding = account %+v zone %+v", result.Account, result.Zone)
	}
	if result.Credential.Status != "active" || result.Credential.FirstFour != "cfat" || result.Credential.LastFour != "abcd" || result.Credential.ExpiresOn == nil || !result.Capability.ReadsVerified || result.Capability.WritesProven {
		t.Fatalf("View() credential = %+v capability %+v", result.Credential, result.Capability)
	}
	if strings.Join(result.Capability.EffectivePermissions, ",") != "Account API Tokens Read,Cloudflare Tunnel Edit,DNS Write" || !result.Capability.Exact || result.Capability.UnapprovedPermissions != 0 {
		t.Fatalf("View() effective capability = %+v", result.Capability)
	}
	verifiedToken, verified := result.VerifiedManagementToken()
	if !verified || strings.Contains(fmt.Sprintf("%v %#v", verifiedToken, verifiedToken), token) {
		t.Fatalf("View() verified State handoff = (%v, %t)", verifiedToken, verified)
	}
	stateToken, consumed := state.NewInfrastructureSecretFrom(verifiedToken)
	if !consumed || strings.Contains(fmt.Sprintf("%v %#v", stateToken, stateToken), token) {
		t.Fatalf("State token handoff = (%v, %t)", stateToken, consumed)
	}
	if _, consumedAgain := state.NewInfrastructureSecretFrom(verifiedToken); consumedAgain {
		t.Fatal("verified State token handoff was reusable")
	}
	if result.LastCheck != checkedAt || result.NetworkPath.HTTPS != networkpolicy.ProofPassed || result.NetworkPath.TCP7844 != networkpolicy.ProofPassed || result.NetworkPath.UDP7844 != networkpolicy.ProofPassed {
		t.Fatalf("View() freshness = %v path %+v", result.LastCheck, result.NetworkPath)
	}
	if result.Walkthrough.DashboardURL != "https://dash.cloudflare.com/" || result.Walkthrough.AccountTokens != "Manage Account > Account API Tokens" || result.Walkthrough.DNSRecords != "selected domain > DNS > Records" || result.Walkthrough.Tunnels != "Cloudflare One > Networks > Tunnels & Mesh" {
		t.Fatalf("View() walkthrough = %+v", result.Walkthrough)
	}
	if strings.Join(result.Walkthrough.Permissions, ",") != "Account > Account API Tokens > Read,Account > Cloudflare Tunnel > Edit,Zone > DNS > Edit" {
		t.Fatalf("View() permission labels = %+v", result.Walkthrough.Permissions)
	}
	if rendered := result.String(); strings.Contains(rendered, token) || strings.Contains(rendered, "MANAGEMENT-TOKEN-MARKER") {
		t.Fatalf("View() leaked token: %s", rendered)
	}
	if api.calls != 1 {
		t.Fatalf("API calls = %d, want 1", api.calls)
	}
}

func TestViewReportsDeliberatelyRemovedManagementTokenWithoutFalseHealth(t *testing.T) {
	result := cloudflaretunnel.New(nil, &controlledClock{now: time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)}).View(context.Background(), cloudflaretunnel.ViewRequest{
		AccountID:    accountID,
		ZoneID:       zoneID,
		ZoneName:     "example.com",
		TokenRemoved: true,
		NetworkPath:  networkpolicy.CloudflareTunnelPath{HTTPS: networkpolicy.ProofPassed, TCP7844: networkpolicy.ProofPassed, UDP7844: networkpolicy.ProofPassed},
	})
	wantActions := []string{"Check now", "Replace token", "Remove from SBXR"}
	if result.Health.Outcome != cloudflaretunnel.Unknown || result.Health.Code != "CLOUDFLARE-MANAGEMENT-TOKEN-REMOVED" || !slices.Equal(result.Health.NextActions, wantActions) || result.Capability.ReadsVerified || result.Capability.WritesProven {
		t.Fatalf("removed-token View = %+v", result)
	}
	if _, ok := result.VerifiedManagementToken(); ok {
		t.Fatal("removed-token View returned stored authority")
	}
}

func TestViewFailsClosedWithoutLeakingAuthority(t *testing.T) {
	managementToken, err := cloudflaretunnel.NewManagementToken(token)
	if err != nil {
		t.Fatal(err)
	}
	healthyPath := networkpolicy.CloudflareTunnelPath{HTTPS: networkpolicy.ProofPassed, TCP7844: networkpolicy.ProofPassed, UDP7844: networkpolicy.ProofPassed}
	request := cloudflaretunnel.ViewRequest{AccountID: accountID, ZoneID: zoneID, ZoneName: "example.com", Token: managementToken, NetworkPath: healthyPath}

	t.Run("general View hides token markers", func(t *testing.T) {
		result := cloudflaretunnel.New(&staticAPI{observation: completeObservation()}, &controlledClock{}).View(context.Background(), request)
		if result.Credential.FirstFour != "" || result.Credential.LastFour != "" || strings.Contains(result.String(), token) || strings.Contains(result.String(), "MANAGEMENT-TOKEN-MARKER") {
			t.Fatalf("general View exposed token material: %+v", result)
		}
		for _, rendered := range []string{managementToken.String(), managementToken.GoString(), request.String(), request.GoString()} {
			if strings.Contains(rendered, token) || strings.Contains(rendered, "MANAGEMENT-TOKEN-MARKER") {
				t.Fatalf("safe formatting leaked token: %s", rendered)
			}
		}
	})

	t.Run("Global API Key is rejected before observation", func(t *testing.T) {
		if _, err := cloudflaretunnel.NewManagementToken("0123456789abcdef0123456789abcdef01234"); err == nil {
			t.Fatal("Global API Key was accepted")
		}
	})

	for _, test := range []struct {
		name   string
		change func(*networkpolicy.CloudflareTunnelPath)
	}{
		{name: "Cloudflare HTTPS", change: func(path *networkpolicy.CloudflareTunnelPath) { path.HTTPS = networkpolicy.ProofFailed }},
		{name: "Tunnel TCP 7844", change: func(path *networkpolicy.CloudflareTunnelPath) { path.TCP7844 = networkpolicy.ProofFailed }},
		{name: "Tunnel UDP 7844", change: func(path *networkpolicy.CloudflareTunnelPath) { path.UDP7844 = networkpolicy.ProofFailed }},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &staticAPI{observation: completeObservation()}
			blocked := request
			test.change(&blocked.NetworkPath)
			result := cloudflaretunnel.New(api, &controlledClock{}).View(context.Background(), blocked)
			if result.Health.Outcome != cloudflaretunnel.Failed || result.Health.Code != "CLOUDFLARE-NETWORK-PATH" || api.calls != 0 {
				t.Fatalf("unproved path = health %+v API calls %d", result.Health, api.calls)
			}
		})
	}

	t.Run("invalid local inputs stop before observation", func(t *testing.T) {
		for _, invalid := range []cloudflaretunnel.ViewRequest{
			{AccountID: "not-an-id", ZoneID: zoneID, ZoneName: "example.com", Token: managementToken, NetworkPath: healthyPath},
			{AccountID: accountID, ZoneID: zoneID, ZoneName: "not a domain", Token: managementToken, NetworkPath: healthyPath},
		} {
			api := &staticAPI{observation: completeObservation()}
			result := cloudflaretunnel.New(api, &controlledClock{}).View(context.Background(), invalid)
			if result.Health.Code != "CLOUDFLARE-VIEW-INVALID" || api.calls != 0 {
				t.Fatalf("invalid input = health %+v calls %d", result.Health, api.calls)
			}
		}
		if result := cloudflaretunnel.New(nil, &controlledClock{}).View(context.Background(), request); result.Health.Code != "CLOUDFLARE-VIEW-INVALID" {
			t.Fatalf("missing API = %+v", result.Health)
		} else if _, verified := result.VerifiedManagementToken(); verified {
			t.Fatal("invalid View returned a State token handoff")
		}
		if result := cloudflaretunnel.New(&staticAPI{}, nil).View(context.Background(), request); result.Health.Code != "CLOUDFLARE-VIEW-INVALID" {
			t.Fatalf("missing clock = %+v", result.Health)
		}
	})

	for _, test := range []struct {
		name   string
		change func(*cloudflaretunnel.Observation)
		found  string
	}{
		{name: "inactive token", change: func(observation *cloudflaretunnel.Observation) { observation.Token.Status = "disabled" }, found: "disabled"},
		{name: "wrong account", change: func(observation *cloudflaretunnel.Observation) {
			observation.Zone.AccountID = "44444444444444444444444444444444"
		}, found: "zone account"},
		{name: "missing capability", change: func(observation *cloudflaretunnel.Observation) {
			observation.Policies[0].PermissionGroups = []string{"Account API Tokens Read"}
		}, found: "missing Cloudflare Tunnel Edit"},
		{name: "overbroad capability", change: func(observation *cloudflaretunnel.Observation) {
			observation.Policies[0].PermissionGroups = append(observation.Policies[0].PermissionGroups, "Billing Read")
		}, found: "unapproved permission"},
		{name: "unexpected permission marker", change: func(observation *cloudflaretunnel.Observation) {
			observation.Policies[0].PermissionGroups = append(observation.Policies[0].PermissionGroups, "PROVIDER-FIELD-MARKER "+token)
		}, found: "unapproved permission"},
		{name: "all-zone scope", change: func(observation *cloudflaretunnel.Observation) {
			observation.Policies[1].Resources = map[string]string{"com.cloudflare.api.account.zone.*": "*"}
		}, found: "unexpected resource"},
		{name: "ambiguous extra scope", change: func(observation *cloudflaretunnel.Observation) {
			observation.Policies[1].Resources["com.cloudflare.api.account.zone.44444444444444444444444444444444"] = "*"
		}, found: "2 resources"},
		{name: "denied permission is not effective", change: func(observation *cloudflaretunnel.Observation) {
			observation.Policies[1].Effect = "deny"
		}, found: "deny"},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation := completeObservation()
			test.change(&observation)
			result := cloudflaretunnel.New(&staticAPI{observation: observation}, &controlledClock{}).View(context.Background(), request)
			wantActions := []string{"Check current token again", "Enter replacement token", "Verify replacement", "Back"}
			if result.Health.Outcome != cloudflaretunnel.Failed || result.Health.Code != "CLOUDFLARE-TOKEN-PERMISSION" || strings.Join(result.Health.NextActions, ",") != strings.Join(wantActions, ",") {
				t.Fatalf("unsafe authority health = %+v", result.Health)
			}
			if result.Capability.Exact {
				t.Fatalf("unsafe authority reported exact capability: %+v", result.Capability)
			}
			if test.name == "all-zone scope" || test.name == "ambiguous extra scope" || test.name == "denied permission is not effective" {
				if slices.Contains(result.Capability.EffectivePermissions, "DNS Write") {
					t.Fatalf("unsafe DNS Write reported effective: %+v", result.Capability)
				}
			}
			if result.Health.Problem == "" || !strings.Contains(result.Health.Found, test.found) || result.Health.Required == "" || result.Health.WhyStopped == "" || result.Health.Evidence == "" || strings.Contains(strings.Join(result.Health.NextActions, " "), "Continue anyway") {
				t.Fatalf("unsafe authority omitted Correction Flow facts: %+v", result.Health)
			}
			if rendered := result.String() + result.Health.Found; strings.Contains(rendered, "PROVIDER-FIELD-MARKER") || strings.Contains(rendered, token) {
				t.Fatalf("unsafe authority leaked provider material: %s", rendered)
			}
		})
	}

	t.Run("expired token is not accepted as active authority", func(t *testing.T) {
		result := cloudflaretunnel.New(&staticAPI{observation: completeObservation()}, &controlledClock{now: time.Date(2028, time.August, 7, 0, 0, 0, 0, time.UTC)}).View(context.Background(), request)
		if result.Health.Code != "CLOUDFLARE-TOKEN-PERMISSION" {
			t.Fatalf("expired token health = %+v", result.Health)
		}
	})

	t.Run("pending delegation has bounded exact actions", func(t *testing.T) {
		observation := completeObservation()
		observation.Zone.Status = "pending"
		observation.Zone.ObservedNameServers = []string{"registrar.example"}
		result := cloudflaretunnel.New(&staticAPI{observation: observation}, &controlledClock{}).View(context.Background(), request)
		want := []string{"Check again", "Wait another 10 minutes", "Back and continue later"}
		if result.Health.Outcome != cloudflaretunnel.NeedsAttention || result.Health.Code != "CLOUDFLARE-ZONE-PENDING" || strings.Join(result.Health.NextActions, ",") != strings.Join(want, ",") {
			t.Fatalf("pending zone health = %+v", result.Health)
		}
		if result.Zone.ActivationCheckWindow != 10*time.Minute || !strings.Contains(result.Zone.RegistrarGuidance, "registrar") || !strings.Contains(result.Zone.RegistrarGuidance, "assigned Cloudflare nameservers") {
			t.Fatalf("pending zone correction = %+v", result.Zone)
		}
	})

	t.Run("temporary failures stop after three attempts within sixty seconds", func(t *testing.T) {
		api := &staticAPI{observation: completeObservation(), errors: []error{
			cloudflaretunnel.APIError{Kind: cloudflaretunnel.APITemporary},
			cloudflaretunnel.APIError{Kind: cloudflaretunnel.APITemporary},
			cloudflaretunnel.APIError{Kind: cloudflaretunnel.APITemporary},
		}}
		clock := &controlledClock{}
		result := cloudflaretunnel.New(api, clock).View(context.Background(), request)
		if result.Health.Outcome != cloudflaretunnel.Unknown || result.Health.Code != "CLOUDFLARE-API-TEMPORARY" || api.calls != 3 || len(clock.sleeps) != 2 || clock.sleeps[0]+clock.sleeps[1] != time.Minute {
			t.Fatalf("temporary API handling = health %+v calls %d sleeps %+v", result.Health, api.calls, clock.sleeps)
		}
	})

	t.Run("provider errors are allowlisted and secret-safe", func(t *testing.T) {
		api := &staticAPI{err: fmt.Errorf("PROVIDER-ERROR-MARKER %s: %w", token, cloudflaretunnel.APIError{Kind: cloudflaretunnel.APIForbidden})}
		result := cloudflaretunnel.New(api, &controlledClock{}).View(context.Background(), request)
		rendered := result.String() + result.Health.Explanation + strings.Join(result.Health.NextActions, " ")
		if result.Health.Outcome != cloudflaretunnel.Failed || result.Health.Code != "CLOUDFLARE-TOKEN-PERMISSION" || strings.Contains(rendered, "PROVIDER-ERROR-MARKER") || strings.Contains(rendered, token) {
			t.Fatalf("provider refusal = %+v", result.Health)
		}
	})
}

func completeObservation() cloudflaretunnel.Observation {
	expires := time.Date(2027, time.August, 7, 0, 0, 0, 0, time.UTC)
	return cloudflaretunnel.Observation{
		Account: cloudflaretunnel.AccountObservation{ID: accountID, Name: "Selected account"},
		Zone: cloudflaretunnel.ZoneObservation{
			ID:                  zoneID,
			AccountID:           accountID,
			Name:                "example.com",
			Status:              "active",
			AssignedNameServers: []string{"ada.ns.cloudflare.com", "bob.ns.cloudflare.com"},
			ObservedNameServers: []string{"bob.ns.cloudflare.com", "ada.ns.cloudflare.com"},
		},
		Token: cloudflaretunnel.TokenObservation{ID: tokenID, Status: "active", ExpiresOn: &expires},
		Policies: []cloudflaretunnel.TokenPolicy{
			{Effect: "allow", PermissionGroups: []string{"Account API Tokens Read", "Cloudflare Tunnel Edit"}, Resources: map[string]string{"com.cloudflare.api.account." + accountID: "*"}},
			{Effect: "allow", PermissionGroups: []string{"DNS Write"}, Resources: map[string]string{"com.cloudflare.api.account.zone." + zoneID: "*"}},
		},
	}
}
