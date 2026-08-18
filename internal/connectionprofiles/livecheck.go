package connectionprofiles

import (
	"context"
	"errors"
	"net/url"
	"sync"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

type LiveProfileSubscription struct {
	mu    sync.Mutex
	value string
	used  bool
}

func NewLiveProfileSubscription(value string) (*LiveProfileSubscription, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Path == "" || parsed.Path == "/" {
		return nil, errors.New("universal subscription is invalid")
	}
	return &LiveProfileSubscription{value: value}, nil
}

func (*LiveProfileSubscription) String() string   { return "Live Profile Check subscription: redacted" }
func (*LiveProfileSubscription) GoString() string { return "Live Profile Check subscription: redacted" }
func (*LiveProfileSubscription) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Live Profile Check subscription cannot be rendered")
}

func (subscription *LiveProfileSubscription) Consume() (string, bool) {
	if subscription == nil {
		return "", false
	}
	subscription.mu.Lock()
	defer subscription.mu.Unlock()
	if subscription.used || subscription.value == "" {
		return "", false
	}
	value := subscription.value
	subscription.value = ""
	subscription.used = true
	return value, true
}

func (subscription *LiveProfileSubscription) available() bool {
	if subscription == nil {
		return false
	}
	subscription.mu.Lock()
	defer subscription.mu.Unlock()
	return !subscription.used && subscription.value != ""
}

type LiveProfileEvidence struct {
	Profile                         ProfileID
	Authenticated, Uplink, Downlink bool
}

type LiveProfileSkip struct {
	Profile ProfileID
	Reason  string
}

type LiveProfileCheckHost interface {
	CheckLiveProfiles(context.Context, *LiveProfileSubscription, []ProfileID) []LiveProfileEvidence
}

type LiveProfileCheckRequest struct {
	Registry     RegistryViewRequest
	Managed      systemchanges.ManagedAuthority
	StateSHA256  string
	Subscription *LiveProfileSubscription
}

type LiveProfileCheckResult struct {
	Health   Health
	evidence []LiveProfileEvidence
	skips    []LiveProfileSkip
}

func (LiveProfileCheckResult) String() string {
	return "Live Profile Check result: redacted and memory-only"
}
func (LiveProfileCheckResult) GoString() string {
	return "Live Profile Check result: redacted and memory-only"
}
func (LiveProfileCheckResult) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Live Profile Check result cannot be retained")
}
func (result LiveProfileCheckResult) Evidence() []LiveProfileEvidence {
	return append([]LiveProfileEvidence(nil), result.evidence...)
}
func (result LiveProfileCheckResult) Skips() []LiveProfileSkip {
	return append([]LiveProfileSkip(nil), result.skips...)
}

func (module Interface) RunLiveProfileCheck(ctx context.Context, request LiveProfileCheckRequest) LiveProfileCheckResult {
	fail := func(code, problem, found, required string) LiveProfileCheckResult {
		return LiveProfileCheckResult{Health: blockedHealth(Health{Module: "Connection Profiles", Profile: "Live Profile Check", Outcome: Failed, Code: code, Problem: problem, Found: found, Required: required, WhyStopped: "Live Profile Check never bypasses Managed state or retains traffic evidence", NextActions: []string{"Check again", "Back"}})}
	}
	revision, stateSHA256, managed := request.Managed.ConnectionProfilesManaged()
	if !managed || revision != request.Registry.Reality.Revision || stateSHA256 != request.StateSHA256 {
		return fail("CONNECTION-PROFILES-LIVE-CHECK-MANAGED", "Live Profile Check is unavailable", "the installation is not freshly proved Managed at this revision", "Managed with no unfinished Change Set")
	}
	registry := module.ViewRegistry(ctx, request.Registry)
	if registry.Health.Outcome != Healthy {
		return fail("CONNECTION-PROFILES-LIVE-CHECK-SERVER", "Server readiness did not pass", registry.Health.Code, "one Healthy canonical registry before outside checking")
	}
	host, ok := module.host.(LiveProfileCheckHost)
	if !ok {
		return fail("CONNECTION-PROFILES-LIVE-CHECK-HOST", "The outside check boundary is unavailable", "no Live Profile Check host", "one bounded outside authenticated check")
	}
	if !request.Subscription.available() {
		return fail("CONNECTION-PROFILES-LIVE-CHECK-SUBSCRIPTION", "The one-time universal subscription is unavailable", "missing or already consumed", "one fresh universal subscription consumed once")
	}
	profiles := registry.Publication.Profiles()
	ids := make([]ProfileID, len(profiles))
	for index, profile := range profiles {
		ids[index] = profile.ID
	}
	evidence := host.CheckLiveProfiles(ctx, request.Subscription, ids)
	if request.Subscription.available() {
		return fail("CONNECTION-PROFILES-LIVE-CHECK-SUBSCRIPTION", "The one-time universal subscription was not consumed", "the outside check left reusable subscription material", "one fresh universal subscription consumed once")
	}
	if !validLiveEvidence(ids, evidence) {
		return fail("CONNECTION-PROFILES-LIVE-CHECK-EVIDENCE", "Outside authenticated traffic proof is incomplete", "a profile is missing, repeated, unauthenticated, or lacks uplink or downlink", "one authenticated uplink and downlink fact for every selected profile")
	}
	skips := make([]LiveProfileSkip, 0, len(registry.Publication.Omissions()))
	for _, omission := range registry.Publication.Omissions() {
		skips = append(skips, LiveProfileSkip{Profile: omission.ID, Reason: omission.Reason()})
	}
	return LiveProfileCheckResult{Health: Health{Module: "Connection Profiles", Profile: "Live Profile Check", Outcome: Healthy, Code: "CONNECTION-PROFILES-LIVE-CHECK-PASSED", NextActions: []string{"Back"}}, evidence: append([]LiveProfileEvidence(nil), evidence...), skips: skips}
}

func validLiveEvidence(required []ProfileID, evidence []LiveProfileEvidence) bool {
	if len(evidence) != len(required) {
		return false
	}
	seen := make(map[ProfileID]bool, len(evidence))
	for _, item := range evidence {
		if seen[item.Profile] || !item.Authenticated || !item.Uplink || !item.Downlink {
			return false
		}
		seen[item.Profile] = true
	}
	for _, profile := range required {
		if !seen[profile] {
			return false
		}
	}
	return true
}
