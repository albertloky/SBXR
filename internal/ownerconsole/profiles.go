package ownerconsole

import (
	"context"
	"fmt"
	"time"
)

// ProfilesModule is the presentation-safe Owner Console seam for Connection
// Profiles, subscriptions, and the optional session-only Live Profile Check.
type ProfilesModule interface {
	ViewProfiles(context.Context) ProfilesPresentation
	ReviewProfileChange(context.Context, ProfileChangeRequest) ChangeReview
	ValidateProfile(context.Context, AccessProfileID) ProfileValidation
	ReviewClientAccessChange(context.Context, ClientAccessChange) ChangeReview
	RunLiveProfileCheck(context.Context) <-chan LiveProfileCheckPresentation
}

type ProfileHealth uint8

const (
	ProfileHealthy ProfileHealth = iota + 1
	ProfileNeedsAttention
	ProfileFailed
	ProfileUnknown
	ProfileDisabled
)

func (health ProfileHealth) String() string {
	names := [...]string{"", "HEALTHY", "NEEDS ATTENTION", "FAILED", "UNKNOWN", "DISABLED"}
	if int(health) >= len(names) {
		return ""
	}
	return names[health]
}

type ProfilePresentation struct {
	ID                  AccessProfileID
	Enabled             bool
	Service, Listener   ProfileHealth
	Address             string
	Port                uint16
	Transport, Settings string
	Exposed, Published  bool
	CredentialRetained  bool
}

type ProfilesPresentation struct {
	Managed  bool
	Profiles [6]ProfilePresentation
}

type ProfileChange uint8

const (
	RotateProfileCredential ProfileChange = 1
	EnableProfile           ProfileChange = 4
	DisableProfile          ProfileChange = 5
)

type ProfileChangeRequest struct {
	Profile AccessProfileID
	Change  ProfileChange
}

type ProfileValidation struct {
	Profile AccessProfileID
	Health  ProfileHealth
	Code    string
}

func validatedProfileValidation(validation ProfileValidation, selected AccessProfileID) ProfileValidation {
	if validation.Profile != selected || validation.Health < ProfileHealthy || validation.Health > ProfileUnknown || !safeIdentifier(validation.Code) || !safeLine(validation.Code) {
		return ProfileValidation{Profile: selected, Health: ProfileUnknown, Code: "OWNER-CONSOLE-PROFILE-VALIDATION-UNAVAILABLE"}
	}
	return validation
}

type ClientAccessChange uint8

const (
	RotateEveryProfileCredential ClientAccessChange = iota + 1
	RotateSubscriptionToken
	RevokeAllClientAccess
)

type LiveProfileResult struct {
	Profile                         AccessProfileID
	Stage                           LiveProfileResultStage
	Authenticated, Uplink, Downlink bool
}

type LiveProfileResultStage uint8

const (
	LiveProfilePending LiveProfileResultStage = iota + 1
	LiveProfileChecked
)

type LiveProfileCheckPresentation struct {
	TemporaryURL string
	Results      [6]LiveProfileResult
	Complete     bool
}

func validatedLiveProfileCheck(presentation, prior LiveProfileCheckPresentation) (LiveProfileCheckPresentation, bool) {
	if !safeURI(presentation.TemporaryURL, "https") || !shortSafeLine(presentation.TemporaryURL, 128) {
		return LiveProfileCheckPresentation{}, false
	}
	initial := prior.TemporaryURL == ""
	if initial && presentation.Complete || !initial && presentation.TemporaryURL != prior.TemporaryURL {
		return LiveProfileCheckPresentation{}, false
	}
	for index, result := range presentation.Results {
		if result.Profile != AccessProfileID(index+1) || result.Stage < LiveProfilePending || result.Stage > LiveProfileChecked || result.Stage == LiveProfilePending && (result.Authenticated || result.Uplink || result.Downlink) || presentation.Complete && result.Stage != LiveProfileChecked {
			return LiveProfileCheckPresentation{}, false
		}
		if initial && result.Stage != LiveProfilePending {
			return LiveProfileCheckPresentation{}, false
		}
		if !initial && prior.Results[index].Stage == LiveProfileChecked && result != prior.Results[index] {
			return LiveProfileCheckPresentation{}, false
		}
	}
	return presentation, true
}

func liveProfileCheckLines(check LiveProfileCheckPresentation, valid bool, width int, unicode bool, elapsedTime time.Duration) []string {
	if !valid {
		return []string{"Live Profile Check facts are unavailable.", "", "No temporary URL, traffic result, or success was inferred.", "", "> Back"}
	}
	state := "Complete"
	if !check.Complete {
		state = spinner(unicode, elapsedTime) + " Running " + elapsed(elapsedTime)
	}
	lines := []string{"Session-only and memory-only - " + state, "Temporary test URL " + check.TemporaryURL}
	if width < 120 {
		lines = append(lines, "QR omitted at this size; exact text remains available.")
	}
	for _, result := range check.Results {
		if result.Stage == LiveProfilePending {
			lines = append(lines, result.Profile.String()+" PENDING")
		} else {
			lines = append(lines, fmt.Sprintf("%s auth=%s up=%s down=%s", result.Profile, yesNo(result.Authenticated), yesNo(result.Uplink), yesNo(result.Downlink)))
		}
	}
	return append(lines, "No manual success; automatic outside traffic only.", "> Back")
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func validatedProfiles(presentation ProfilesPresentation) (ProfilesPresentation, bool) {
	if !presentation.Managed {
		return ProfilesPresentation{}, false
	}
	for index, profile := range presentation.Profiles {
		if profile.ID != AccessProfileID(index+1) || profile.Service.String() == "" || profile.Listener.String() == "" || profile.Port == 0 || !shortSafeLine(profile.Address, 48) || !shortSafeLine(profile.Transport, 32) || !shortSafeLine(profile.Settings, 48) {
			return ProfilesPresentation{}, false
		}
		if profile.Enabled {
			if profile.Service == ProfileDisabled || profile.Listener == ProfileDisabled || !profile.Exposed || !profile.Published {
				return ProfilesPresentation{}, false
			}
		} else if profile.Service != ProfileDisabled || profile.Listener != ProfileDisabled || profile.Exposed || profile.Published || !profile.CredentialRetained {
			return ProfilesPresentation{}, false
		}
	}
	return presentation, true
}

func shortSafeLine(value string, maximum int) bool {
	return len(value) <= maximum && safeLine(value)
}

func profileLines(profile ProfilePresentation, selectedAction int) []string {
	state := "ENABLED"
	if !profile.Enabled {
		state = "DISABLED"
	}
	lines := []string{
		"Connection Profile " + profile.ID.String(),
		"[" + state + "] " + profile.ID.String(),
		"Service " + profile.Service.String() + " - Listener " + profile.Listener.String(),
		"Public address or hostname " + profile.Address,
		fmt.Sprintf("Selected port and transport %d - %s", profile.Port, profile.Transport),
		"Settings " + profile.Settings,
	}
	if profile.Enabled {
		lines = append(lines, "Exposure OPEN - Publication INCLUDED")
	} else {
		lines = append(lines, "Settings and credential retained", "Exposure CLOSED - Publication OMITTED")
	}
	lines = append(lines, "")
	for index, action := range profileActions(profile.Enabled) {
		prefix := "  "
		if index == selectedAction {
			prefix = "> "
		}
		lines = append(lines, prefix+action.label)
	}
	return lines
}

type journeyActionKind uint8

const (
	openAccessAction journeyActionKind = iota + 1
	reviewProfileChangeAction
	validateProfileAction
	reviewClientAccessChangeAction
	runLiveProfileCheckAction
)

type profileAction struct {
	label  string
	kind   journeyActionKind
	change ProfileChange
}

func profileActions(enabled bool) []profileAction {
	toggle := "Disable"
	toggleChange := DisableProfile
	if !enabled {
		toggle = "Enable"
		toggleChange = EnableProfile
	}
	return []profileAction{
		{label: "Open in Access", kind: openAccessAction},
		{label: "Rotate credential", kind: reviewProfileChangeAction, change: RotateProfileCredential},
		{label: "Validate native configuration", kind: validateProfileAction},
		{label: toggle, kind: reviewProfileChangeAction, change: toggleChange},
	}
}

type subscriptionAction struct {
	label  string
	kind   journeyActionKind
	change ClientAccessChange
}

func subscriptionActions() []subscriptionAction {
	return []subscriptionAction{
		{label: "Open Access", kind: openAccessAction},
		{label: "Rotate all", kind: reviewClientAccessChangeAction, change: RotateEveryProfileCredential},
		{label: "Rotate subscription token only", kind: reviewClientAccessChangeAction, change: RotateSubscriptionToken},
		{label: "Revoke all client access", kind: reviewClientAccessChangeAction, change: RevokeAllClientAccess},
		{label: "Run Live Profile Check", kind: runLiveProfileCheckAction},
	}
}

func subscriptionLines(entries []accessEntry, selectedAction int) []string {
	lines := []string{"Published subscription representations"}
	for _, entry := range entries {
		line := fmt.Sprintf("%s %d/6", entry.name, entry.profileCount)
		for _, omission := range entry.omissions {
			line += " - " + omission
		}
		lines = append(lines, line)
	}
	lines = append(lines, "")
	for index, action := range subscriptionActions() {
		prefix := "  "
		if index == selectedAction {
			prefix = "> "
		}
		lines = append(lines, prefix+action.label)
	}
	return lines
}

func subscriptionFactsAgree(profiles ProfilesPresentation, entries []accessEntry) bool {
	if len(entries) == 0 {
		return false
	}
	for _, entry := range entries {
		if entry.profileCount != len(profiles.Profiles)-len(entry.omissions) {
			return false
		}
		for _, profile := range profiles.Profiles {
			want := profile.ID.String() + " - Disabled"
			has := false
			for _, omission := range entry.omissions {
				if omission == want {
					has = true
					break
				}
			}
			if has == profile.Published {
				return false
			}
		}
	}
	return true
}
