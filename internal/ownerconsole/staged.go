package ownerconsole

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// ProfileSetupModule is the presentation-safe seam from Owner Console to the
// Cloudflare Profile Setup outcome. The owning Module keeps provider, secret,
// Plan, transaction, rollback, and recovery authority.
type ProfileSetupModule interface {
	OutcomeModule
	ViewProfileSetup(context.Context) ProfileSetupPresentation
	ActProfileSetup(context.Context, ProfileSetupRequest) ProfileSetupResponse
}

type ProfileSetupKind uint8

const (
	ProfileSetupEntry ProfileSetupKind = iota + 1
	ProfileSetupGuideOne
	ProfileSetupGuideTwo
	ProfileSetupTokenEntry
	ProfileSetupZoneSelection
	ProfileSetupFieldsReview
	ProfileSetupPlanReviewScreen
	ProfileSetupFinalConfirmation
	ProfileSetupProgress
	ProfileSetupRolledBack
	ProfileSetupRecoveryRequired
	ProfileSetupComplete
	ProfileSetupCorrection
)

type ProfileSetupAction uint8

const (
	BeginProfileSetup ProfileSetupAction = iota + 1
	NextProfileSetupGuide
	AcceptProfileSetupAuthority
	SubmitProfileSetupToken
	SelectProfileSetupZone
	BuildProfileSetupPlan
	PrepareProfileSetup
	StartIrreversibleProfileSetup
	CancelPreparedProfileSetup
	RetryProfileSetupRecovery
	ViewProfileSetupEvidence
	FixProfileSetup
	CheckProfileSetupAgain
	BackProfileSetup
)

type ProfileSetupRequest struct {
	Action          ProfileSetupAction
	From            ProfileSetupKind
	Token           string
	Zone            string
	Plan            PlanIdentity
	Text, Selection string
}

type ProfileSetupResponse struct {
	Presentation *ProfileSetupPresentation
	Review       *ProfileSetupPlan
}

type ProfileSetupPlanSection struct {
	Name  string
	Facts []string
}

type ProfileSetupPlan struct {
	Plan     PlanPresentation
	Sections [8]ProfileSetupPlanSection
}

type ProfileSetupZone struct{ Account, Name string }

type ProfileSetupPresentation struct {
	Kind                            ProfileSetupKind
	Revision                        uint64
	Zones                           []ProfileSetupZone
	SelectedZone                    string
	Hostnames                       [3]string
	Ports                           []uint16
	Checkpoint, Candidate, Evidence string
	Correction                      *CorrectionPresentation
}

var profileSetupSectionNames = [...]string{
	"Starting authority",
	"Cloudflare authority",
	"Names and ports",
	"Provider and local effects",
	"Certificate and network",
	"Profiles and publication",
	"Checks and unchanged resources",
	"Interruption and recovery",
}

func validatedProfileSetup(p ProfileSetupPresentation) (ProfileSetupPresentation, bool) {
	if p.Kind < ProfileSetupEntry || p.Kind > ProfileSetupCorrection || p.Revision == 0 {
		return ProfileSetupPresentation{}, false
	}
	if p.Kind == ProfileSetupZoneSelection {
		if len(p.Zones) == 0 || len(p.Zones) > 32 {
			return ProfileSetupPresentation{}, false
		}
		for _, zone := range p.Zones {
			if !safeLine(zone.Account) || !safeLine(zone.Name) {
				return ProfileSetupPresentation{}, false
			}
		}
		p.Zones = append([]ProfileSetupZone(nil), p.Zones...)
	}
	if p.Kind == ProfileSetupFieldsReview {
		if !safeProviderLines(p.Hostnames[:], len(p.Hostnames)) || !safeLine(p.SelectedZone) || len(p.Ports) == 0 || len(p.Ports) > 5 {
			return ProfileSetupPresentation{}, false
		}
		for _, port := range p.Ports {
			if port == 0 {
				return ProfileSetupPresentation{}, false
			}
		}
		p.Ports = append([]uint16(nil), p.Ports...)
	}
	if p.Kind == ProfileSetupRecoveryRequired && (!safeLine(p.Checkpoint) || !safeLine(p.Candidate) || !safeLine(p.Evidence)) {
		return ProfileSetupPresentation{}, false
	}
	if p.Kind == ProfileSetupCorrection {
		correction := validatedChangeReview(ChangeReview{Correction: p.Correction}).Correction
		if correction == nil {
			return ProfileSetupPresentation{}, false
		}
		p.Correction = correction
	}
	return p, true
}

func validatedProfileSetupPlan(review ProfileSetupPlan) (ProfileSetupPlan, bool) {
	validated := validatedChangeReview(ChangeReview{Plan: &review.Plan}).Plan
	if validated == nil {
		return ProfileSetupPlan{}, false
	}
	review.Plan = *validated
	for index, section := range review.Sections {
		if section.Name != profileSetupSectionNames[index] || !completeStrings(section.Facts, 32) {
			return ProfileSetupPlan{}, false
		}
		review.Sections[index].Facts = append([]string(nil), section.Facts...)
	}
	return review, true
}

func profileSetupScenario(kind ProfileSetupKind) Scenario {
	return map[ProfileSetupKind]Scenario{
		ProfileSetupEntry: CloudflareSetupEntry, ProfileSetupGuideOne: CloudflareSetupGuideOne,
		ProfileSetupGuideTwo: CloudflareSetupGuideTwo, ProfileSetupTokenEntry: CloudflareSetupToken,
		ProfileSetupZoneSelection: CloudflareSetupZone, ProfileSetupFieldsReview: CloudflareSetupFields,
		ProfileSetupPlanReviewScreen: CloudflareSetupPlan, ProfileSetupRolledBack: CloudflareSetupRollback,
		ProfileSetupFinalConfirmation: CloudflareSetupConfirmation, ProfileSetupProgress: CloudflareSetupProgress,
		ProfileSetupRecoveryRequired: CloudflareSetupRecovery, ProfileSetupComplete: CloudflareSetupComplete,
		ProfileSetupCorrection: CorrectionFlow,
	}[kind]
}

func isProfileSetupScenario(scenario Scenario) bool {
	return scenario >= CloudflareSetupEntry && scenario <= CloudflareSetupRollback
}

var profileSetupProgressStages = [...]string{
	"Prepare",
	"Cross irreversible boundary",
	"Create Tunnel and origins",
	"Create direct DNS and certificate",
	"Start direct profiles and admit ports",
	"Create public routes",
	"Activate subscriptions and pass gates",
	"Publish, prove, and Complete",
}

func profileSetupLines(view ProfileSetupPresentation, valid bool, plan ProfileSetupPlan, planValid bool, scenario Scenario, input string, focused, revealed bool, action, selection, page, width, height int) []string {
	if !valid {
		return []string{"Cloudflare Profile Setup facts are unavailable.", "", "No Plan, provider authority, secret input, or Apply action was inferred.", "", "> Back"}
	}
	switch scenario {
	case CloudflareSetupEntry:
		return []string{"Optional collective setup for five profiles.", "", "VLESS REALITY Vision Enabled", "Five Cloudflare profiles Not set up", "", "Not set up is accepted and is not unhealthy.", "No setup-completion percentage exists.", "", selectedAction(action, 0, "Set up Cloudflare profiles"), selectedAction(action, 1, "Back to Overview")}
	case CloudflareSetupGuideOne:
		return []string{"Create one Dedicated Broad Cloudflare User API Token.", "", "Open My Profile > API Tokens > Create Custom Token.", "Use the exact four permissions on the next screen.", "", selectedAction(action, 0, "Continue"), selectedAction(action, 1, "Back")}
	case CloudflareSetupGuideTwo:
		return []string{"User API Tokens Edit - all user tokens", "Cloudflare Tunnel Edit - all accounts", "DNS Edit - all zones", "Zone Read - all zones", "", "No expiry; no client-IP restriction", "Global API Key REJECTED", "Account API Token REJECTED", "", "API Tokens Edit can manage every User API Token owned by this user.", "SBXR restricts product use to selected immutable IDs.", "", selectedAction(action, 0, "I understand; enter the token"), selectedAction(action, 1, "Back")}
	case CloudflareSetupToken:
		value := strings.Repeat("*", len([]rune(input)))
		if value == "" {
			value = "-"
		}
		if revealed {
			value = input
		}
		fieldPrefix := "  "
		if focused {
			fieldPrefix = "> "
		}
		lines := []string{"Dedicated Broad Cloudflare User API Token", "", fieldPrefix + "Token " + value + " [masked and memory-only]", "Focused Ctrl+R reveals it temporarily.", "", selectedAction(action, 0, "Verify token"), selectedAction(action, 1, "Back")}
		if revealed {
			lines = append(lines, "", "TOKEN REVEALED — screenshots and recordings can capture it.")
		}
		return lines
	case CloudflareSetupZone:
		lines := []string{"Select one active zone returned by the owning Module.", ""}
		for index, zone := range view.Zones {
			lines = append(lines, selectedAction(action, index, zone.Account+" - "+zone.Name))
		}
		return append(lines, "", selectedAction(action, len(view.Zones), "Back"))
	case CloudflareSetupFields:
		return []string{"Zone " + view.SelectedZone, "XHTTP " + view.Hostnames[0], "WebSocket " + view.Hostnames[1], "Direct TLS " + view.Hostnames[2], "Ports " + portsText(view.Ports), "", selectedAction(action, 0, "Build exact Plan"), selectedAction(action, 1, "Back and correct")}
	case CloudflareSetupPlan:
		if !planValid {
			return []string{"The owning Module did not supply one complete exact Plan.", "", "> Back"}
		}
		return providerPage(profileSetupAllPlanLines(plan, action), 3, width, height, page)
	case CloudflareSetupConfirmation:
		return []string{"Preparation is complete. Rollback is available.", "", "Only the selected action crosses Irreversible Cloudflare setup started.", "Rollback authority is then deleted and proved absent before the first provider write.", "After it, Cancel and rollback are unavailable.", "", selectedAction(action, 0, "Start irreversible Cloudflare setup"), selectedAction(action, 1, "Cancel and restore revision "+fmt.Sprint(view.Revision)), "  View prepared evidence"}
	case CloudflareSetupProgress:
		lines := []string{"No percentage, completion time, or result is inferred.", ""}
		for index, stage := range profileSetupProgressStages {
			prefix := "  "
			if index == action {
				prefix = "> "
			}
			lines = append(lines, prefix+fmt.Sprintf("%d. %s", index+1, stage))
		}
		return append(lines, "", "Cancel and rollback are unavailable.")
	case CloudflareSetupRollback:
		return []string{"Rolled back", "Revision " + fmt.Sprint(view.Revision) + " remains the complete committed result.", "No candidate profile or Client Access Value was published.", "", "> Back to Overview"}
	case CloudflareSetupRecovery:
		return []string{"Recovery Required", "Last committed revision " + fmt.Sprint(view.Revision), "Checkpoint " + view.Checkpoint, "Candidate " + view.Candidate, "Evidence " + view.Evidence, "", selectedAction(action, 0, "Retry Cloudflare Profile Setup recovery"), selectedAction(action, 1, "View safe evidence"), selectedAction(action, 2, "Check again"), selectedAction(action, 3, "Complete removal"), "", "No Access, repair, update, rotation, or Live Profile Check."}
	case CloudflareSetupComplete:
		return []string{"Desired State revision " + fmt.Sprint(view.Revision) + " is durable and proven.", "", "Profiles 6 of 6 set up", "VLESS REALITY Vision Enabled", "VLESS XHTTP Enabled", "VLESS WebSocket Enabled", "Hysteria2 Enabled", "TUIC Enabled", "AnyTLS Enabled", "", "No Client Access Value appears here.", "", selectedAction(action, 0, "Open Access"), selectedAction(action, 1, "Run Live Profile Check"), selectedAction(action, 2, "Manage Cloudflare")}
	case CorrectionFlow:
		c := view.Correction
		lines := []string{"Problem: " + c.Problem, "Found: " + c.Found, "Required: " + c.Required, "Why stopped: " + c.WhyStopped}
		for _, step := range c.OwnerSteps {
			lines = append(lines, "Owner step: "+step)
		}
		for index, choice := range c.Selections {
			lines = append(lines, selectedAction(selection, index, "Selection: "+choice.Label))
		}
		if c.InputLabel != "" {
			value := "-"
			if input != "" {
				value = strconv.QuoteToGraphic(input)
			}
			prefix := "  "
			if focused {
				prefix = "> "
			}
			lines = append(lines, prefix+c.InputLabel+": "+value)
		}
		lines = append(lines, "Evidence: "+c.Evidence, "")
		index := 0
		if c.FixWithSBXR {
			lines = append(lines, selectedAction(action, index, "Fix with SBXR"))
			index++
		}
		if !c.HideCheckAgain {
			lines = append(lines, selectedAction(action, index, "Check again"))
			index++
		}
		return append(lines, selectedAction(action, index, "Back"))
	}
	return []string{"Cloudflare Profile Setup facts are unavailable.", "", "> Back"}
}

func profileSetupAllPlanLines(plan ProfileSetupPlan, action int) []string {
	var lines []string
	for page, section := range plan.Sections {
		lines = append(lines, fmt.Sprintf("SECTION %d OF 8 - %s", page+1, section.Name))
		lines = append(lines, section.Facts...)
		lines = append(lines, profileSetupBoundPlanLines(plan.Plan, page)...)
		lines = append(lines, "")
	}
	return append(lines, selectedAction(action, 0, "Apply this exact Plan"), selectedAction(action, 1, "View every effect and gate"), selectedAction(action, 2, "Back and edit"))
}

func profileSetupBoundPlanLines(plan PlanPresentation, page int) []string {
	switch page {
	case 0:
		return []string{"Plan identity " + string(plan.Identity), fmt.Sprintf("Desired State revision %d", plan.DesiredStateRevision), "Desired State SHA-256 " + plan.DesiredStateSHA256, "Observed State " + plan.ObservedState}
	case 1:
		return prefixedLines("Verified external input ", plan.VerifiedExternalInputs)
	case 3:
		return prefixedLines("Exact effect ", plan.Effects)
	case 4:
		return prefixedLines("Required check ", plan.RequiredChecks)
	case 6:
		return append(prefixedLines("Relevant checksum ", plan.RelevantChecksums), prefixedLines("Advisory check ", plan.AdvisoryChecks)...)
	case 7:
		return []string{"Interruption " + plan.Interruption, "Cancellation " + plan.Cancellation, "Rollback " + plan.Rollback}
	}
	return nil
}

func prefixedLines(prefix string, values []string) []string {
	lines := make([]string, len(values))
	for index, value := range values {
		lines[index] = prefix + value
	}
	return lines
}

func selectedAction(selected, index int, label string) string {
	if selected == index {
		return "> " + label
	}
	return "  " + label
}

func portsText(ports []uint16) string {
	values := make([]string, len(ports))
	for index, port := range ports {
		values[index] = fmt.Sprint(port)
	}
	return strings.Join(values, ", ")
}
