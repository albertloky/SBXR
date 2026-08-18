package ownerconsole

import (
	"context"
	"errors"
	"io"
	"strings"
)

type controlledRemovalObserver struct{}

func (controlledRemovalObserver) ReviewedCategories(string) ([]string, error) {
	return CompleteRemovalCategories(), nil
}
func (controlledRemovalObserver) TypedPhrase(string) (string, bool, error) {
	return completeRemovalPhrase, true, nil
}
func (controlledRemovalObserver) PermanentRemovalSelected(string) (bool, error) { return true, nil }

// ControlledRemovalReview returns the genuine reviewed-category authority.
func ControlledRemovalReview(identity string) (RemovalReview, error) {
	return New(controlledRemovalObserver{}).StartRemovalReview(identity)
}

// ControlledCloudflareWalkthrough returns the fixed packaged guide facts.
// The facts are packaged text and do not claim current external validation.
func ControlledCloudflareWalkthrough() CloudflarePresentation {
	return CloudflarePresentation{Kind: CloudflareWalkthroughPresentation, Walkthrough: CloudflareWalkthroughFacts{
		DashboardURL:            "https://dash.cloudflare.com/",
		AccountTokensPage:       "My Profile > API Tokens",
		CreateControl:           "Create Token",
		TokenName:               "SBXR dedicated broad management",
		DNSRecordsPage:          "selected domain > DNS > Records",
		TunnelsPage:             "Cloudflare One > Networks > Tunnels & Mesh",
		AccountControl:          "Permissions > User > API Tokens > Edit; Account > Cloudflare Tunnel > Edit",
		ZoneControl:             "Permissions > Zone > DNS > Edit; Zone > Zone > Read",
		AccountResource:         "Account Resources > Include > All accounts",
		ZoneResource:            "Zone Resources > Include > All zones",
		SummaryControl:          "Continue to summary > Create Token > copy once",
		RejectsGlobalAPIKey:     true,
		RejectsAccountAPIToken:  true,
		RequiresBroadAuthority:  true,
		RequiresNoExpiry:        true,
		RequiresNoIPRestriction: true,
	}}
}

type controlledQualificationProfileSetup struct{ initial ProfileSetupPresentation }

func (module *controlledQualificationProfileSetup) ViewProfileSetup(context.Context) ProfileSetupPresentation {
	return module.initial
}

func (*controlledQualificationProfileSetup) ActProfileSetup(_ context.Context, request ProfileSetupRequest) ProfileSetupResponse {
	if request.Action != BuildProfileSetupPlan {
		return ProfileSetupResponse{}
	}
	plan := controlledProfileSetupPlan("controlled-cloudflare-profile-setup")
	return ProfileSetupResponse{Review: &plan}
}

func controlledProfileSetupPlan(identity PlanIdentity) ProfileSetupPlan {
	plan := ProfileSetupPlan{Plan: PlanPresentation{
		Identity: identity, DesiredStateRevision: 2, DesiredStateSHA256: strings.Repeat("a", 64),
		RelevantChecksums: []string{"controlled " + strings.Repeat("b", 64)}, ObservedState: "Managed revision 1 proved", VerifiedExternalInputs: []string{"Controlled Cloudflare authority proved"},
		Effects: []string{"Set up all five deferred Connection Profiles"}, RequiredChecks: []string{"All six profiles agree after publication"}, AdvisoryChecks: []string{"No live provider work"},
		Interruption: "Rollback before the irreversible checkpoint.", Cancellation: "Cancel before the irreversible checkpoint.", Rollback: "Restore Managed revision 1.",
	}}
	for index, name := range profileSetupSectionNames {
		plan.Sections[index] = ProfileSetupPlanSection{Name: name, Facts: []string{"Controlled " + name + " fact"}}
	}
	return plan
}

func (*controlledQualificationProfileSetup) Review(context.Context) ChangeReview {
	return ChangeReview{}
}
func (*controlledQualificationProfileSetup) Fix(context.Context, CorrectionInput) ChangeReview {
	return ChangeReview{}
}
func (*controlledQualificationProfileSetup) CheckAgain(context.Context) ChangeReview {
	return ChangeReview{}
}
func (*controlledQualificationProfileSetup) Back(context.Context) ChangeReview { return ChangeReview{} }
func (*controlledQualificationProfileSetup) Edit(context.Context, EditingInput) ChangeReview {
	return ChangeReview{}
}
func (*controlledQualificationProfileSetup) Apply(context.Context, PlanIdentity) ChangeResult {
	return ChangeResult{}
}
func (*controlledQualificationProfileSetup) Inspect(context.Context) DurableChangeSet {
	return DurableChangeSet{}
}
func (*controlledQualificationProfileSetup) RequestCancellation(context.Context, OperationIdentity) ChangeResult {
	return ChangeResult{}
}

type qualificationStep struct{ wait, send string }

type qualificationTerminal struct {
	ctx      context.Context
	steps    []qualificationStep
	requests chan any
}

func newQualificationTerminal(ctx context.Context, steps []qualificationStep) *qualificationTerminal {
	terminal := &qualificationTerminal{ctx: ctx, steps: steps, requests: make(chan any)}
	go terminal.serve()
	return terminal
}

type qualificationRead struct {
	destination []byte
	result      chan qualificationReadResult
}

type qualificationReadResult struct {
	written int
	err     error
}

type qualificationWrite struct {
	source []byte
	result chan qualificationReadResult
}

type qualificationTranscript struct{ result chan string }

func (terminal *qualificationTerminal) serve() {
	var body strings.Builder
	var pending *qualificationRead
	next := 0
	reply := func() {
		if pending == nil {
			return
		}
		if next == len(terminal.steps) {
			pending.result <- qualificationReadResult{err: io.EOF}
			pending = nil
			return
		}
		step := terminal.steps[next]
		if strings.Contains(body.String(), step.wait) {
			pending.result <- qualificationReadResult{written: copy(pending.destination, step.send)}
			pending = nil
			next++
		}
	}
	for {
		select {
		case <-terminal.ctx.Done():
			if pending != nil {
				pending.result <- qualificationReadResult{err: terminal.ctx.Err()}
			}
			return
		case request := <-terminal.requests:
			switch request := request.(type) {
			case qualificationRead:
				pending = &request
				reply()
			case qualificationWrite:
				written, err := body.Write(request.source)
				request.result <- qualificationReadResult{written: written, err: err}
				reply()
			case qualificationTranscript:
				request.result <- body.String()
			}
		}
	}
}

func (terminal *qualificationTerminal) Read(destination []byte) (int, error) {
	result := make(chan qualificationReadResult, 1)
	select {
	case terminal.requests <- qualificationRead{destination: destination, result: result}:
	case <-terminal.ctx.Done():
		return 0, terminal.ctx.Err()
	}
	response := <-result
	return response.written, response.err
}

func (terminal *qualificationTerminal) Write(source []byte) (int, error) {
	result := make(chan qualificationReadResult, 1)
	select {
	case terminal.requests <- qualificationWrite{source: source, result: result}:
	case <-terminal.ctx.Done():
		return 0, terminal.ctx.Err()
	}
	response := <-result
	return response.written, response.err
}

func (terminal *qualificationTerminal) transcript() string {
	result := make(chan string, 1)
	select {
	case terminal.requests <- qualificationTranscript{result: result}:
		return <-result
	case <-terminal.ctx.Done():
		return ""
	}
}

type controlledTerminalScreen struct {
	scenario Scenario
	initial  ProfileSetupPresentation
	steps    []qualificationStep
	want     []string
}

// QualifyControlledStagedOnboardingTerminal runs the seven decision-critical
// screens through Run at both approved terminal sizes and returns no transcript.
func QualifyControlledStagedOnboardingTerminal(ctx context.Context) error {
	const marker = "sbxr_QUALIFICATION-MANAGEMENT-TOKEN-01234567890123456789"
	installation := strings.Join(scenarioFixture(InstallationComplete).lines, "\n")
	if !strings.Contains(installation, "XHTTP, WebSocket, Hysteria2, TUIC, AnyTLS Not set up") {
		return errors.New("controlled Owner Console terminal qualification disagrees")
	}
	screens := []controlledTerminalScreen{
		{scenario: InstallationComplete, steps: []qualificationStep{{wait: "Subscription 1 profile", send: "\x03\r"}}, want: []string{"Profiles 1 of 6 set up", "VLESS REALITY Vision Enabled", "Cloudflare Not required for first Installation", "Subscription 1 profile", "five exact omissions"}},
		{scenario: CloudflareSetupEntry, initial: ProfileSetupPresentation{Kind: ProfileSetupEntry, Revision: 1}, steps: []qualificationStep{{wait: "Optional collective setup for five profiles", send: "\x03\r"}}, want: []string{"Optional collective setup for five profiles", "Five Cloudflare profiles Not set up"}},
		{scenario: CloudflareSetupToken, initial: ProfileSetupPresentation{Kind: ProfileSetupTokenEntry, Revision: 1}, steps: []qualificationStep{{wait: "Dedicated Broad Cloudflare User API Token", send: marker}, {wait: "********", send: "\x03\r"}}, want: []string{"Dedicated Broad Cloudflare User API Token", "masked and memory-only"}},
		{scenario: CloudflareSetupFields, initial: ProfileSetupPresentation{Kind: ProfileSetupFieldsReview, Revision: 1, SelectedZone: "example.test", Hostnames: [3]string{"xhttp.example.test", "ws.example.test", "direct.example.test"}, Ports: []uint16{443, 8443, 9443}}, steps: []qualificationStep{{wait: "Zone example.test", send: "\r"}, {wait: "controlled-cloudflare-profile-setup", send: "\x03\r"}}, want: []string{"controlled-cloudflare-profile-setup", "Starting authority", "Managed revision 1 proved"}},
		{scenario: CloudflareSetupConfirmation, initial: ProfileSetupPresentation{Kind: ProfileSetupFinalConfirmation, Revision: 1}, steps: []qualificationStep{{wait: "Preparation is complete", send: "\x03\r"}}, want: []string{"Only the selected action crosses", "setup started", "Cancel and restore revision 1"}},
		{scenario: CloudflareSetupRecovery, initial: ProfileSetupPresentation{Kind: ProfileSetupRecoveryRequired, Revision: 1, Checkpoint: "Irreversible boundary crossed", Candidate: "Protected revision 2 candidate", Evidence: "Durable setup journal"}, steps: []qualificationStep{{wait: "Last committed revision 1", send: "\x03\r"}}, want: []string{"Recovery Required", "Retry Cloudflare Profile Setup recovery", "Complete removal"}},
		{scenario: CloudflareSetupComplete, initial: ProfileSetupPresentation{Kind: ProfileSetupComplete, Revision: 2}, steps: []qualificationStep{{wait: "Desired State revision 2", send: "\x03\r"}}, want: []string{"Profiles 6 of 6 set up", "VLESS XHTTP Enabled", "AnyTLS Enabled", "No Client Access Value appears here"}},
	}
	for _, size := range [][2]int{{80, 24}, {120, 36}} {
		for _, screen := range screens {
			if err := runControlledTerminalScreen(ctx, size, screen, marker); err != nil {
				return err
			}
		}
	}
	return nil
}

// QualifyControlledStagedOnboardingGuideText proves the fixed packaged text.
// It makes no claim about current external documentation or dashboard labels.
func QualifyControlledStagedOnboardingGuideText(ctx context.Context) error {
	guideOne := strings.Join(profileSetupLines(ProfileSetupPresentation{Kind: ProfileSetupGuideOne, Revision: 1}, true, ProfileSetupPlan{}, false, CloudflareSetupGuideOne, "", false, false, 0, 0, 0, 120, 36), "\n")
	guide := strings.Join(profileSetupLines(ProfileSetupPresentation{Kind: ProfileSetupGuideTwo, Revision: 1}, true, ProfileSetupPlan{}, false, CloudflareSetupGuideTwo, "", false, false, 0, 0, 0, 120, 36), "\n")
	if !strings.Contains(guideOne, "Create one Dedicated Broad Cloudflare User API Token.") {
		return errors.New("controlled Owner Console guide-text qualification disagrees")
	}
	for _, fixed := range []string{"User API Tokens Edit - all user tokens", "Cloudflare Tunnel Edit - all accounts", "DNS Edit - all zones", "Zone Read - all zones", "No expiry; no client-IP restriction", "Global API Key REJECTED", "Account API Token REJECTED", "API Tokens Edit can manage every User API Token owned by this user.", "SBXR restricts product use to selected immutable IDs."} {
		if !strings.Contains(guide, fixed) {
			return errors.New("controlled Owner Console guide-text qualification disagrees")
		}
	}
	screens := []controlledTerminalScreen{
		{scenario: CloudflareSetupGuideOne, initial: ProfileSetupPresentation{Kind: ProfileSetupGuideOne, Revision: 1}, steps: []qualificationStep{{wait: "Create one Dedicated Broad", send: "\x03\r"}}, want: []string{"Dedicated Broad"}},
		{scenario: CloudflareSetupGuideTwo, initial: ProfileSetupPresentation{Kind: ProfileSetupGuideTwo, Revision: 1}, steps: []qualificationStep{{wait: "User API Tokens Edit - all user tokens", send: "\x03\r"}}, want: []string{"User API Tokens Edit", "Cloudflare Tunnel Edit", "DNS Edit", "Zone Read", "No expiry", "no client-IP restriction", "Global API Key REJECTED", "Account API Token REJECTED", "API Tokens Edit can manage", "SBXR restricts product use"}},
	}
	for _, size := range [][2]int{{80, 24}, {120, 36}} {
		for _, screen := range screens {
			if err := runControlledTerminalScreen(ctx, size, screen, ""); err != nil {
				return err
			}
		}
	}
	return nil
}

func runControlledTerminalScreen(ctx context.Context, size [2]int, screen controlledTerminalScreen, secret string) error {
	terminal := newQualificationTerminal(ctx, screen.steps)
	capabilities := Capabilities{InteractiveInput: true, InteractiveOutput: true, AlternateScreen: true, CursorAddressing: true, ReadableEncoding: true, KeyboardInput: true, Unicode: true, Width: size[0], Height: size[1]}
	session := Session{Input: terminal, Output: terminal, Environment: []string{"TERM=xterm-256color", "LANG=C.UTF-8", "NO_COLOR=1"}, Capabilities: &capabilities, Scenario: screen.scenario}
	if screen.initial.Kind != 0 {
		session.ProfileSetup = &controlledQualificationProfileSetup{initial: screen.initial}
	}
	if err := Run(ctx, session); err != nil {
		return errors.New("controlled Owner Console terminal qualification failed")
	}
	transcript := terminal.transcript()
	for _, want := range append([]string{scenarioFixture(screen.scenario).title}, screen.want...) {
		if !strings.Contains(transcript, want) {
			return errors.New("controlled Owner Console terminal qualification disagrees")
		}
	}
	if secret != "" && strings.Contains(transcript, secret) {
		return errors.New("controlled Owner Console terminal qualification exposed a marker")
	}
	return nil
}
