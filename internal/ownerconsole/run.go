package ownerconsole

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const minimumWidth, minimumHeight = 80, 24
const maxInputRunes = 1024
const navigationWidth = 21

type ProgressKind uint8

const (
	NoProgress ProgressKind = iota
	MeasuredProgress
	UnknownProgress
	MixedStepProgress
)

type Progress struct {
	Kind                    ProgressKind
	OperationID             uint64
	Completed, Total        uint64
	CurrentStep, TotalSteps uint16
}

type PresentationUpdate struct {
	Progress Progress
}

type AuthenticationResult uint8

const (
	AuthenticationSucceeded AuthenticationResult = iota + 1
	AuthenticationDenied
	AuthenticationCancelled
	AuthenticationFailed
	AuthenticationExpired
)

type Authenticator interface {
	Authenticate(context.Context, io.Reader, io.Writer) AuthenticationResult
}

type AuthenticationPolicy uint8

const (
	AuthenticateForAccess AuthenticationPolicy = iota
	DeferAuthenticationUntilApply
)

type Capabilities struct {
	InteractiveInput         bool
	InteractiveOutput        bool
	AlternateScreen          bool
	CursorAddressing         bool
	ReadableEncoding         bool
	KeyboardInput            bool
	Unicode                  bool
	DrawingModeProbeRequired bool
	Width                    int
	Height                   int
}

type Session struct {
	Input                   io.Reader
	Output                  io.Writer
	Environment             []string
	Capabilities            *Capabilities
	Scenario                Scenario
	Updates                 <-chan PresentationUpdate
	Authenticator           Authenticator
	AuthenticationPolicy    AuthenticationPolicy
	Access                  AccessPresentation
	AccessProvider          func(context.Context) AccessPresentation
	StartupProvider         func(context.Context) StartupPresentation
	Clipboard               Clipboard
	Outcome                 OutcomeModule
	Profiles                ProfilesModule
	ProfileOutcomes         OutcomeModule
	Cloudflare              CloudflareModule
	CloudflareOutcomes      OutcomeModule
	Certificates            CertificatesModule
	CertificateOutcomes     OutcomeModule
	Diagnostics             DiagnosticsModule
	Lifecycle               LifecycleModule
	LifecycleOutcomes       OutcomeModule
	Recovery                RecoveryModule
	RecoveryOutcomes        OutcomeModule
	CompleteRemoval         CompleteRemovalModule
	CompleteRemovalOutcomes OutcomeModule
}

func Run(ctx context.Context, session Session) error {
	if session.Output == nil {
		session.Output = io.Discard
	}
	if session.Capabilities == nil {
		return refuse(session.Output, "terminal capabilities could not be detected", "run sbxr in a supported interactive terminal")
	}
	c := *session.Capabilities
	checks := []struct {
		ok                     bool
		capability, correction string
	}{
		{ok: c.InteractiveInput, capability: "interactive input", correction: "run sbxr in an interactive terminal"},
		{ok: c.InteractiveOutput, capability: "interactive output", correction: "run sbxr with the terminal attached to standard output"},
		{ok: c.DrawingModeProbeRequired || c.AlternateScreen, capability: "alternate-screen support", correction: "use a terminal that supports an alternate screen"},
		{ok: c.DrawingModeProbeRequired || c.CursorAddressing, capability: "full-screen cursor addressing and drawing", correction: "use a terminal with full-screen cursor support"},
		{ok: c.ReadableEncoding, capability: "readable text encoding", correction: "use a UTF-8 terminal locale"},
		{ok: c.KeyboardInput, capability: "standard keyboard input", correction: "use a terminal with standard keyboard input"},
	}
	for _, check := range checks {
		if !check.ok {
			return refuse(session.Output, check.capability+" is unavailable", check.correction)
		}
	}
	if c.Width < minimumWidth || c.Height < minimumHeight {
		return refuse(session.Output, fmt.Sprintf("current size is %dx%d; required size is %dx%d", c.Width, c.Height, minimumWidth, minimumHeight), "enlarge the terminal")
	}
	if session.Input == nil {
		return refuse(session.Output, "interactive input is unavailable", "run sbxr in an interactive terminal")
	}
	if session.Environment == nil {
		session.Environment = os.Environ()
	}
	_, noColor := environmentValues(session.Environment)["NO_COLOR"]
	initialModes := map[int]bool{}
	queryOwnedModes(session.Output)
	resetOwnedModes(session.Output)
	probeCursorAddressing(session.Output)
	runContext, stop := context.WithCancel(ctx)
	defer stop()
	fixture := scenarioFixture(session.Scenario)
	accessCatalog := session.Access.catalog()
	program := tea.NewProgram(
		model{width: c.Width, height: c.Height, scenario: session.Scenario, selected: selectedNavigation(session.Scenario), unicode: c.Unicode, noColor: noColor, initialModes: initialModes, drawingModeProbeRequired: c.DrawingModeProbeRequired, inputFocused: fixture.acceptsInput, progressExpected: session.Updates != nil, authenticator: session.Authenticator, authenticationPolicy: session.AuthenticationPolicy, runContext: runContext, accessCatalog: accessCatalog, accessProvider: session.AccessProvider, startupProvider: session.StartupProvider, clipboard: session.Clipboard, outcome: session.Outcome, defaultOutcome: session.Outcome, profiles: session.Profiles, profileOutcomes: session.ProfileOutcomes, profileViewGeneration: 1, cloudflare: session.Cloudflare, cloudflareOutcomes: session.CloudflareOutcomes, cloudflareGeneration: 1, certificates: session.Certificates, certificateOutcomes: session.CertificateOutcomes, certificateGeneration: 1, diagnostics: session.Diagnostics, diagnosticsScreen: diagnosticsScreenState{generation: 1}, lifecycle: session.Lifecycle, lifecycleOutcomes: session.LifecycleOutcomes, lifecycleScreen: lifecycleScreenState{generation: 1}, recovery: session.Recovery, recoveryOutcomes: session.RecoveryOutcomes, recoveryScreen: recoveryScreenState{generation: 1}, completeRemoval: session.CompleteRemoval, completeRemovalOutcomes: session.CompleteRemovalOutcomes, completeRemovalScreen: completeRemovalScreenState{generation: 1, action: 1, forwardOnly: session.Scenario == ForwardOnlyRemoval}},
		tea.WithContext(runContext),
		tea.WithInput(session.Input),
		tea.WithOutput(session.Output),
		tea.WithEnvironment(session.Environment),
		tea.WithWindowSize(c.Width, c.Height),
	)
	if session.Updates != nil {
		go forwardPresentationUpdates(runContext, program, session.Updates)
	}
	result, err := program.Run()
	stop()
	restoreOwnedModes(session.Output, initialModes)
	if err == nil {
		if final, ok := result.(model); ok && final.probeFailure != "" {
			return refuse(session.Output, final.probeFailure, probeCorrection(final.probeFailure))
		}
	}
	return err
}

type presentationUpdateMsg struct{ PresentationUpdate }

func forwardPresentationUpdates(ctx context.Context, program *tea.Program, updates <-chan PresentationUpdate) {
	for {
		select {
		case <-ctx.Done():
			return
		case update, open := <-updates:
			if !open {
				return
			}
			program.Send(presentationUpdateMsg{update})
		}
	}
}

func probeCorrection(failure string) string {
	switch failure {
	case "alternate-screen support is unavailable":
		return "use a terminal that supports an alternate screen"
	case "standard keyboard input is unavailable":
		return "use a terminal with standard keyboard input"
	default:
		return "use a terminal with full-screen cursor support"
	}
}

func refuse(output io.Writer, failed, correction string) error {
	err := errors.New(failed)
	_, _ = fmt.Fprintf(output, "SBXR cannot start: %s.\nCorrection: %s.\n", failed, correction)
	return err
}

func resetOwnedModes(output io.Writer) {
	// Reset modes SBXR owns before Bubble Tea starts, so a contaminated shell
	// cannot turn pasted text or mouse input into an action.
	_, _ = io.WriteString(output, "\x1b[?6l\x1b[?1049l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?25h\x1b[0m")
}

func queryOwnedModes(output io.Writer) {
	_, _ = io.WriteString(output, "\x1b[?1$p\x1b[?6$p\x1b[?25$p\x1b[?1000$p\x1b[?1002$p\x1b[?1003$p\x1b[?1006$p\x1b[?1049$p\x1b[?2004$p")
}

func probeCursorAddressing(output io.Writer) {
	_, _ = io.WriteString(output, "\x1b7\x1b[s\x1b[1;1H\x1b[6n\x1b[u\x1b8")
}

func restoreOwnedModes(output io.Writer, modes map[int]bool) {
	for _, mode := range []int{6, 1049, 1000, 1002, 1003, 1006, 2004} {
		if modes[mode] {
			_, _ = fmt.Fprintf(output, "\x1b[?%dh", mode)
		}
	}
	if visible, reported := modes[25]; reported && !visible {
		_, _ = io.WriteString(output, "\x1b[?25l")
	}
}

type model struct {
	width, height              int
	exitConfirm                bool
	scenario                   Scenario
	selected                   int
	unicode                    bool
	noColor                    bool
	dark                       bool
	appearanceKnown            bool
	initialModes               map[int]bool
	drawingModeProbeRequired   bool
	probeDone                  bool
	probeFailure               string
	cursorAddressingConfirmed  bool
	input                      string
	inputFocused               bool
	inputTruncated             bool
	pasteNeutralized           bool
	pasteGuard                 bool
	refreshed                  bool
	pendingUpdate              *PresentationUpdate
	operationState             operationPendingState
	progress                   Progress
	progressExpected           bool
	progressReceived           bool
	progressStartedAt          time.Time
	progressElapsed            time.Duration
	progressClock              progressClock
	progressTicking            bool
	privacySelection           int
	limitedMode                bool
	limitedSelection           int
	authenticator              Authenticator
	authenticationPolicy       AuthenticationPolicy
	limitedReason              string
	runContext                 context.Context
	accessCatalog              accessCatalog
	accessProvider             func(context.Context) AccessPresentation
	startupProvider            func(context.Context) StartupPresentation
	accessUnlocked             bool
	accessFocused              bool
	accessSelection            int
	clipboard                  Clipboard
	copyFeedback               string
	outcome                    OutcomeModule
	defaultOutcome             OutcomeModule
	changeReview               ChangeReview
	changeSet                  DurableChangeSet
	pendingPlanApply           bool
	changeFeedback             string
	correctionSelection        int
	correctionAction           int
	planPage                   int
	profiles                   ProfilesModule
	profileOutcomes            OutcomeModule
	changeOrigin               Scenario
	hasChangeOrigin            bool
	profilesView               ProfilesPresentation
	profilesAvailable          bool
	profileSelection           int
	profileAction              int
	profileValidation          ProfileValidation
	profileViewGeneration      uint64
	actionGeneration           uint64
	subscriptionAction         int
	liveProfileCheck           LiveProfileCheckPresentation
	liveProfileCheckValid      bool
	liveProfileCheckPending    bool
	liveProfileCheckCancel     context.CancelFunc
	liveProfileCheckGeneration uint64
	pendingLiveProfileCheck    *liveProfileCheckMsg
	liveProfileCheckStartedAt  time.Time
	liveProfileCheckElapsed    time.Duration
	cloudflare                 CloudflareModule
	cloudflareOutcomes         OutcomeModule
	cloudflareView             CloudflarePresentation
	cloudflareAvailable        bool
	cloudflareAction           int
	cloudflareGeneration       uint64
	cloudflareReplacing        bool
	cloudflareOperation        cloudflarePendingOperation
	certificates               CertificatesModule
	certificateOutcomes        OutcomeModule
	certificatesView           CertificatesPresentation
	certificatesAvailable      bool
	certificateAction          int
	certificateGeneration      uint64
	providerPage               int
	diagnostics                DiagnosticsModule
	diagnosticsScreen          diagnosticsScreenState
	lifecycle                  LifecycleModule
	lifecycleOutcomes          OutcomeModule
	lifecycleScreen            lifecycleScreenState
	recovery                   RecoveryModule
	recoveryOutcomes           OutcomeModule
	recoveryScreen             recoveryScreenState
	completeRemoval            CompleteRemovalModule
	completeRemovalOutcomes    OutcomeModule
	completeRemovalScreen      completeRemovalScreenState
}

type operationPendingState struct {
	started      time.Time
	elapsed      time.Duration
	queuedResult tea.Msg
}

func (state *operationPendingState) start()               { state.started, state.elapsed = time.Now(), 0 }
func (state *operationPendingState) stop()                { state.started, state.elapsed = time.Time{}, 0 }
func (state *operationPendingState) queue(result tea.Msg) { state.queuedResult = result }
func (state *operationPendingState) take() tea.Msg {
	result := state.queuedResult
	state.queuedResult = nil
	return result
}

type diagnosticsScreenState struct {
	view                 DiagnosticsPresentation
	result               SupportBundleResult
	feedback             string
	replacement          BundleReplacement
	generation           uint64
	action, page         int
	available, reviewing bool
	pending              bool
}

type lifecycleScreenState struct {
	view         LifecyclePresentation
	generation   uint64
	action, page int
	available    bool
	pending      bool
}

type recoveryScreenState struct {
	view         RecoveryPresentation
	generation   uint64
	action, page int
	available    bool
	pending      bool
}

type completeRemovalScreenState struct {
	view               CompleteRemovalPresentation
	generation         uint64
	action, page       int
	available, pending bool
	pendingAction      completeRemovalAction
	forwardOnly        bool
}

type probeTimeoutMsg struct{}
type progressTickMsg time.Time
type operationTickMsg time.Time
type pasteGuardExpiredMsg struct{}
type authenticationFinishedMsg struct {
	result AuthenticationResult
}
type accessLoadedMsg struct{ access AccessPresentation }
type startupLoadedMsg struct{ startup StartupPresentation }
type copyFinishedMsg struct {
	name   string
	result CopyResult
}
type changeReviewMsg struct{ review ChangeReview }
type changeResultMsg struct{ result ChangeResult }
type changeSetUpdateMsg struct{ change DurableChangeSet }
type changeBackMsg struct{ review ChangeReview }
type asyncRequestIdentity struct {
	generation uint64
	origin     Scenario
}

func (identity asyncRequestIdentity) matches(m model) bool {
	return identity.generation == m.actionGeneration && identity.origin == m.scenario
}

type profilesViewMsg struct {
	identity asyncRequestIdentity
	view     ProfilesPresentation
}
type profileReviewMsg struct {
	identity asyncRequestIdentity
	review   ChangeReview
}
type profileValidationMsg struct {
	identity   asyncRequestIdentity
	validation ProfileValidation
}
type openAccessMsg struct {
	identity  asyncRequestIdentity
	selection int
}
type liveProfileCheckMsg struct {
	generation uint64
	ctx        context.Context
	check      LiveProfileCheckPresentation
	updates    <-chan LiveProfileCheckPresentation
	ok         bool
}
type liveProfileCheckTickMsg time.Time
type cloudflareViewMsg struct {
	generation uint64
	view       CloudflarePresentation
}
type cloudflareResponseMsg struct {
	identity asyncRequestIdentity
	response CloudflareResponse
}
type cloudflareTickMsg time.Time

type cloudflarePendingOperation struct {
	active  bool
	label   string
	started time.Time
	elapsed time.Duration
	cancel  context.CancelFunc
	queued  *cloudflareResponseMsg
}

func (operation *cloudflarePendingOperation) start(label string, cancel context.CancelFunc) {
	*operation = cloudflarePendingOperation{active: true, label: label, started: time.Now(), cancel: cancel}
}

func (operation *cloudflarePendingOperation) stop() {
	if operation.cancel != nil {
		operation.cancel()
	}
	*operation = cloudflarePendingOperation{}
}

type certificatesViewMsg struct {
	generation uint64
	view       CertificatesPresentation
}
type certificateReviewMsg struct {
	identity asyncRequestIdentity
	review   ChangeReview
}
type diagnosticsViewMsg struct {
	generation uint64
	view       DiagnosticsPresentation
}
type supportBundleMsg struct {
	identity asyncRequestIdentity
	result   SupportBundleResult
}
type lifecycleViewMsg struct {
	generation uint64
	view       LifecyclePresentation
}
type lifecycleReviewMsg struct {
	identity asyncRequestIdentity
	review   ChangeReview
}
type recoveryViewMsg struct {
	generation uint64
	view       RecoveryPresentation
}
type recoveryRetryMsg struct {
	identity asyncRequestIdentity
	change   DurableChangeSet
}
type recoveryReviewMsg struct {
	identity asyncRequestIdentity
	review   ChangeReview
}
type completeRemovalViewMsg struct {
	generation uint64
	view       CompleteRemovalPresentation
	updates    <-chan CompleteRemovalPresentation
}
type completeRemovalUpdateMsg struct {
	generation uint64
	view       CompleteRemovalPresentation
	updates    <-chan CompleteRemovalPresentation
	closed     bool
}
type completeRemovalReviewMsg struct {
	identity asyncRequestIdentity
	review   ChangeReview
}
type completeRemovalCancelMsg struct {
	identity asyncRequestIdentity
	view     CompleteRemovalPresentation
}

type progressClock struct {
	kind        ProgressKind
	operationID uint64
	currentStep uint16
}

func (m model) Init() tea.Cmd {
	commands := []tea.Cmd{tea.RequestBackgroundColor}
	if m.outcome != nil {
		if m.scenario == InstallationReview {
			commands = append(commands, m.enterChangeCommand())
		} else if m.scenario != PrivacyChoice {
			commands = append(commands, m.inspectChangeCommand())
		}
	}
	if m.profiles != nil && (m.scenario == ConnectionProfilesScreen || m.scenario == SubscriptionScreen) {
		commands = append(commands, m.viewProfilesCommand())
	}
	if m.cloudflare != nil && m.scenario == CloudflareWalkthrough {
		commands = append(commands, m.viewCloudflareCommand())
	}
	if m.certificates != nil && m.scenario == CertificatesScreen {
		commands = append(commands, m.viewCertificatesCommand())
	}
	if m.diagnostics != nil && m.scenario == ServicesDiagnosticsScreen {
		commands = append(commands, m.viewDiagnosticsCommand())
	}
	if m.lifecycle != nil && m.scenario == UpdateReview {
		commands = append(commands, m.viewLifecycleCommand())
	}
	if m.recovery != nil && isRecoveryScenario(m.scenario) {
		commands = append(commands, m.viewRecoveryCommand())
	}
	if m.completeRemoval != nil && (m.scenario == CompleteRemovalConfirmation || m.scenario == ForwardOnlyRemoval) {
		commands = append(commands, m.viewCompleteRemovalCommand())
	}
	if m.drawingModeProbeRequired {
		commands = append(commands, tea.Tick(time.Second, func(time.Time) tea.Msg { return probeTimeoutMsg{} }))
	}
	return tea.Batch(commands...)
}

func (m model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = message.Width, message.Height
	case tea.BackgroundColorMsg:
		m.dark = message.IsDark()
		m.appearanceKnown = true
	case tea.ModeReportMsg:
		mode := message.Mode.Mode()
		if message.Value.IsSet() || message.Value.IsReset() {
			m.initialModes[mode] = message.Value.IsSet()
		}
		if m.drawingModeProbeRequired && (mode == 1 || mode == 1049) {
			if message.Value.IsNotRecognized() {
				if mode == 1 {
					m.probeFailure = "standard keyboard input is unavailable"
				} else {
					m.probeFailure = "alternate-screen support is unavailable"
				}
				return m, tea.Quit
			}
			m.probeDone = m.drawingModesConfirmed()
		}
	case tea.CursorPositionMsg:
		if m.drawingModeProbeRequired {
			if message.X != 0 || message.Y != 0 {
				m.probeFailure = "full-screen cursor addressing and drawing is unavailable"
				return m, tea.Quit
			}
			m.cursorAddressingConfirmed = true
			m.probeDone = m.drawingModesConfirmed()
		}
	case probeTimeoutMsg:
		if m.drawingModeProbeRequired && !m.probeDone {
			switch {
			case !reportedMode(m.initialModes, 1049):
				m.probeFailure = "alternate-screen support is unavailable"
			case !m.cursorAddressingConfirmed:
				m.probeFailure = "full-screen cursor addressing and drawing is unavailable"
			default:
				m.probeFailure = "standard keyboard input is unavailable"
			}
			return m, tea.Quit
		}
	case presentationUpdateMsg:
		if m.exitConfirm {
			update := message.PresentationUpdate
			m.pendingUpdate = &update
			return m, nil
		}
		return m, m.applyPresentationUpdate(message.PresentationUpdate)
	case progressTickMsg:
		if !m.progressStartedAt.IsZero() {
			m.progressElapsed = time.Time(message).Sub(m.progressStartedAt)
			return m, progressTick()
		}
		m.progressTicking = false
	case operationTickMsg:
		if m.operationsPending() && !m.operationState.started.IsZero() {
			m.operationState.elapsed = time.Time(message).Sub(m.operationState.started)
			return m, operationTick()
		}
	case liveProfileCheckTickMsg:
		if m.liveProfileCheckPending && !m.liveProfileCheckStartedAt.IsZero() {
			m.liveProfileCheckElapsed = time.Time(message).Sub(m.liveProfileCheckStartedAt)
			return m, liveProfileCheckTick()
		}
	case cloudflareTickMsg:
		if m.cloudflareOperation.active && !m.cloudflareOperation.started.IsZero() {
			m.cloudflareOperation.elapsed = time.Time(message).Sub(m.cloudflareOperation.started)
			return m, cloudflareTick()
		}
	case pasteGuardExpiredMsg:
		m.pasteGuard = false
	case authenticationFinishedMsg:
		if message.result == AuthenticationSucceeded {
			if m.pendingPlanApply {
				m.pendingPlanApply = false
				return m, m.applyChangeCommand()
			}
			m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
			m.limitedMode = false
			m.accessUnlocked = len(m.accessCatalog.all) != 0
			if m.startupProvider != nil {
				return m, func() tea.Msg { return startupLoadedMsg{startup: m.startupProvider(m.runContext)} }
			}
			if m.accessProvider != nil {
				return m, func() tea.Msg { return accessLoadedMsg{access: m.accessProvider(m.runContext)} }
			}
			if m.outcome != nil {
				return m, m.inspectChangeCommand()
			}
			return m, nil
		}
		m.scenario, m.selected = LimitedDashboard, selectedNavigation(LimitedDashboard)
		m.limitedMode, m.limitedSelection = true, 0
		m.limitedReason = authenticationExplanation(message.result)
	case accessLoadedMsg:
		m.accessCatalog = message.access.catalog()
		m.accessUnlocked = len(m.accessCatalog.all) != 0
	case startupLoadedMsg:
		switch message.startup.Status {
		case InstallationManaged:
			m.accessCatalog = message.startup.Access.catalog()
			m.accessUnlocked = len(m.accessCatalog.all) != 0
		case InstallationRecoveryRequired:
			view, valid := validatedRecovery(message.startup.Recovery)
			m.recoveryScreen.view, m.recoveryScreen.available = view, valid
			if valid {
				m.scenario, m.selected = recoveryScenario(view.Kind), selectedNavigation(recoveryScenario(view.Kind))
			} else {
				m.scenario, m.selected = RecoveryWithoutRecovery, selectedNavigation(RecoveryWithoutRecovery)
			}
		default:
			m.scenario, m.selected = RecoveryWithoutRecovery, selectedNavigation(RecoveryWithoutRecovery)
		}
	case copyFinishedMsg:
		switch message.result {
		case CopyConfirmed:
			m.copyFeedback = "Copied " + message.name + "."
		case CopyRequested:
			m.copyFeedback = "Copy request sent. If it is not in your clipboard, select the text manually."
		default:
			m.copyFeedback = "Copy failed. Select the text manually."
		}
	case changeReviewMsg:
		m.changeReview = validatedChangeReview(message.review)
		m.planPage, m.correctionAction, m.correctionSelection = 0, 0, 0
		m.copyFeedback = ""
		m.focusChangeInput()
	case changeBackMsg:
		if m.hasChangeOrigin && message.review == (ChangeReview{}) {
			m.scenario, m.selected = m.changeOrigin, selectedNavigation(m.changeOrigin)
			m.changeReview, m.changeFeedback, m.outcome = ChangeReview{}, "", m.defaultOutcome
			m.hasChangeOrigin = false
			m.inputFocused = false
			return m, nil
		}
		m.changeReview = validatedChangeReview(message.review)
		m.planPage, m.changeFeedback = 0, ""
		m.focusChangeInput()
	case changeSetUpdateMsg:
		m.changeSet = validatedDurableChangeSet(message.change)
		if m.changeSet.Kind != NoChangeSet {
			m.scenario, m.selected = MultiStepChangeSet, selectedNavigation(MultiStepChangeSet)
		}
	case changeResultMsg:
		message.result = validatedChangeResult(message.result)
		switch message.result.Kind {
		case ChangeStarted, ChangeCancellationRequested:
			if m.hasChangeOrigin && m.changeOrigin == CompleteRemovalConfirmation && m.completeRemoval != nil {
				m.scenario, m.selected, m.outcome = CompleteRemovalConfirmation, selectedNavigation(CompleteRemovalConfirmation), m.defaultOutcome
				return m, m.refreshCompleteRemovalCommand()
			}
			explanation := message.result.Explanation
			if message.result.Kind == ChangeCancellationRequested && explanation == "" {
				explanation = "Cancellation requested; waiting for a safe rollback checkpoint."
			}
			m.changeSet = DurableChangeSet{Kind: ChangeSetActive, OperationID: message.result.OperationID, Explanation: explanation}
			m.scenario, m.selected = MultiStepChangeSet, selectedNavigation(MultiStepChangeSet)
		case ChangePlanRejected:
			m.scenario, m.selected = InstallationReview, selectedNavigation(InstallationReview)
			m.changeReview = ChangeReview{}
			m.changeFeedback = message.result.Explanation
			if m.changeFeedback == "" {
				m.changeFeedback = "The Plan was stale, changed, or already used. A fresh Plan was rebuilt for review."
			}
			return m, m.reviewChangeCommand()
		case changeFactsUnavailable:
			m.changeFeedback = message.result.Explanation
			if m.changeReview.Plan != nil {
				m.changeReview = ChangeReview{}
				m.pendingPlanApply = false
			}
		}
	case profilesViewMsg:
		if message.identity.generation != m.profileViewGeneration || message.identity.origin != m.scenario {
			return m, nil
		}
		m.profilesView, m.profilesAvailable = validatedProfiles(message.view)
		m.profilesAvailable = m.profilesAvailable && m.profileOutcomes != nil
		m.actionGeneration++
		m.profileSelection, m.profileAction, m.subscriptionAction = 0, 0, 0
		m.profileValidation = ProfileValidation{}
	case profileReviewMsg:
		if m.profileOutcomes == nil || !message.identity.matches(m) {
			return m, nil
		}
		m.changeOrigin, m.hasChangeOrigin = m.scenario, true
		m.outcome = m.profileOutcomes
		m.changeReview = validatedChangeReview(message.review)
		m.planPage, m.changeFeedback = 0, ""
		m.focusChangeInput()
		m.scenario, m.selected = InstallationReview, selectedNavigation(InstallationReview)
	case profileValidationMsg:
		if !message.identity.matches(m) {
			return m, nil
		}
		m.profileValidation = validatedProfileValidation(message.validation, m.profilesView.Profiles[m.profileSelection].ID)
	case openAccessMsg:
		if !message.identity.matches(m) {
			return m, nil
		}
		m.scenario, m.selected, m.accessFocused = DedicatedAccess, selectedNavigation(DedicatedAccess), true
		m.accessSelection, m.copyFeedback = message.selection, ""
	case liveProfileCheckMsg:
		if message.generation != m.liveProfileCheckGeneration || m.scenario != LiveProfileCheckScreen {
			return m, nil
		}
		if m.exitConfirm {
			pending := message
			m.pendingLiveProfileCheck = &pending
			return m, nil
		}
		return m, m.finishLiveProfileCheck(message)
	case cloudflareViewMsg:
		if message.generation != m.cloudflareGeneration || m.scenario != CloudflareWalkthrough {
			return m, nil
		}
		m.cloudflareView, m.cloudflareAvailable = validatedCloudflarePresentation(message.view)
		m.cloudflareAction, m.cloudflareReplacing, m.providerPage = 0, false, 0
		m.inputFocused = m.cloudflareAvailable && m.cloudflareView.Kind == CloudflareWalkthroughPresentation && m.cloudflarePageCount() == 1
	case cloudflareResponseMsg:
		if !message.identity.matches(m) || m.cloudflare == nil {
			return m, nil
		}
		if m.exitConfirm {
			pending := message
			m.cloudflareOperation.queued = &pending
			return m, nil
		}
		return m, m.finishCloudflareResponse(message)
	case certificatesViewMsg:
		if message.generation != m.certificateGeneration || m.scenario != CertificatesScreen {
			return m, nil
		}
		m.certificatesView, m.certificatesAvailable = validatedCertificates(message.view)
		m.certificateAction, m.providerPage = 0, 0
	case certificateReviewMsg:
		if !message.identity.matches(m) || m.certificateOutcomes == nil {
			return m, nil
		}
		m.changeOrigin, m.hasChangeOrigin = m.scenario, true
		m.outcome = m.certificateOutcomes
		m.changeReview = validatedChangeReview(message.review)
		m.planPage, m.changeFeedback, m.inputFocused = 0, "", false
		m.scenario, m.selected = InstallationReview, selectedNavigation(InstallationReview)
	case diagnosticsViewMsg:
		if message.generation != m.diagnosticsScreen.generation || m.scenario != ServicesDiagnosticsScreen {
			return m, nil
		}
		if m.exitConfirm {
			m.operationState.queue(message)
			return m, nil
		}
		m.diagnosticsScreen.view, m.diagnosticsScreen.available = validatedDiagnostics(message.view)
	case supportBundleMsg:
		if !message.identity.matches(m) || m.scenario != ServicesDiagnosticsScreen {
			return m, nil
		}
		if m.exitConfirm {
			m.operationState.queue(message)
			return m, nil
		}
		m.diagnosticsScreen.pending = false
		m.operationState.stop()
		if result, valid := validatedSupportBundle(message.result, m.diagnosticsScreen.view, m.diagnosticsScreen.replacement); valid {
			m.diagnosticsScreen.result = result
			m.diagnosticsScreen.view.Bundles = append([]SupportBundlePresentation(nil), result.Bundles...)
			m.diagnosticsScreen.feedback = ""
		} else {
			m.diagnosticsScreen.result = SupportBundleResult{}
			m.diagnosticsScreen.feedback = "Support bundle result is unavailable."
		}
		m.diagnosticsScreen.reviewing, m.diagnosticsScreen.action, m.diagnosticsScreen.page = false, 0, 0
		m.diagnosticsScreen.replacement = BundleReplacement{}
	case lifecycleViewMsg:
		if message.generation != m.lifecycleScreen.generation || m.scenario != UpdateReview {
			return m, nil
		}
		if m.exitConfirm {
			m.operationState.queue(message)
			return m, nil
		}
		m.lifecycleScreen.view, m.lifecycleScreen.available = validatedLifecycle(message.view)
		m.lifecycleScreen.available = m.lifecycleScreen.available && m.lifecycleOutcomes != nil
	case lifecycleReviewMsg:
		if !message.identity.matches(m) || m.lifecycleOutcomes == nil {
			return m, nil
		}
		if m.exitConfirm {
			m.operationState.queue(message)
			return m, nil
		}
		m.lifecycleScreen.pending = false
		m.operationState.stop()
		m.changeOrigin, m.hasChangeOrigin = m.scenario, true
		m.outcome = m.lifecycleOutcomes
		m.changeReview = validatedChangeReview(message.review)
		m.planPage, m.changeFeedback, m.inputFocused = 0, "", false
		m.scenario, m.selected = InstallationReview, selectedNavigation(InstallationReview)
	case recoveryViewMsg:
		if message.generation != m.recoveryScreen.generation || !isRecoveryScenario(m.scenario) {
			return m, nil
		}
		if m.exitConfirm {
			m.operationState.queue(message)
			return m, nil
		}
		m.recoveryScreen.view, m.recoveryScreen.available = validatedRecovery(message.view)
		if m.recoveryScreen.available {
			m.scenario = recoveryScenario(m.recoveryScreen.view.Kind)
			m.selected = selectedNavigation(m.scenario)
		}
		if m.recoveryScreen.view.Kind == RecoveryCurrentStateRepairAvailable {
			m.recoveryScreen.available = m.recoveryScreen.available && m.recoveryOutcomes != nil
		}
	case recoveryRetryMsg:
		if !message.identity.matches(m) {
			return m, nil
		}
		if m.exitConfirm {
			m.operationState.queue(message)
			return m, nil
		}
		m.recoveryScreen.pending = false
		m.operationState.stop()
		m.changeSet = validatedDurableChangeSet(message.change)
		if m.changeSet.Kind == NoChangeSet {
			return m, nil
		}
		m.scenario, m.selected = MultiStepChangeSet, selectedNavigation(MultiStepChangeSet)
	case recoveryReviewMsg:
		if !message.identity.matches(m) || m.recoveryOutcomes == nil {
			return m, nil
		}
		if m.exitConfirm {
			m.operationState.queue(message)
			return m, nil
		}
		m.recoveryScreen.pending = false
		m.operationState.stop()
		m.changeOrigin, m.hasChangeOrigin, m.outcome = m.scenario, true, m.recoveryOutcomes
		m.changeReview = validatedChangeReview(message.review)
		m.planPage, m.changeFeedback, m.inputFocused = 0, "", false
		m.scenario, m.selected = InstallationReview, selectedNavigation(InstallationReview)
	case completeRemovalViewMsg:
		if message.generation != m.completeRemovalScreen.generation || m.scenario != CompleteRemovalConfirmation && m.scenario != ForwardOnlyRemoval {
			return m, nil
		}
		if m.exitConfirm {
			m.operationState.queue(message)
			return m, nil
		}
		forwardOnly := m.completeRemovalScreen.forwardOnly || m.scenario == ForwardOnlyRemoval
		m.completeRemovalScreen.view, m.completeRemovalScreen.available = validatedCompleteRemoval(message.view)
		definition, defined := completeRemovalDefinitionFor(m.completeRemovalScreen.view.Kind)
		if defined && definition.watchesUpdates {
			m.completeRemovalScreen.available = m.completeRemovalScreen.available && message.updates != nil
		}
		if defined && definition.acceptsInput {
			m.completeRemovalScreen.available = m.completeRemovalScreen.available && m.completeRemovalOutcomes != nil
		}
		if m.completeRemovalScreen.available && defined && definition.scenario == ForwardOnlyRemoval {
			forwardOnly = true
		}
		if forwardOnly && m.completeRemovalScreen.available && defined && definition.scenario != ForwardOnlyRemoval {
			m.completeRemovalScreen.available = false
		}
		m.completeRemovalScreen.forwardOnly = forwardOnly
		m.completeRemovalScreen.action, m.completeRemovalScreen.page = 0, 0
		if defined && definition.acceptsInput {
			m.completeRemovalScreen.action = 1
		}
		m.scenario = completeRemovalScenario(m.completeRemovalScreen.view.Kind)
		if m.completeRemovalScreen.forwardOnly {
			m.scenario = ForwardOnlyRemoval
		}
		m.selected = selectedNavigation(m.scenario)
		m.inputFocused = false
		if m.completeRemovalScreen.available && defined && definition.watchesUpdates {
			return m, waitCompleteRemovalUpdate(m.runContext, message.generation, message.updates)
		}
	case completeRemovalUpdateMsg:
		if message.generation != m.completeRemovalScreen.generation || m.scenario != ForwardOnlyRemoval {
			return m, nil
		}
		if m.exitConfirm {
			m.operationState.queue(message)
			return m, nil
		}
		if message.closed {
			m.completeRemovalScreen.available = false
			return m, nil
		}
		prior := m.completeRemovalScreen.view
		next, valid := validatedCompleteRemoval(message.view)
		if !valid || !validCompleteRemovalTransition(prior, next) {
			m.completeRemovalScreen.available = false
			return m, nil
		}
		m.completeRemovalScreen.view = next
		m.scenario, m.selected = completeRemovalScenario(next.Kind), selectedNavigation(completeRemovalScenario(next.Kind))
		if definition, defined := completeRemovalDefinitionFor(next.Kind); defined && definition.watchesUpdates {
			return m, waitCompleteRemovalUpdate(m.runContext, message.generation, message.updates)
		}
	case completeRemovalReviewMsg:
		if !message.identity.matches(m) || m.completeRemovalOutcomes == nil {
			return m, nil
		}
		if m.exitConfirm {
			m.operationState.queue(message)
			return m, nil
		}
		m.completeRemovalScreen.pending = false
		m.completeRemovalScreen.pendingAction = 0
		m.operationState.stop()
		m.discardInput()
		m.changeOrigin, m.hasChangeOrigin, m.outcome = CompleteRemovalConfirmation, true, m.completeRemovalOutcomes
		m.changeReview = validatedChangeReview(message.review)
		m.planPage, m.changeFeedback = 0, ""
		m.scenario, m.selected = InstallationReview, selectedNavigation(InstallationReview)
	case completeRemovalCancelMsg:
		if !message.identity.matches(m) {
			return m, nil
		}
		if m.exitConfirm {
			m.operationState.queue(message)
			return m, nil
		}
		m.completeRemovalScreen.pending = false
		m.completeRemovalScreen.pendingAction = 0
		m.operationState.stop()
		prior := m.completeRemovalScreen.view
		m.completeRemovalScreen.view, m.completeRemovalScreen.available = validatedCompleteRemoval(message.view)
		m.completeRemovalScreen.available = m.completeRemovalScreen.available && validCompleteRemovalCancellation(prior, m.completeRemovalScreen.view)
		m.completeRemovalScreen.action, m.completeRemovalScreen.page = 0, 0
		m.scenario, m.selected = CompleteRemovalConfirmation, selectedNavigation(CompleteRemovalConfirmation)
	case tea.PasteMsg:
		if m.width >= minimumWidth && m.height >= minimumHeight && !m.exitConfirm && m.inputFocused {
			m.appendInput(message.Content)
			m.pasteNeutralized = true
		}
	case tea.PasteEndMsg:
		m.pasteGuard = true
		return m, tea.Tick(10*time.Millisecond, func(time.Time) tea.Msg { return pasteGuardExpiredMsg{} })
	case tea.MouseClickMsg:
		mouse := message.Mouse()
		if m.scenario == DedicatedAccess && m.accessUnlocked && m.accessFocused && mouse.Button == tea.MouseLeft && m.accessValueHit(mouse.X, mouse.Y) {
			return m, m.copySelectedAccessValue()
		}
	case tea.KeyPressMsg:
		if m.pasteGuard {
			if m.inputFocused {
				m.appendInput(safeKeyData(message))
			}
			return m, nil
		}
		if m.width < minimumWidth || m.height < minimumHeight {
			switch message.String() {
			case "ctrl+c":
				m.exitConfirm = true
			case "enter", "space":
				if m.exitConfirm {
					return m, tea.Quit
				}
			case "esc":
				return m, m.dismissExitConfirmation()
			}
			return m, nil
		}
		if m.exitConfirm {
			switch message.String() {
			case "enter", "space":
				return m, tea.Quit
			case "esc":
				return m, m.dismissExitConfirmation()
			}
			return m, nil
		}
		if message.String() == "ctrl+c" {
			m.exitConfirm = true
			return m, nil
		}
		if m.scenario == InstallationReview && m.outcome != nil {
			if m.inputFocused {
				if m.editFocusedInput(message) {
					return m, m.backChangeCommand()
				}
				return m, nil
			}
			switch message.String() {
			case "enter", "space":
				if m.changeReview.Plan != nil {
					if m.planPage+1 < m.planPageCount() {
						m.planPage++
						return m, nil
					}
					m.pendingPlanApply = true
					return m, m.authenticationCommand()
				}
				if correction := m.changeReview.Correction; correction != nil {
					if m.planPage+1 < m.correctionPageCount(correction) {
						m.planPage++
						return m, nil
					}
					switch m.correctionActionDefinition(correction) {
					case correctionFix:
						return m, m.fixChangeCommand()
					case correctionCheck:
						return m, m.checkChangeAgainCommand()
					case correctionCopy:
						return m, m.copyValue("redacted evidence", correction.Evidence)
					case correctionBack:
						return m, m.backChangeCommand()
					}
				}
				if m.changeReview.Editing != nil {
					return m, m.editChangeCommand()
				}
			case "up":
				if correction := m.changeReview.Correction; correction != nil {
					m.correctionAction = (m.correctionAction + m.correctionActionCount(correction) - 1) % m.correctionActionCount(correction)
				}
			case "down":
				if correction := m.changeReview.Correction; correction != nil {
					m.correctionAction = (m.correctionAction + 1) % m.correctionActionCount(correction)
				}
			case "left":
				if correction := m.changeReview.Correction; correction != nil && len(correction.Selections) > 0 {
					m.correctionSelection = (m.correctionSelection + len(correction.Selections) - 1) % len(correction.Selections)
				}
			case "right":
				if correction := m.changeReview.Correction; correction != nil && len(correction.Selections) > 0 {
					m.correctionSelection = (m.correctionSelection + 1) % len(correction.Selections)
				}
			case "r":
				return m, m.checkChangeAgainCommand()
			case "tab", "shift+tab":
				if correction := m.changeReview.Correction; correction != nil && correction.InputLabel != "" {
					m.inputFocused = true
				} else if m.changeReview.Editing != nil {
					m.inputFocused = true
				}
			case "esc":
				if (m.changeReview.Plan != nil || m.changeReview.Correction != nil) && m.planPage > 0 {
					m.planPage--
					return m, nil
				}
				return m, m.backChangeCommand()
			}
			return m, nil
		}
		if m.scenario == MultiStepChangeSet && m.outcome != nil && message.String() == "c" && m.changeSet.Kind == ChangeSetActive {
			return m, m.cancelChangeCommand()
		}
		if m.scenario == PrivacyChoice {
			switch message.String() {
			case "up", "shift+tab":
				m.privacySelection = (m.privacySelection + 2) % 3
			case "down", "tab":
				m.privacySelection = (m.privacySelection + 1) % 3
			case "enter", "space":
				switch m.privacySelection {
				case 0:
					switch m.authenticationPolicy {
					case DeferAuthenticationUntilApply:
						m.scenario, m.selected = InstallationReview, selectedNavigation(InstallationReview)
						if m.outcome != nil {
							return m, m.enterChangeCommand()
						}
						return m, nil
					case AuthenticateForAccess:
						return m, m.authenticationCommand()
					default:
						m.scenario, m.selected = LimitedDashboard, selectedNavigation(LimitedDashboard)
						m.limitedMode, m.limitedSelection = true, 0
						m.limitedReason = "Authentication policy is unavailable."
						return m, nil
					}
				case 1:
					m.scenario, m.selected = LimitedDashboard, selectedNavigation(LimitedDashboard)
					m.limitedMode, m.limitedSelection = true, 0
					m.limitedReason = "Owner selected the limited read-only dashboard."
				case 2:
					return m, tea.Quit
				}
			}
			return m, nil
		}
		if m.limitedMode {
			if m.scenario != LimitedDashboard {
				if message.String() == "esc" {
					m.scenario, m.selected = LimitedDashboard, selectedNavigation(LimitedDashboard)
				}
				return m, nil
			}
			actions := m.legalLimitedActions()
			switch message.String() {
			case "up", "shift+tab":
				m.limitedSelection = (m.limitedSelection + len(actions) - 1) % len(actions)
			case "down", "tab":
				m.limitedSelection = (m.limitedSelection + 1) % len(actions)
			case "enter", "space":
				switch actions[m.limitedSelection].action {
				case retryAuthentication:
					return m, m.authenticationCommand()
				case viewSafeDiagnostics:
					m.scenario, m.selected = ServicesDiagnosticsScreen, selectedNavigation(ServicesDiagnosticsScreen)
				case exitLimitedDashboard:
					return m, tea.Quit
				}
			}
			return m, nil
		}
		if m.scenario == DedicatedAccess && m.accessUnlocked && m.accessFocused {
			switch message.String() {
			case "up", "shift+tab":
				m.accessSelection = (m.accessSelection + len(m.accessCatalog.all) - 1) % len(m.accessCatalog.all)
				m.copyFeedback = ""
			case "down":
				m.accessSelection = (m.accessSelection + 1) % len(m.accessCatalog.all)
				m.copyFeedback = ""
			case "tab":
				m.accessFocused = false
			case "enter", "space":
				return m, m.copySelectedAccessValue()
			case "esc":
				m.scenario, m.selected, m.accessFocused = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview), false
			}
			return m, nil
		}
		if m.scenario == DedicatedAccess && m.accessUnlocked && !m.accessFocused && message.String() == "shift+tab" {
			m.accessFocused = true
			return m, nil
		}
		if m.scenario == ConnectionProfilesScreen && m.profiles != nil {
			if !m.profilesAvailable {
				if message.String() == "esc" {
					m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
				}
				return m, nil
			}
			actions := profileActions(m.profilesView.Profiles[m.profileSelection].Enabled)
			switch message.String() {
			case "up", "shift+tab":
				m.actionGeneration++
				m.profileSelection = (m.profileSelection + len(m.profilesView.Profiles) - 1) % len(m.profilesView.Profiles)
				m.profileAction = 0
				m.profileValidation = ProfileValidation{}
			case "down", "tab":
				m.actionGeneration++
				m.profileSelection = (m.profileSelection + 1) % len(m.profilesView.Profiles)
				m.profileAction = 0
				m.profileValidation = ProfileValidation{}
			case "left":
				m.actionGeneration++
				m.profileAction = (m.profileAction + len(actions) - 1) % len(actions)
			case "right":
				m.actionGeneration++
				m.profileAction = (m.profileAction + 1) % len(actions)
			case "enter", "space":
				return m, m.activateProfileAction()
			case "esc":
				m.actionGeneration++
				m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
			}
			return m, nil
		}
		if m.scenario == LiveProfileCheckScreen && m.profiles != nil {
			if message.String() == "esc" {
				m.cancelLiveProfileCheck()
				m.liveProfileCheckGeneration++
				m.pendingLiveProfileCheck = nil
				m.liveProfileCheck, m.liveProfileCheckValid, m.liveProfileCheckPending = LiveProfileCheckPresentation{}, false, false
				m.liveProfileCheckStartedAt, m.liveProfileCheckElapsed = time.Time{}, 0
				m.scenario, m.selected = SubscriptionScreen, selectedNavigation(SubscriptionScreen)
				return m, m.refreshProfilesCommand()
			}
			return m, nil
		}
		if m.scenario == CloudflareWalkthrough && m.cloudflare != nil {
			if m.cloudflareOperation.active {
				if message.String() == "esc" {
					m.cancelCloudflareAction()
					m.discardInput()
					m.actionGeneration++
					m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
				}
				return m, nil
			}
			if !m.cloudflareAvailable {
				if message.String() == "esc" {
					m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
				}
				return m, nil
			}
			if m.providerPage+1 < m.cloudflarePageCount() {
				switch message.String() {
				case "enter", "space":
					m.providerPage++
					m.inputFocused = m.cloudflareView.Kind == CloudflareWalkthroughPresentation && m.providerPage+1 == m.cloudflarePageCount()
				case "esc":
					if m.providerPage > 0 {
						m.providerPage--
					} else {
						m.actionGeneration++
						m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
					}
				}
				return m, nil
			}
			if m.inputFocused {
				if m.editFocusedInput(message) {
					m.discardInput()
					if m.cloudflareReplacing {
						m.cloudflareReplacing, m.cloudflareAction = false, 0
					} else {
						m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
					}
				}
				return m, nil
			}
			actions := cloudflareActions(m.cloudflareView.Kind, m.cloudflareReplacing)
			switch message.String() {
			case "up":
				m.actionGeneration++
				m.cloudflareAction = (m.cloudflareAction + len(actions) - 1) % len(actions)
			case "down", "tab":
				m.actionGeneration++
				m.cloudflareAction = (m.cloudflareAction + 1) % len(actions)
			case "shift+tab":
				m.actionGeneration++
				if m.cloudflareView.Kind == CloudflareWalkthroughPresentation || m.cloudflareReplacing || m.cloudflareView.Kind == CloudflareMissingPermissionPresentation {
					m.inputFocused = true
				} else {
					m.cloudflareAction = (m.cloudflareAction + len(actions) - 1) % len(actions)
				}
			case "enter", "space":
				return m, m.activateCloudflareAction()
			case "esc":
				m.cloudflareGeneration++
				m.actionGeneration++
				m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
			}
			return m, nil
		}
		if m.scenario == CertificatesScreen && m.certificates != nil {
			if !m.certificatesAvailable {
				if message.String() == "esc" {
					m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
				}
				return m, nil
			}
			if m.providerPage+1 < m.certificatePageCount() {
				switch message.String() {
				case "enter", "space":
					m.providerPage++
				case "esc":
					if m.providerPage > 0 {
						m.providerPage--
					} else {
						m.actionGeneration++
						m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
					}
				}
				return m, nil
			}
			actions := certificateActions(m.certificatesView)
			switch message.String() {
			case "up", "shift+tab":
				m.actionGeneration++
				m.certificateAction = (m.certificateAction + len(actions) - 1) % len(actions)
			case "down", "tab":
				m.actionGeneration++
				m.certificateAction = (m.certificateAction + 1) % len(actions)
			case "enter", "space":
				return m, m.activateCertificateAction()
			case "esc":
				m.actionGeneration++
				m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
			}
			return m, nil
		}
		if m.scenario == ServicesDiagnosticsScreen && m.diagnostics != nil {
			return m.updateDiagnosticsKey(message)
		}
		if m.scenario == UpdateReview && m.lifecycle != nil {
			return m.updateLifecycleKey(message)
		}
		if isRecoveryScenario(m.scenario) && m.recovery != nil {
			return m.updateRecoveryKey(message)
		}
		if (m.scenario == CompleteRemovalConfirmation || m.scenario == ForwardOnlyRemoval) && m.completeRemoval != nil {
			return m.updateCompleteRemovalKey(message)
		}
		if m.scenario == SubscriptionScreen && m.profiles != nil {
			if !m.profilesAvailable || !subscriptionFactsAgree(m.profilesView, m.accessCatalog.subscriptions) {
				if message.String() == "esc" {
					m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
				}
				return m, nil
			}
			actions := subscriptionActions()
			switch message.String() {
			case "up", "shift+tab":
				m.actionGeneration++
				m.subscriptionAction = (m.subscriptionAction + len(actions) - 1) % len(actions)
			case "down", "tab":
				m.actionGeneration++
				m.subscriptionAction = (m.subscriptionAction + 1) % len(actions)
			case "enter", "space":
				return m, m.activateSubscriptionAction()
			case "esc":
				m.actionGeneration++
				m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
			}
			return m, nil
		}
		if scenarioFixture(m.scenario).acceptsInput {
			if m.inputFocused {
				if m.editFocusedInput(message) {
					m.scenario, m.selected, m.inputFocused = AuthenticatedOverview, 0, false
				}
				return m, nil
			}
			if message.String() == "shift+tab" {
				m.inputFocused = true
				return m, nil
			}
		}
		switch message.String() {
		case "up", "shift+tab":
			m.selected = (m.selected + len(navigation) - 1) % len(navigation)
		case "down", "tab":
			m.selected = (m.selected + 1) % len(navigation)
		case "enter", "space":
			if m.exitConfirm {
				return m, tea.Quit
			}
			item := navigation[m.selected]
			if item.exit {
				m.exitConfirm = true
			} else {
				m.scenario = item.scenario
				m.inputFocused = scenarioFixture(item.scenario).acceptsInput
				m.accessFocused = item.scenario == DedicatedAccess && m.accessUnlocked
				m.accessSelection, m.copyFeedback = 0, ""
				m.progress, m.progressReceived = Progress{}, false
				m.progressStartedAt, m.progressElapsed = time.Time{}, 0
				m.progressClock = progressClock{}
				m.progressTicking = false
				if (item.scenario == ConnectionProfilesScreen || item.scenario == SubscriptionScreen) && m.profiles != nil {
					return m, m.refreshProfilesCommand()
				}
				if item.scenario == CloudflareWalkthrough && m.cloudflare != nil {
					m.discardInput()
					m.providerPage = 0
					return m, m.refreshCloudflareCommand()
				}
				if item.scenario == CertificatesScreen && m.certificates != nil {
					m.providerPage = 0
					return m, m.refreshCertificatesCommand()
				}
				if item.scenario == ServicesDiagnosticsScreen && m.diagnostics != nil {
					m.diagnosticsScreen.page = 0
					return m, m.refreshDiagnosticsCommand()
				}
				if item.scenario == UpdateReview && m.lifecycle != nil {
					m.lifecycleScreen.page = 0
					return m, m.refreshLifecycleCommand()
				}
				if item.scenario == CompleteRemovalConfirmation && m.completeRemoval != nil {
					m.discardInput()
					m.completeRemovalScreen.page = 0
					m.completeRemovalScreen.forwardOnly = false
					return m, m.refreshCompleteRemovalCommand()
				}
			}
		case "esc":
			if m.exitConfirm {
				m.exitConfirm = false
			} else if m.scenario != ForwardOnlyRemoval {
				m.scenario, m.selected = AuthenticatedOverview, 0
			}
		}
	}
	return m, nil
}

func (m *model) updateSectionPage(key string, page *int, count int) bool {
	if *page+1 >= count {
		return false
	}
	switch key {
	case "enter", "space":
		*page++
	case "esc":
		if *page > 0 {
			*page--
		} else {
			m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
		}
	}
	return true
}

func (m model) operationsPending() bool {
	return m.diagnosticsScreen.pending || m.lifecycleScreen.pending || m.recoveryScreen.pending || m.completeRemovalScreen.pending
}
func operationTick() tea.Cmd {
	return tea.Tick(time.Second, func(now time.Time) tea.Msg { return operationTickMsg(now) })
}

func (m model) updateDiagnosticsKey(message tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := message.String()
	if m.diagnosticsScreen.pending {
		if key == "esc" {
			m.actionGeneration++
			m.diagnosticsScreen.pending = false
			m.diagnosticsScreen.replacement = BundleReplacement{}
			m.operationState.stop()
			m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
		}
		return m, nil
	}
	if !m.diagnosticsScreen.available {
		if key == "esc" {
			m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
		}
		return m, nil
	}
	if m.updateSectionPage(key, &m.diagnosticsScreen.page, m.diagnosticsPageCount()) {
		return m, nil
	}
	actions := diagnosticsActions(m.diagnosticsScreen.view, m.diagnosticsScreen.reviewing)
	switch key {
	case "up", "shift+tab":
		m.diagnosticsScreen.action = (m.diagnosticsScreen.action + len(actions) - 1) % len(actions)
	case "down", "tab":
		m.diagnosticsScreen.action = (m.diagnosticsScreen.action + 1) % len(actions)
	case "enter", "space":
		action := actions[m.diagnosticsScreen.action]
		switch action.action {
		case diagnosticsCheckAgain:
			return m, m.refreshDiagnosticsCommand()
		case diagnosticsCreateBundle:
			m.actionGeneration++
			identity := asyncRequestIdentity{generation: m.actionGeneration, origin: m.scenario}
			m.diagnosticsScreen.pending = true
			m.diagnosticsScreen.feedback = ""
			m.diagnosticsScreen.replacement = action.replacement
			m.operationState.start()
			return m, tea.Batch(func() tea.Msg {
				return supportBundleMsg{identity: identity, result: m.diagnostics.CreateSupportBundle(m.runContext, action.replacement)}
			}, operationTick())
		case diagnosticsReviewReplacement:
			m.diagnosticsScreen.reviewing, m.diagnosticsScreen.action, m.diagnosticsScreen.page = true, 0, 0
		case diagnosticsBack:
			if m.diagnosticsScreen.reviewing {
				m.diagnosticsScreen.reviewing, m.diagnosticsScreen.action, m.diagnosticsScreen.page = false, 0, 0
			} else {
				m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
			}
		}
	case "esc":
		m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
	}
	return m, nil
}

func (m model) updateLifecycleKey(message tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := message.String()
	if m.lifecycleScreen.pending {
		if key == "esc" {
			m.actionGeneration++
			m.lifecycleScreen.pending = false
			m.operationState.stop()
			m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
		}
		return m, nil
	}
	if !m.lifecycleScreen.available {
		if key == "esc" {
			m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
		}
		return m, nil
	}
	if m.updateSectionPage(key, &m.lifecycleScreen.page, m.lifecyclePageCount()) {
		return m, nil
	}
	switch key {
	case "up", "down", "tab", "shift+tab":
		m.actionGeneration++
		m.lifecycleScreen.action = 1 - m.lifecycleScreen.action
	case "enter", "space":
		if m.lifecycleScreen.action == 1 {
			m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
			return m, nil
		}
		m.actionGeneration++
		m.lifecycleScreen.pending = true
		m.operationState.start()
		identity, change := asyncRequestIdentity{generation: m.actionGeneration, origin: m.scenario}, m.lifecycleScreen.view.Change
		return m, tea.Batch(func() tea.Msg {
			return lifecycleReviewMsg{identity: identity, review: m.lifecycle.ReviewLifecycleChange(m.runContext, change)}
		}, operationTick())
	case "esc":
		m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
	}
	return m, nil
}

func (m model) updateRecoveryKey(message tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := message.String()
	if m.recoveryScreen.pending {
		if key == "esc" {
			m.actionGeneration++
			m.recoveryScreen.pending = false
			m.operationState.stop()
			m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
		}
		return m, nil
	}
	if !m.recoveryScreen.available {
		if key == "esc" {
			m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
		}
		return m, nil
	}
	if m.updateSectionPage(key, &m.recoveryScreen.page, m.recoveryPageCount()) {
		return m, nil
	}
	actions := recoveryActions(m.recoveryScreen.view, m.diagnostics != nil)
	switch key {
	case "up", "shift+tab":
		m.actionGeneration++
		m.recoveryScreen.action = (m.recoveryScreen.action + len(actions) - 1) % len(actions)
	case "down", "tab":
		m.actionGeneration++
		m.recoveryScreen.action = (m.recoveryScreen.action + 1) % len(actions)
	case "enter", "space":
		switch actions[m.recoveryScreen.action].action {
		case recoveryRetry:
			m.actionGeneration++
			m.recoveryScreen.pending = true
			m.operationState.start()
			identity := asyncRequestIdentity{generation: m.actionGeneration, origin: m.scenario}
			return m, tea.Batch(func() tea.Msg {
				return recoveryRetryMsg{identity: identity, change: m.recovery.RetryAutomaticRollback(context.Background())}
			}, operationTick())
		case recoveryRepair:
			m.actionGeneration++
			m.recoveryScreen.pending = true
			m.operationState.start()
			identity := asyncRequestIdentity{generation: m.actionGeneration, origin: m.scenario}
			return m, tea.Batch(func() tea.Msg {
				return recoveryReviewMsg{identity: identity, review: m.recovery.ReviewCurrentStateRepair(m.runContext)}
			}, operationTick())
		case recoveryCopyEvidence:
			return m, m.copyValue("safe recovery evidence", m.recoveryScreen.view.Evidence)
		case recoveryDiagnostics:
			m.scenario, m.selected = ServicesDiagnosticsScreen, selectedNavigation(ServicesDiagnosticsScreen)
			if m.diagnostics != nil {
				return m, m.refreshDiagnosticsCommand()
			}
		case recoveryCheckAgain:
			return m, m.refreshRecoveryCommand()
		case recoveryRemoval:
			m.scenario, m.selected, m.inputFocused = CompleteRemovalConfirmation, selectedNavigation(CompleteRemovalConfirmation), false
			m.completeRemovalScreen.forwardOnly = false
			if m.completeRemoval != nil {
				return m, m.refreshCompleteRemovalCommand()
			}
		case recoveryBack:
			m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
		}
	case "esc":
		m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
	}
	return m, nil
}

func (m model) updateCompleteRemovalKey(message tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := message.String()
	if m.completeRemovalScreen.pending {
		if key == "esc" {
			m.actionGeneration++
			m.completeRemovalScreen.pending = false
			m.completeRemovalScreen.pendingAction = 0
			m.operationState.stop()
			m.discardInput()
			m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
		}
		return m, nil
	}
	if !m.completeRemovalScreen.available {
		if m.completeRemovalScreen.forwardOnly {
			return m, nil
		}
		if key == "esc" || key == "enter" || key == "space" {
			m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
		}
		return m, nil
	}
	view := m.completeRemovalScreen.view
	definition, _ := completeRemovalDefinitionFor(view.Kind)
	actions := completeRemovalActions(view, m.input)
	if len(actions) == 0 {
		return m, nil
	}
	if m.inputFocused {
		if m.editFocusedInput(message) {
			m.discardInput()
			m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
		}
		return m, nil
	}
	if m.updateSectionPage(key, &m.completeRemovalScreen.page, m.completeRemovalPageCount()) {
		return m, nil
	}
	switch key {
	case "up", "shift+tab":
		m.completeRemovalScreen.action = (m.completeRemovalScreen.action + len(actions) - 1) % len(actions)
	case "down":
		m.completeRemovalScreen.action = (m.completeRemovalScreen.action + 1) % len(actions)
	case "tab":
		if definition.acceptsInput {
			m.inputFocused = true
		} else {
			m.completeRemovalScreen.action = (m.completeRemovalScreen.action + 1) % len(actions)
		}
	case "enter", "space":
		switch actions[m.completeRemovalScreen.action].action {
		case completeRemovalLocked:
			return m, nil
		case completeRemovalReview:
			m.actionGeneration++
			m.completeRemovalScreen.pending = true
			m.completeRemovalScreen.pendingAction = completeRemovalReview
			m.operationState.start()
			identity := asyncRequestIdentity{generation: m.actionGeneration, origin: m.scenario}
			return m, tea.Batch(func() tea.Msg {
				return completeRemovalReviewMsg{identity: identity, review: m.completeRemoval.ReviewCompleteRemoval(m.runContext, CompleteRemovalApproval{approved: true})}
			}, operationTick())
		case completeRemovalCancel:
			m.actionGeneration++
			m.completeRemovalScreen.pending = true
			m.completeRemovalScreen.pendingAction = completeRemovalCancel
			m.operationState.start()
			identity, operation := asyncRequestIdentity{generation: m.actionGeneration, origin: m.scenario}, view.Progress.OperationID
			return m, tea.Batch(func() tea.Msg {
				return completeRemovalCancelMsg{identity: identity, view: m.completeRemoval.CancelCompleteRemoval(context.Background(), operation)}
			}, operationTick())
		case completeRemovalBack:
			m.discardInput()
			m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
		}
	case "esc":
		m.discardInput()
		m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
	}
	return m, nil
}

func (m model) legalLimitedActions() []limitedActionDefinition {
	if m.authenticationPolicy == AuthenticateForAccess {
		return limitedActions[:]
	}
	return limitedActions[1:]
}

func (m model) copySelectedAccessValue() tea.Cmd {
	entry := m.accessCatalog.all[m.accessSelection]
	return m.copyValue(entry.name, entry.value)
}

func (m model) copyValue(name, value string) tea.Cmd {
	if m.clipboard == nil {
		return tea.Sequence(tea.SetClipboard(value), func() tea.Msg { return copyFinishedMsg{name: name, result: CopyRequested} })
	}
	return func() tea.Msg {
		return copyFinishedMsg{name: name, result: m.clipboard.Copy(m.runContext, value)}
	}
}

func (m model) authenticationCommand() tea.Cmd {
	if m.authenticator == nil {
		return func() tea.Msg { return authenticationFinishedMsg{result: AuthenticationFailed} }
	}
	command := &authenticationCommand{ctx: m.runContext, authenticator: m.authenticator}
	return tea.Exec(command, func(error) tea.Msg {
		return authenticationFinishedMsg{result: command.result}
	})
}

func (m model) reviewChangeCommand() tea.Cmd {
	return func() tea.Msg { return changeReviewMsg{review: m.outcome.Review(m.runContext)} }
}

func (m model) enterChangeCommand() tea.Cmd {
	return func() tea.Msg {
		if current := validatedDurableChangeSet(m.outcome.Inspect(m.runContext)); current.Kind != NoChangeSet {
			return changeSetUpdateMsg{change: current}
		}
		return changeReviewMsg{review: m.outcome.Review(m.runContext)}
	}
}

func (m model) fixChangeCommand() tea.Cmd {
	request := CorrectionInput{Text: m.input}
	if correction := m.changeReview.Correction; correction != nil && correction.InputLabel != "" && request.Text == "" {
		return func() tea.Msg {
			return changeResultMsg{result: ChangeResult{Kind: changeFactsUnavailable, Explanation: "Required correction input is empty. Nothing was submitted."}}
		}
	}
	if correction := m.changeReview.Correction; correction != nil && m.correctionSelection < len(correction.Selections) {
		request.Selection = correction.Selections[m.correctionSelection].Identity
	}
	return func() tea.Msg { return changeReviewMsg{review: m.outcome.Fix(m.runContext, request)} }
}

func (m model) checkChangeAgainCommand() tea.Cmd {
	return func() tea.Msg { return changeReviewMsg{review: m.outcome.CheckAgain(m.runContext)} }
}

func (m model) backChangeCommand() tea.Cmd {
	return func() tea.Msg {
		return changeBackMsg{review: m.outcome.Back(m.runContext)}
	}
}

func (m model) viewProfilesCommand() tea.Cmd {
	identity := asyncRequestIdentity{generation: m.profileViewGeneration, origin: m.scenario}
	return func() tea.Msg {
		return profilesViewMsg{identity: identity, view: m.profiles.ViewProfiles(m.runContext)}
	}
}

func (m *model) refreshProfilesCommand() tea.Cmd {
	m.profileViewGeneration++
	return m.viewProfilesCommand()
}

func (m model) viewCloudflareCommand() tea.Cmd {
	generation := m.cloudflareGeneration
	return func() tea.Msg {
		return cloudflareViewMsg{generation: generation, view: m.cloudflare.ViewCloudflare(m.runContext)}
	}
}

func (m *model) refreshCloudflareCommand() tea.Cmd {
	m.cloudflareGeneration++
	return m.viewCloudflareCommand()
}

func (m *model) activateCloudflareAction() tea.Cmd {
	actions := cloudflareActions(m.cloudflareView.Kind, m.cloudflareReplacing)
	if m.cloudflareAction >= len(actions) {
		return nil
	}
	action := actions[m.cloudflareAction]
	switch action.kind {
	case cloudflareBack:
		if m.cloudflareReplacing {
			m.cloudflareReplacing, m.cloudflareAction = false, 0
			m.discardInput()
			return nil
		}
		m.cloudflareGeneration++
		m.actionGeneration++
		m.discardInput()
		m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
		return nil
	case cloudflareBeginReplacement:
		m.actionGeneration++
		m.discardInput()
		m.inputFocused, m.cloudflareReplacing = true, true
		if m.cloudflareView.Kind == CloudflareMissingPermissionPresentation {
			m.cloudflareAction = 2
		} else {
			m.cloudflareAction = 0
		}
		return nil
	case cloudflareModuleAction:
		if (action.request == VerifyInitialManagementToken || action.request == VerifyReplacementManagementToken) && m.input == "" {
			return nil
		}
		request := CloudflareRequest{Action: action.request}
		if action.request == VerifyInitialManagementToken || action.request == VerifyReplacementManagementToken {
			request.Token = m.input
		}
		m.actionGeneration++
		identity := asyncRequestIdentity{generation: m.actionGeneration, origin: m.scenario}
		requestContext, cancel := context.WithCancel(m.runContext)
		m.cloudflareOperation.start(action.label, cancel)
		command := func() tea.Msg {
			return cloudflareResponseMsg{identity: identity, response: m.cloudflare.ActOnCloudflare(requestContext, request)}
		}
		return tea.Batch(command, cloudflareTick())
	}
	return nil
}

func (m model) cloudflarePageCount() int {
	if !m.cloudflareAvailable {
		return 1
	}
	actions := cloudflareActions(m.cloudflareView.Kind, m.cloudflareReplacing)
	lines := cloudflareLines(m.cloudflareView, m.cloudflareAvailable, m.input, m.cloudflareAction, m.cloudflareReplacing)
	return providerPageCount(lines, len(actions), m.width, m.height)
}

func (m model) viewCertificatesCommand() tea.Cmd {
	generation := m.certificateGeneration
	return func() tea.Msg {
		return certificatesViewMsg{generation: generation, view: m.certificates.ViewCertificates(m.runContext)}
	}
}

func (m *model) refreshCertificatesCommand() tea.Cmd {
	m.certificateGeneration++
	return m.viewCertificatesCommand()
}

func (m *model) activateCertificateAction() tea.Cmd {
	actions := certificateActions(m.certificatesView)
	if m.certificateAction >= len(actions) {
		return nil
	}
	action := actions[m.certificateAction]
	if action.kind == certificateBack {
		m.actionGeneration++
		m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
		return nil
	}
	m.actionGeneration++
	identity := asyncRequestIdentity{generation: m.actionGeneration, origin: m.scenario}
	return func() tea.Msg {
		return certificateReviewMsg{identity: identity, review: m.certificates.ReviewCertificateChange(m.runContext, action.change)}
	}
}

func (m model) certificatePageCount() int {
	if !m.certificatesAvailable {
		return 1
	}
	actions := certificateActions(m.certificatesView)
	lines := certificateLines(m.certificatesView, m.certificatesAvailable, m.certificateAction)
	return providerPageCount(lines, len(actions), m.width, m.height)
}

func (m model) viewDiagnosticsCommand() tea.Cmd {
	generation := m.diagnosticsScreen.generation
	return func() tea.Msg {
		return diagnosticsViewMsg{generation: generation, view: m.diagnostics.ViewDiagnostics(m.runContext)}
	}
}

func (m *model) refreshDiagnosticsCommand() tea.Cmd {
	m.diagnosticsScreen.generation++
	return m.viewDiagnosticsCommand()
}

func (m model) diagnosticsPageCount() int {
	if !m.diagnosticsScreen.available {
		return 1
	}
	actions := diagnosticsActions(m.diagnosticsScreen.view, m.diagnosticsScreen.reviewing)
	lines := diagnosticsLines(m.diagnosticsScreen.view, true, m.diagnosticsScreen.action, m.diagnosticsScreen.reviewing, m.diagnosticsScreen.result, m.diagnosticsScreen.feedback)
	return providerPageCount(lines, len(actions), m.width, m.height)
}

func (m model) viewLifecycleCommand() tea.Cmd {
	generation := m.lifecycleScreen.generation
	return func() tea.Msg {
		return lifecycleViewMsg{generation: generation, view: m.lifecycle.ViewLifecycle(m.runContext)}
	}
}

func (m *model) refreshLifecycleCommand() tea.Cmd {
	m.lifecycleScreen.generation++
	return m.viewLifecycleCommand()
}

func (m model) lifecyclePageCount() int {
	if !m.lifecycleScreen.available {
		return 1
	}
	lines := lifecycleLines(m.lifecycleScreen.view, true, m.lifecycleScreen.action)
	return providerPageCount(lines, len(lifecycleActions(m.lifecycleScreen.view)), m.width, m.height)
}

func (m model) viewRecoveryCommand() tea.Cmd {
	generation := m.recoveryScreen.generation
	return func() tea.Msg {
		return recoveryViewMsg{generation: generation, view: m.recovery.ViewRecovery(m.runContext)}
	}
}
func (m *model) refreshRecoveryCommand() tea.Cmd {
	m.recoveryScreen.generation++
	return m.viewRecoveryCommand()
}
func (m model) recoveryPageCount() int {
	if !m.recoveryScreen.available {
		return 1
	}
	lines := recoveryLines(m.recoveryScreen.view, true, m.recoveryScreen.action, m.diagnostics != nil)
	return providerPageCount(lines, len(recoveryActions(m.recoveryScreen.view, m.diagnostics != nil)), m.width, m.height)
}

func (m model) viewCompleteRemovalCommand() tea.Cmd {
	generation := m.completeRemovalScreen.generation
	return func() tea.Msg {
		return completeRemovalViewMsg{generation: generation, view: m.completeRemoval.ViewCompleteRemoval(m.runContext), updates: m.completeRemoval.WatchCompleteRemoval(m.runContext)}
	}
}

func waitCompleteRemovalUpdate(ctx context.Context, generation uint64, updates <-chan CompleteRemovalPresentation) tea.Cmd {
	return func() tea.Msg {
		select {
		case <-ctx.Done():
			return nil
		case update, open := <-updates:
			return completeRemovalUpdateMsg{generation: generation, view: update, updates: updates, closed: !open}
		}
	}
}

func (m *model) refreshCompleteRemovalCommand() tea.Cmd {
	m.completeRemovalScreen.generation++
	return m.viewCompleteRemovalCommand()
}

func (m model) completeRemovalPageCount() int {
	if !m.completeRemovalScreen.available {
		return 1
	}
	lines := completeRemovalLines(m.completeRemovalScreen.view, true, m.input, m.completeRemovalScreen.action)
	return providerPageCount(lines, len(completeRemovalActions(m.completeRemovalScreen.view, m.input)), m.width, m.height)
}

func (m *model) activateProfileAction() tea.Cmd {
	profile := m.profilesView.Profiles[m.profileSelection]
	action := profileActions(profile.Enabled)[m.profileAction]
	m.actionGeneration++
	identity := asyncRequestIdentity{generation: m.actionGeneration, origin: m.scenario}
	switch action.kind {
	case openAccessAction:
		if selection, ok := m.accessCatalog.profileFocus(profile.ID); m.accessUnlocked && ok {
			return func() tea.Msg { return openAccessMsg{identity: identity, selection: selection} }
		}
		return nil
	case validateProfileAction:
		return func() tea.Msg {
			return profileValidationMsg{identity: identity, validation: m.profiles.ValidateProfile(m.runContext, profile.ID)}
		}
	case reviewProfileChangeAction:
		request := ProfileChangeRequest{Profile: profile.ID, Change: action.change}
		return func() tea.Msg {
			return profileReviewMsg{identity: identity, review: m.profiles.ReviewProfileChange(m.runContext, request)}
		}
	}
	return nil
}

func (m *model) activateSubscriptionAction() tea.Cmd {
	action := subscriptionActions()[m.subscriptionAction]
	m.actionGeneration++
	identity := asyncRequestIdentity{generation: m.actionGeneration, origin: m.scenario}
	switch action.kind {
	case openAccessAction:
		if selection, ok := m.accessCatalog.subscriptionFocus(); m.accessUnlocked && ok {
			return func() tea.Msg { return openAccessMsg{identity: identity, selection: selection} }
		}
		return nil
	case runLiveProfileCheckAction:
		if !m.accessUnlocked || !m.profilesView.Managed {
			return nil
		}
		checkContext, cancel := context.WithCancel(m.runContext)
		m.liveProfileCheckGeneration++
		liveGeneration := m.liveProfileCheckGeneration
		m.liveProfileCheck, m.liveProfileCheckValid, m.liveProfileCheckPending, m.liveProfileCheckCancel = LiveProfileCheckPresentation{}, false, true, cancel
		m.liveProfileCheckStartedAt, m.liveProfileCheckElapsed = time.Now(), 0
		m.pendingLiveProfileCheck = nil
		m.scenario, m.selected = LiveProfileCheckScreen, selectedNavigation(SubscriptionScreen)
		updates := m.profiles.RunLiveProfileCheck(checkContext)
		return tea.Batch(waitLiveProfileCheck(checkContext, liveGeneration, updates), liveProfileCheckTick())
	case reviewClientAccessChangeAction:
		return func() tea.Msg {
			return profileReviewMsg{identity: identity, review: m.profiles.ReviewClientAccessChange(m.runContext, action.change)}
		}
	}
	return nil
}

func (m model) editChangeCommand() tea.Cmd {
	editing := m.changeReview.Editing
	if editing == nil {
		return nil
	}
	if editing.Field.Required && m.input == "" {
		return func() tea.Msg {
			return changeResultMsg{result: ChangeResult{Kind: changeFactsUnavailable, Explanation: "Required editing input is empty. Nothing was submitted."}}
		}
	}
	request := EditingInput{Field: editing.Field.Identity, Text: m.input}
	return func() tea.Msg { return changeReviewMsg{review: m.outcome.Edit(m.runContext, request)} }
}

func (m *model) focusChangeInput() {
	m.inputFocused = false
	if correction := m.changeReview.Correction; correction != nil && correction.InputLabel != "" {
		m.inputFocused = true
		return
	}
	if editing := m.changeReview.Editing; editing != nil {
		m.input = editing.Field.Value
		m.inputFocused = true
	}
}

func (m model) inspectChangeCommand() tea.Cmd {
	return func() tea.Msg { return changeSetUpdateMsg{change: m.outcome.Inspect(m.runContext)} }
}

func (m model) applyChangeCommand() tea.Cmd {
	plan := m.changeReview.Plan
	if plan == nil {
		return nil
	}
	return func() tea.Msg { return changeResultMsg{result: m.outcome.Apply(context.Background(), plan.Identity)} }
}

func (m model) cancelChangeCommand() tea.Cmd {
	operation := m.changeSet.OperationID
	return func() tea.Msg {
		return changeResultMsg{result: m.outcome.RequestCancellation(context.Background(), operation)}
	}
}

func (m model) accessValueLines(entry accessEntry) []string {
	width := m.width - navigationWidth - 1
	if m.width >= 120 {
		width = 48
	}
	return wrapLines([]string{entry.value}, width)
}

func (m model) accessValueHit(x, y int) bool {
	if m.accessSelection >= len(m.accessCatalog.all) {
		return false
	}
	const frameRowsBeforeBody, accessRowsBeforeValue = 2, 5
	lines := m.accessValueLines(m.accessCatalog.all[m.accessSelection])
	right := m.width
	if m.width >= 120 {
		right = navigationWidth + 1 + 48
	}
	return x > navigationWidth && x < right && y >= frameRowsBeforeBody+accessRowsBeforeValue && y < frameRowsBeforeBody+accessRowsBeforeValue+len(lines)
}

type authenticationCommand struct {
	ctx           context.Context
	authenticator Authenticator
	input         io.Reader
	output        io.Writer
	result        AuthenticationResult
}

func (command *authenticationCommand) SetStdin(input io.Reader)   { command.input = input }
func (command *authenticationCommand) SetStdout(output io.Writer) { command.output = output }
func (command *authenticationCommand) SetStderr(output io.Writer) {
	if command.output == nil {
		command.output = output
	}
}
func (command *authenticationCommand) Run() error {
	command.result = command.authenticator.Authenticate(command.ctx, command.input, command.output)
	if command.result < AuthenticationSucceeded || command.result > AuthenticationExpired {
		command.result = AuthenticationFailed
	}
	return nil
}

func authenticationExplanation(result AuthenticationResult) string {
	switch result {
	case AuthenticationDenied:
		return "System authentication was denied."
	case AuthenticationCancelled:
		return "System authentication was cancelled."
	case AuthenticationExpired:
		return "System authentication expired."
	default:
		return "System authentication failed."
	}
}

func (m *model) dismissExitConfirmation() tea.Cmd {
	m.exitConfirm = false
	var liveCommand, cloudflareCommand, operationCommand tea.Cmd
	if m.pendingLiveProfileCheck != nil {
		message := *m.pendingLiveProfileCheck
		m.pendingLiveProfileCheck = nil
		if message.generation == m.liveProfileCheckGeneration && m.scenario == LiveProfileCheckScreen {
			liveCommand = m.finishLiveProfileCheck(message)
		}
	}
	if m.cloudflareOperation.queued != nil {
		message := *m.cloudflareOperation.queued
		m.cloudflareOperation.queued = nil
		if message.identity.matches(*m) {
			cloudflareCommand = m.finishCloudflareResponse(message)
		}
	}
	if message := m.operationState.take(); message != nil {
		if updated, command := m.Update(message); updated != nil {
			*m = updated.(model)
			operationCommand = command
		}
	}
	if m.pendingUpdate == nil {
		return tea.Batch(liveCommand, cloudflareCommand, operationCommand)
	}
	update := *m.pendingUpdate
	m.pendingUpdate = nil
	return tea.Batch(liveCommand, cloudflareCommand, operationCommand, m.applyPresentationUpdate(update))
}

func (m *model) finishCloudflareResponse(message cloudflareResponseMsg) tea.Cmd {
	m.cancelCloudflareAction()
	m.discardInput()
	if message.response.Presentation != nil && message.response.Review == nil {
		m.cloudflareView, m.cloudflareAvailable = validatedCloudflarePresentation(*message.response.Presentation)
		m.cloudflareAction, m.cloudflareReplacing, m.providerPage = 0, false, 0
		return nil
	}
	if message.response.Review != nil && message.response.Presentation == nil && m.cloudflareOutcomes != nil {
		m.changeOrigin, m.hasChangeOrigin = m.scenario, true
		m.outcome = m.cloudflareOutcomes
		m.changeReview = validatedChangeReview(*message.response.Review)
		m.planPage, m.changeFeedback = 0, ""
		m.scenario, m.selected = InstallationReview, selectedNavigation(InstallationReview)
		return nil
	}
	m.cloudflareView, m.cloudflareAvailable = CloudflarePresentation{}, false
	return nil
}

func (m *model) cancelCloudflareAction() {
	m.cloudflareOperation.stop()
}

func (m *model) discardInput() {
	m.input, m.inputFocused = "", false
	m.inputTruncated, m.pasteNeutralized, m.pasteGuard = false, false, false
}

func (m *model) finishLiveProfileCheck(message liveProfileCheckMsg) tea.Cmd {
	check, valid := validatedLiveProfileCheck(message.check, m.liveProfileCheck)
	if !message.ok || !valid {
		m.liveProfileCheck, m.liveProfileCheckValid, m.liveProfileCheckPending = LiveProfileCheckPresentation{}, false, false
		m.cancelLiveProfileCheck()
		return nil
	}
	m.liveProfileCheck, m.liveProfileCheckValid = check, true
	if check.Complete {
		m.liveProfileCheckPending = false
		m.cancelLiveProfileCheck()
		return nil
	}
	return waitLiveProfileCheck(message.ctx, message.generation, message.updates)
}

func (m *model) cancelLiveProfileCheck() {
	if m.liveProfileCheckCancel != nil {
		m.liveProfileCheckCancel()
		m.liveProfileCheckCancel = nil
	}
}

func waitLiveProfileCheck(ctx context.Context, generation uint64, updates <-chan LiveProfileCheckPresentation) tea.Cmd {
	return func() tea.Msg {
		if updates == nil {
			return liveProfileCheckMsg{generation: generation, ctx: ctx}
		}
		select {
		case <-ctx.Done():
			return liveProfileCheckMsg{generation: generation, ctx: ctx}
		case check, ok := <-updates:
			return liveProfileCheckMsg{generation: generation, ctx: ctx, check: check, updates: updates, ok: ok}
		}
	}
}

func liveProfileCheckTick() tea.Cmd {
	return tea.Tick(time.Second, func(at time.Time) tea.Msg { return liveProfileCheckTickMsg(at) })
}

func cloudflareTick() tea.Cmd {
	return tea.Tick(time.Second, func(at time.Time) tea.Msg { return cloudflareTickMsg(at) })
}

func (m *model) applyPresentationUpdate(update PresentationUpdate) tea.Cmd {
	m.refreshed = true
	if update.Progress.Kind == NoProgress {
		return nil
	}
	clock := progressClock{kind: update.Progress.Kind, operationID: update.Progress.OperationID, currentStep: update.Progress.CurrentStep}
	timed := presentProgress(scenarioFixture(m.scenario).progress, update.Progress, 0, m.unicode).timed
	continuing := timed && clock == m.progressClock && !m.progressStartedAt.IsZero()
	m.progress = update.Progress
	m.progressReceived = true
	if !timed {
		m.progressStartedAt, m.progressElapsed = time.Time{}, 0
		m.progressClock = progressClock{}
		m.progressTicking = false
		return nil
	}
	if !continuing {
		m.progressStartedAt, m.progressElapsed = time.Now(), 0
		m.progressClock = clock
	}
	if m.progressTicking {
		return nil
	}
	m.progressTicking = true
	return progressTick()
}

func safeKeyData(message tea.KeyPressMsg) string {
	if text := message.Key().Text; text != "" {
		return text
	}
	return "<" + message.String() + ">"
}

func (m *model) appendInput(value string) {
	if value == "" {
		return
	}
	remaining := maxInputRunes - len([]rune(m.input))
	if remaining <= 0 {
		m.inputTruncated = true
		return
	}
	runes := []rune(value)
	if len(runes) > remaining {
		runes = runes[:remaining]
		m.inputTruncated = true
	}
	m.input += string(runes)
}

func (m *model) editFocusedInput(message tea.KeyPressMsg) bool {
	switch message.String() {
	case "tab", "shift+tab":
		m.inputFocused = false
	case "backspace":
		runes := []rune(m.input)
		if len(runes) > 0 {
			m.input = string(runes[:len(runes)-1])
		}
	case "esc":
		return true
	default:
		m.appendInput(message.Key().Text)
	}
	return false
}

func progressTick() tea.Cmd {
	return tea.Tick(time.Second, func(now time.Time) tea.Msg { return progressTickMsg(now) })
}

func (m model) drawingModesConfirmed() bool {
	return reportedMode(m.initialModes, 1) && reportedMode(m.initialModes, 1049) && m.cursorAddressingConfirmed
}

func reportedMode(modes map[int]bool, mode int) bool {
	_, reported := modes[mode]
	return reported
}

func (m model) View() tea.View {
	if m.drawingModeProbeRequired && !m.probeDone {
		return tea.NewView("")
	}
	view := tea.NewView(m.frame())
	view.AltScreen = true
	view.MouseMode = tea.MouseModeNone
	if m.scenario == DedicatedAccess && m.accessUnlocked {
		view.MouseMode = tea.MouseModeCellMotion
	}
	return view
}

func (m model) frame() string {
	width, height := m.width, m.height
	if width < minimumWidth || height < minimumHeight {
		content := fmt.Sprintf("TERMINAL IS TOO SMALL\n\nRequired   %d columns x %d rows\nCurrent    %d columns x %d rows\n\nThe current screen, input and selection are preserved.\nNothing was approved, discarded, or partly redrawn.\n\nEnlarge the terminal to continue.\n\nCtrl+C Exit confirmation", minimumWidth, minimumHeight, width, height)
		if m.exitConfirm {
			content += "\n\nExit SBXR?\n> Exit SBXR\n  Stay in SBXR\n\nEnter Exit  Esc Stay"
		}
		return content
	}
	currentFixture := scenarioFixture(m.scenario)
	header, title := m.frameIdentity(currentFixture)
	privacyChoices := []string{
		"  Continue with authenticated Client Access Values",
		"  Open the limited read-only dashboard",
		"  Exit SBXR",
	}
	privacyChoices[m.privacySelection] = ">" + privacyChoices[m.privacySelection][1:]
	main := []string{
		"PRIVACY BEFORE ACCESS", "",
		"Client Access Values may remain in terminal scrollback,",
		"screenshots, screen recordings, SSH session logs, clipboard",
		"history, and synchronized clipboards.", "",
		"No Client Access Value or sudo prompt appears before your choice.", "",
		privacyChoices[0], privacyChoices[1], privacyChoices[2], "",
		"Up/Down Select  Enter Continue  Ctrl+C Exit confirmation",
	}
	if m.scenario != PrivacyChoice {
		main = append([]string{title, ""}, m.scenarioLines(currentFixture)...)
	}
	if m.scenario == LimitedDashboard {
		if m.limitedReason != "" {
			main[2] = m.limitedReason
		}
	}
	if m.exitConfirm {
		main = []string{
			"Exit SBXR?", "",
			"No approved Change Set will be cancelled.", "",
			"> Exit SBXR", "  Stay in SBXR", "",
			"Enter Exit  Esc Stay",
		}
	}
	leftWidth := navigationWidth
	bodyHeight := height - 5
	rightWidth := width - leftWidth - 1
	contentWidth := rightWidth
	if width >= 120 {
		contentWidth = 48
	}
	main = wrapLines(main, contentWidth)
	if len(main) > 0 {
		main[0] = m.title(main[0])
	}
	rows := make([]string, 0, height)
	if header == "" {
		header = "Managed - Owner Console"
	}
	if m.refreshed {
		header += " - refreshed"
	}
	rows = append(rows, fit(" SBXR", 18)+fit(header, width-18))
	horizontal, vertical, crossing := "-", "|", "+"
	if m.unicode {
		horizontal, vertical, crossing = "─", "│", "┼"
	}
	rows = append(rows, strings.Repeat(horizontal, leftWidth)+crossing+strings.Repeat(horizontal, rightWidth))
	details := m.scenarioDetails(currentFixture)
	if width >= 120 {
		if m.scenario != DedicatedAccess || !m.accessUnlocked || m.accessSelection >= len(m.accessCatalog.all) || !m.accessCatalog.all[m.accessSelection].qr {
			details = wrapLines(details, rightWidth-49)
		}
	}
	for row := range bodyHeight {
		left, right := "", ""
		if row < len(navigation) {
			prefix := "  "
			if row == m.selected && !m.inputFocused && !m.accessFocused && m.scenario != PrivacyChoice && !m.limitedMode {
				prefix = "> "
			}
			left = prefix + navigation[row].label
		}
		if row < len(main) {
			right = main[row]
		}
		if width >= 120 {
			mainWidth := 48
			detailsWidth := rightWidth - mainWidth - 1
			detail := ""
			if row == 0 {
				detail = "RELEVANT DETAILS"
			} else if row >= 2 && row-2 < len(details) {
				detail = details[row-2]
			}
			right = fit(right, mainWidth) + vertical + fit(detail, detailsWidth)
		}
		rows = append(rows, fit(left, leftWidth)+vertical+fit(right, rightWidth))
	}
	bottomCrossing := crossing
	if m.unicode {
		bottomCrossing = "┴"
	}
	rows = append(rows, strings.Repeat(horizontal, leftWidth)+bottomCrossing+strings.Repeat(horizontal, rightWidth))
	shortcuts := m.shortcuts()
	rows = append(rows, fit(shortcuts[0], width))
	rows = append(rows, fit(shortcuts[1], width))
	return strings.Join(rows, "\n")
}

func (m model) frameIdentity(current fixture) (string, string) {
	if m.scenario == InstallationReview && m.hasChangeOrigin && m.changeOrigin == CompleteRemovalConfirmation {
		status := m.completeRemovalScreen.view.StartingStatus.String()
		if status == "" {
			status = "Status unavailable"
		}
		return status + " - authenticated", "REVIEW COMPLETE REMOVAL PLAN"
	}
	if m.completeRemoval != nil && m.completeRemovalScreen.available && (m.scenario == CompleteRemovalConfirmation || m.scenario == ForwardOnlyRemoval) {
		if definition, valid := completeRemovalDefinitionFor(m.completeRemovalScreen.view.Kind); valid {
			return definition.header(m.completeRemovalScreen.view), definition.title
		}
	}
	if m.scenario != MultiStepChangeSet || m.outcome != nil || m.changeSet.Kind == NoChangeSet {
		return current.header, current.title
	}
	switch m.changeSet.Kind {
	case ChangeSetActive:
		return "Change in progress - automatic rollback - authenticated", "AUTOMATIC ROLLBACK IN PROGRESS"
	case ChangeSetSucceeded:
		return "Managed - automatic rollback succeeded - authenticated", "AUTOMATIC ROLLBACK - PROVEN SUCCESS"
	case ChangeSetRolledBack:
		return "Managed - proven rollback - authenticated", "AUTOMATIC ROLLBACK - PROVEN ROLLBACK"
	case ChangeSetRecoveryRequired:
		return "Recovery Required - authenticated", "AUTOMATIC ROLLBACK - RECOVERY REQUIRED"
	default:
		return "Status unavailable - authenticated", "AUTOMATIC ROLLBACK - FACTS UNAVAILABLE"
	}
}

func (m model) scenarioDetails(current fixture) []string {
	if m.scenario == LiveProfileCheckScreen && m.liveProfileCheckValid {
		if qr := qrLines(m.liveProfileCheck.TemporaryURL, 49, m.height-8); len(qr) != 0 {
			return append([]string{"QR - same temporary test URL", ""}, qr...)
		}
		return []string{"QR omitted; exact temporary test URL remains visible."}
	}
	if m.scenario == InstallationReview && m.outcome != nil {
		if correction := m.changeReview.Correction; correction != nil {
			return []string{"REDACTED EVIDENCE", "", correction.Evidence, "", "No raw output or secrets."}
		}
		if plan := m.changeReview.Plan; plan != nil {
			return append([]string{"PLAN BINDING", "", "Identity  " + string(plan.Identity), fmt.Sprintf("Revision  %d", plan.DesiredStateRevision), "Desired State SHA-256", plan.DesiredStateSHA256, ""}, plan.RelevantChecksums...)
		}
	}
	if m.scenario == MultiStepChangeSet && m.changeSet.Kind != NoChangeSet {
		if m.outcome == nil {
			return []string{"AUTOMATIC ROLLBACK", "", "Typed durable Change Set result.", "Closing the Console does not stop rollback."}
		}
		return changeSetDetails(m.changeSet)
	}
	if m.scenario == DedicatedAccess {
		if !m.accessUnlocked || m.accessSelection >= len(m.accessCatalog.all) {
			return current.details
		}
		entry := m.accessCatalog.all[m.accessSelection]
		if entry.qr && m.width >= 120 {
			if qr := qrLines(entry.value, 49, m.height-8); len(qr) != 0 {
				return append([]string{"QR - same value as text", ""}, qr...)
			}
		}
		return accessMetadata(entry)
	}
	if !m.progressExpected || current.progress == NoProgress {
		return current.details
	}
	if !m.progressReceived {
		return []string{"WAITING FOR FACTS", "", "No progress is inferred."}
	}
	return presentProgress(current.progress, m.progress, m.progressElapsed, m.unicode).details
}

func (m model) scenarioLines(current fixture) []string {
	if (m.scenario == CompleteRemovalConfirmation || m.scenario == ForwardOnlyRemoval) && m.completeRemoval != nil {
		if m.completeRemovalScreen.pending {
			label, explanation := "Building exact Complete removal Plan", "No mutation, percentage, or result is inferred."
			if m.completeRemovalScreen.pendingAction == completeRemovalCancel {
				label, explanation = "Requesting safe Complete removal cancellation", "No restored status, rollback, percentage, or result is inferred."
			}
			return []string{spinner(m.unicode, m.operationState.elapsed) + " " + label + " - " + elapsed(m.operationState.elapsed), "The Software Lifecycle Module decides how long this takes.", explanation, "", "> Back"}
		}
		if !m.completeRemovalScreen.available && m.completeRemovalScreen.forwardOnly {
			return []string{"FORWARD-ONLY COMPLETE REMOVAL", "Irreversible removal started remains durable.", "Current progress facts are unavailable or unsafe.", "No completion, rollback, or restored status was inferred.", "Restart continues from protected transaction evidence.", "Back and Cancel remain unavailable.", "", "Use Ctrl+C for Exit SBXR confirmation."}
		}
		lines := completeRemovalLines(m.completeRemovalScreen.view, m.completeRemovalScreen.available, m.input, m.completeRemovalScreen.action)
		actionCount := 1
		if m.completeRemovalScreen.available {
			actionCount = len(completeRemovalActions(m.completeRemovalScreen.view, m.input))
		}
		if actionCount == 0 {
			return lines
		}
		return providerPage(lines, actionCount, m.width, m.height, m.completeRemovalScreen.page)
	}
	if m.scenario == CloudflareWalkthrough && m.cloudflare != nil {
		if m.cloudflareOperation.active {
			return []string{
				spinner(m.unicode, m.cloudflareOperation.elapsed) + " " + m.cloudflareOperation.label + " is running - " + elapsed(m.cloudflareOperation.elapsed),
				"The provider decides how long this takes.",
				"No percentage, completion time, or result is inferred.",
				"",
				"> Back",
			}
		}
		lines := cloudflareLines(m.cloudflareView, m.cloudflareAvailable, m.input, m.cloudflareAction, m.cloudflareReplacing)
		actionCount := 1
		if m.cloudflareAvailable {
			actionCount = len(cloudflareActions(m.cloudflareView.Kind, m.cloudflareReplacing))
		}
		return providerPage(lines, actionCount, m.width, m.height, m.providerPage)
	}
	if m.scenario == CertificatesScreen && m.certificates != nil {
		lines := certificateLines(m.certificatesView, m.certificatesAvailable, m.certificateAction)
		actionCount := 1
		if m.certificatesAvailable {
			actionCount = len(certificateActions(m.certificatesView))
		}
		return providerPage(lines, actionCount, m.width, m.height, m.providerPage)
	}
	if m.scenario == ServicesDiagnosticsScreen && m.diagnostics != nil {
		if m.diagnosticsScreen.pending {
			return []string{spinner(m.unicode, m.operationState.elapsed) + " Creating support bundle - " + elapsed(m.operationState.elapsed), "The Diagnostics Module decides how long this takes.", "No percentage or completion time is inferred.", "", "> Back"}
		}
		lines := diagnosticsLines(m.diagnosticsScreen.view, m.diagnosticsScreen.available, m.diagnosticsScreen.action, m.diagnosticsScreen.reviewing, m.diagnosticsScreen.result, m.diagnosticsScreen.feedback)
		actionCount := 1
		if m.diagnosticsScreen.available {
			actionCount = len(diagnosticsActions(m.diagnosticsScreen.view, m.diagnosticsScreen.reviewing))
		}
		return providerPage(lines, actionCount, m.width, m.height, m.diagnosticsScreen.page)
	}
	if m.scenario == UpdateReview && m.lifecycle != nil {
		if m.lifecycleScreen.pending {
			return []string{spinner(m.unicode, m.operationState.elapsed) + " Building exact release Plan - " + elapsed(m.operationState.elapsed), "The Software Lifecycle Module decides how long this takes.", "No percentage or result is inferred.", "", "> Back"}
		}
		lines := lifecycleLines(m.lifecycleScreen.view, m.lifecycleScreen.available, m.lifecycleScreen.action)
		actionCount := 1
		if m.lifecycleScreen.available {
			actionCount = len(lifecycleActions(m.lifecycleScreen.view))
		}
		return providerPage(lines, actionCount, m.width, m.height, m.lifecycleScreen.page)
	}
	if isRecoveryScenario(m.scenario) && m.recovery != nil {
		if m.recoveryScreen.pending {
			return []string{spinner(m.unicode, m.operationState.elapsed) + " Checking recovery action - " + elapsed(m.operationState.elapsed), "The State-owning Module decides how long this takes.", "No percentage or result is inferred.", "", "> Back"}
		}
		lines := recoveryLines(m.recoveryScreen.view, m.recoveryScreen.available, m.recoveryScreen.action, m.diagnostics != nil)
		actionCount := 1
		if m.recoveryScreen.available {
			actionCount = len(recoveryActions(m.recoveryScreen.view, m.diagnostics != nil))
		}
		return providerPage(lines, actionCount, m.width, m.height, m.recoveryScreen.page)
	}
	if m.scenario == InstallationReview && m.outcome != nil {
		lines := changeReviewLines(m.changeReview, m.width, m.height, m.planPage)
		if correction := m.changeReview.Correction; correction != nil {
			for index, line := range lines {
				if correction.InputLabel != "" && strings.HasPrefix(line, correction.InputLabel+":") {
					value := "-"
					if m.input != "" {
						value = strconv.QuoteToGraphic(m.input)
					}
					lines[index] = correction.InputLabel + ": " + value
				}
				if m.correctionSelection < len(correction.Selections) && line == "Selection: "+correction.Selections[m.correctionSelection].Label {
					lines[index] = "> " + line
				}
			}
			if m.planPage+1 == m.correctionPageCount(correction) {
				lines = append(lines, "")
				for index, action := range m.correctionActions(correction) {
					prefix := "  "
					if index == m.correctionAction {
						prefix = "> "
					}
					lines = append(lines, prefix+action.label)
				}
			}
			if m.copyFeedback != "" {
				lines = append(lines, "", m.copyFeedback)
			}
		}
		if editing := m.changeReview.Editing; editing != nil {
			value := "-"
			if m.input != "" {
				value = strconv.QuoteToGraphic(m.input)
			}
			for index, line := range lines {
				if strings.HasPrefix(line, editing.Field.Label+":") {
					lines[index] = editing.Field.Label + ": " + value
				}
			}
		}
		if m.changeFeedback != "" {
			lines = append([]string{m.changeFeedback, ""}, lines...)
		}
		return lines
	}
	if m.scenario == MultiStepChangeSet && m.changeSet.Kind != NoChangeSet {
		lines := changeSetLines(m.changeSet)
		if m.outcome == nil && m.changeSet.Kind == ChangeSetActive {
			return append(lines[:len(lines)-3], "", "Close TUI - automatic rollback continues")
		}
		return lines
	}
	if m.scenario == ConnectionProfilesScreen && m.profiles != nil {
		if !m.profilesAvailable {
			return []string{"Connection Profile facts are unavailable.", "", "No health, exposure, publication, or action was inferred.", "", "> Back"}
		}
		lines := profileLines(m.profilesView.Profiles[m.profileSelection], m.profileAction)
		if m.profileValidation.Health != 0 {
			lines = append(lines, "", "Native validation "+m.profileValidation.Health.String()+" - "+m.profileValidation.Code)
		}
		return lines
	}
	if m.scenario == SubscriptionScreen && m.profiles != nil {
		if !m.profilesAvailable || !subscriptionFactsAgree(m.profilesView, m.accessCatalog.subscriptions) {
			return []string{"Subscription facts are unavailable.", "", "No representation count, omission, or action was inferred.", "", "> Back"}
		}
		return subscriptionLines(m.accessCatalog.subscriptions, m.subscriptionAction)
	}
	if m.scenario == LiveProfileCheckScreen && m.profiles != nil {
		if m.liveProfileCheckPending && !m.liveProfileCheckValid {
			return []string{spinner(m.unicode, m.liveProfileCheckElapsed) + " Live Profile Check is starting - " + elapsed(m.liveProfileCheckElapsed), "Session-only and memory-only", "", "> Back"}
		}
		return liveProfileCheckLines(m.liveProfileCheck, m.liveProfileCheckValid, m.width, m.unicode, m.liveProfileCheckElapsed)
	}
	if m.scenario == DedicatedAccess {
		if !m.accessUnlocked || m.accessSelection >= len(m.accessCatalog.all) {
			return current.lines
		}
		entry := m.accessCatalog.all[m.accessSelection]
		valueLines := m.accessValueLines(entry)
		for index := range valueLines {
			valueLines[index] = "\x1b[4m" + valueLines[index] + "\x1b[24m"
		}
		lines := []string{fmt.Sprintf("Access value %d of %d", m.accessSelection+1, len(m.accessCatalog.all)), entry.name, ""}
		lines = append(lines, valueLines...)
		lines = append(lines, "Click or press Enter to copy", "")
		if m.width < 120 {
			lines = append(lines, accessMetadata(entry)...)
			if entry.qr {
				lines = append(lines, "QR omitted at this size; exact text remains available.")
			}
		}
		if m.copyFeedback != "" {
			lines = append(lines, "", m.copyFeedback)
		}
		return append(lines, "", "Clipboard history may retain copied values.")
	}
	if m.scenario == LimitedDashboard {
		lines := append([]string(nil), current.lines...)
		for index, action := range m.legalLimitedActions() {
			prefix := "  "
			if index == m.limitedSelection {
				prefix = "> "
			}
			lines = append(lines, prefix+action.label)
		}
		return lines
	}
	if m.progressExpected && current.progress != NoProgress {
		if !m.progressReceived {
			return []string{"Waiting for typed progress.", "", "No percentage or result is inferred while facts are absent."}
		}
		return presentProgress(current.progress, m.progress, m.progressElapsed, m.unicode).lines
	}
	lines := append([]string(nil), current.lines...)
	if current.acceptsInput {
		prefix := "  "
		if m.inputFocused {
			prefix = "> "
		}
		value := "-"
		if m.input != "" {
			value = strconv.QuoteToGraphic(m.input)
		}
		if m.pasteNeutralized {
			value += " [terminal controls neutralized]"
		}
		if m.inputTruncated {
			value += " [input limit reached]"
		}
		lines[current.inputLine] = prefix + value
	}
	return lines
}

type correctionActionDefinition struct {
	action correctionAction
	label  string
}

func (m model) correctionActions(correction *CorrectionPresentation) []correctionActionDefinition {
	actions := make([]correctionActionDefinition, 0, 4)
	if correction.FixWithSBXR {
		actions = append(actions, correctionActionDefinition{correctionFix, "Fix with SBXR - review a separate Plan"})
	}
	return append(actions,
		correctionActionDefinition{correctionCheck, "Check again"},
		correctionActionDefinition{correctionCopy, "Copy redacted evidence"},
		correctionActionDefinition{correctionBack, "Back"},
	)
}

func (m model) correctionActionCount(correction *CorrectionPresentation) int {
	return len(m.correctionActions(correction))
}

func (m model) correctionActionDefinition(correction *CorrectionPresentation) correctionAction {
	return m.correctionActions(correction)[m.correctionAction].action
}

func (m model) correctionPageCount(correction *CorrectionPresentation) int {
	return len(minimumCorrectionPages(correction, m.width, m.height))
}

func (m model) planPageCount() int {
	if m.changeReview.Plan == nil {
		return 1
	}
	return len(minimumPlanPages(m.changeReview.Plan, m.width, m.height))
}

func accessMetadata(entry accessEntry) []string {
	if entry.qr {
		return []string{"Six approved Connection Profile values"}
	}
	lines := []string{fmt.Sprintf("%d Connection Profiles", entry.profileCount)}
	if entry.candidate {
		status := "Candidate"
		if len(entry.ownerAcceptancePending) != 0 {
			status += " - Owner Acceptance Pending"
		}
		lines = append(lines, status)
		for _, profile := range entry.ownerAcceptancePending {
			lines = append(lines, "Pending: "+profile)
		}
	}
	for _, omission := range entry.omissions {
		lines = append(lines, omission)
	}
	return lines
}

type progressPresentation struct {
	lines, details []string
	timed          bool
}

func presentProgress(expected ProgressKind, progress Progress, elapsedTime time.Duration, unicode bool) progressPresentation {
	invalid := func(message string) progressPresentation {
		return progressPresentation{
			lines:   []string{message, "", "No percentage, completion time, success, rollback, or service state was inferred.", "", "> Request cancellation", "  Close TUI"},
			details: []string{"INVALID PROGRESS", "", "Typed facts were rejected.", "No result was inferred."},
		}
	}
	if progress.Kind < MeasuredProgress || progress.Kind > MixedStepProgress {
		return invalid("Progress unavailable: unsupported typed progress kind.")
	}
	if progress.Kind != expected {
		names := [...]string{"", "measured", "unknown-duration", "mixed-step"}
		return invalid("Progress unavailable: " + names[progress.Kind] + " progress is not legal on this screen.")
	}
	switch progress.Kind {
	case MeasuredProgress:
		if progress.Total == 0 {
			return invalid("Progress unavailable: measured progress requires a real total.")
		}
		if progress.Completed > progress.Total || progress.Total > 1<<50 {
			return invalid("Progress unavailable: measurement is outside its real total.")
		}
		return progressPresentation{
			lines:   []string{"The total is known, so SBXR shows real progress.", "", "Downloading  " + measuredBar(progress.Completed, progress.Total), fmt.Sprintf("%d of %d units", progress.Completed, progress.Total), "", "The percentage is measured from completed and total units.", "", "> Request cancellation", "  Close TUI"},
			details: []string{"MEASURED PROGRESS", "", fmt.Sprintf("Completed  %d", progress.Completed), fmt.Sprintf("Total      %d", progress.Total), "", "Percentage uses these units."},
		}
	case UnknownProgress:
		if progress.Completed != 0 || progress.Total != 0 {
			return invalid("Progress unavailable: measurement is outside its real total.")
		}
		return progressPresentation{
			lines:   []string{"The provider decides how long this takes.", "", fmt.Sprintf("%s Current task  %s", spinner(unicode, elapsedTime), elapsed(elapsedTime)), "", "No percentage or completion time is shown.", "", "> Request cancellation", "  Close TUI"},
			details: []string{"UNKNOWN DURATION", "", "Elapsed time is monotonic.", "No percentage is available."},
			timed:   true,
		}
	case MixedStepProgress:
		if progress.TotalSteps == 0 || progress.CurrentStep == 0 || progress.CurrentStep > progress.TotalSteps {
			return invalid("Progress unavailable: current step is outside the step list.")
		}
		if progress.Completed > progress.Total || progress.Total > 1<<50 {
			return invalid("Progress unavailable: measurement is outside its real total.")
		}
		lines := []string{fmt.Sprintf("Current step %d of %d", progress.CurrentStep, progress.TotalSteps), "", "[NOW] Validate prepared sing-box configuration"}
		timed := progress.Total == 0
		if !timed {
			lines = append(lines, measuredBar(progress.Completed, progress.Total), fmt.Sprintf("%d of %d current-step units", progress.Completed, progress.Total))
		} else {
			lines = append(lines, fmt.Sprintf("%s Current step  %s", spinner(unicode, elapsedTime), elapsed(elapsedTime)), "No percentage is shown for this step.")
		}
		units := "Step units    unknown"
		if !timed {
			units = fmt.Sprintf("Step units    %d of %d", progress.Completed, progress.Total)
		}
		return progressPresentation{
			lines:   append(lines, "", "No overall percentage, completion time, or result is inferred.", "", "> Request cancellation", "  Close TUI", "  View safe evidence"),
			details: []string{"MIXED-STEP PROGRESS", "", fmt.Sprintf("Current step  %d of %d", progress.CurrentStep, progress.TotalSteps), units, "", "No overall percentage."},
			timed:   timed,
		}
	}
	return invalid("Progress unavailable: unsupported typed progress kind.")
}

func measuredBar(completed, total uint64) string {
	percent := completed * 100 / total
	filled := int(percent) * 20 / 100
	return fmt.Sprintf("[%s%s] %d%%", strings.Repeat("=", filled), strings.Repeat("-", 20-filled), percent)
}

func spinner(unicode bool, elapsedTime time.Duration) string {
	frames := "|/-\\"
	if unicode {
		frames = "⠋⠙⠹⠸"
	}
	characters := []rune(frames)
	return string(characters[int(elapsedTime/time.Second)%len(characters)])
}

func elapsed(duration time.Duration) string {
	seconds := int(duration / time.Second)
	return fmt.Sprintf("%02d:%02d", seconds/60, seconds%60)
}

func (m model) shortcuts() [2]string {
	if m.exitConfirm {
		return [2]string{" Enter Exit  Esc Stay", " Q is never Exit"}
	}
	if m.width < minimumWidth || m.height < minimumHeight || m.scenario == UndersizedPause {
		return [2]string{" Ctrl+C Exit confirmation", " Q is never Exit"}
	}
	if m.inputFocused {
		return [2]string{" Type or paste input  Tab Navigation", " Q is input data  Ctrl+C Exit confirmation  Esc Back"}
	}
	if m.scenario == PrivacyChoice {
		return [2]string{" Up/Down Choose  Enter/Space Continue", " Ctrl+C Exit confirmation  Q is never Exit"}
	}
	if m.scenario == InstallationReview && m.outcome != nil {
		if correction := m.changeReview.Correction; correction != nil {
			if m.planPage+1 < m.correctionPageCount(correction) {
				return [2]string{" Enter/Space Next correction section  Esc Back", " Tab Input  Ctrl+C Exit confirmation"}
			}
			return [2]string{" Up/Down Action  Left/Right Choice  Enter/Space Select", " Tab Input  Esc Back  Ctrl+C Exit confirmation"}
		}
		if m.changeReview.Plan != nil && m.planPage+1 < m.planPageCount() {
			return [2]string{" Enter/Space Next plan section  Esc Back", " Ctrl+C Exit confirmation  Q is never Exit"}
		}
		if m.changeReview.Plan != nil {
			return [2]string{" Enter/Space Apply exact Plan  Esc Back", " Ctrl+C Exit confirmation  Q is never Exit"}
		}
		if m.changeReview.Editing != nil {
			return [2]string{" Type or paste input  Tab Actions  Enter/Space Review", " Esc Back  Ctrl+C Exit confirmation"}
		}
		return [2]string{" R Check again  Esc Back", " No result inferred  Ctrl+C Exit confirmation"}
	}
	if m.scenario == DedicatedAccess && m.accessUnlocked && m.accessFocused {
		return [2]string{" Up/Down Choose value  Enter/Space Copy  Tab Navigation", " Esc Overview  Ctrl+C Exit confirmation  Q is never Exit"}
	}
	if m.scenario == ConnectionProfilesScreen && m.profiles != nil {
		return [2]string{" Up/Down Profile  Left/Right Action  Enter/Space Select", " Esc Back  Ctrl+C Exit confirmation"}
	}
	if m.scenario == SubscriptionScreen && m.profiles != nil {
		return [2]string{" Up/Down Action  Enter/Space Select", " Esc Back  Ctrl+C Exit confirmation"}
	}
	if m.scenario == LiveProfileCheckScreen && m.profiles != nil {
		return [2]string{" Esc Back", " Ctrl+C Exit confirmation  Q is never Exit"}
	}
	if (m.scenario == CompleteRemovalConfirmation || m.scenario == ForwardOnlyRemoval) && m.completeRemoval != nil {
		if m.completeRemovalScreen.pending {
			return [2]string{" Esc Back", " Ctrl+C Exit confirmation  Q is never Exit"}
		}
		if m.completeRemovalScreen.forwardOnly {
			return [2]string{" No Back, Cancel, or restore", " Ctrl+C Exit confirmation  Q is never Exit"}
		}
		if m.completeRemovalScreen.page+1 < m.completeRemovalPageCount() {
			return [2]string{" Enter/Space Next section  Esc Back", " Ctrl+C Exit confirmation  Q is never Exit"}
		}
		return [2]string{" Up/Down Action  Tab Exact text  Enter/Space Select", " Esc Back  Ctrl+C Exit confirmation"}
	}
	if m.scenario == CloudflareWalkthrough && m.cloudflare != nil {
		if m.cloudflareOperation.active {
			return [2]string{" Esc Back", " Ctrl+C Exit confirmation  Q is never Exit"}
		}
		if m.providerPage+1 < m.cloudflarePageCount() {
			return [2]string{" Enter/Space Next section  Esc Back", " Ctrl+C Exit confirmation  Q is never Exit"}
		}
		if m.inputFocused {
			return [2]string{" Type or paste masked token  Tab Actions", " Esc Back  Ctrl+C Exit confirmation"}
		}
		return [2]string{" Up/Down Action  Enter/Space Select", " Shift+Tab Token  Esc Back  Ctrl+C Exit confirmation"}
	}
	if m.scenario == CertificatesScreen && m.certificates != nil {
		if m.providerPage+1 < m.certificatePageCount() {
			return [2]string{" Enter/Space Next section  Esc Back", " Ctrl+C Exit confirmation  Q is never Exit"}
		}
		return [2]string{" Up/Down Action  Enter/Space Select", " Esc Back  Ctrl+C Exit confirmation  Q is never Exit"}
	}
	if m.scenario == ServicesDiagnosticsScreen && m.diagnostics != nil {
		if m.diagnosticsScreen.pending {
			return [2]string{" Esc Back", " Ctrl+C Exit confirmation  Q is never Exit"}
		}
		if m.diagnosticsScreen.page+1 < m.diagnosticsPageCount() {
			return [2]string{" Enter/Space Next section  Esc Back", " Ctrl+C Exit confirmation  Q is never Exit"}
		}
		return [2]string{" Up/Down Action  Enter/Space Select", " Esc Back  Ctrl+C Exit confirmation  Q is never Exit"}
	}
	if m.scenario == UpdateReview && m.lifecycle != nil {
		if m.lifecycleScreen.pending {
			return [2]string{" Esc Back", " Ctrl+C Exit confirmation  Q is never Exit"}
		}
		if m.lifecycleScreen.page+1 < m.lifecyclePageCount() {
			return [2]string{" Enter/Space Next section  Esc Back", " Ctrl+C Exit confirmation  Q is never Exit"}
		}
		return [2]string{" Up/Down Action  Enter/Space Select", " Esc Back  Ctrl+C Exit confirmation  Q is never Exit"}
	}
	if isRecoveryScenario(m.scenario) && m.recovery != nil {
		if m.recoveryScreen.pending {
			return [2]string{" Esc Back", " Ctrl+C Exit confirmation  Q is never Exit"}
		}
		if m.recoveryScreen.page+1 < m.recoveryPageCount() {
			return [2]string{" Enter/Space Next section  Esc Back", " Ctrl+C Exit confirmation  Q is never Exit"}
		}
		return [2]string{" Up/Down Action  Enter/Space Select", " Esc Back  Ctrl+C Exit confirmation  Q is never Exit"}
	}
	second := " Ctrl+C Exit confirmation  Q is never Exit"
	if scenarioFixture(m.scenario).allowsBack {
		second = " Esc Back " + second
	}
	return [2]string{" Up/Down Navigate  Tab/Shift+Tab Move  Enter/Space Select", second}
}

func (m model) title(value string) string {
	style := lipgloss.NewStyle().Bold(true)
	if !m.noColor && m.appearanceKnown {
		style = style.Foreground(lipgloss.LightDark(m.dark)(lipgloss.Color("#005CC5"), lipgloss.Color("#75BFFF")))
	}
	return style.Render(value)
}

func selectedNavigation(scenario Scenario) int {
	want := scenarioFixture(scenario).navigation
	for index, item := range navigation {
		if item.id == want {
			return index
		}
	}
	return 0
}

func isRecoveryScenario(scenario Scenario) bool {
	return scenario == RecoveryWithRollback || scenario == RecoveryWithoutRecovery || scenario == ManagedStateRepair
}

func recoveryScenario(kind RecoveryKind) Scenario {
	switch kind {
	case RecoveryRollbackAvailable:
		return RecoveryWithRollback
	case RecoveryCurrentStateRepairAvailable:
		return ManagedStateRepair
	default:
		return RecoveryWithoutRecovery
	}
}

func completeRemovalScenario(kind CompleteRemovalKind) Scenario {
	if definition, valid := completeRemovalDefinitionFor(kind); valid {
		return definition.scenario
	}
	return CompleteRemovalConfirmation
}

func fit(value string, width int) string {
	plainWidth := lipgloss.Width(value)
	if plainWidth > width {
		value = lipgloss.NewStyle().MaxWidth(width).Render(value)
		plainWidth = lipgloss.Width(value)
	}
	return value + strings.Repeat(" ", width-plainWidth)
}

func wrapLines(lines []string, width int) []string {
	var wrapped []string
	for _, line := range lines {
		if line == "" {
			wrapped = append(wrapped, "")
			continue
		}
		current := ""
		for _, word := range strings.Fields(line) {
			candidate := word
			if current != "" {
				candidate = current + " " + word
			}
			if lipgloss.Width(candidate) <= width {
				current = candidate
				continue
			}
			if current != "" {
				wrapped = append(wrapped, current)
				current = ""
			}
			for lipgloss.Width(word) > width {
				part := ""
				for _, character := range word {
					if lipgloss.Width(part+string(character)) > width {
						break
					}
					part += string(character)
				}
				wrapped = append(wrapped, part)
				word = strings.TrimPrefix(word, part)
			}
			current = word
		}
		wrapped = append(wrapped, current)
	}
	return wrapped
}
