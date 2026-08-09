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
	Input                io.Reader
	Output               io.Writer
	Environment          []string
	Capabilities         *Capabilities
	Scenario             Scenario
	Updates              <-chan PresentationUpdate
	Authenticator        Authenticator
	AuthenticationPolicy AuthenticationPolicy
	Access               AccessPresentation
	Clipboard            Clipboard
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
	accessEntries := session.Access.entries()
	program := tea.NewProgram(
		model{width: c.Width, height: c.Height, scenario: session.Scenario, selected: selectedNavigation(session.Scenario), unicode: c.Unicode, noColor: noColor, initialModes: initialModes, drawingModeProbeRequired: c.DrawingModeProbeRequired, inputFocused: fixture.acceptsInput, progressExpected: session.Updates != nil, authenticator: session.Authenticator, authenticationPolicy: session.AuthenticationPolicy, runContext: runContext, accessEntries: accessEntries, clipboard: session.Clipboard},
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
	width, height             int
	exitConfirm               bool
	scenario                  Scenario
	selected                  int
	unicode                   bool
	noColor                   bool
	dark                      bool
	appearanceKnown           bool
	initialModes              map[int]bool
	drawingModeProbeRequired  bool
	probeDone                 bool
	probeFailure              string
	cursorAddressingConfirmed bool
	input                     string
	inputFocused              bool
	inputTruncated            bool
	pasteNeutralized          bool
	pasteGuard                bool
	refreshed                 bool
	pendingUpdate             *PresentationUpdate
	progress                  Progress
	progressExpected          bool
	progressReceived          bool
	progressStartedAt         time.Time
	progressElapsed           time.Duration
	progressClock             progressClock
	progressTicking           bool
	privacySelection          int
	limitedMode               bool
	limitedSelection          int
	authenticator             Authenticator
	authenticationPolicy      AuthenticationPolicy
	limitedReason             string
	runContext                context.Context
	accessEntries             []accessEntry
	accessUnlocked            bool
	accessFocused             bool
	accessSelection           int
	clipboard                 Clipboard
	copyFeedback              string
}

type probeTimeoutMsg struct{}
type progressTickMsg time.Time
type pasteGuardExpiredMsg struct{}
type authenticationFinishedMsg struct {
	result AuthenticationResult
}
type copyFinishedMsg struct {
	name   string
	result CopyResult
}

type progressClock struct {
	kind        ProgressKind
	operationID uint64
	currentStep uint16
}

func (m model) Init() tea.Cmd {
	commands := []tea.Cmd{tea.RequestBackgroundColor}
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
	case pasteGuardExpiredMsg:
		m.pasteGuard = false
	case authenticationFinishedMsg:
		if message.result == AuthenticationSucceeded {
			m.scenario, m.selected = AuthenticatedOverview, selectedNavigation(AuthenticatedOverview)
			m.limitedMode = false
			m.accessUnlocked = len(m.accessEntries) != 0
			return m, nil
		}
		m.scenario, m.selected = LimitedDashboard, selectedNavigation(LimitedDashboard)
		m.limitedMode, m.limitedSelection = true, 0
		m.limitedReason = authenticationExplanation(message.result)
	case copyFinishedMsg:
		switch message.result {
		case CopyConfirmed:
			m.copyFeedback = "Copied " + message.name + "."
		case CopyRequested:
			m.copyFeedback = "Copy request sent. If it is not in your clipboard, select the text manually."
		default:
			m.copyFeedback = "Copy failed. Select the text manually."
		}
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
				m.accessSelection = (m.accessSelection + len(m.accessEntries) - 1) % len(m.accessEntries)
				m.copyFeedback = ""
			case "down":
				m.accessSelection = (m.accessSelection + 1) % len(m.accessEntries)
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
		if scenarioFixture(m.scenario).acceptsInput {
			if m.inputFocused {
				switch message.String() {
				case "tab", "shift+tab":
					m.inputFocused = false
				case "backspace":
					runes := []rune(m.input)
					if len(runes) > 0 {
						m.input = string(runes[:len(runes)-1])
					}
				case "esc":
					m.scenario, m.selected, m.inputFocused = AuthenticatedOverview, 0, false
				default:
					m.appendInput(message.Key().Text)
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

func (m model) legalLimitedActions() []limitedActionDefinition {
	if m.authenticationPolicy == AuthenticateForAccess {
		return limitedActions[:]
	}
	return limitedActions[1:]
}

func (m model) copySelectedAccessValue() tea.Cmd {
	entry := m.accessEntries[m.accessSelection]
	if m.clipboard == nil {
		return tea.Sequence(tea.SetClipboard(entry.value), func() tea.Msg { return copyFinishedMsg{name: entry.name, result: CopyRequested} })
	}
	return func() tea.Msg {
		return copyFinishedMsg{name: entry.name, result: m.clipboard.Copy(m.runContext, entry.value)}
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

func (m model) accessValueLines(entry accessEntry) []string {
	width := m.width - navigationWidth - 1
	if m.width >= 120 {
		width = 48
	}
	return wrapLines([]string{entry.value}, width)
}

func (m model) accessValueHit(x, y int) bool {
	if m.accessSelection >= len(m.accessEntries) {
		return false
	}
	const frameRowsBeforeBody, accessRowsBeforeValue = 2, 5
	lines := m.accessValueLines(m.accessEntries[m.accessSelection])
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
	if m.pendingUpdate == nil {
		return nil
	}
	update := *m.pendingUpdate
	m.pendingUpdate = nil
	return m.applyPresentationUpdate(update)
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
		main = append([]string{currentFixture.title, ""}, m.scenarioLines(currentFixture)...)
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
	header := currentFixture.header
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
		if m.scenario != DedicatedAccess || !m.accessUnlocked || m.accessSelection >= len(m.accessEntries) || !m.accessEntries[m.accessSelection].qr {
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

func (m model) scenarioDetails(current fixture) []string {
	if m.scenario == DedicatedAccess {
		if !m.accessUnlocked || m.accessSelection >= len(m.accessEntries) {
			return current.details
		}
		entry := m.accessEntries[m.accessSelection]
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
	if m.scenario == DedicatedAccess {
		if !m.accessUnlocked || m.accessSelection >= len(m.accessEntries) {
			return current.lines
		}
		entry := m.accessEntries[m.accessSelection]
		valueLines := m.accessValueLines(entry)
		for index := range valueLines {
			valueLines[index] = "\x1b[4m" + valueLines[index] + "\x1b[24m"
		}
		lines := []string{fmt.Sprintf("Access value %d of %d", m.accessSelection+1, len(m.accessEntries)), entry.name, ""}
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
	if m.scenario == DedicatedAccess && m.accessUnlocked && m.accessFocused {
		return [2]string{" Up/Down Choose value  Enter/Space Copy  Tab Navigation", " Esc Overview  Ctrl+C Exit confirmation  Q is never Exit"}
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
