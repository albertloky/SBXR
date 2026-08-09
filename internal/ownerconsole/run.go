package ownerconsole

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const minimumWidth, minimumHeight = 80, 24

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
	Input        io.Reader
	Output       io.Writer
	Environment  []string
	Capabilities *Capabilities
	Scenario     Scenario
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
	program := tea.NewProgram(
		model{width: c.Width, height: c.Height, scenario: session.Scenario, selected: selectedNavigation(session.Scenario), unicode: c.Unicode, noColor: noColor, initialModes: initialModes, drawingModeProbeRequired: c.DrawingModeProbeRequired},
		tea.WithContext(ctx),
		tea.WithInput(session.Input),
		tea.WithOutput(session.Output),
		tea.WithEnvironment(session.Environment),
		tea.WithWindowSize(c.Width, c.Height),
	)
	result, err := program.Run()
	restoreOwnedModes(session.Output, initialModes)
	if err == nil {
		if final, ok := result.(model); ok && final.probeFailure != "" {
			return refuse(session.Output, final.probeFailure, probeCorrection(final.probeFailure))
		}
	}
	return err
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
}

type probeTimeoutMsg struct{}

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
	case tea.KeyPressMsg:
		if m.width < minimumWidth || m.height < minimumHeight {
			switch message.String() {
			case "ctrl+c":
				m.exitConfirm = true
			case "enter", "space":
				if m.exitConfirm {
					return m, tea.Quit
				}
			case "esc":
				m.exitConfirm = false
			}
			return m, nil
		}
		switch message.String() {
		case "ctrl+c":
			m.exitConfirm = true
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
	main := []string{
		"PRIVACY BEFORE ACCESS", "",
		"Client Access Values may remain in terminal scrollback,",
		"screenshots, screen recordings, SSH session logs, clipboard",
		"history, and synchronized clipboards.", "",
		"No Client Access Value or sudo prompt appears before your choice.", "",
		"> Continue with authenticated Client Access Values",
		"  Open the limited read-only dashboard",
		"  Exit SBXR", "",
		"Up/Down Select  Enter Continue  Ctrl+C Exit confirmation",
	}
	if m.scenario != PrivacyChoice {
		main = append([]string{currentFixture.title, ""}, currentFixture.lines...)
	}
	if m.exitConfirm {
		main = []string{
			"Exit SBXR?", "",
			"No approved Change Set will be cancelled.", "",
			"> Exit SBXR", "  Stay in SBXR", "",
			"Enter Exit  Esc Stay",
		}
	}
	leftWidth := 21
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
	rows = append(rows, fit(" SBXR", 18)+fit(header, width-18))
	horizontal, vertical, crossing := "-", "|", "+"
	if m.unicode {
		horizontal, vertical, crossing = "─", "│", "┼"
	}
	rows = append(rows, strings.Repeat(horizontal, leftWidth)+crossing+strings.Repeat(horizontal, rightWidth))
	details := currentFixture.details
	if width >= 120 {
		details = wrapLines(details, rightWidth-49)
	}
	for row := range bodyHeight {
		left, right := "", ""
		if row < len(navigation) {
			prefix := "  "
			if row == m.selected {
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

func (m model) shortcuts() [2]string {
	if m.exitConfirm {
		return [2]string{" Enter Exit  Esc Stay", " Q is never Exit"}
	}
	if m.width < minimumWidth || m.height < minimumHeight || m.scenario == UndersizedPause {
		return [2]string{" Ctrl+C Exit confirmation", " Q is never Exit"}
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
