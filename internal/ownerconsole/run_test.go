package ownerconsole

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"charm.land/lipgloss/v2"
)

func TestRunRefusesUnsafeTerminalBeforeDrawing(t *testing.T) {
	capable := Capabilities{
		InteractiveInput:  true,
		InteractiveOutput: true,
		AlternateScreen:   true,
		CursorAddressing:  true,
		ReadableEncoding:  true,
		KeyboardInput:     true,
		Width:             80,
		Height:            24,
	}
	tests := []struct {
		name       string
		change     func(*Capabilities)
		want       string
		correction string
	}{
		{name: "redirected input", change: func(c *Capabilities) { c.InteractiveInput = false }, want: "interactive input", correction: "run sbxr in an interactive terminal"},
		{name: "redirected output", change: func(c *Capabilities) { c.InteractiveOutput = false }, want: "interactive output", correction: "run sbxr with the terminal attached to standard output"},
		{name: "alternate screen", change: func(c *Capabilities) { c.AlternateScreen = false }, want: "alternate-screen support", correction: "use a terminal that supports an alternate screen"},
		{name: "cursor addressing", change: func(c *Capabilities) { c.CursorAddressing = false }, want: "full-screen cursor addressing and drawing", correction: "use a terminal with full-screen cursor support"},
		{name: "encoding", change: func(c *Capabilities) { c.ReadableEncoding = false }, want: "readable text encoding", correction: "use a UTF-8 terminal locale"},
		{name: "keyboard", change: func(c *Capabilities) { c.KeyboardInput = false }, want: "standard keyboard input", correction: "use a terminal with standard keyboard input"},
		{name: "undersized", change: func(c *Capabilities) { c.Width, c.Height = 79, 23 }, want: "current size is 79x23; required size is 80x24", correction: "enlarge the terminal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capabilities := capable
			tt.change(&capabilities)
			var output bytes.Buffer
			err := Run(context.Background(), Session{
				Input:        strings.NewReader("CLIENT-ACCESS-MARKER"),
				Output:       &output,
				Capabilities: &capabilities,
			})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Run() error = %v, want %q", err, tt.want)
			}
			if got := output.String(); !strings.Contains(got, tt.want) || !strings.Contains(got, tt.correction) {
				t.Fatalf("refusal = %q, want capability and correction", got)
			}
			if strings.Contains(output.String(), "CLIENT-ACCESS-MARKER") {
				t.Fatal("refusal exposed a Client Access Value")
			}
		})
	}
}

func TestRunUsesStyleAEventLoopAndRestoresTerminal(t *testing.T) {
	capabilities := capableTerminal(80, 24)
	var output bytes.Buffer
	input, writeInput := io.Pipe()
	defer input.Close()
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = writeInput.Write([]byte("\x03\r"))
		_ = writeInput.Close()
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	err := Run(ctx, Session{
		Input:        input,
		Output:       &output,
		Capabilities: &capabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, want := range []string{
		"\x1b[?1000l", // reset contaminated mouse reporting before drawing
		"\x1b[?2004l", // reset contaminated bracketed paste before drawing
		"\x1b[?1049h", // enter the required alternate screen
		"PRIVACY BEFORE ACCESS",
		"Overview",
		"Connection Profiles",
		"Complete removal",
		"Exit SBXR?",
		"\x1b[?1049l", // restore the prior screen on exit
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("terminal transcript missing %q\n%s", want, got)
		}
	}
	if strings.Contains(got, "CLIENT-ACCESS-MARKER") {
		t.Fatal("Client Access Value rendered before the privacy choice")
	}
}

func capableTerminal(width, height int) Capabilities {
	return Capabilities{
		InteractiveInput:  true,
		InteractiveOutput: true,
		AlternateScreen:   true,
		CursorAddressing:  true,
		ReadableEncoding:  true,
		KeyboardInput:     true,
		Width:             width,
		Height:            height,
	}
}

func TestRunRendersCanonicalStyleAFixturesAtBothApprovedSizes(t *testing.T) {
	fixtures := []struct {
		scenario Scenario
		title    string
	}{
		{AuthenticatedOverview, "OVERVIEW"},
		{DedicatedAccess, "CLIENT ACCESS VALUES"},
		{LimitedDashboard, "LIMITED DASHBOARD"},
		{InstallationReview, "REVIEW INSTALLATION PLAN"},
		{CloudflareWalkthrough, "CLOUDFLARE TOKEN"},
		{CorrectionFlow, "CORRECTION FLOW"},
		{MeasuredDownload, "DOWNLOAD RELEASE"},
		{UnknownCloudflareVerification, "CHECK CLOUDFLARE CONNECTION"},
		{MultiStepChangeSet, "UPDATE TO v1.1.0 - 00:01:42"},
		{CancellationRequested, "CANCELLATION REQUESTED"},
		{RecoveryWithRollback, "AUTOMATIC ROLLBACK IS AVAILABLE"},
		{RecoveryWithoutRecovery, "THIS INSTALLATION CANNOT BE RECOVERED"},
		{UpdateReview, "REVIEW UPDATE PLAN"},
		{CompleteRemovalConfirmation, "COMPLETE REMOVAL - PERMANENT"},
		{ForwardOnlyRemoval, "IRREVERSIBLE REMOVAL STARTED"},
		{UndersizedPause, "TERMINAL IS TOO SMALL"},
	}
	for _, size := range [][2]int{{80, 24}, {120, 36}} {
		for _, fixture := range fixtures {
			name := fmt.Sprintf("%s/%dx%d", fixture.title, size[0], size[1])
			t.Run(name, func(t *testing.T) {
				got := runTranscript(t, Session{Scenario: fixture.scenario}, size[0], size[1], "\x03\r")
				if !strings.Contains(got, fixture.title) {
					t.Fatalf("transcript missing %q", fixture.title)
				}
				for _, navigation := range []string{"Overview", "Access", "Connection Profiles", "Complete removal"} {
					if !strings.Contains(got, navigation) {
						t.Fatalf("transcript missing stable navigation %q", navigation)
					}
				}
				if size[0] == 120 && !strings.Contains(got, "RELEVANT DETAILS") {
					t.Fatal("large fixture missing the approved detail column")
				}
				if size[0] == 80 && strings.Contains(got, "RELEVANT DETAILS") {
					t.Fatal("minimum fixture unexpectedly changed navigation for a detail column")
				}
			})
		}
	}
}

func TestCanonicalFramesRemainExact(t *testing.T) {
	scenarios := []Scenario{
		AuthenticatedOverview, DedicatedAccess, LimitedDashboard, InstallationReview,
		CloudflareWalkthrough, CorrectionFlow, MeasuredDownload, UnknownCloudflareVerification,
		MultiStepChangeSet, CancellationRequested, RecoveryWithRollback, RecoveryWithoutRecovery,
		UpdateReview, CompleteRemovalConfirmation, ForwardOnlyRemoval, UndersizedPause,
	}
	var frames strings.Builder
	for _, size := range [][2]int{{80, 24}, {120, 36}} {
		for _, scenario := range scenarios {
			fixture := scenarioFixture(scenario)
			frame := (model{width: size[0], height: size[1], scenario: scenario, selected: selectedNavigation(scenario), unicode: true, noColor: true, inputFocused: fixture.acceptsInput}).frame()
			rows := strings.Split(frame, "\n")
			if len(rows) != size[1] {
				t.Fatalf("%s at %dx%d has %d rows", fixture.title, size[0], size[1], len(rows))
			}
			for row, line := range rows {
				if width := lipgloss.Width(line); width != size[0] {
					t.Fatalf("%s at %dx%d row %d has width %d", fixture.title, size[0], size[1], row, width)
				}
			}
			contentWidth := size[0] - 22
			if size[0] == 120 {
				contentWidth = 48
			}
			for _, line := range wrapLines(fixture.lines, contentWidth) {
				if line != "" && !strings.Contains(frame, line) {
					t.Fatalf("%s at %dx%d hides required line %q", fixture.title, size[0], size[1], line)
				}
			}
			if size[0] == 120 {
				for _, detail := range wrapLines(fixture.details, 49) {
					if detail != "" && !strings.Contains(frame, detail) {
						t.Fatalf("%s at 120x36 hides detail %q", fixture.title, detail)
					}
				}
			}
			fmt.Fprintf(&frames, "%d/%d/%d\n%s\n", scenario, size[0], size[1], frame)
		}
	}
	want := "4e6247fb87c1679c8ff77fbda1b4d75cfdee76fde904c5fe7477b539f809cfae"
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(frames.String()))); got != want {
		t.Fatalf("canonical frame snapshot = %s, want %s", got, want)
	}
}

func runTranscript(t *testing.T, session Session, width, height int, keys string) string {
	t.Helper()
	capabilities := capableTerminal(width, height)
	if session.Capabilities == nil {
		session.Capabilities = &capabilities
	}
	var output bytes.Buffer
	session.Output = &output
	input, writeInput := io.Pipe()
	session.Input = input
	defer input.Close()
	go func() {
		time.Sleep(30 * time.Millisecond)
		_, _ = writeInput.Write([]byte(keys))
		_ = writeInput.Close()
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := Run(ctx, session); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func TestRunNavigationUsesSafeKeysAndNeverQ(t *testing.T) {
	tests := []struct {
		name     string
		start    Scenario
		keys     []string
		wantView string
	}{
		{name: "arrow and Enter", start: AuthenticatedOverview, keys: []string{"q\x1b[200~Q\nCOMPLETE REMOVAL\x1b[201~", "\x1b[B\r"}, wantView: "CLIENT ACCESS VALUES"},
		{name: "Tab and Space", start: AuthenticatedOverview, keys: []string{"\t "}, wantView: "CLIENT ACCESS VALUES"},
		{name: "arrow up and Enter", start: DedicatedAccess, keys: []string{"\x1b[A\r"}, wantView: "OVERVIEW"},
		{name: "Shift-Tab and Space", start: DedicatedAccess, keys: []string{"\x1b[Z "}, wantView: "OVERVIEW"},
		{name: "Esc goes back", start: DedicatedAccess, keys: []string{"\x1b[27u"}, wantView: "OVERVIEW"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runTranscriptSteps(t, Session{Scenario: tt.start}, 80, 24, append(tt.keys, "\x03\r")...)
			if !strings.Contains(got, tt.wantView) {
				t.Fatalf("safe navigation did not open %q\n%s", tt.wantView, got)
			}
			if !strings.Contains(got, "Exit SBXR?") {
				t.Fatal("Ctrl+C did not open the visible exit confirmation")
			}
		})
	}
}

func TestRunEveryPersistentNavigationItemOpensItsScreen(t *testing.T) {
	screens := []string{
		"OVERVIEW", "CLIENT ACCESS VALUES", "CONNECTION PROFILES", "CLOUDFLARE TOKEN",
		"CERTIFICATES", "SUBSCRIPTION", "NETWORK", "SERVICES AND DIAGNOSTICS",
		"REVIEW UPDATE PLAN", "SECURITY", "COMPLETE REMOVAL - PERMANENT",
	}
	for index, title := range screens {
		t.Run(title, func(t *testing.T) {
			keys := strings.Repeat("\x1b[B", index) + "\r"
			got := runTranscriptSteps(t, Session{Scenario: AuthenticatedOverview}, 80, 24, keys, "\x03\r")
			if !strings.Contains(got, title) {
				t.Fatalf("navigation item %d did not open %q", index, title)
			}
		})
	}
}

func runTranscriptSteps(t *testing.T, session Session, width, height int, steps ...string) string {
	t.Helper()
	capabilities := capableTerminal(width, height)
	if session.Capabilities == nil {
		session.Capabilities = &capabilities
	}
	var output bytes.Buffer
	session.Output = &output
	input, writeInput := io.Pipe()
	session.Input = input
	defer input.Close()
	go func() {
		for _, step := range steps {
			time.Sleep(30 * time.Millisecond)
			_, _ = writeInput.Write([]byte(step))
		}
		_ = writeInput.Close()
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := Run(ctx, session); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func TestRunDegradesColorAndUnicodeWithoutLosingMeaning(t *testing.T) {
	palettes := [][]string{
		{"TERM=xterm-direct", "COLORTERM=truecolor", "LANG=C.UTF-8"},
		{"TERM=xterm-256color", "LANG=C.UTF-8"},
		{"TERM=xterm", "LANG=C.UTF-8"},
		{"TERM=xterm", "NO_COLOR=1", "LANG=C.UTF-8"},
	}
	for _, environment := range palettes {
		got := runTranscript(t, Session{Scenario: AuthenticatedOverview, Environment: environment}, 80, 24, "\x03\r")
		for _, meaning := range []string{"[HEALTHY]", "> Overview", "Exit SBXR?"} {
			if !strings.Contains(got, meaning) {
				t.Fatalf("palette %v lost non-color meaning %q", environment, meaning)
			}
		}
	}

	capabilities := capableTerminal(80, 24)
	capabilities.Unicode = true
	got := runTranscriptSteps(t, Session{Scenario: AuthenticatedOverview, Capabilities: &capabilities}, 80, 24, "\x03\r")
	if !strings.Contains(got, "─") || !strings.Contains(got, "│") {
		t.Fatal("Unicode-capable terminal did not receive Unicode separators")
	}
	capabilities.Unicode = false
	got = runTranscriptSteps(t, Session{Scenario: AuthenticatedOverview, Capabilities: &capabilities}, 80, 24, "\x03\r")
	if strings.Contains(got, "─") || strings.Contains(got, "│") {
		t.Fatal("limited terminal did not receive ASCII fallbacks")
	}
}

func TestRunWrapsSafetyTextAndShowsOnlyLegalShortcuts(t *testing.T) {
	installation := runTranscript(t, Session{Scenario: InstallationReview}, 80, 24, "\x03\r")
	if !strings.Contains(installation, "Download, verification and unprivileged preflight passed.") {
		t.Fatal("minimum-size frame clipped safety text instead of wrapping it")
	}
	forwardOnly := runTranscript(t, Session{Scenario: ForwardOnlyRemoval}, 80, 24, "\x03\r")
	if strings.Contains(forwardOnly, "Esc Back") {
		t.Fatal("forward-only removal advertised an illegal Back action")
	}
	forwardOnly = runTranscriptSteps(t, Session{Scenario: ForwardOnlyRemoval}, 80, 24, "\x1b[27u", "\x03\r")
	if strings.Contains(forwardOnly, "OVERVIEW") {
		t.Fatal("Esc left forward-only removal")
	}
	for _, transcript := range []string{installation, forwardOnly} {
		if strings.Contains(transcript, "PgDn") {
			t.Fatal("a screen depends on PgDn")
		}
		if !strings.Contains(transcript, "Q is never Exit") {
			t.Fatal("contextual shortcut bar is missing")
		}
	}
}

func TestRunKeepsHostilePasteAsVisibleInputData(t *testing.T) {
	tests := []struct {
		name, pasted, visible string
	}{
		{name: "shortcut letters", pasted: "Qq", visible: `"Qq"`},
		{name: "multiline confirmation", pasted: "COMPLETE REMOVAL\nAPPLY\nRESTORE", visible: `"COMPLETE REMOVAL\nAPPLY\nRESTORE"`},
		{name: "escape-like bytes", pasted: "before\x1b[31mafter", visible: `"beforeafter" [terminal controls neutralized]`},
		{name: "untrusted controls", pasted: "a\x00\x07\tb", visible: `"a\x00\a\tb"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			paste := "\x1b[200~" + test.pasted + "\x1b[201~"
			got := runTranscriptSteps(t, Session{Scenario: CorrectionFlow}, 80, 24, paste, "", "", "\x03\r")
			if !strings.Contains(got, test.visible) {
				t.Fatalf("pasted data missing safe visible form %q\n%s", test.visible, got)
			}
			if strings.Contains(got, test.pasted) && strings.ContainsAny(test.pasted, "\x00\x07\x1b") {
				t.Fatal("untrusted control bytes were rendered verbatim")
			}
			if !strings.Contains(got, "CORRECTION FLOW") || !strings.Contains(got, "Exit SBXR?") {
				t.Fatal("pasted shortcut or confirmation text changed the active screen")
			}
		})
	}

	got := runTranscriptSteps(t, Session{Scenario: CorrectionFlow}, 80, 24, "\x1b[200~safe\x1b[201~q\x03\r", "", "", "\x03\r")
	if !strings.Contains(got, `"safeq`) || !strings.Contains(got, `ctrl+c><enter>"`) || !strings.Contains(got, "[terminal controls neutralized]") {
		t.Fatalf("bytes after a hostile paste terminator became shortcuts instead of safe data\n%s", got)
	}
}

func TestRunBackgroundRefreshKeepsConfirmationUntilExplicitDismissal(t *testing.T) {
	for _, size := range [][2]int{{80, 24}, {120, 36}} {
		t.Run(fmt.Sprintf("%dx%d", size[0], size[1]), func(t *testing.T) {
			held := runRefreshConfirmation(t, size[0], size[1], false)
			if !strings.Contains(held, "Exit SBXR?") || strings.Contains(held, "refreshed") || strings.Contains(held, "36%") {
				t.Fatalf("refresh changed the visible confirmation\n%s", held)
			}
			dismissed := runRefreshConfirmation(t, size[0], size[1], true)
			if !strings.Contains(dismissed, "Exit SBXR?") || !strings.Contains(dismissed, "refreshed") || !strings.Contains(dismissed, "36%") {
				t.Fatalf("explicit dismissal did not reveal the pending refresh\n%s", dismissed)
			}
		})
	}
}

func runRefreshConfirmation(t *testing.T, width, height int, dismiss bool) string {
	t.Helper()
	updates := make(chan PresentationUpdate)
	go func() {
		time.Sleep(45 * time.Millisecond)
		updates <- PresentationUpdate{Progress: Progress{Kind: MeasuredProgress, Completed: 37, Total: 101}}
		close(updates)
	}()
	steps := []string{"\x03", "\r"}
	if dismiss {
		steps = []string{"\x03", "\x1b[27u", "", "\x03\r"}
	}
	return runTranscriptSteps(t, Session{Scenario: MeasuredDownload, Updates: updates}, width, height, steps...)
}

func TestRunPresentsOnlyTypedTruthfulProgress(t *testing.T) {
	tests := []struct {
		name     string
		scenario Scenario
		progress Progress
		wait     time.Duration
		want     []string
		reject   []string
	}{
		{name: "measured", scenario: MeasuredDownload, progress: Progress{Kind: MeasuredProgress, Completed: 37, Total: 101}, want: []string{"37 of 101 units", "36%", "Request cancellation", "Close TUI"}, reject: []string{"42%"}},
		{name: "unknown duration", scenario: UnknownCloudflareVerification, progress: Progress{Kind: UnknownProgress, OperationID: 1}, wait: 1100 * time.Millisecond, want: []string{"Current task", "00:01", "Request cancellation", "Close TUI"}, reject: []string{"%"}},
		{name: "mixed measured step", scenario: MultiStepChangeSet, progress: Progress{Kind: MixedStepProgress, CurrentStep: 4, TotalSteps: 7, Completed: 31, Total: 80}, want: []string{"Current step 4 of 7", "38%", "Request cancellation", "Close TUI"}, reject: []string{"success"}},
		{name: "mixed unknown step", scenario: MultiStepChangeSet, progress: Progress{Kind: MixedStepProgress, OperationID: 1, CurrentStep: 2, TotalSteps: 7}, wait: 1100 * time.Millisecond, want: []string{"Current step 2 of 7", "00:01", "Request cancellation", "Close TUI"}, reject: []string{"%"}},
		{name: "invalid measurement", scenario: MeasuredDownload, progress: Progress{Kind: MeasuredProgress, Completed: 1}, want: []string{"Progress unavailable: measured progress requires a real", "total.", "Request cancellation", "Close TUI"}, reject: []string{"%"}},
		{name: "unknown kind", scenario: MeasuredDownload, progress: Progress{Kind: ProgressKind(99)}, want: []string{"Progress unavailable: unsupported typed progress kind.", "Request cancellation", "Close TUI"}, reject: []string{"%"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := runProgressTranscript(t, test.scenario, test.progress, test.wait)
			for _, want := range test.want {
				if !strings.Contains(got, want) {
					t.Fatalf("progress missing %q\n%s", want, got)
				}
			}
			for _, reject := range test.reject {
				if strings.Contains(got, reject) {
					t.Fatalf("progress invented %q\n%s", reject, got)
				}
			}
		})
	}
}

func TestRunContinuingUnknownProgressNeverRestartsElapsedTime(t *testing.T) {
	tests := []struct {
		name     string
		scenario Scenario
		progress Progress
	}{
		{name: "unknown work", scenario: UnknownCloudflareVerification, progress: Progress{Kind: UnknownProgress, OperationID: 41}},
		{name: "mixed unmeasured step", scenario: MultiStepChangeSet, progress: Progress{Kind: MixedStepProgress, OperationID: 42, CurrentStep: 2, TotalSteps: 7}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := runContinuingProgressTranscript(t, test.scenario, test.progress)
			firstSecond := strings.LastIndex(got, "00:01")
			if firstSecond < 0 || !strings.Contains(got[firstSecond:], "00:02") {
				t.Fatalf("elapsed time did not continue after a refresh\n%s", got)
			}
			if strings.Contains(got[firstSecond:], "00:00") {
				t.Fatalf("elapsed time restarted after a refresh\n%s", got)
			}
		})
	}
}

func runContinuingProgressTranscript(t *testing.T, scenario Scenario, progress Progress) string {
	t.Helper()
	updates := make(chan PresentationUpdate)
	capabilities := capableTerminal(80, 24)
	var output bytes.Buffer
	input, writeInput := io.Pipe()
	defer input.Close()
	go func() {
		time.Sleep(20 * time.Millisecond)
		updates <- PresentationUpdate{Progress: progress}
		time.Sleep(1100 * time.Millisecond)
		updates <- PresentationUpdate{Progress: progress}
		time.Sleep(1100 * time.Millisecond)
		close(updates)
		_, _ = writeInput.Write([]byte("\x03\r"))
		_ = writeInput.Close()
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	if err := Run(ctx, Session{Input: input, Output: &output, Capabilities: &capabilities, Scenario: scenario, Updates: updates}); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func runProgressTranscript(t *testing.T, scenario Scenario, progress Progress, wait time.Duration) string {
	return runProgressTranscriptAtWidth(t, scenario, progress, wait, 80)
}

func runProgressTranscriptAtWidth(t *testing.T, scenario Scenario, progress Progress, wait time.Duration, width int) string {
	t.Helper()
	updates := make(chan PresentationUpdate, 1)
	updates <- PresentationUpdate{Progress: progress}
	close(updates)
	height := 24
	if width == 120 {
		height = 36
	}
	capabilities := capableTerminal(width, height)
	var output bytes.Buffer
	input, writeInput := io.Pipe()
	defer input.Close()
	go func() {
		time.Sleep(50*time.Millisecond + wait)
		_, _ = writeInput.Write([]byte("\x03\r"))
		_ = writeInput.Close()
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	if err := Run(ctx, Session{Input: input, Output: &output, Capabilities: &capabilities, Scenario: scenario, Updates: updates}); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func TestRunTypedProgressNeverConflictsWithLargeDetails(t *testing.T) {
	tests := []struct {
		name     string
		scenario Scenario
		progress Progress
		want     string
		reject   []string
	}{
		{name: "measured", scenario: MeasuredDownload, progress: Progress{Kind: MeasuredProgress, Completed: 37, Total: 101}, want: "37 of 101 units", reject: []string{"42%", "26.4 MiB"}},
		{name: "mixed", scenario: MultiStepChangeSet, progress: Progress{Kind: MixedStepProgress, CurrentStep: 4, TotalSteps: 7, Completed: 31, Total: 80}, want: "Current step 4 of 7", reject: []string{"Step 3", "54%"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := runProgressTranscriptAtWidth(t, test.scenario, test.progress, 0, 120)
			if !strings.Contains(got, test.want) {
				t.Fatalf("large progress missing %q", test.want)
			}
			for _, reject := range test.reject {
				if strings.Contains(got, reject) {
					t.Fatalf("large details retained stale progress %q\n%s", reject, got)
				}
			}
		})
	}
}
