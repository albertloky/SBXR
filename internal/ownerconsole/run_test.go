package ownerconsole

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/creack/pty"
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

type clipboardStub struct {
	result CopyResult
	mu     sync.Mutex
	values []string
}

func (stub *clipboardStub) Copy(_ context.Context, value string) CopyResult {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.values = append(stub.values, value)
	return stub.result
}

func (stub *clipboardStub) copied() []string {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return append([]string(nil), stub.values...)
}

func clientAccessPresentation() AccessPresentation {
	return AccessPresentation{
		Profiles: [6]AccessProfile{
			{ShareURI: "vless://CLIENT-REALITY-MARKER@example.test:443"},
			{ShareURI: "vless://CLIENT-XHTTP-MARKER@xhttp.example.test:443"},
			{ShareURI: "vless://CLIENT-WEBSOCKET-MARKER@ws.example.test:443"},
			{ShareURI: "hysteria2://CLIENT-HYSTERIA2-MARKER@example.test:443"},
			{ShareURI: "tuic://CLIENT-TUIC-MARKER@example.test:8443"},
			{ShareURI: "anytls://CLIENT-ANYTLS-MARKER@example.test:9443"},
		},
		Links: [6]AccessLink{
			{URL: "https://203.0.113.10:10443/s/CLIENT-SUBSCRIPTION-MARKER", ProfileCount: 6},
			{URL: "https://203.0.113.10:10443/s/CLIENT-V2RAYN-MARKER/v2rayn", ProfileCount: 6},
			{URL: "https://203.0.113.10:10443/s/CLIENT-SHADOWROCKET-MARKER/shadowrocket", ProfileCount: 6, OwnerAcceptancePending: []AccessProfileID{RealityVisionProfile, XHTTPProfile, WebSocketProfile, Hysteria2Profile, TUICProfile, AnyTLSProfile}},
			{URL: "https://203.0.113.10:10443/s/CLIENT-KARING-MARKER/karing", ProfileCount: 5, Omissions: []AccessOmission{{Profile: XHTTPProfile, Status: NotOffered}}},
			{URL: "https://203.0.113.10:10443/s/CLIENT-MIHOMO-MARKER/mihomo", ProfileCount: 6},
			{URL: "https://203.0.113.10:10443/s/CLIENT-SINGBOX-MARKER/sing-box", ProfileCount: 5, Omissions: []AccessOmission{{Profile: XHTTPProfile, Status: NotOffered}}},
		},
	}
}

func TestRunRevealsOnlyAuthenticatedDedicatedAccessValues(t *testing.T) {
	access := clientAccessPresentation()
	beforeAccess := runTranscriptSteps(t, Session{Access: access}, 80, 24, "\x1b[B", "\r", "\x03\r")
	if strings.Contains(beforeAccess, "CLIENT-REALITY-MARKER") || strings.Contains(beforeAccess, "CLIENT-SUBSCRIPTION-MARKER") {
		t.Fatal("a Client Access Value appeared in the privacy choice or ordinary Overview")
	}

	steps := []string{"\r", "", "\x1b[B", "\r"}
	for range 11 {
		steps = append(steps, "\x1b[B")
	}
	steps = append(steps, "\x03\r")
	got := runTranscriptSteps(t, Session{Authenticator: &authenticationStub{result: AuthenticationSucceeded}, Access: access}, 80, 24, steps...)
	for _, marker := range []string{"REALITY-MARKER", "XHTTP-MARKER", "WEBSOCKET-MARKER", "HYSTERIA2-MARKER", "TUIC-MARKER", "ANYTLS-MARKER", "SUBSCRIPTION-MARKER", "V2RAYN-MARKER", "SHADOWROCKET-MARKER", "KARING-MARKER", "MIHOMO-MARKER", "SINGBOX-MARKER"} {
		if !strings.Contains(got, marker) {
			t.Fatalf("authenticated Access omitted %q\n%s", marker, got)
		}
	}
	for _, fact := range []string{"6 Connection Profiles", "5 Connection Profiles", "XHTTP - Not offered", "andidate - Owner Acceptance Pending", "Pending: REALITY Vision", "Click or press Enter to copy", "Clipboard history may retain copied values."} {
		if !strings.Contains(got, fact) {
			t.Fatalf("authenticated Access omitted %q\n%s", fact, got)
		}
	}
}

func TestRunRejectsInfrastructureSecretMarkerAtTheAccessBoundary(t *testing.T) {
	access := clientAccessPresentation()
	access.Links[3].URL = "https://INFRASTRUCTURE-SECRET-MARKER-COMPLETE-TOKEN@example.test/karing"
	clipboard := &clipboardStub{result: CopyConfirmed}
	got := runTranscriptSteps(t, Session{Authenticator: &authenticationStub{result: AuthenticationSucceeded}, Clipboard: clipboard, Access: access}, 80, 24, "\r", "", "\x1b[B", "\r", "\r", "\x03\r")
	if strings.Contains(got, "INFRASTRUCTURE-SECRET-MARKER") || len(clipboard.copied()) != 0 || !strings.Contains(got, "No value is available") {
		t.Fatalf("Access accepted or copied an Infrastructure Secret marker\n%s", got)
	}
}

func TestRunCopiesEveryApprovedAccessValueWithExactFeedback(t *testing.T) {
	access := clientAccessPresentation()
	clipboard := &clipboardStub{result: CopyConfirmed}
	steps := []string{"\r", "", "\x1b[B", "\r"}
	for index := range 12 {
		steps = append(steps, "\r", "")
		if index != 11 {
			steps = append(steps, "\x1b[B")
		}
	}
	steps = append(steps, "\x03\r")
	got := runTranscriptSteps(t, Session{Authenticator: &authenticationStub{result: AuthenticationSucceeded}, Clipboard: clipboard, Access: access}, 80, 24, steps...)
	want := make([]string, 0, 12)
	for index, profile := range access.Profiles {
		want = append(want, profile.ShareURI)
		name := AccessProfileID(index + 1).String()
		if !strings.Contains(got, "opied "+name+".") {
			t.Fatalf("copy feedback did not name %q\n%s", name, got)
		}
	}
	for index, link := range access.Links {
		want = append(want, link.URL)
		if !strings.Contains(got, "opied "+accessLinkNames[index]+".") {
			t.Fatalf("copy feedback did not name %q\n%s", accessLinkNames[index], got)
		}
	}
	if !strings.Contains(got, "opied subscription URL.") || !slices.Equal(clipboard.copied(), want) {
		t.Fatalf("copy requests = %#v, want %#v\n%s", clipboard.copied(), want, got)
	}
}

func TestRunReportsUnconfirmedAndFailedCopyWithoutLosingManualSelection(t *testing.T) {
	for _, test := range []struct {
		name, want string
		result     CopyResult
	}{
		{name: "unconfirmed", result: CopyRequested, want: "opy request sent. If it is not in your clipboard, select"},
		{name: "failed", result: CopyFailed, want: "opy failed. Select the text manually."},
	} {
		t.Run(test.name, func(t *testing.T) {
			access := clientAccessPresentation()
			clipboard := &clipboardStub{result: test.result}
			got := runTranscriptSteps(t, Session{Authenticator: &authenticationStub{result: AuthenticationSucceeded}, Clipboard: clipboard, Access: access}, 80, 24, "\r", "", "\x1b[B", "\r", "\r", "", "\x03\r")
			if !strings.Contains(got, test.want) || !strings.Contains(got, "CLIENT-REALITY-MARKER") || len(clipboard.copied()) != 1 {
				t.Fatalf("%s copy lost its exact fallback or selectable value\n%s", test.name, got)
			}
		})
	}
}

func TestRunMouseClickAndEnterUseTheSameExplicitCopyAction(t *testing.T) {
	access := clientAccessPresentation()
	clipboard := &clipboardStub{result: CopyConfirmed}
	got := runTranscriptSteps(t, Session{Authenticator: &authenticationStub{result: AuthenticationSucceeded}, Clipboard: clipboard, Access: access}, 80, 24, "\r", "", "\x1b[B", "\r", "", "\x1b[<0;30;8M", "", "\x03\r")
	if !slices.Equal(clipboard.copied(), []string{access.Profiles[0].ShareURI}) || !strings.Contains(got, "opied REALITY Vision.") {
		t.Fatalf("mouse click did not use the selected value's explicit copy action\n%s", got)
	}
}

func TestRunShowsQRFromTheSameValueOnlyWhenItFits(t *testing.T) {
	access := clientAccessPresentation()
	minimum := runTranscriptSteps(t, Session{Authenticator: &authenticationStub{result: AuthenticationSucceeded}, Access: access}, 80, 24, "\r", "", "\x1b[B", "\r", "", "\x03\r")
	if !strings.Contains(minimum, "QR omitted at this size; exact text remains available.") || strings.Contains(minimum, "QR - same value as text") {
		t.Fatalf("minimum Access did not omit only the QR\n%s", minimum)
	}
	large := runTranscriptSteps(t, Session{Authenticator: &authenticationStub{result: AuthenticationSucceeded}, Access: access}, 120, 36, "\r", "", "\x1b[B", "\r", "", "\x03\r")
	if !strings.Contains(large, "QR - same value as text") || !strings.ContainsAny(large, "▀▄█") || !strings.Contains(large, "CLIENT-REALITY-MARKER") {
		t.Fatalf("large Access did not render a QR beside its exact text\n%s", large)
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

type authenticationStub struct {
	result   AuthenticationResult
	calls    int
	prompted chan struct{}
	done     chan struct{}
	once     sync.Once
}

func (stub *authenticationStub) Authenticate(_ context.Context, input io.Reader, output io.Writer) AuthenticationResult {
	stub.calls++
	_, _ = io.WriteString(output, "Normal system sudo authentication\n")
	if stub.prompted != nil {
		close(stub.prompted)
	}
	_, _ = io.CopyN(io.Discard, input, 1)
	if stub.done != nil {
		stub.once.Do(func() { close(stub.done) })
	}
	return stub.result
}

func TestRunMakesThePerLaunchPrivacyAndAuthenticationDecisionBeforeAccess(t *testing.T) {
	t.Run("limited choice", func(t *testing.T) {
		authentication := &authenticationStub{result: AuthenticationSucceeded}
		got := runTranscriptSteps(t, Session{Authenticator: authentication, Access: clientAccessPresentation()}, 80, 24, "\x1b[B", "\r", "\x1b[B", "\r", "\x03\r")
		if authentication.calls != 0 || !strings.Contains(got, "LIMITED DASHBOARD") || !strings.Contains(got, "Owner selected the limited read-only dashboard.") || !strings.Contains(got, "SERVICES AND DIAGNOSTICS") || strings.Contains(got, "CLIENT-REALITY-MARKER") {
			t.Fatalf("limited choice escaped its read-only boundary or lost its explanation\n%s", got)
		}
	})

	t.Run("exit choice", func(t *testing.T) {
		authentication := &authenticationStub{result: AuthenticationSucceeded}
		got := runTranscriptSteps(t, Session{Authenticator: authentication}, 80, 24, "\x1b[B\x1b[B\r")
		if authentication.calls != 0 || strings.Contains(got, "Normal system sudo authentication") {
			t.Fatalf("exit choice requested authentication\n%s", got)
		}
	})

	t.Run("successful system authentication", func(t *testing.T) {
		authentication := &authenticationStub{result: AuthenticationSucceeded}
		got := runAuthenticationTranscript(t, authentication, "OVERVIEW")
		if authentication.calls != 1 || !strings.Contains(got, "OVERVIEW") {
			t.Fatalf("successful system authentication did not enter the authenticated overview\n%s", got)
		}
	})

	t.Run("fresh installation remains unprivileged", func(t *testing.T) {
		authentication := &authenticationStub{result: AuthenticationSucceeded}
		got := runTranscriptSteps(t, Session{Authenticator: authentication, AuthenticationPolicy: DeferAuthenticationUntilApply}, 80, 24, "\r", "\x03\r")
		if authentication.calls != 0 || !strings.Contains(got, "REVIEW INSTALLATION PLAN") || strings.Contains(got, "Normal system sudo authentication") {
			t.Fatalf("fresh installation requested authentication before Apply\n%s", got)
		}
	})

	for _, activation := range []string{"\r", " "} {
		t.Run("deferred limited action "+fmt.Sprintf("%q", activation), func(t *testing.T) {
			authentication := &authenticationStub{result: AuthenticationSucceeded}
			got := runTranscriptSteps(t, Session{Authenticator: authentication, AuthenticationPolicy: DeferAuthenticationUntilApply}, 80, 24, "\x1b[B", "\r", activation, "\x03\r")
			if authentication.calls != 0 || strings.Contains(got, "Authenticate again") || !strings.Contains(got, "SERVICES AND DIAGNOSTICS") {
				t.Fatalf("deferred limited mode exposed authentication before Apply\n%s", got)
			}
		})
	}

	t.Run("unknown authentication policy fails closed", func(t *testing.T) {
		authentication := &authenticationStub{result: AuthenticationSucceeded}
		got := runTranscriptSteps(t, Session{Authenticator: authentication, AuthenticationPolicy: AuthenticationPolicy(255), Access: clientAccessPresentation()}, 80, 24, "\r", "\r", "\x03\r")
		if authentication.calls != 0 || strings.Contains(got, "Authenticate again") || !strings.Contains(got, "Authentication policy is unavailable.") || !strings.Contains(got, "SERVICES AND DIAGNOSTICS") || strings.Contains(got, "CLIENT-REALITY-MARKER") {
			t.Fatalf("unknown authentication policy did not fail closed\n%s", got)
		}
	})

	for _, test := range []struct {
		name, explanation string
		result            AuthenticationResult
	}{
		{name: "denied", result: AuthenticationDenied, explanation: "System authentication was denied."},
		{name: "cancelled", result: AuthenticationCancelled, explanation: "System authentication was cancelled."},
		{name: "failed", result: AuthenticationFailed, explanation: "System authentication failed."},
		{name: "expired", result: AuthenticationExpired, explanation: "System authentication expired."},
	} {
		t.Run(test.name, func(t *testing.T) {
			authentication := &authenticationStub{result: test.result}
			got := runAuthenticationTranscript(t, authentication, "LIMITED DASHBOARD")
			if authentication.calls != 1 || !strings.Contains(got, "LIMITED DASHBOARD") || !strings.Contains(got, test.explanation) || !strings.Contains(got, "Client Access Values HIDDEN") || !strings.Contains(got, "Privileged actions UNAVAILABLE") {
				t.Fatalf("%s authentication did not enter explained limited mode\n%s", test.name, got)
			}
		})
	}
}

func runAuthenticationTranscript(t *testing.T, authentication *authenticationStub, wanted string) string {
	t.Helper()
	got := runPseudoTerminalTranscriptSteps(t, Session{Authenticator: authentication}, 80, 24, "\r", "", "\x03\r")
	if !strings.Contains(got, wanted) {
		t.Fatalf("authentication transcript did not reach %q\n%s", wanted, got)
	}
	return got
}

func waitForTranscript(t *testing.T, output *synchronizedBuffer, wanted string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(output.String(), wanted) {
		if time.Now().After(deadline) {
			t.Fatalf("transcript did not reach %q\n%s", wanted, output.String())
		}
		time.Sleep(5 * time.Millisecond)
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
	want := "284f66d1c80b33a9c4b416403ac36852af1f2d584e9370e7fceb4a31296e0454"
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
		{name: "arrow and Enter", start: AuthenticatedOverview, keys: []string{"q\x1b[200~Q\nCOMPLETE REMOVAL\x1b[201~", "\x1b[B", "\r"}, wantView: "CLIENT ACCESS VALUES"},
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
	if session.Authenticator != nil {
		return runPseudoTerminalTranscriptSteps(t, session, width, height, steps...)
	}
	capabilities := capableTerminal(width, height)
	if session.Capabilities == nil {
		session.Capabilities = &capabilities
	}
	var output synchronizedBuffer
	session.Output = &output
	input, writeInput := io.Pipe()
	session.Input = input
	defer input.Close()
	go func() {
		for _, step := range steps {
			if step == "" {
				time.Sleep(60 * time.Millisecond)
				continue
			}
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

func runPseudoTerminalTranscriptSteps(t *testing.T, session Session, width, height int, steps ...string) string {
	t.Helper()
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	if err := pty.Setsize(slave, &pty.Winsize{Cols: uint16(width), Rows: uint16(height)}); err != nil {
		t.Fatal(err)
	}
	capabilities := capableTerminal(width, height)
	var output synchronizedBuffer
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&output, master)
		close(copyDone)
	}()
	session.Input, session.Output, session.Capabilities = slave, slave, &capabilities
	if session.Environment == nil {
		session.Environment = []string{"TERM=xterm-256color", "COLORTERM=truecolor", "LANG=C.UTF-8"}
	}
	authentication, _ := session.Authenticator.(*authenticationStub)
	if authentication != nil {
		authentication.prompted = make(chan struct{})
		authentication.done = make(chan struct{})
	}
	done := make(chan error, 1)
	go func() { done <- Run(t.Context(), session) }()
	authenticationWaited := false
	for _, step := range steps {
		if step == "" {
			if authentication != nil && !authenticationWaited {
				select {
				case <-authentication.prompted:
				case <-time.After(time.Second):
					t.Fatal("authentication prompt did not appear")
				}
				_, _ = master.Write([]byte("\n"))
				select {
				case <-authentication.done:
				case <-time.After(time.Second):
					t.Fatal("authentication did not finish")
				}
				wanted := "LIMITED DASHBOARD"
				if authentication.result == AuthenticationSucceeded {
					wanted = "OVERVIEW"
				}
				if session.Outcome == nil {
					waitForTranscript(t, &output, wanted)
				} else {
					time.Sleep(100 * time.Millisecond)
				}
				authenticationWaited = true
			}
			time.Sleep(30 * time.Millisecond)
			continue
		}
		time.Sleep(30 * time.Millisecond)
		_, _ = master.Write([]byte(step))
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pseudo-terminal Run did not exit")
	}
	_ = slave.Close()
	_ = master.Close()
	select {
	case <-copyDone:
	case <-time.After(time.Second):
	}
	return output.String()
}

type synchronizedBuffer struct {
	mu sync.RWMutex
	bytes.Buffer
}

func (buffer *synchronizedBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.Buffer.Write(value)
}

func (buffer *synchronizedBuffer) ReadFrom(reader io.Reader) (int64, error) {
	return io.Copy(synchronizedBufferWriter{buffer}, reader)
}

type synchronizedBufferWriter struct{ buffer *synchronizedBuffer }

func (writer synchronizedBufferWriter) Write(value []byte) (int, error) {
	return writer.buffer.Write(value)
}

func (buffer *synchronizedBuffer) String() string {
	buffer.mu.RLock()
	defer buffer.mu.RUnlock()
	return buffer.Buffer.String()
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
	if !strings.Contains(got, `"safe`) || !strings.Contains(got, `q`) || !strings.Contains(got, `ctrl+c>`) || !strings.Contains(got, `<enter>"`) || !strings.Contains(got, "[terminal controls neutralized]") {
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
