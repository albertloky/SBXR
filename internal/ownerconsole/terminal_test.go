package ownerconsole

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

func TestRunThroughPseudoTerminalRestoresTerminal(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	if err := pty.Setsize(master, &pty.Winsize{Cols: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	environment := []string{"TERM=unknown-sbxr-terminal", "LANG=C.UTF-8"}
	capabilities := DetectTerminal(slave, slave, environment)
	if !capabilities.InteractiveInput || !capabilities.InteractiveOutput || !capabilities.DrawingModeProbeRequired || !capabilities.ReadableEncoding || !capabilities.KeyboardInput || capabilities.Width != 80 || capabilities.Height != 24 {
		t.Fatalf("detected capabilities = %#v", capabilities)
	}
	ascii := DetectTerminal(slave, slave, []string{"TERM=another-unknown-terminal", "LANG=C"})
	if !ascii.ReadableEncoding || ascii.Unicode {
		t.Fatalf("ASCII capabilities = %#v", ascii)
	}
	before := terminalState(t, slave)

	transcript := make(chan []byte, 1)
	go func() {
		var output bytes.Buffer
		buffer := make([]byte, 4096)
		responded := false
		for {
			n, err := master.Read(buffer)
			if n > 0 {
				_, _ = output.Write(buffer[:n])
				if !responded && bytes.Contains(output.Bytes(), []byte("\x1b[?2004$p")) {
					responded = true
					_, _ = master.Write([]byte("\x1b[?1;2$y\x1b[?6;1$y\x1b[?25;2$y\x1b[?1000;1$y\x1b[?1002;2$y\x1b[?1003;2$y\x1b[?1006;1$y\x1b[?1049;2$y\x1b[?2004;1$y\x1b[1;1R"))
				}
			}
			if err != nil {
				break
			}
		}
		transcript <- output.Bytes()
	}()
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), Session{
			Input:        slave,
			Output:       slave,
			Environment:  environment,
			Capabilities: &capabilities,
			Scenario:     AuthenticatedOverview,
		})
	}()
	time.Sleep(100 * time.Millisecond)
	if _, err := master.Write([]byte("\x03\r")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Owner Console did not exit")
	}
	after := terminalState(t, slave)
	if after != before {
		t.Fatal("terminal input settings were not restored")
	}
	if err := slave.Close(); err != nil {
		t.Fatal(err)
	}
	got := string(<-transcript)
	for _, sequence := range []string{"\x1b[?1000$p", "\x1b[?2004$p", "\x1b[?1000l", "\x1b[?2004l", "\x1b[?1049h", "\x1b[?1049l", "\x1b[?25h"} {
		if !bytes.Contains([]byte(got), []byte(sequence)) {
			t.Fatalf("pseudo-terminal transcript missing %q", sequence)
		}
	}
	exit := strings.LastIndex(got, "\x1b[?1049l")
	for _, restored := range []string{"\x1b[?6h", "\x1b[?1000h", "\x1b[?1006h", "\x1b[?2004h", "\x1b[?25l"} {
		if strings.LastIndex(got, restored) < exit {
			t.Fatalf("mode %q was not restored after alternate-screen exit", restored)
		}
	}
}

func TestRunRefusesUnconfirmedDrawingModesBeforeAFrame(t *testing.T) {
	owned := "\x1b[?6;2$y\x1b[?25;2$y\x1b[?1000;2$y\x1b[?1002;2$y\x1b[?1003;2$y\x1b[?1006;2$y\x1b[?2004;2$y"
	tests := []struct {
		name, response, failure, correction string
	}{
		{name: "alternate screen", response: "\x1b[?1;2$y\x1b[?1049;0$y\x1b[1;1R" + owned, failure: "alternate-screen support is unavailable", correction: "use a terminal that supports an alternate screen"},
		{name: "cursor addressing", response: "\x1b[?1;2$y\x1b[?1049;2$y" + owned, failure: "full-screen cursor addressing and drawing is unavailable", correction: "use a terminal with full-screen cursor support"},
		{name: "keyboard input", response: "\x1b[?1;0$y\x1b[?1049;2$y\x1b[1;1R" + owned, failure: "standard keyboard input is unavailable", correction: "use a terminal with standard keyboard input"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testDrawingModeRefusal(t, test.response, test.failure, test.correction)
		})
	}
}

func testDrawingModeRefusal(t *testing.T, response, failure, correction string) {
	t.Helper()
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	if err := pty.Setsize(master, &pty.Winsize{Cols: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	capabilities := DetectTerminal(slave, slave, []string{"TERM=unknown-sbxr-terminal", "LANG=C.UTF-8"})
	transcript := make(chan string, 1)
	go func() {
		var output bytes.Buffer
		buffer := make([]byte, 4096)
		responded := false
		for {
			n, err := master.Read(buffer)
			if n > 0 {
				_, _ = output.Write(buffer[:n])
				if !responded && bytes.Contains(output.Bytes(), []byte("\x1b[?2004$p")) {
					responded = true
					_, _ = master.Write([]byte(response))
				}
			}
			if err != nil {
				transcript <- output.String()
				return
			}
		}
	}()
	err = Run(context.Background(), Session{Input: slave, Output: slave, Environment: []string{"TERM=unknown-sbxr-terminal", "LANG=C.UTF-8"}, Capabilities: &capabilities})
	if err == nil || err.Error() != failure {
		t.Fatalf("Run() error = %v", err)
	}
	if err := slave.Close(); err != nil {
		t.Fatal(err)
	}
	got := <-transcript
	if strings.Contains(got, "PRIVACY BEFORE ACCESS") {
		t.Fatal("Owner Console drew a frame before terminal admission")
	}
	if !strings.Contains(got, "SBXR cannot start: "+failure) || !strings.Contains(got, "Correction: "+correction) {
		t.Fatalf("refusal missing exact failed capability: %q", got)
	}
}

func terminalState(t *testing.T, terminal *os.File) string {
	t.Helper()
	command := exec.Command("stty", "-g")
	command.Stdin = terminal
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(output)
}

func TestRunCannotPromiseRestorationAfterForcedTermination(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	if err := pty.Setsize(master, &pty.Winsize{Cols: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestOwnerConsoleForcedTerminationHelper$")
	command.Env = append(os.Environ(), "SBXR_FORCED_TERMINATION_HELPER=1", "TERM=unknown-sbxr-terminal", "LANG=C.UTF-8")
	command.Stdin, command.Stdout, command.Stderr = slave, slave, slave
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := slave.Close(); err != nil {
		t.Fatal(err)
	}
	transcript := make(chan string, 1)
	entered := make(chan struct{})
	go func() {
		var output bytes.Buffer
		buffer := make([]byte, 4096)
		responded, signaled := false, false
		for {
			n, err := master.Read(buffer)
			if n > 0 {
				_, _ = output.Write(buffer[:n])
				if !responded && bytes.Contains(output.Bytes(), []byte("\x1b[?2004$p")) {
					responded = true
					_, _ = master.Write([]byte("\x1b[?1;2$y\x1b[?6;2$y\x1b[?25;1$y\x1b[?1000;2$y\x1b[?1002;2$y\x1b[?1003;2$y\x1b[?1006;2$y\x1b[?1049;2$y\x1b[?2004;2$y\x1b[1;1R"))
				}
				if !signaled && bytes.Contains(output.Bytes(), []byte("\x1b[?1049h")) {
					signaled = true
					close(entered)
				}
			}
			if err != nil {
				transcript <- output.String()
				return
			}
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		_ = command.Process.Kill()
		t.Fatal("Owner Console did not enter the alternate screen")
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	got := <-transcript
	if strings.LastIndex(got, "\x1b[?1049h") < strings.LastIndex(got, "\x1b[?1049l") {
		t.Fatal("forced termination test unexpectedly observed manageable restoration")
	}
}

func TestOwnerConsoleForcedTerminationHelper(t *testing.T) {
	if os.Getenv("SBXR_FORCED_TERMINATION_HELPER") != "1" {
		return
	}
	environment := []string{"TERM=unknown-sbxr-terminal", "LANG=C.UTF-8"}
	capabilities := DetectTerminal(os.Stdin, os.Stdout, environment)
	_ = Run(context.Background(), Session{Input: os.Stdin, Output: os.Stdout, Environment: environment, Capabilities: &capabilities, Scenario: AuthenticatedOverview})
}

func TestForcedTerminationDocumentationNamesExactResetCommand(t *testing.T) {
	documentation, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(documentation), "After a forced termination that prevented restoration, run the terminal's standard recovery command:\n\n```sh\nreset\n```") {
		t.Fatal("forced-termination documentation must name the exact reset command")
	}
}

func TestRunPausesAndResumesAfterResize(t *testing.T) {
	for _, test := range []struct {
		name, title string
		scenario    Scenario
	}{
		{name: "input", scenario: CorrectionFlow, title: "CORRECTION FLOW"},
		{name: "Plan", scenario: InstallationReview, title: "REVIEW INSTALLATION PLAN"},
		{name: "operation", scenario: MultiStepChangeSet, title: "UPDATE TO v1.1.0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := runResizePseudoTerminal(t, test.scenario, true)
			if strings.Count(got, test.title) < 2 {
				t.Fatalf("resize did not resume the same state\n%s", got)
			}
			for _, want := range []string{"TERMINAL IS TOO SMALL", "Required   80 columns x 24 rows", "Current    72 columns x 20 rows"} {
				if !strings.Contains(got, want) {
					t.Fatalf("resize pause missing %q", want)
				}
			}
		})
	}
}

func TestRunAllowsSafeExitWhileUndersized(t *testing.T) {
	got := runResizePseudoTerminal(t, CorrectionFlow, false)
	if !strings.Contains(got, "TERMINAL IS TOO SMALL") || !strings.Contains(got, "Exit SBXR?") {
		t.Fatal("undersized exit did not remain visible and explicit")
	}
}

func TestRunResizeRemasksInitialAndManagedCloudflareTokens(t *testing.T) {
	const secret = "cfat_RESIZE-SECRET-MARKER-012345678901234567890"
	help := EditingHelp{
		Purpose: "Authorize only SBXR's Cloudflare work.", Instructions: []string{"Open Manage Account > Account API Tokens; Create Token."},
		AcceptedFormat: "cfat_ plus 35 to 75 letters, digits, _ or -.", CommonMistakes: []string{"No Global API Key or broad authority."},
		Recovery: "Create the exact scoped Account API Token.", URL: "https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/", Sensitivity: InfrastructureSecret,
	}
	initial := ChangeReview{Editing: &EditingPresentation{Title: "Clean VPS installation", Field: EditingField{Identity: "cloudflare-token", Label: "Cloudflare Account API Token", Required: true}, Help: help}}
	credential := CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: completeCloudflareCredential()}
	for _, test := range []struct {
		name    string
		session Session
		setup   []string
	}{
		{name: "initial Installation", session: Session{Scenario: InstallationReview, Outcome: &outcomeStub{reviews: []ChangeReview{initial}}}, setup: []string{secret, "\x12"}},
		{name: "managed replacement", session: Session{Scenario: CloudflareWalkthrough, Cloudflare: &cloudflareStub{view: credential}}, setup: []string{"\x1b[B\r", "\r", secret, "\x12"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := runRevealedResizePseudoTerminal(t, test.session, test.setup)
			if strings.Count(got, "cfat_RESIZE-SECRET-MARKER") != 1 || !strings.Contains(got, "TOKEN REVEALED") || !strings.Contains(got, "TERMINAL IS TOO SMALL") || !strings.Contains(got, "Ctrl+R Reveal token") {
				t.Fatalf("resize did not remask the controlled Reveal\n%s", got)
			}
		})
	}
}

func runRevealedResizePseudoTerminal(t *testing.T, session Session, setup []string) string {
	t.Helper()
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	if err := pty.Setsize(master, &pty.Winsize{Cols: 120, Rows: 36}); err != nil {
		t.Fatal(err)
	}
	capabilities := capableTerminal(120, 36)
	transcript := make(chan string, 1)
	go func() {
		var output bytes.Buffer
		_, _ = io.Copy(&output, master)
		transcript <- output.String()
	}()
	session.Input, session.Output, session.Capabilities = slave, slave, &capabilities
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), session) }()
	time.Sleep(100 * time.Millisecond)
	for _, keys := range setup {
		if _, err := master.Write([]byte(keys)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(60 * time.Millisecond)
	}
	if err := pty.Setsize(master, &pty.Winsize{Cols: 72, Rows: 20}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := master.Write([]byte("\x03\x1b")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := pty.Setsize(master, &pty.Winsize{Cols: 120, Rows: 36}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := master.Write([]byte("\x03\r")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Owner Console did not exit after token resize")
	}
	_ = slave.Close()
	return <-transcript
}

func TestRunPreservesInteractionStateThroughResizeAndRefresh(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	if err := pty.Setsize(master, &pty.Winsize{Cols: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	capabilities := capableTerminal(80, 24)
	updates := make(chan PresentationUpdate)
	transcript := make(chan string, 1)
	go func() {
		var output bytes.Buffer
		_, _ = io.Copy(&output, master)
		transcript <- output.String()
	}()
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), Session{Input: slave, Output: slave, Capabilities: &capabilities, Scenario: CorrectionFlow, Updates: updates})
	}()
	time.Sleep(100 * time.Millisecond)
	if _, err := master.Write([]byte("\x1b[200~Q\nCOMPLETE REMOVAL\x1b[201~")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := master.Write([]byte("\t\x1b[B\x1b[Z")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	updates <- PresentationUpdate{}
	if err := pty.Setsize(master, &pty.Winsize{Cols: 72, Rows: 20}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := pty.Setsize(master, &pty.Winsize{Cols: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := master.Write([]byte("\t\r")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := master.Write([]byte("\x03\r")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Owner Console did not exit after resize-resume")
	}
	close(updates)
	if err := slave.Close(); err != nil {
		t.Fatal(err)
	}
	got := <-transcript
	for _, want := range []string{"TERMINAL IS TOO SMALL", "Current    72 columns x 20 rows", `"Q\nCOMPLETE REMOVAL"`, "refreshed", "SERVICES AND DIAGNOSTICS", "No mutation has begun."} {
		if !strings.Contains(got, want) {
			t.Fatalf("resized interaction lost %q\n%s", want, got)
		}
	}
}

func runResizePseudoTerminal(t *testing.T, scenario Scenario, resume bool) string {
	t.Helper()
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	if err := pty.Setsize(master, &pty.Winsize{Cols: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	capabilities := capableTerminal(80, 24)
	transcript := make(chan []byte, 1)
	go func() {
		var output bytes.Buffer
		_, _ = io.Copy(&output, master)
		transcript <- output.Bytes()
	}()
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), Session{Input: slave, Output: slave, Capabilities: &capabilities, Scenario: scenario})
	}()
	time.Sleep(100 * time.Millisecond)
	if err := pty.Setsize(master, &pty.Winsize{Cols: 72, Rows: 20}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if resume {
		if err := pty.Setsize(master, &pty.Winsize{Cols: 80, Rows: 24}); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := master.Write([]byte("\x03\r")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Owner Console did not exit after resize")
	}
	if err := slave.Close(); err != nil {
		t.Fatal(err)
	}
	return string(<-transcript)
}
