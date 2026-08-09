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

func TestRunPausesAndResumesAfterResize(t *testing.T) {
	got := runResizePseudoTerminal(t, true)
	if strings.Count(got, "CORRECTION FLOW") < 2 {
		t.Fatalf("resize did not resume the same state\n%s", got)
	}
	for _, want := range []string{"TERMINAL IS TOO SMALL", "Required   80 columns x 24 rows", "Current    72 columns x 20 rows"} {
		if !strings.Contains(got, want) {
			t.Fatalf("resize pause missing %q", want)
		}
	}
}

func TestRunAllowsSafeExitWhileUndersized(t *testing.T) {
	got := runResizePseudoTerminal(t, false)
	if !strings.Contains(got, "TERMINAL IS TOO SMALL") || !strings.Contains(got, "Exit SBXR?") {
		t.Fatal("undersized exit did not remain visible and explicit")
	}
}

func runResizePseudoTerminal(t *testing.T, resume bool) string {
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
		done <- Run(context.Background(), Session{Input: slave, Output: slave, Capabilities: &capabilities, Scenario: CorrectionFlow})
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
