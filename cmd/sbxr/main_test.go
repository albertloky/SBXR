package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/ownerconsole"
)

func TestDefaultRunRefusesRedirectedTerminal(t *testing.T) {
	input, writeInput, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writeInput.Close()
	readOutput, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readOutput.Close()
	if err := runOwnerConsole(context.Background(), input, output, []string{"TERM=xterm-256color", "LANG=C.UTF-8"}); err == nil {
		t.Fatal("redirected default Run was admitted")
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	refusal, err := io.ReadAll(readOutput)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(refusal); !strings.Contains(got, "interactive input") || strings.Contains(got, "CLIENT-ACCESS-MARKER") {
		t.Fatalf("refusal = %q", got)
	}
}

func TestSystemAuthenticationReportsEveryOutcome(t *testing.T) {
	if got := systemAuthenticationResult(nil, nil); got != ownerconsole.AuthenticationSucceeded {
		t.Fatalf("successful authentication = %v", got)
	}
	denied := exec.Command("/usr/bin/false").Run()
	if got := systemAuthenticationResult(denied, nil); got != ownerconsole.AuthenticationDenied {
		t.Fatalf("denied authentication = %v", got)
	}
	cancelled := exec.Command("/bin/sh", "-c", "kill -INT $$").Run()
	if got := systemAuthenticationResult(cancelled, nil); got != ownerconsole.AuthenticationCancelled {
		t.Fatalf("cancelled authentication = %v", got)
	}
	if got := systemAuthenticationResult(errors.New("command unavailable"), nil); got != ownerconsole.AuthenticationFailed {
		t.Fatalf("failed authentication = %v", got)
	}
	if got := systemAuthenticationResult(context.DeadlineExceeded, context.DeadlineExceeded); got != ownerconsole.AuthenticationExpired {
		t.Fatalf("expired authentication = %v", got)
	}
}
