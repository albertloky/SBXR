package main

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"syscall"
	"time"

	"github.com/albertloky/SBXR/internal/ownerconsole"
)

type systemAuthenticator struct{}

func (systemAuthenticator) Authenticate(ctx context.Context, input io.Reader, output io.Writer) ownerconsole.AuthenticationResult {
	authenticationContext, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(authenticationContext, "/usr/bin/sudo", "-v")
	command.Stdin, command.Stdout, command.Stderr = input, output, output
	return systemAuthenticationResult(command.Run(), authenticationContext.Err())
}

func systemAuthenticationResult(err, contextErr error) ownerconsole.AuthenticationResult {
	if err == nil {
		return ownerconsole.AuthenticationSucceeded
	}
	if errors.Is(contextErr, context.DeadlineExceeded) {
		return ownerconsole.AuthenticationExpired
	}
	if errors.Is(contextErr, context.Canceled) {
		return ownerconsole.AuthenticationCancelled
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return ownerconsole.AuthenticationFailed
	}
	if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return ownerconsole.AuthenticationCancelled
	}
	if exit.ExitCode() == 1 {
		return ownerconsole.AuthenticationDenied
	}
	return ownerconsole.AuthenticationFailed
}
