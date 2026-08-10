package ownerconsole

import (
	"context"
	"strings"
	"testing"
)

func TestAccessProviderRunsOnlyAfterSuccessfulAuthentication(t *testing.T) {
	calls := 0
	provider := func(context.Context) AccessPresentation {
		calls++
		return clientAccessPresentation()
	}
	before := runTranscriptSteps(t, Session{Authenticator: &authenticationStub{result: AuthenticationDenied}, AuthenticationPolicy: AuthenticateForAccess, AccessProvider: provider}, 80, 24, "\r", "", "\x03\r")
	if calls != 0 || strings.Contains(before, "CLIENT-REALITY-MARKER") {
		t.Fatalf("Access values were requested before successful authentication\n%s", before)
	}
	after := runTranscriptSteps(t, Session{Authenticator: &authenticationStub{result: AuthenticationSucceeded}, AuthenticationPolicy: AuthenticateForAccess, AccessProvider: provider}, 80, 24, "\r", "", "\x1b[B\r", "", "\x03\r")
	if calls != 1 || !strings.Contains(after, "CLIENT-REALITY-MARKER") {
		t.Fatalf("authenticated Access values were unavailable\n%s", after)
	}
}
