package ownerconsole

import (
	"context"
	"strings"
	"testing"
)

func TestAccessProviderRunsOnlyAfterTheRootConsolePrivacyChoice(t *testing.T) {
	calls := 0
	provider := func(context.Context) AccessPresentation {
		calls++
		return clientAccessPresentation()
	}
	before := runTranscriptSteps(t, Session{AccessProvider: provider}, 80, 24, "\x1b[B\r", "\x03\r")
	if calls != 0 || strings.Contains(before, "CLIENT-REALITY-MARKER") {
		t.Fatalf("Access values were requested after the Owner continued without them\n%s", before)
	}
	after := runTranscriptSteps(t, Session{AccessProvider: provider}, 80, 24, "\r", "", "\x1b[B\r", "", "\x03\r")
	if calls != 1 || !strings.Contains(after, "CLIENT-REALITY-MARKER") {
		t.Fatalf("privacy-approved Access values were unavailable\n%s", after)
	}
}
