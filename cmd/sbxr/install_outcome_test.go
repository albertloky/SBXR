package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/installation"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/creack/pty"
)

func TestInstallationSSHFailureCauseSelectsOnlyLegalCorrectionActions(t *testing.T) {
	for _, test := range []struct {
		cause networkpolicy.SSHPreservationFailureCause
		hide  bool
	}{
		{cause: networkpolicy.SSHLaunchIdentityInvalid, hide: true},
		{cause: networkpolicy.SSHOriginalSessionLost, hide: true},
		{cause: networkpolicy.SSHObservationUnavailable},
	} {
		presented := ownerCorrection(&installation.Correction{Problem: "SSH proof failed", Found: "redacted cause", Required: "fresh proof", WhyStopped: "Installation stopped", OwnerSteps: []string{"Follow the exact safe guidance."}, Evidence: "NETWORK-INSTALLATION-SSH-UNPROVED", SSHFailureCause: test.cause})
		if presented.Correction == nil || presented.Correction.HideCheckAgain != test.hide {
			t.Fatalf("SSH Correction action mapping for %q was wrong", test.cause)
		}
	}
}

func newTestInstallOutcome(t *testing.T) *installOutcome {
	t.Helper()
	module, err := newInstallationModuleWith(
		func() (versionReport, error) {
			return versionReport{Build: softwarelifecycle.EmbeddedBuildIdentity{Tag: "v1.0.7"}, Architecture: softwarelifecycle.AMD64}, nil
		},
		func() networkpolicy.InstallationPreflightResult {
			return networkpolicy.InstallationPreflightResult{ActiveSSHPort: 22, UsablePublicIPv4: []string{"8.8.8.8"}}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return &installOutcome{module: module}
}

func TestInstallationBackDiscardsUnfinishedInput(t *testing.T) {
	var outcome ownerconsole.OutcomeModule = newTestInstallOutcome(t)
	if review := outcome.Review(t.Context()); review.Editing == nil || review.Editing.Field.Identity != "owner-email" || review.Editing.Help.Purpose == "" || review.Editing.Help.URL != "https://eff-certbot.readthedocs.io/en/stable/using.html#certbot-command-line-options" {
		t.Fatalf("Owner email Help did not cross the Installation presentation boundary: %+v", review)
	}
	if review := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "owner-email", Text: "owner@example.net"}); review.Editing == nil || review.Editing.Field.Identity != "subscriber-agreement" || review.Editing.Help.Recovery == "" {
		t.Fatalf("edited Installation input = %+v", review)
	}
	if review := outcome.Back(t.Context()); review.Editing == nil || review.Editing.Field.Identity != "owner-email" || review.Editing.Field.Value != "" {
		t.Fatalf("Back retained unfinished Installation input: %+v", review)
	}
	if review := outcome.Review(t.Context()); review.Editing == nil || review.Editing.Field.Identity != "owner-email" || review.Editing.Field.Value != "" {
		t.Fatalf("Installation Review restored unfinished input: %+v", review)
	}
}

func TestProductionInstallationRunAdvancesOwnerEmailToAgreementAtExactSizes(t *testing.T) {
	for _, size := range []struct{ width, height uint16 }{{80, 24}, {120, 36}} {
		master, slave, err := pty.Open()
		if err != nil {
			t.Fatal(err)
		}
		if err := pty.Setsize(slave, &pty.Winsize{Cols: size.width, Rows: size.height}); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		copied := make(chan struct{})
		go func() { _, _ = io.Copy(&output, master); close(copied) }()
		capabilities := ownerconsole.Capabilities{InteractiveInput: true, InteractiveOutput: true, AlternateScreen: true, CursorAddressing: true, ReadableEncoding: true, KeyboardInput: true, Width: int(size.width), Height: int(size.height)}
		outcome := newTestInstallOutcome(t)
		done := make(chan error, 1)
		go func() {
			done <- ownerconsole.Run(t.Context(), ownerconsole.Session{Input: slave, Output: slave, Environment: []string{"TERM=xterm-256color", "COLORTERM=truecolor", "LANG=C.UTF-8"}, Capabilities: &capabilities, Scenario: ownerconsole.InstallationReview, Outcome: outcome})
		}()
		time.Sleep(500 * time.Millisecond)
		for _, input := range []string{"owner@example.net", "\r", "", "\t", "\x1b[B", "\r", "", "\x03\r"} {
			time.Sleep(80 * time.Millisecond)
			_, _ = master.Write([]byte(input))
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Owner Console Run did not exit")
		}
		_ = slave.Close()
		_ = master.Close()
		select {
		case <-copied:
		case <-time.After(time.Second):
			t.Fatal("Owner Console transcript did not close")
		}
		got := output.String()
		for _, want := range []string{"ACME subscriber agreement", "No Plan, Change Set, rollback material, or sudo"} {
			if !strings.Contains(got, want) {
				t.Fatalf("%dx%d Owner email transition omitted %q\n%s", size.width, size.height, want, got)
			}
		}
		helpStart := strings.LastIndex(got, "ACME SUBSCRIBER AGREEMENT HELP")
		if helpStart < 0 {
			t.Fatalf("%dx%d ACME agreement Help was unavailable\n%s", size.width, size.height, got)
		}
		help := got[helpStart:]
		for _, want := range []string{"Purpose: Record acceptance", "Instructions: Enter accepted", "format: accepted", "Common mistakes: Do not continue before review.", "Recovery: Review the agreement", "https://letsencrypt.org/repository/"} {
			if !strings.Contains(help, want) {
				t.Fatalf("%dx%d ACME agreement Help omitted %q\n%s", size.width, size.height, want, got)
			}
		}
		if strings.Contains(got, "OWNER-CONSOLE-TYPED-OUTCOME-REFUSED") || strings.Contains(help, "EXAMPLE ONLY") {
			t.Fatalf("%dx%d Owner email did not advance to the ACME agreement\n%s", size.width, size.height, got)
		}
	}
}

func TestLaterProcessStartsWithFreshInstallationInput(t *testing.T) {
	abandoned := newTestInstallOutcome(t)
	if review := abandoned.Edit(t.Context(), ownerconsole.EditingInput{Field: "owner-email", Text: "owner@example.net"}); review.Editing == nil || review.Editing.Field.Identity != "subscriber-agreement" {
		t.Fatalf("abandoned process input = %+v", review)
	}

	later := newTestInstallOutcome(t)
	if review := later.Review(t.Context()); review.Editing == nil || review.Editing.Field.Identity != "owner-email" || review.Editing.Field.Value != "" {
		t.Fatalf("later process restored abandoned input: %+v", review)
	}
}

func TestProductionInstallationJourneyReturnsInvalidAgreementToItsExactField(t *testing.T) {
	outcome := newTestInstallOutcome(t)
	if review := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "owner-email", Text: "owner@example.net"}); review.Editing == nil {
		t.Fatalf("owner-email did not continue field-local editing: %+v", review)
	}
	review := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "subscriber-agreement", Text: "agree"})
	if review.Editing == nil || review.Editing.Field.Identity != "subscriber-agreement" || review.Editing.Field.Value != "agree" {
		t.Fatalf("invalid agreement did not return to its field: %+v", review)
	}
	review = outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "subscriber-agreement", Text: "accepted"})
	if review.Editing == nil || review.Editing.Field.Identity != "reality-target" {
		t.Fatalf("accepted agreement did not advance to REALITY target: %+v", review)
	}
}

func TestProductionInstallationJourneyHasNoCloudflareInput(t *testing.T) {
	want := []string{"owner-email", "subscriber-agreement", "primary-address", "reality-port", "subscription-port", "reality-target"}
	if len(installFields) != len(want) {
		t.Fatalf("installation fields = %+v", installFields)
	}
	for index, field := range installFields {
		if field.Identity != want[index] {
			t.Fatalf("installation field %d = %q, want %q", index, field.Identity, want[index])
		}
	}
}
