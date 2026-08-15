package main

import (
	"testing"

	"github.com/albertloky/SBXR/internal/installation"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
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
	if review := outcome.Review(t.Context()); review.Editing == nil || review.Editing.Field.Identity != "domain" || review.Editing.Help.Purpose == "" || review.Editing.Help.URL != "https://developers.cloudflare.com/fundamentals/manage-domains/add-site/" {
		t.Fatalf("Domain Help did not cross the Installation presentation boundary: %+v", review)
	}
	if review := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "domain", Text: "example.com"}); review.Editing == nil || review.Editing.Field.Identity != "owner-email" || review.Editing.Help.Recovery == "" || review.Editing.Help.Sensitivity != ownerconsole.PersonalInformation || review.Editing.Help.URL != "https://eff-certbot.readthedocs.io/en/stable/using.html#certbot-command-line-options" {
		t.Fatalf("edited Installation input = %+v", review)
	}
	if review := outcome.Back(t.Context()); review.Editing == nil || review.Editing.Field.Identity != "domain" || review.Editing.Field.Value != "" {
		t.Fatalf("Back retained unfinished Installation input: %+v", review)
	}
	if review := outcome.Review(t.Context()); review.Editing == nil || review.Editing.Field.Identity != "domain" || review.Editing.Field.Value != "" {
		t.Fatalf("Installation Review restored unfinished input: %+v", review)
	}
}

func TestLaterProcessStartsWithFreshInstallationInput(t *testing.T) {
	abandoned := newTestInstallOutcome(t)
	if review := abandoned.Edit(t.Context(), ownerconsole.EditingInput{Field: "domain", Text: "example.com"}); review.Editing == nil || review.Editing.Field.Identity != "owner-email" {
		t.Fatalf("abandoned process input = %+v", review)
	}

	later := newTestInstallOutcome(t)
	if review := later.Review(t.Context()); review.Editing == nil || review.Editing.Field.Identity != "domain" || review.Editing.Field.Value != "" {
		t.Fatalf("later process restored abandoned input: %+v", review)
	}
}

func TestProductionInstallationJourneyReturnsAnInvalidPortToItsExactField(t *testing.T) {
	outcome := newTestInstallOutcome(t)
	steps := []ownerconsole.EditingInput{
		{Field: "domain", Text: "example.com"},
		{Field: "owner-email", Text: "owner@example.com"},
		{Field: "public-ipv4", Text: "8.8.8.8"},
	}
	for _, step := range steps {
		if review := outcome.Edit(t.Context(), step); review.Editing == nil {
			t.Fatalf("%s did not continue field-local editing: %+v", step.Field, review)
		}
	}
	review := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "reality-port", Text: "invalid"})
	if review.Editing == nil || review.Editing.Field.Identity != "reality-port" || review.Editing.Field.Value != "invalid" {
		t.Fatalf("invalid REALITY port did not return to its field: %+v", review)
	}
	review = outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "reality-port", Text: "1443"})
	if review.Editing == nil || review.Editing.Field.Identity != "hysteria2-port" || review.Editing.Field.Value != "443" {
		t.Fatalf("corrected REALITY port lost earlier input or the next default: %+v", review)
	}
}

func TestProductionInstallationJourneyCarriesCloudflareOwnedTokenHelp(t *testing.T) {
	outcome := newTestInstallOutcome(t)
	for _, input := range []ownerconsole.EditingInput{
		{Field: "domain", Text: "example.com"},
		{Field: "owner-email", Text: "owner@example.com"},
		{Field: "public-ipv4", Text: "8.8.8.8"},
		{Field: "reality-port", Text: "443"},
		{Field: "hysteria2-port", Text: "443"},
		{Field: "tuic-port", Text: "8443"},
		{Field: "anytls-port", Text: "9443"},
		{Field: "subscription-port", Text: "10443"},
		{Field: "cloudflare-account", Text: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{Field: "cloudflare-zone", Text: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	} {
		if review := outcome.Edit(t.Context(), input); review.Editing == nil {
			t.Fatalf("%s did not continue field-local editing: %+v", input.Field, review)
		}
	}
	review := outcome.Review(t.Context())
	if review.Editing == nil || review.Editing.Field.Identity != "cloudflare-token" || review.Editing.Help.Sensitivity != ownerconsole.InfrastructureSecret || review.Editing.Help.Example != "" || review.Editing.Help.URL != "https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/" {
		t.Fatalf("Cloudflare token Help did not cross the production presentation boundary: %+v", review)
	}
}
