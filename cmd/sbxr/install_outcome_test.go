package main

import (
	"testing"

	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

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
	if review := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "domain", Text: "example.com"}); review.Editing == nil || review.Editing.Field.Identity != "owner-email" {
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
