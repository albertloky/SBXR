package main

import (
	"testing"

	"github.com/albertloky/SBXR/internal/ownerconsole"
)

func TestInstallationBackDiscardsUnfinishedInput(t *testing.T) {
	var outcome ownerconsole.OutcomeModule = newInstallOutcome()
	if review := outcome.Edit(t.Context(), ownerconsole.EditingInput{Field: "release-tag", Text: "v1.0.0"}); review.Editing == nil || review.Editing.Field.Identity != "domain" {
		t.Fatalf("edited Installation input = %+v", review)
	}
	if review := outcome.Back(t.Context()); review.Editing == nil || review.Editing.Field.Identity != "release-tag" || review.Editing.Field.Value != "" {
		t.Fatalf("Back retained unfinished Installation input: %+v", review)
	}
	if review := outcome.Review(t.Context()); review.Editing == nil || review.Editing.Field.Identity != "release-tag" || review.Editing.Field.Value != "" {
		t.Fatalf("Installation Review restored unfinished input: %+v", review)
	}
}

func TestLaterProcessStartsWithFreshInstallationInput(t *testing.T) {
	abandoned := newInstallOutcome()
	if review := abandoned.Edit(t.Context(), ownerconsole.EditingInput{Field: "release-tag", Text: "v1.0.0"}); review.Editing == nil || review.Editing.Field.Identity != "domain" {
		t.Fatalf("abandoned process input = %+v", review)
	}

	later := newInstallOutcome()
	if review := later.Review(t.Context()); review.Editing == nil || review.Editing.Field.Identity != "release-tag" || review.Editing.Field.Value != "" {
		t.Fatalf("later process restored abandoned input: %+v", review)
	}
}

func TestProductionInstallationJourneyReturnsAnInvalidPortToItsExactField(t *testing.T) {
	outcome := newInstallOutcome()
	steps := []ownerconsole.EditingInput{
		{Field: "release-tag", Text: "v1.0.0"},
		{Field: "domain", Text: "example.com"},
		{Field: "owner-email", Text: "owner@example.com"},
		{Field: "public-ipv4", Text: "192.0.2.10"},
		{Field: "primary-address", Text: "192.0.2.10"},
		{Field: "ssh-port", Text: "22"},
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
