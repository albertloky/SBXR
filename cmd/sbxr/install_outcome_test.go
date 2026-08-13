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
