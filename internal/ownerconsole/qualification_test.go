package ownerconsole_test

import (
	"testing"

	"github.com/albertloky/SBXR/internal/ownerconsole"
)

func TestControlledStagedOnboardingQualifiesTerminalAndFixedGuideText(t *testing.T) {
	if err := ownerconsole.QualifyControlledStagedOnboardingTerminal(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := ownerconsole.QualifyControlledStagedOnboardingGuideText(t.Context()); err != nil {
		t.Fatal(err)
	}
}
