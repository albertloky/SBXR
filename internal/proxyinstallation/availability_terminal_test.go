package proxyinstallation_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/proxyinstallation"
	"github.com/albertloky/SBXR/internal/proxyinstallation/adapter/terminal"
)

func TestAvailabilityMenuUsesLocalEvidence(t *testing.T) {
	for _, tc := range []struct{ name, proxy, subscription string }{
		{"running", "proved working", "proved working"},
		{"disabled", "proved working", "proved stopped"},
		{"stopped", "cannot be verified", "proved stopped"},
		{"unknown", "cannot be verified", "cannot be verified"},
		{"recovery-disabled", "cannot be verified", "proved stopped"},
		{"recovery-enabled", "cannot be verified", "cannot be verified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := proxyinstallation.AvailabilityMenuFixture(t, tc.name)
			input := "0\n"
			if strings.HasPrefix(tc.name, "recovery-") {
				input = "1\nn\n0\n"
			}
			var output bytes.Buffer
			if code := terminal.Run(t.Context(), nil, strings.NewReader(input), &output, &output, m, nil); code != 0 {
				t.Fatalf("exit %d: %s", code, output.String())
			}
			for _, want := range []string{
				"Local proxy runtime: " + tc.proxy,
				"Local subscription serving: " + tc.subscription,
				"Outside connectivity: not established by these local checks (including Karing).",
			} {
				minimum := 1
				if strings.HasPrefix(tc.name, "recovery-") {
					minimum = 3
				} // Both frames and the reviewed plan.
				if strings.Count(output.String(), want) < minimum {
					t.Errorf("missing %q: %s", want, output.String())
				}
			}
			for _, forbidden := range []string{"Proxy traffic availability:", "Subscription serving availability:"} {
				if strings.Contains(output.String(), forbidden) {
					t.Errorf("unsupported availability claim %q", forbidden)
				}
			}
		})
	}
}
