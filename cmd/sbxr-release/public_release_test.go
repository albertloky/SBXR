package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type taggedPublicSource struct {
	latestSource
	tag string
}

func (source *taggedPublicSource) CheckRelease(_ context.Context, tag string) (softwarelifecycle.LatestRelease, softwarelifecycle.LatestReleaseOutcome) {
	source.tag = tag
	return source.latest, source.outcome
}

func TestPublicTaggedVerificationRequiresTheRequestedIdentity(t *testing.T) {
	for _, outcome := range []softwarelifecycle.LatestReleaseOutcome{softwarelifecycle.LatestReleaseAccepted, softwarelifecycle.LatestReleaseRefused, softwarelifecycle.LatestReleaseUnavailable} {
		source := &taggedPublicSource{latestSource: latestSource{latest: softwarelifecycle.LatestRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v2.0.1", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}, Sequence: 18}, outcome: outcome}}
		var output bytes.Buffer
		if err := writePublicReleaseVerification(t.Context(), &output, source, "v2.0.1"); err != nil || source.tag != "v2.0.1" {
			t.Fatalf("tagged verification = %s, %v, tag %q", output.String(), err, source.tag)
		}
		if outcome == softwarelifecycle.LatestReleaseAccepted {
			output.Reset()
			if err := writePublicReleaseVerification(t.Context(), &output, source, "v2.0.2"); err == nil || output.Len() != 0 {
				t.Fatalf("accepted mismatched tag: %s, %v", output.String(), err)
			}
		}
	}
}
