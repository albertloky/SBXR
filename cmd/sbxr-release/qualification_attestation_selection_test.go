package main

import (
	"strings"
	"testing"
)

func attestationPublicationFixture() (publishStableReleaseAction, stablePublicationObservation) {
	identity := decisionReleaseIdentity{
		Commit: strings.Repeat("a", 40), ReleaseIndexSHA256: strings.Repeat("b", 64),
		Repository: "albertloky/SBXR", Tag: "v3.1.93",
	}
	action := publishStableReleaseAction{
		Assets: []decisionAsset{
			{Name: "install.sh", SHA256: strings.Repeat("c", 64), Size: 10},
			{Name: "release-index.json", SHA256: identity.ReleaseIndexSHA256, Size: 20},
			{Name: "sbxr-linux-amd64.tar.gz", SHA256: strings.Repeat("d", 64), Size: 30},
			{Name: "sbxr-linux-arm64.tar.gz", SHA256: strings.Repeat("e", 64), Size: 40},
		},
		Body: "exact qualified acceptance record", Commit: identity.Commit, Immutable: true,
		Latest: true, ReleaseID: 700, ReleaseIdentity: identity, Sequence: 171, Tag: identity.Tag,
	}
	assets := make([]observedDraftAsset, len(action.Assets))
	for i, asset := range action.Assets {
		assets[i] = observedDraftAsset{ID: int64(800 + i), Name: asset.Name, SHA256: asset.SHA256, Size: asset.Size}
	}
	latestID, sequence, publicIdentity := action.ReleaseID, action.Sequence, action.ReleaseIdentity
	observation := stablePublicationObservation{
		Assets: assets, Attestation: &stableReleaseAttestation{Commit: action.Commit, Count: 2, Initiator: "github", PredicateType: "release"},
		Body: action.Body, Commit: action.Commit, Downloads: append([]decisionAsset(nil), action.Assets...),
		Immutable: true, LatestInstallSHA256: action.Assets[0].SHA256, LatestReleaseID: &latestID,
		PublicVerification: &publicLatestVerification{Outcome: "accepted", ReleaseIdentity: &publicIdentity, Sequence: &sequence},
		ReleaseID:          action.ReleaseID, ReleaseIdentity: action.ReleaseIdentity, Sequence: action.Sequence, Tag: action.Tag,
	}
	return action, observation
}

func TestStablePublicationAttestationSelection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*stablePublicationObservation)
		want   bool
	}{
		{"two native attestations with exact public verification", func(*stablePublicationObservation) {}, true},
		{"single native attestation remains supported", func(o *stablePublicationObservation) { o.Attestation.Count = 1 }, true},
		{"non-saturated native attestation page", func(o *stablePublicationObservation) { o.Attestation.Count = 99 }, true},
		{"missing attestation", func(o *stablePublicationObservation) { o.Attestation = nil }, false},
		{"zero native attestations", func(o *stablePublicationObservation) { o.Attestation.Count = 0 }, false},
		{"negative native count", func(o *stablePublicationObservation) { o.Attestation.Count = -1 }, false},
		{"saturated native page", func(o *stablePublicationObservation) { o.Attestation.Count = 100 }, false},
		{"oversized native count", func(o *stablePublicationObservation) { o.Attestation.Count = 101 }, false},
		{"non-GitHub initiator", func(o *stablePublicationObservation) { o.Attestation.Initiator = "unknown" }, false},
		{"mixed or missing initiator", func(o *stablePublicationObservation) { o.Attestation.Initiator = "" }, false},
		{"other source commit", func(o *stablePublicationObservation) { o.Attestation.Commit = strings.Repeat("f", 40) }, false},
		{"other predicate", func(o *stablePublicationObservation) { o.Attestation.PredicateType = "https://slsa.dev/provenance/v1" }, false},
		{"missing public verification", func(o *stablePublicationObservation) { o.PublicVerification = nil }, false},
		{"refused public verification", func(o *stablePublicationObservation) { o.PublicVerification.Outcome = "refused" }, false},
		{"unavailable public verification", func(o *stablePublicationObservation) { o.PublicVerification.Outcome = "unavailable" }, false},
		{"missing verified identity", func(o *stablePublicationObservation) { o.PublicVerification.ReleaseIdentity = nil }, false},
		{"other verified commit", func(o *stablePublicationObservation) {
			o.PublicVerification.ReleaseIdentity.Commit = strings.Repeat("f", 40)
		}, false},
		{"other verified tag", func(o *stablePublicationObservation) { o.PublicVerification.ReleaseIdentity.Tag = "v3.1.91" }, false},
		{"other verified repository", func(o *stablePublicationObservation) {
			o.PublicVerification.ReleaseIdentity.Repository = "someone/SBXR"
		}, false},
		{"other verified index", func(o *stablePublicationObservation) {
			o.PublicVerification.ReleaseIdentity.ReleaseIndexSHA256 = strings.Repeat("f", 64)
		}, false},
		{"missing verified sequence", func(o *stablePublicationObservation) { o.PublicVerification.Sequence = nil }, false},
		{"stale verified sequence", func(o *stablePublicationObservation) { *o.PublicVerification.Sequence-- }, false},
		{"missing asset", func(o *stablePublicationObservation) { o.Assets = o.Assets[:3] }, false},
		{"duplicate asset ID", func(o *stablePublicationObservation) { o.Assets[1].ID = o.Assets[0].ID }, false},
		{"changed asset bytes", func(o *stablePublicationObservation) { o.Assets[2].SHA256 = strings.Repeat("f", 64) }, false},
		{"changed downloaded bytes", func(o *stablePublicationObservation) { o.Downloads[3].SHA256 = strings.Repeat("f", 64) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			action, observation := attestationPublicationFixture()
			if !validStablePublicationTarget(observation, action) {
				t.Fatal("fixture does not bind the complete publication target")
			}
			tc.change(&observation)
			if got := validStablePublicationObservation(observation, action, &action.ReleaseID, true); got != tc.want {
				t.Fatalf("public observation accepted = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStablePropagationAttestationSelection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*stablePublicationObservation)
		want   bool
	}{
		{"two native attestations while public verification unavailable", func(*stablePublicationObservation) {}, true},
		{"missing native attestation still propagating", func(o *stablePublicationObservation) { o.Attestation = nil }, true},
		{"empty native response still propagating", func(o *stablePublicationObservation) { o.Attestation.Count, o.Attestation.Initiator = 0, "" }, true},
		{"single native attestation still propagating", func(o *stablePublicationObservation) { o.Attestation.Count = 1 }, true},
		{"non-saturated native page still propagating", func(o *stablePublicationObservation) { o.Attestation.Count = 99 }, true},
		{"negative native count", func(o *stablePublicationObservation) { o.Attestation.Count = -1 }, false},
		{"saturated native page", func(o *stablePublicationObservation) { o.Attestation.Count = 100 }, false},
		{"oversized native count", func(o *stablePublicationObservation) { o.Attestation.Count = 101 }, false},
		{"zero count with inconsistent initiator", func(o *stablePublicationObservation) { o.Attestation.Count = 0 }, false},
		{"non-GitHub initiator", func(o *stablePublicationObservation) { o.Attestation.Initiator = "unknown" }, false},
		{"mixed or missing initiator", func(o *stablePublicationObservation) { o.Attestation.Initiator = "" }, false},
		{"other source commit", func(o *stablePublicationObservation) { o.Attestation.Commit = strings.Repeat("f", 40) }, false},
		{"other predicate", func(o *stablePublicationObservation) { o.Attestation.PredicateType = "other" }, false},
		{"missing public verification", func(o *stablePublicationObservation) { o.PublicVerification = nil }, false},
		{"refused public verification", func(o *stablePublicationObservation) { o.PublicVerification.Outcome = "refused" }, false},
		{"unavailable with unexpected identity", func(o *stablePublicationObservation) {
			identity := o.ReleaseIdentity
			o.PublicVerification.ReleaseIdentity = &identity
		}, false},
		{"unavailable with unexpected sequence", func(o *stablePublicationObservation) {
			sequence := o.Sequence
			o.PublicVerification.Sequence = &sequence
		}, false},
		{"exact accepted public verification", func(o *stablePublicationObservation) {
			identity, sequence := o.ReleaseIdentity, o.Sequence
			o.PublicVerification = &publicLatestVerification{Outcome: "accepted", ReleaseIdentity: &identity, Sequence: &sequence}
		}, true},
		{"stale accepted public verification can keep waiting", func(o *stablePublicationObservation) {
			identity, sequence := o.ReleaseIdentity, o.Sequence-1
			identity.Tag = "v3.1.90"
			o.PublicVerification = &publicLatestVerification{Outcome: "accepted", ReleaseIdentity: &identity, Sequence: &sequence}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			action, observation := attestationPublicationFixture()
			prior := stablePublicationObservation{}
			observation.PublicVerification = &publicLatestVerification{Outcome: "unavailable"}
			tc.change(&observation)
			if got := validStablePropagationObservation(observation, prior, action); got != tc.want {
				t.Fatalf("propagation observation permitted = %v, want %v", got, tc.want)
			}
		})
	}
}
