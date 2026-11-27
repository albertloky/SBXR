package main

import (
	"reflect"
	"testing"
)

func TestRetiredBuild245IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.171", Sequence: 245, ReleaseID: 459496903,
		Commit: "c5a02688806307c8c9438efe48b99a571959ff82", RunID: "45826862648", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "192c817f25815067a2d9ba61416b48ae6aceaf2efb8627e78daebeca1e903095",
		QualificationManifestSHA256: "df4b49f8bb95f52ca2941a835c10860230b3d6b351a47c27c2c94cbedae678c5",
		Assets: []observedAsset{
			{ID: 796181498, Name: "install.sh", Size: 77206, Digest: "f804333d175ae8542a0c386462361686586ea9e36c1bbb09224b161320fc5d5b"},
			{ID: 796181497, Name: "release-index.json", Size: 609, Digest: "192c817f25815067a2d9ba61416b48ae6aceaf2efb8627e78daebeca1e903095"},
			{ID: 796181494, Name: "sbxr-linux-amd64.tar.gz", Size: 6259762, Digest: "c3b74d83d45da5103896b367e500b53a47dc0690977c12a964bd27aa422396f2"},
			{ID: 796181492, Name: "sbxr-linux-arm64.tar.gz", Size: 5333742, Digest: "5961e58ba25feceb70432bf5a0b8ad4ba60fd105f987a97cf06510b8305faad7"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 43 || !reflect.DeepEqual(policy[42], expected) {
		t.Fatal("exact build 245 reservation is missing")
	}
	if documentSHA256(mustJSON(policy[:42])) != "d99d842a029bf4be975a5ebeeb050a5347c9da4d4c0eace783817d879b890a52" {
		t.Fatal("an earlier reservation changed")
	}
	if !reservedCandidate(expected.Tag, 0, 0) ||
		!reservedCandidate("", expected.Sequence, 0) ||
		!reservedCandidate("", 0, expected.ReleaseID) {
		t.Fatal("retired build can be reused by tag, sequence or draft ID")
	}
	observed := reservationFixture()
	if !checkCandidateReservations(observed, nil) ||
		checkCandidateReservations(observed, []string{expected.Tag}) {
		t.Fatal("build 245 must be preserved and unavailable to the current candidate")
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.172", 246
	facts.ReservedIdentities = policy
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh build 246 refused: %v", err)
	}
	for _, signingState := range []string{"unsigned", "unknown"} {
		facts.ReservedIdentities = approvedCandidateReservations()
		facts.ReservedIdentities[42].SigningState = signingState
		if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err == nil {
			t.Fatalf("build 245 signing authority accepted the label %q", signingState)
		}
	}
}
