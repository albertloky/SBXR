package main

import (
	"reflect"
	"testing"
)

func TestRetiredBuild238IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.164", Sequence: 238, ReleaseID: 456901275,
		Commit: "5aa6c80c47c45087b844d3a48ba3f64ec31eda2d", RunID: "45407968687", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "8f0b962bb8304f5b3e5bc24fbb93d2cf83380f9c989ef760623a9f1479c42bf4",
		QualificationManifestSHA256: "10fd48951e970dc88bdf72416359836ca51496b64e47878337fcd61abded480d",
		Assets: []observedAsset{
			{ID: 787586011, Name: "install.sh", Size: 77206, Digest: "ea61f1f7243c85ab6a7ebedd7632f922abcfea69d5d41f7021c6c17e506c6f16"},
			{ID: 787586013, Name: "release-index.json", Size: 609, Digest: "8f0b962bb8304f5b3e5bc24fbb93d2cf83380f9c989ef760623a9f1479c42bf4"},
			{ID: 787586012, Name: "sbxr-linux-amd64.tar.gz", Size: 6259836, Digest: "68506b8dc3669933bef91ac85c4fbef721474d53b8030bbde0ad0a38baa14664"},
			{ID: 787586020, Name: "sbxr-linux-arm64.tar.gz", Size: 5333800, Digest: "6b93280cb98d502c1b02f5b2770d19a087eae3d3cfbd230375092335a9b5fff0"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 36 || !reflect.DeepEqual(policy[35], expected) {
		t.Fatal("exact build 238 reservation is missing")
	}
	if documentSHA256(mustJSON(policy[:35])) != "0fc7028f587043fc53b9bc4066ec90a5005ecd3f46a5de51b6347c1668294efd" {
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
		t.Fatal("build 238 must be preserved and unavailable to the current candidate")
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.165", 239
	facts.ReservedIdentities = policy
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh build 239 refused: %v", err)
	}
	for _, signingState := range []string{"unsigned", "unknown"} {
		facts.ReservedIdentities = approvedCandidateReservations()
		facts.ReservedIdentities[35].SigningState = signingState
		if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err == nil {
			t.Fatalf("build 238 signing authority accepted the label %q", signingState)
		}
	}
}
