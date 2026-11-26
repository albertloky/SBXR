package main

import (
	"reflect"
	"testing"
)

func TestRetiredBuild239IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.165", Sequence: 239, ReleaseID: 457594332,
		Commit: "87d70a276ad234344b054b6cc712eb67672c7c21", RunID: "45530167834", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "223562ff78a2e12bbfb87513f3a9c1074c4cf5c92b0681d41359456a26b34f50",
		QualificationManifestSHA256: "ced229372a484edf648e5b9da47ee686a7ddb7dd29ebaa95fffd6371ee0c47c0",
		Assets: []observedAsset{
			{ID: 789808644, Name: "install.sh", Size: 77206, Digest: "6c2bd94ad8d065965115b279edcf0f5fa719230c9ef89d448a7eb8e45c2e78aa"},
			{ID: 789808649, Name: "release-index.json", Size: 609, Digest: "223562ff78a2e12bbfb87513f3a9c1074c4cf5c92b0681d41359456a26b34f50"},
			{ID: 789808647, Name: "sbxr-linux-amd64.tar.gz", Size: 6259673, Digest: "fe98f8527a2023da97399706921b1ed00fb68f3a9ea70e651610689e252594bb"},
			{ID: 789808639, Name: "sbxr-linux-arm64.tar.gz", Size: 5333882, Digest: "8f85290581c4caf8eba1c2a7f013b1ee3f393b744b2a3071341144ebac04299e"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 38 || !reflect.DeepEqual(policy[36], expected) {
		t.Fatal("exact build 239 reservation is missing")
	}
	if documentSHA256(mustJSON(policy[:36])) != "aaf72cdd321741b1e4f8b920c99b63ac130da8e418e4045e0f0236f0d4693bd8" {
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
		t.Fatal("build 239 must be preserved and unavailable to the current candidate")
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.167", 241
	facts.ReservedIdentities = policy
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh build 241 refused: %v", err)
	}
	for _, signingState := range []string{"unsigned", "unknown"} {
		facts.ReservedIdentities = approvedCandidateReservations()
		facts.ReservedIdentities[36].SigningState = signingState
		if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err == nil {
			t.Fatalf("build 239 signing authority accepted the label %q", signingState)
		}
	}
}
