package main

import (
	"reflect"
	"testing"
)

func TestRetiredBuild235IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.161", Sequence: 235, ReleaseID: 454604534,
		Commit: "1fc9e3ab05c910ad7f0614ac21212e24f50d30ac", RunID: "45042678522", SigningState: "unknown",
		ReleaseIndexSHA256: "a4a54acdd441f560e132b39b90a56fe6dbed7dfa707f082507874b54e5ec1d57",
		Assets: []observedAsset{
			{ID: 779786473, Name: "install.sh", Size: 77206, Digest: "73d272f5e57aed66961a2e8fc1b80de8201a8a88b29aa49f4f0d75d71f16fd76"},
			{ID: 779786472, Name: "release-index.json", Size: 609, Digest: "a4a54acdd441f560e132b39b90a56fe6dbed7dfa707f082507874b54e5ec1d57"},
			{ID: 779786482, Name: "sbxr-linux-amd64.tar.gz", Size: 6254637, Digest: "31f0b7c58f32bfa653020d6c5436ce875f9365fa2773cbe075c7d3f542241d02"},
			{ID: 779786457, Name: "sbxr-linux-arm64.tar.gz", Size: 5340529, Digest: "60291f7d2bd25d0b1d4906bdce314fd8d84a9fcf97977df55af9e5412e568867"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 34 || !reflect.DeepEqual(policy[32], expected) {
		t.Fatal("exact build 235 reservation is missing")
	}
	if documentSHA256(mustJSON(policy[:32])) != "ead820e79f2c5170425fd699a67faacfc5d112b8ace20f4b0d498d656bba05e0" {
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
		t.Fatal("build 235 must be preserved and unavailable to the current candidate")
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.163", 237
	facts.ReservedIdentities = policy
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh build 237 refused: %v", err)
	}
	for _, signingState := range []string{"unsigned", "signed-unqualified"} {
		facts.ReservedIdentities = approvedCandidateReservations()
		facts.ReservedIdentities[32].SigningState = signingState
		if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err == nil {
			t.Fatalf("build 235 signing authority accepted the label %q", signingState)
		}
	}
}
