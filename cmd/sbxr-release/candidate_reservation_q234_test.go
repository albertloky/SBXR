package main

import (
	"reflect"
	"testing"
)

func TestRetiredBuild234IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.160", Sequence: 234, ReleaseID: 454438007,
		Commit: "72ddf4587dfc17f7de18f194907ba8bac2cb905d", RunID: "45019124957", SigningState: "unknown",
		ReleaseIndexSHA256: "474d62eafaa661d0c5b73c1836f4f627068aa0157154c8485ef133d0942a9546",
		Assets: []observedAsset{
			{ID: 779024353, Name: "install.sh", Size: 77206, Digest: "3fbd62cf619b26beff16c74db105cb7a0157621d72fec918f0cf8b46e0887117"},
			{ID: 779024352, Name: "release-index.json", Size: 609, Digest: "474d62eafaa661d0c5b73c1836f4f627068aa0157154c8485ef133d0942a9546"},
			{ID: 779024371, Name: "sbxr-linux-amd64.tar.gz", Size: 6254665, Digest: "72cfeb525c5e9438b8b2c67923ec74d05078fcb4a6cdea6c0bb29cec4015012e"},
			{ID: 779024358, Name: "sbxr-linux-arm64.tar.gz", Size: 5340542, Digest: "90ffcf7ea373f6a5ed65f94905595c7dd69b5291ba27113e92f44f83a2a4babe"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 38 || !reflect.DeepEqual(policy[31], expected) {
		t.Fatal("exact build 234 reservation is missing")
	}
	if documentSHA256(mustJSON(policy[:31])) != "a1e8a32a419716f6c8eb4b97c389167f8730ed2d56b9c30544ffe73775bae531" {
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
		t.Fatal("build 234 must be preserved and unavailable to the current candidate")
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.167", 241
	facts.ReservedIdentities = policy
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh build 241 refused: %v", err)
	}
	for _, signingState := range []string{"unsigned", "signed-unqualified"} {
		facts.ReservedIdentities = approvedCandidateReservations()
		facts.ReservedIdentities[31].SigningState = signingState
		if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err == nil {
			t.Fatalf("build 234 signing authority accepted the label %q", signingState)
		}
	}
}
