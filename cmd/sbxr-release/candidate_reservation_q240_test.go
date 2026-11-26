package main

import (
	"reflect"
	"testing"
)

func TestRetiredBuild240IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.166", Sequence: 240, ReleaseID: 458388340,
		Commit: "44e9fdb3e97cef714b470a1985c0790e88584735", RunID: "45650409988", SigningState: "unknown",
		ReleaseIndexSHA256: "cda62e7974dbbf0d7da822ecec8fbfd9adaa096f777ee7bd6a1743012e83d28e",
		Assets: []observedAsset{
			{ID: 792355354, Name: "install.sh", Size: 77206, Digest: "eb59d915dd920ca20bfb8e5b70dcb5d07684559d5a79bdd572c51a883dc2f89a"},
			{ID: 792355353, Name: "release-index.json", Size: 609, Digest: "cda62e7974dbbf0d7da822ecec8fbfd9adaa096f777ee7bd6a1743012e83d28e"},
			{ID: 792355350, Name: "sbxr-linux-amd64.tar.gz", Size: 6259742, Digest: "8c406b0a57d5d328ed50548fd604ce7ac732ef94ac890e7c4f15f24aef001cd9"},
			{ID: 792355352, Name: "sbxr-linux-arm64.tar.gz", Size: 5333972, Digest: "9258c74e6fe9431597a17b71d261e85498a5b7bfbf080586bf8547a8ad6424f0"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 38 || !reflect.DeepEqual(policy[37], expected) {
		t.Fatal("exact build 240 reservation is missing")
	}
	if documentSHA256(mustJSON(policy[:37])) != "8b32d554d958068148c2be71e622afa03e85e161bd8cd9f1b5f780d33b196c20" {
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
		t.Fatal("build 240 must be preserved and unavailable to the current candidate")
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
		facts.ReservedIdentities[37].SigningState = signingState
		if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err == nil {
			t.Fatalf("build 240 signing authority accepted the label %q", signingState)
		}
	}
}
