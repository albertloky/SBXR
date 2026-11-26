package main

import (
	"reflect"
	"testing"
)

func TestRetiredBuild242IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.168", Sequence: 242, ReleaseID: 459027331,
		Commit: "ac196038260b80ed985581b71b0b3c358e30c413", RunID: "45758998511", SigningState: "unknown",
		ReleaseIndexSHA256: "e8c8ba06f60f3185932d7099b9a705b58f096c4e873c215dbcdbc667c59a6ee3",
		Assets: []observedAsset{
			{ID: 794569345, Name: "install.sh", Size: 77206, Digest: "4e3eeaada37c192cb47864ebcc225da7c0e55b1e353f9ec525abeca8131b3124"},
			{ID: 794569340, Name: "release-index.json", Size: 609, Digest: "e8c8ba06f60f3185932d7099b9a705b58f096c4e873c215dbcdbc667c59a6ee3"},
			{ID: 794569342, Name: "sbxr-linux-amd64.tar.gz", Size: 6259901, Digest: "c5311ad6fc0620093da8186b03fdab29e0219e605861c96a259a993f4fac44b3"},
			{ID: 794569346, Name: "sbxr-linux-arm64.tar.gz", Size: 5333799, Digest: "4f26c3e84b33253099500b8fdb56edd28b800a3e1062e3dcab59ba9e47fb2cb8"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 41 || !reflect.DeepEqual(policy[39], expected) {
		t.Fatal("exact build 242 reservation is missing")
	}
	if documentSHA256(mustJSON(policy[:39])) != "aa8e8d9ed31cadfa88b2ab1cec67540657a461f7002d3660989bc2325d993070" {
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
		t.Fatal("build 242 must be preserved and unavailable to the current candidate")
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.170", 244
	facts.ReservedIdentities = policy
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh build 244 refused: %v", err)
	}
	for _, signingState := range []string{"unsigned", "signed-unqualified"} {
		facts.ReservedIdentities = approvedCandidateReservations()
		facts.ReservedIdentities[39].SigningState = signingState
		if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err == nil {
			t.Fatalf("build 242 signing authority accepted the label %q", signingState)
		}
	}
}
