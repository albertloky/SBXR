package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

func TestRetiredBuild229IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.155", Sequence: 229, ReleaseID: 453483664,
		Commit: "7fdf2dc6c5c0319b3ebc072ea0d83196e262e635", RunID: "44870708966", SigningState: "unknown",
		ReleaseIndexSHA256: "7c252746ef5e51484e6f8446321867ca404a872b22ecc6b40b20c727809b9c84",
		Assets: []observedAsset{
			{ID: 774625228, Name: "install.sh", Size: 77206, Digest: "7e9f30f4cbeefcb7b1b513943171b00d5a09ff03fe718d0dc99f1b86f096a3c2"},
			{ID: 774625226, Name: "release-index.json", Size: 609, Digest: "7c252746ef5e51484e6f8446321867ca404a872b22ecc6b40b20c727809b9c84"},
			{ID: 774625232, Name: "sbxr-linux-amd64.tar.gz", Size: 6253969, Digest: "d02d106e9914994762981357c1b70bfe8d368d02ed855885f509dab6091e2a48"},
			{ID: 774625225, Name: "sbxr-linux-arm64.tar.gz", Size: 5311325, Digest: "179bbe9aa6430f750d462fee65de5405e97817d2383d25e121882987b37b9de7"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 30 || !reflect.DeepEqual(policy[26], expected) {
		t.Fatal("exact build 229 reservation is missing")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(mustJSON(policy[:26]))); got != "950e6fb61d5ae00e074a1066d341b21bffc9a87a6dcd059e1a42d46d9d74ae05" {
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
		t.Fatal("build 229 must be preserved and unavailable to the current candidate")
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.159", 233
	facts.ReservedIdentities = policy
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh build 233 refused: %v", err)
	}
}
