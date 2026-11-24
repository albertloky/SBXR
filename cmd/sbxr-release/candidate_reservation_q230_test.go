package main

import (
	"reflect"
	"testing"
)

func TestRetiredBuild230IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.156", Sequence: 230, ReleaseID: 453589120,
		Commit: "a65bfb6f6631077fc16ef83addc181ba32306139", RunID: "44887573881", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "e90e17a2544462bb2f542e61318951e8511c7240763b64a3d84fe24273862edb",
		QualificationManifestSHA256: "8f998a3a5fd06731ef4a8052726b27549f2fa92ca9eab0de0ea21b3a801e4934",
		Assets: []observedAsset{
			{ID: 775108288, Name: "install.sh", Size: 77206, Digest: "7baf7d1eeb1c272942736434259608ef55a8f518ec68e8eb32fe796406f02d12"},
			{ID: 775108292, Name: "release-index.json", Size: 609, Digest: "e90e17a2544462bb2f542e61318951e8511c7240763b64a3d84fe24273862edb"},
			{ID: 775108284, Name: "sbxr-linux-amd64.tar.gz", Size: 6253951, Digest: "904c53bab68dc8c5528fa2e06d3cfe1360d454f5039e861085d2fdef467851ab"},
			{ID: 775108285, Name: "sbxr-linux-arm64.tar.gz", Size: 5311282, Digest: "84c9eded7d56ce376c36b103b3ab1236ba9a811e218ac86bc574f74c1ed0094f"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 35 || !reflect.DeepEqual(policy[27], expected) {
		t.Fatal("exact signed-unqualified reservation for build 230 is missing")
	}
	if documentSHA256(mustJSON(policy[:27])) != "68488f44e671856f1b550faece5cac219a9b2c5cda7349ea3e9853804408c539" {
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
		t.Fatal("build 230 must be preserved and unavailable to the current candidate")
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.164", 238
	facts.ReservedIdentities = policy
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh build 238 refused: %v", err)
	}
}
