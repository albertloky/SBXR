package main

import (
	"reflect"
	"testing"
)

func TestRetiredBuild243IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.169", Sequence: 243, ReleaseID: 459156224,
		Commit: "a9f7f2cbb929481074132a4896407be9508f91fa", RunID: "45779449291", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "d3777552d077927a92b47d7dbfb7ff7a79e46e74959b91171db04f367e32642f",
		QualificationManifestSHA256: "f552aa6a86c75c9080ffb2aba2678906e15cacdd818b375b74970b8f1b374760",
		Assets: []observedAsset{
			{ID: 795040355, Name: "install.sh", Size: 77206, Digest: "a6bd036f11854cc6dc76d992d3e633f92b51d889ebda588834af3ce3df27e991"},
			{ID: 795040350, Name: "release-index.json", Size: 609, Digest: "d3777552d077927a92b47d7dbfb7ff7a79e46e74959b91171db04f367e32642f"},
			{ID: 795040352, Name: "sbxr-linux-amd64.tar.gz", Size: 6259953, Digest: "eb7b8a06968c0d978337959b7742c28427347a387952de92aef5f3ada74d688d"},
			{ID: 795040351, Name: "sbxr-linux-arm64.tar.gz", Size: 5333901, Digest: "d640d7ade1784f99b5399deaddc45bc2c10686eb22f8f497f2aa363654eaeea3"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 43 || !reflect.DeepEqual(policy[40], expected) {
		t.Fatal("exact build 243 reservation is missing")
	}
	if documentSHA256(mustJSON(policy[:40])) != "2bc5a416f70d8316eb862f511150555b3189cb69961d93ef9f7680a8351c0c33" {
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
		t.Fatal("build 243 must be preserved and unavailable to the current candidate")
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
		facts.ReservedIdentities[40].SigningState = signingState
		if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err == nil {
			t.Fatalf("build 243 signing authority accepted the label %q", signingState)
		}
	}
}
