package main

import (
	"reflect"
	"testing"
)

func TestRetiredBuild241IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.167", Sequence: 241, ReleaseID: 458865361,
		Commit: "c9f3c5a113f2f9c04d82b1b855ad65a82a02c9e7", RunID: "45735394188", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "1ff37d650b62d5827fc560142b425810073d5312edaa6ed219590eea4f899cae",
		QualificationManifestSHA256: "c932e7937603d0d33b18188d60894144152374adf31b093face54945904a230d",
		Assets: []observedAsset{
			{ID: 793975047, Name: "install.sh", Size: 77206, Digest: "10da8fa9eb6238c139cc70687d9134a440354995f5243f8a599133bb7b435452"},
			{ID: 793975054, Name: "release-index.json", Size: 609, Digest: "1ff37d650b62d5827fc560142b425810073d5312edaa6ed219590eea4f899cae"},
			{ID: 793975051, Name: "sbxr-linux-amd64.tar.gz", Size: 6259793, Digest: "fd48a3a1d34dada7a1a446c75f775f853e3002cc532a662c023107e8c8e3f883"},
			{ID: 793975050, Name: "sbxr-linux-arm64.tar.gz", Size: 5333733, Digest: "1d93f2ea92294a5ae174d5adb80f1b6e53a7583845497f2c736cece52a48ee72"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 39 || !reflect.DeepEqual(policy[38], expected) {
		t.Fatal("exact build 241 reservation is missing")
	}
	if documentSHA256(mustJSON(policy[:38])) != "43e7477a7f0eb2df9d1c865e721d72495f1f0ff8e4cd0fd1121aa7ab520ae9ba" {
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
		t.Fatal("build 241 must be preserved and unavailable to the current candidate")
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.168", 242
	facts.ReservedIdentities = policy
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh build 242 refused: %v", err)
	}
	for _, signingState := range []string{"unsigned", "unknown"} {
		facts.ReservedIdentities = approvedCandidateReservations()
		facts.ReservedIdentities[38].SigningState = signingState
		if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err == nil {
			t.Fatalf("build 241 signing authority accepted the label %q", signingState)
		}
	}
}
