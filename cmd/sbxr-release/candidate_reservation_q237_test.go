package main

import (
	"reflect"
	"testing"
)

func TestRetiredBuild237IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.163", Sequence: 237, ReleaseID: 456494759,
		Commit: "9373a863a1ff9d24cb22639657d0f6fa6b9045fc", RunID: "45351436999", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "3603ea6d41d58810c4a265e30c05b8291c99d1225e301c1465c7fb7dcf871653",
		QualificationManifestSHA256: "8bd35b6a24440b29c1981b74aac490f8c245a4fe2c17ed137ce6248cce12d673",
		Assets: []observedAsset{
			{ID: 786375483, Name: "install.sh", Size: 77206, Digest: "d4957fcc4ff4a35ffc07d1f3ccf7e9bbb3600af0137e890b47bcacbf7455aa94"},
			{ID: 786375485, Name: "release-index.json", Size: 609, Digest: "3603ea6d41d58810c4a265e30c05b8291c99d1225e301c1465c7fb7dcf871653"},
			{ID: 786375480, Name: "sbxr-linux-amd64.tar.gz", Size: 6259801, Digest: "dde8bce0b7cd058846bbc9b306fa19a6856463da5a870c629ab495f69e861368"},
			{ID: 786375481, Name: "sbxr-linux-arm64.tar.gz", Size: 5333744, Digest: "2c4da2783f9fce945520e8f5576acf64b6fd373944edec866fd66b22f2ea2b34"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 37 || !reflect.DeepEqual(policy[34], expected) {
		t.Fatal("exact build 237 reservation is missing")
	}
	if documentSHA256(mustJSON(policy[:34])) != "c4347941f6d1b948bae801567f29956972386fab35d79ecd91907b79aa6751d7" {
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
		t.Fatal("build 237 must be preserved and unavailable to the current candidate")
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.166", 240
	facts.ReservedIdentities = policy
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh build 240 refused: %v", err)
	}
	for _, signingState := range []string{"unsigned", "unknown"} {
		facts.ReservedIdentities = approvedCandidateReservations()
		facts.ReservedIdentities[34].SigningState = signingState
		if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err == nil {
			t.Fatalf("build 237 signing authority accepted the label %q", signingState)
		}
	}
}
