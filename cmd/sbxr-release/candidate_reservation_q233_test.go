package main

import (
	"reflect"
	"testing"
)

func TestRetiredBuild233IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.159", Sequence: 233, ReleaseID: 454346483,
		Commit: "8332aa71ca6640f754369fe151c0a46e5175e15f", RunID: "45005500246", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "a6e634922685923448b6911f1267cb4fd5fd8850d1db3454c0053c0bae461b69",
		QualificationManifestSHA256: "4a456fc8f72a14aa96babf328856b7231e4fdb1fa3752614c90aeb9bfbf37934",
		Assets: []observedAsset{
			{ID: 778587127, Name: "install.sh", Size: 77206, Digest: "a9f7dd0eb0b994034515f478f1736790ff3de2157233f1a264535c33a8878c90"},
			{ID: 778587128, Name: "release-index.json", Size: 609, Digest: "a6e634922685923448b6911f1267cb4fd5fd8850d1db3454c0053c0bae461b69"},
			{ID: 778587125, Name: "sbxr-linux-amd64.tar.gz", Size: 6254660, Digest: "1a10d3aa56a5707bb5dfadb182a74a38cbb350125772a7d6797ac7b50d48171b"},
			{ID: 778587126, Name: "sbxr-linux-arm64.tar.gz", Size: 5340530, Digest: "1af5d318128f888936f648c1c416f4c8d8cebb56dee1be9270f4e892cbbb7812"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 43 || !reflect.DeepEqual(policy[30], expected) {
		t.Fatal("exact signed-unqualified reservation for build 233 is missing")
	}
	if documentSHA256(mustJSON(policy[:30])) != "e59fbc00b52f34f778b6c2830cfb10ac56ae37b9c2ec9216a02bc778d9f3edec" {
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
		t.Fatal("build 233 must be preserved and unavailable to the current candidate")
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.172", 246
	facts.ReservedIdentities = policy
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh build 246 refused: %v", err)
	}
}
