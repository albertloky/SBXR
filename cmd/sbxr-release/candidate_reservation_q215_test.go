package main

import (
	"reflect"
	"testing"
)

func TestQ215SignedReservation(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.141", Sequence: 215, ReleaseID: 438186606,
		Commit: "84af948bc2a1d92607aa2e6b902512b648133c43", RunID: "42470439088", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "07d718204039c8026b42157097aca1c8bf9c3ee537d6c3a4b25bf098c5e33d0b",
		QualificationManifestSHA256: "8a9a38a86f2e12b92689c715021d02b51b7aab402a2735b3329231c1cad6f332",
		Assets: []observedAsset{
			{ID: 723667643, Name: "install.sh", Size: 76781, Digest: "ab42ff6477a5fd205580341837e5a1d07db7fd76c8e57052778ada51f49f9f66"},
			{ID: 723667644, Name: "release-index.json", Size: 609, Digest: "07d718204039c8026b42157097aca1c8bf9c3ee537d6c3a4b25bf098c5e33d0b"},
			{ID: 723667639, Name: "sbxr-linux-amd64.tar.gz", Size: 6236654, Digest: "382567563476de20bf3e48ce8a0038aeb191675fb5e4625585f546e973697ab7"},
			{ID: 723667642, Name: "sbxr-linux-arm64.tar.gz", Size: 5335609, Digest: "1d59594041a9459355a8317a588b9dfa61e8614b886a3a98d4f07c44e8968fd2"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 13 || !reflect.DeepEqual(policy[12], expected) {
		t.Fatal("exact signed build 215 reservation missing")
	}
	for _, mutate := range []func(*qualificationFacts){
		func(f *qualificationFacts) { f.Candidate.BTag = expected.Tag },
		func(f *qualificationFacts) { f.Candidate.BSequence = 215 },
		func(f *qualificationFacts) { f.ReservedIdentities = f.ReservedIdentities[:12] },
		func(f *qualificationFacts) { f.ReservedIdentities[12].SigningState = "unknown" },
		func(f *qualificationFacts) { f.ReservedIdentities[12].QualificationManifestSHA256 = "" },
	} {
		f := candidateFacts("v3")
		f.Candidate.ATag = ""
		f.Candidate.ASequence = 0
		f.Candidate.BTag = "v3.1.142"
		f.Candidate.BSequence = 216
		f.ReservedIdentities = approvedCandidateReservations()
		mutate(&f)
		if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
			t.Fatal("reserved authority bypassed")
		}
	}
}
