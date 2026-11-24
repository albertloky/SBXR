package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

func TestRetiredBuild225IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.151", Sequence: 225, ReleaseID: 451382653,
		Commit: "197497a92b8957cc2f29529edb3ba3a1a3952147", RunID: "44526156427", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "b4d54791aa71a2d5487e5798f0c8417fa421b0821b53130c3959a2e5ecf160d9",
		QualificationManifestSHA256: "e86b024c5356cdead620a9389296cf8aa5816b3c643884ba895572ac0c052bc6",
		Assets: []observedAsset{
			{ID: 767797843, Name: "install.sh", Size: 77206, Digest: "072addcb901df6691abb689170fa93b2d737373a1afbf49d226f423dbfead991"},
			{ID: 767797842, Name: "release-index.json", Size: 609, Digest: "b4d54791aa71a2d5487e5798f0c8417fa421b0821b53130c3959a2e5ecf160d9"},
			{ID: 767797841, Name: "sbxr-linux-amd64.tar.gz", Size: 6254155, Digest: "01b555d67e08bbfb266e02b1edd7031e81d02a5133287a180cedd391cb81ef1e"},
			{ID: 767797844, Name: "sbxr-linux-arm64.tar.gz", Size: 5311244, Digest: "f40a3646a607638a08d8a07c9e93c0ef74782aaf98aa764d5b89989545b968ee"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 35 || !reflect.DeepEqual(policy[22], expected) {
		t.Fatal("exact signed-unqualified reservation for build 225 is missing")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(mustJSON(policy[:22]))); got != "0b455c3c908444997923a2d2c8439f640c90c9aa0074399a4ca9be7173c9889c" {
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
		t.Fatal("build 225 must be preserved and unavailable to the current candidate")
	}
}
