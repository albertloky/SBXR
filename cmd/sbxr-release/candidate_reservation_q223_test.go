package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

func TestRetiredBuild223IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.149", Sequence: 223, ReleaseID: 450895501,
		Commit: "e96888ed8e11a47b16ee89aefb1f8491d17a59c6", RunID: "44456189920", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "e2f0ac89f33ba7c234f0a488513dd9f0fb7d8ac56e6e8c50bcfd30f5b874f12b",
		QualificationManifestSHA256: "db2921412d322a7c029d92651f1c5246bc634491d4365df8b694fe93c5e9705c",
		Assets: []observedAsset{
			{ID: 766277215, Name: "install.sh", Size: 77206, Digest: "bef0b5f8342e2cdf452f2e791e4ddec0736f90854401449ad8373ad35bd8bc18"},
			{ID: 766277214, Name: "release-index.json", Size: 609, Digest: "e2f0ac89f33ba7c234f0a488513dd9f0fb7d8ac56e6e8c50bcfd30f5b874f12b"},
			{ID: 766277212, Name: "sbxr-linux-amd64.tar.gz", Size: 6245711, Digest: "2f64a44f227f3bd42a525fb942f966c11498dbd6452dd3f7200abb281f56ef82"},
			{ID: 766277211, Name: "sbxr-linux-arm64.tar.gz", Size: 5338594, Digest: "7be0bb23e932f0905b9c80bf457a94e4139713a959d65683b5ebf8a08219f639"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 40 || !reflect.DeepEqual(policy[20], expected) {
		t.Fatal("exact signed-unqualified reservation for build 223 is missing")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(mustJSON(policy[:20]))); got != "fa731fb5f5146dc728c5ff8e8627a0be3261b64351d74348f89a7d866fb859f8" {
		t.Fatal("an earlier signed or retained identity changed")
	}
	if !reservedCandidate(expected.Tag, 0, 0) ||
		!reservedCandidate("", expected.Sequence, 0) ||
		!reservedCandidate("", 0, expected.ReleaseID) {
		t.Fatal("retired build can be reused by tag, sequence or draft ID")
	}
	observed := reservationFixture()
	if !checkCandidateReservations(observed, nil) ||
		checkCandidateReservations(observed, []string{expected.Tag}) {
		t.Fatal("build 223 must be preserved and unavailable to the current candidate")
	}
}
