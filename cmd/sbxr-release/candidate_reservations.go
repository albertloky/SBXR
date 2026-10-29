package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"reflect"
)

// A reservation preserves unresolved authority. It is neither unsigned proof
// nor a signed burn, and grants no cleanup, signing or publication action.
type candidateReservation struct {
	Assets                      []observedAsset `json:"assets"`
	Commit                      string          `json:"commit"`
	QualificationManifestSHA256 string          `json:"qualification_manifest_sha256,omitempty"`
	ReleaseID                   int64           `json:"release_id"`
	ReleaseIndexSHA256          string          `json:"release_index_sha256"`
	RunID                       string          `json:"run_id"`
	Sequence                    uint64          `json:"sequence"`
	SigningState                string          `json:"signing_state"`
	Tag                         string          `json:"tag"`
}

// Source-controlled Owner decision of 2026-10-29. Return fresh values so callers
// cannot mutate the policy. Changing this record requires a separate review.
func approvedCandidateReservations() []candidateReservation {
	return []candidateReservation{{
		Tag: "v3.1.129", Sequence: 203, ReleaseID: 426359967,
		Commit: "3656473eb694f18018c1ebbd95829dfe96ed8e3c", RunID: "40644460970", SigningState: "unknown",
		ReleaseIndexSHA256: "44d06c277c7f116fbf76d67841524b9ececca2c6fbeb89521823e9b8858bc668",
		Assets: []observedAsset{
			{ID: 684172605, Name: "install.sh", Size: 76781, Digest: "acd87640b35ab94e5b094348e47748cc417d97a2afeffe373d75e808a1eb518a"},
			{ID: 684172610, Name: "release-index.json", Size: 609, Digest: "44d06c277c7f116fbf76d67841524b9ececca2c6fbeb89521823e9b8858bc668"},
			{ID: 684172607, Name: "sbxr-linux-amd64.tar.gz", Size: 6195309, Digest: "0dcb441160c1873b4833eaed4fae4c27632f2e8f6871f52a37f09c5948a4cdeb"},
			{ID: 684172609, Name: "sbxr-linux-arm64.tar.gz", Size: 5321872, Digest: "b7a1b60e6f16f8f9de0406ca219d15e0901ca817a679cfa54095a09c2dee6d0e"},
		},
	}, {
		Tag: "v3.1.130", Sequence: 204, ReleaseID: 427453228,
		Commit: "8ef6898573d8e7886d11c65b693f79d7c502787f", RunID: "40811037642", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "96d95146293481005b8977aac80c35e088a681d6c135cf2c00e7ee103b92e47c",
		QualificationManifestSHA256: "0fe088fd0cd19a7bd27e0dc62ab7c510736ba7991cc827d45a85d140749334bf",
		Assets: []observedAsset{
			{ID: 687290587, Name: "install.sh", Size: 76781, Digest: "f0e30ec1c69d12e15ab71c649d13f82502a913b5738d9762590f04e9f2523bf1"},
			{ID: 687290585, Name: "release-index.json", Size: 609, Digest: "96d95146293481005b8977aac80c35e088a681d6c135cf2c00e7ee103b92e47c"},
			{ID: 687290581, Name: "sbxr-linux-amd64.tar.gz", Size: 6223869, Digest: "ad40ce76868fa253cad6048a5eec3963d5e5e3b7a771001f2905877ba1f98dc9"},
			{ID: 687290588, Name: "sbxr-linux-arm64.tar.gz", Size: 5273247, Digest: "a44812c96362a949c00353dcb73538fb430d2b1a4b6c7366ee8f719ddffa8b94"},
		},
	}}
}

func reservedCandidate(tag string, sequence uint64, releaseID int64) bool {
	for _, r := range approvedCandidateReservations() {
		if tag == r.Tag || sequence == r.Sequence || releaseID == r.ReleaseID {
			return true
		}
	}
	return false
}

// Only pre-reservation historical facts may omit this field. Every subsequent
// candidate must bind the exact policy; omission cannot restore old allocation.
func validCandidateReservations(facts qualificationFacts) bool {
	if facts.ReservedIdentities == nil {
		for _, r := range approvedCandidateReservations() {
			if facts.Candidate.ASequence >= r.Sequence || facts.Candidate.BSequence >= r.Sequence {
				return false
			}
		}
		return true
	}
	if !reflect.DeepEqual(facts.ReservedIdentities, approvedCandidateReservations()) {
		return false
	}
	for _, r := range facts.ReservedIdentities {
		if tagPresent(facts.Tags, r.Tag) {
			return false
		}
		for _, release := range facts.Releases {
			if release.Tag == r.Tag || release.ID == r.ReleaseID || release.Sequence != nil && *release.Sequence == r.Sequence {
				return false
			}
		}
		if collidesWithBurned(facts.BurnedIdentities, r.Tag, r.Sequence) {
			return false
		}
	}
	return true
}

type reservationRelease struct {
	Assets     []observedAsset `json:"assets"`
	Body       string          `json:"body"`
	Commit     string          `json:"commit"`
	Draft      bool            `json:"draft"`
	ID         int64           `json:"id"`
	Immutable  bool            `json:"immutable"`
	Prerelease bool            `json:"prerelease"`
	Tag        string          `json:"tag"`
}
type reservationRef struct {
	State string          `json:"state"`
	Value json.RawMessage `json:"value"`
}
type reservationIdentityRefs struct {
	Burn    reservationRef `json:"burn"`
	Release reservationRef `json:"release"`
	Tag     string         `json:"tag"`
}
type reservationObservations struct {
	Refs     []reservationIdentityRefs `json:"refs"`
	Releases []reservationRelease      `json:"releases"`
}

func checkCandidateReservations(observed reservationObservations, allowed []string) bool {
	policy := approvedCandidateReservations()
	// The Owner-approved exception is exactly these two retained identities.
	if len(policy) != 2 || observed.Releases == nil || len(observed.Refs) != len(policy) {
		return false
	}
	for i, r := range policy {
		refs := observed.Refs[i]
		if refs.Tag != r.Tag || refs.Release.State != "absent" || !bytes.Equal(refs.Release.Value, []byte("null")) || refs.Burn.State != "absent" || !bytes.Equal(refs.Burn.Value, []byte("null")) {
			return false
		}
	}
	allow := map[string]bool{}
	for _, tag := range allowed {
		if !validTag(tag) || reservedCandidate(tag, 0, 0) || allow[tag] {
			return false
		}
		allow[tag] = true
	}
	seenIDs := map[int64]bool{}
	seenTags := map[string]bool{}
	found := map[string]bool{}
	for _, release := range observed.Releases {
		if release.ID <= 0 || release.Tag == "" || seenIDs[release.ID] || seenTags[release.Tag] {
			return false
		}
		seenIDs[release.ID] = true
		seenTags[release.Tag] = true
		reserved := false
		for _, r := range policy {
			if release.ID != r.ReleaseID && release.Tag != r.Tag {
				continue
			}
			expected := reservationRelease{Assets: r.Assets, Body: "Qualification pending.", Commit: r.Commit, Draft: true, ID: r.ReleaseID, Tag: r.Tag}
			if found[r.Tag] || !reflect.DeepEqual(release, expected) {
				return false
			}
			found[r.Tag] = true
			reserved = true
			break
		}
		if !reserved && release.Draft && !allow[release.Tag] {
			return false
		}
	}
	return len(found) == len(policy)
}

func runCandidateReservations(args []string, input io.Reader, output io.Writer) error {
	refused := errors.New("candidate reservation refused")
	flags := flag.NewFlagSet("candidate-reservations", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policy := flags.Bool("policy", false, "read the fixed reservation policy")
	allowedJSON := flags.String("allowed-draft-tags", "[]", "current authenticated workflow candidate tags")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return refused
	}
	if *policy {
		if *allowedJSON != "[]" {
			return refused
		}
	} else {
		var allowed []string
		if !decodeCanonical([]byte(*allowedJSON), &allowed) || allowed == nil {
			return refused
		}
		raw, err := io.ReadAll(io.LimitReader(input, 16<<20+1))
		var observed reservationObservations
		if err != nil || len(raw) > 16<<20 || !decodeCanonical(raw, &observed) || !checkCandidateReservations(observed, allowed) {
			return refused
		}
	}
	body, err := marshalCanonical(approvedCandidateReservations())
	if err != nil {
		return refused
	}
	_, err = output.Write(body)
	return err
}
