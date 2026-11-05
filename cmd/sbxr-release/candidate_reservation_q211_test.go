package main

import (
	"strings"
	"testing"
)

func TestQ211ExactReservation(t *testing.T) {
	p := approvedCandidateReservations()
	if len(p) != 10 || p[8].Tag != "v3.1.137" || p[8].Sequence != 211 || p[8].ReleaseID != 430636507 || p[8].SigningState != "signed-unqualified" || p[8].RunID != "41312490744" {
		t.Fatal("wrong ninth identity")
	}
	if p[8].Commit != "a0abe154f4380b2c2f5d28a979c9417d4059e90d" || p[8].ReleaseIndexSHA256 != "5bf9794eef667e8459eda7e24c6d0e4d9aed687bed7cae8e6297273c46185d68" || p[8].QualificationManifestSHA256 != "81107d0cbeed9c0b3f2c759938065d08259966411acb68c1f1d01e282280989e" {
		t.Fatal("wrong signed source or evidence binding")
	}
	if !checkCandidateReservations(reservationFixture(), nil) {
		t.Fatal("exact set refused")
	}
	for _, a := range []struct {
		tag string
		seq uint64
		id  int64
	}{{"v3.1.137", 0, 0}, {"", 211, 0}, {"", 0, 430636507}} {
		if !reservedCandidate(a.tag, a.seq, a.id) {
			t.Fatal("reuse allowed")
		}
	}
	for name, change := range map[string]func(*reservationObservations){
		"missing ninth":  func(o *reservationObservations) { o.Releases = o.Releases[:8] },
		"published":      func(o *reservationObservations) { o.Releases[8].Draft = false },
		"immutable":      func(o *reservationObservations) { o.Releases[8].Immutable = true },
		"prerelease":     func(o *reservationObservations) { o.Releases[8].Prerelease = true },
		"commit":         func(o *reservationObservations) { o.Releases[8].Commit = strings.Repeat("a", 40) },
		"asset identity": func(o *reservationObservations) { o.Releases[8].Assets[0].ID++ },
		"asset bytes":    func(o *reservationObservations) { o.Releases[8].Assets[0].Digest = strings.Repeat("a", 64) },
		"asset size":     func(o *reservationObservations) { o.Releases[8].Assets[0].Size++ },
		"body":           func(o *reservationObservations) { o.Releases[8].Body = "Qualified" },
		"tag present":    func(o *reservationObservations) { o.Refs[8].Release.State = "present" },
		"burn present":   func(o *reservationObservations) { o.Refs[8].Burn.State = "present" },
		"unknown ref":    func(o *reservationObservations) { o.Refs[8].Release.State = "unavailable" },
		"duplicate":      func(o *reservationObservations) { o.Releases = append(o.Releases, o.Releases[8]) },
		"unrelated draft": func(o *reservationObservations) {
			o.Releases = append(o.Releases, reservationRelease{ID: 8, Tag: "v9.9.9", Draft: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			o := reservationFixture()
			change(&o)
			if checkCandidateReservations(o, nil) {
				t.Fatal("unsafe ninth admitted")
			}
		})
	}
	if checkCandidateReservations(reservationFixture(), []string{"v3.1.137"}) {
		t.Fatal("reserved allowlist admitted")
	}
}

func TestQ211ReservationCannotBeOmittedOrRelabeled(t *testing.T) {
	if len(approvedCandidateReservations()) != 10 {
		t.Fatal("missing ninth reservation")
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.139", 213
	for name, mutate := range map[string]func(*qualificationFacts){
		"old eight only": func(f *qualificationFacts) { f.ReservedIdentities = f.ReservedIdentities[:8] },
		"unsigned":       func(f *qualificationFacts) { f.ReservedIdentities[8].SigningState = "unsigned" },
		"manifest": func(f *qualificationFacts) {
			f.ReservedIdentities[8].QualificationManifestSHA256 = strings.Repeat("a", 64)
		},
		"tag reuse":      func(f *qualificationFacts) { f.Candidate.BTag = "v3.1.137" },
		"sequence reuse": func(f *qualificationFacts) { f.Candidate.BSequence = 211 },
	} {
		t.Run(name, func(t *testing.T) {
			f := facts
			f.ReservedIdentities = approvedCandidateReservations()
			mutate(&f)
			if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
				t.Fatal("q211 reservation bypassed")
			}
		})
	}
}
