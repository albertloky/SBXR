package main

import (
	"strings"
	"testing"
)

func TestQ207ExactReservation(t *testing.T) {
	p := approvedCandidateReservations()
	if len(p) != 5 || p[4].Tag != "v3.1.133" || p[4].Sequence != 207 || p[4].ReleaseID != 429811498 || p[4].SigningState != "signed-unqualified" || p[4].RunID != "41181652726" {
		t.Fatal("wrong fifth identity")
	}
	if !checkCandidateReservations(reservationFixture(), nil) {
		t.Fatal("exact set refused")
	}
	for _, a := range []struct {
		tag string
		seq uint64
		id  int64
	}{{"v3.1.133", 0, 0}, {"", 207, 0}, {"", 0, 429811498}} {
		if !reservedCandidate(a.tag, a.seq, a.id) {
			t.Fatal("reuse allowed")
		}
	}
	for name, change := range map[string]func(*reservationObservations){
		"missing fifth":  func(o *reservationObservations) { o.Releases = o.Releases[:4] },
		"published":      func(o *reservationObservations) { o.Releases[4].Draft = false },
		"immutable":      func(o *reservationObservations) { o.Releases[4].Immutable = true },
		"prerelease":     func(o *reservationObservations) { o.Releases[4].Prerelease = true },
		"commit":         func(o *reservationObservations) { o.Releases[4].Commit = strings.Repeat("a", 40) },
		"asset identity": func(o *reservationObservations) { o.Releases[4].Assets[0].ID++ },
		"asset bytes":    func(o *reservationObservations) { o.Releases[4].Assets[0].Digest = strings.Repeat("a", 64) },
		"asset size":     func(o *reservationObservations) { o.Releases[4].Assets[0].Size++ },
		"body":           func(o *reservationObservations) { o.Releases[4].Body = "Qualified" },
		"tag present":    func(o *reservationObservations) { o.Refs[4].Release.State = "present" },
		"burn present":   func(o *reservationObservations) { o.Refs[4].Burn.State = "present" },
		"unknown ref":    func(o *reservationObservations) { o.Refs[4].Release.State = "unavailable" },
		"duplicate":      func(o *reservationObservations) { o.Releases = append(o.Releases, o.Releases[4]) },
		"unrelated draft": func(o *reservationObservations) {
			o.Releases = append(o.Releases, reservationRelease{ID: 8, Tag: "v9.9.9", Draft: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			o := reservationFixture()
			change(&o)
			if checkCandidateReservations(o, nil) {
				t.Fatal("unsafe fifth admitted")
			}
		})
	}
	if checkCandidateReservations(reservationFixture(), []string{"v3.1.133"}) {
		t.Fatal("reserved allowlist admitted")
	}
}

func TestQ207ReservationCannotBeOmittedOrRelabeled(t *testing.T) {
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.134", 208
	for name, mutate := range map[string]func(*qualificationFacts){
		"old four only": func(f *qualificationFacts) { f.ReservedIdentities = f.ReservedIdentities[:4] },
		"unsigned":      func(f *qualificationFacts) { f.ReservedIdentities[4].SigningState = "unsigned" },
		"manifest": func(f *qualificationFacts) {
			f.ReservedIdentities[4].QualificationManifestSHA256 = strings.Repeat("a", 64)
		},
		"tag reuse":      func(f *qualificationFacts) { f.Candidate.BTag = "v3.1.133" },
		"sequence reuse": func(f *qualificationFacts) { f.Candidate.BSequence = 207 },
	} {
		t.Run(name, func(t *testing.T) {
			f := facts
			f.ReservedIdentities = approvedCandidateReservations()
			mutate(&f)
			if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
				t.Fatal("q207 reservation bypassed")
			}
		})
	}
}
