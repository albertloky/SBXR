package main

import (
	"strings"
	"testing"
)

func TestQ208ExactReservation(t *testing.T) {
	p := approvedCandidateReservations()
	if len(p) != 15 || p[5].Tag != "v3.1.134" || p[5].Sequence != 208 || p[5].ReleaseID != 429914221 || p[5].SigningState != "signed-unqualified" || p[5].RunID != "41196706730" {
		t.Fatal("wrong sixth identity")
	}
	if !checkCandidateReservations(reservationFixture(), nil) {
		t.Fatal("exact set refused")
	}
	for _, a := range []struct {
		tag string
		seq uint64
		id  int64
	}{{"v3.1.134", 0, 0}, {"", 208, 0}, {"", 0, 429914221}} {
		if !reservedCandidate(a.tag, a.seq, a.id) {
			t.Fatal("reuse allowed")
		}
	}
	for name, change := range map[string]func(*reservationObservations){
		"missing sixth":  func(o *reservationObservations) { o.Releases = o.Releases[:5] },
		"published":      func(o *reservationObservations) { o.Releases[5].Draft = false },
		"immutable":      func(o *reservationObservations) { o.Releases[5].Immutable = true },
		"prerelease":     func(o *reservationObservations) { o.Releases[5].Prerelease = true },
		"commit":         func(o *reservationObservations) { o.Releases[5].Commit = strings.Repeat("a", 40) },
		"asset identity": func(o *reservationObservations) { o.Releases[5].Assets[0].ID++ },
		"asset bytes":    func(o *reservationObservations) { o.Releases[5].Assets[0].Digest = strings.Repeat("a", 64) },
		"asset size":     func(o *reservationObservations) { o.Releases[5].Assets[0].Size++ },
		"body":           func(o *reservationObservations) { o.Releases[5].Body = "Qualified" },
		"tag present":    func(o *reservationObservations) { o.Refs[5].Release.State = "present" },
		"burn present":   func(o *reservationObservations) { o.Refs[5].Burn.State = "present" },
		"unknown ref":    func(o *reservationObservations) { o.Refs[5].Release.State = "unavailable" },
		"duplicate":      func(o *reservationObservations) { o.Releases = append(o.Releases, o.Releases[5]) },
		"unrelated draft": func(o *reservationObservations) {
			o.Releases = append(o.Releases, reservationRelease{ID: 8, Tag: "v9.9.9", Draft: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			o := reservationFixture()
			change(&o)
			if checkCandidateReservations(o, nil) {
				t.Fatal("unsafe sixth admitted")
			}
		})
	}
	if checkCandidateReservations(reservationFixture(), []string{"v3.1.134"}) {
		t.Fatal("reserved allowlist admitted")
	}
}

func TestQ208ReservationCannotBeOmittedOrRelabeled(t *testing.T) {
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.144", 218
	for name, mutate := range map[string]func(*qualificationFacts){
		"old five only": func(f *qualificationFacts) { f.ReservedIdentities = f.ReservedIdentities[:5] },
		"unsigned":      func(f *qualificationFacts) { f.ReservedIdentities[5].SigningState = "unsigned" },
		"manifest": func(f *qualificationFacts) {
			f.ReservedIdentities[5].QualificationManifestSHA256 = strings.Repeat("a", 64)
		},
		"tag reuse":      func(f *qualificationFacts) { f.Candidate.BTag = "v3.1.134" },
		"sequence reuse": func(f *qualificationFacts) { f.Candidate.BSequence = 208 },
	} {
		t.Run(name, func(t *testing.T) {
			f := facts
			f.ReservedIdentities = approvedCandidateReservations()
			mutate(&f)
			if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
				t.Fatal("q208 reservation bypassed")
			}
		})
	}
}
