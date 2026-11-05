package main

import (
	"strings"
	"testing"
)

func TestQ210ExactReservation(t *testing.T) {
	p := approvedCandidateReservations()
	if len(p) != 10 || p[7].Tag != "v3.1.136" || p[7].Sequence != 210 || p[7].ReleaseID != 430449719 || p[7].SigningState != "signed-unqualified" || p[7].RunID != "41285797719" {
		t.Fatal("wrong eighth identity")
	}
	if !checkCandidateReservations(reservationFixture(), nil) {
		t.Fatal("exact set refused")
	}
	for _, a := range []struct {
		tag string
		seq uint64
		id  int64
	}{{"v3.1.136", 0, 0}, {"", 210, 0}, {"", 0, 430449719}} {
		if !reservedCandidate(a.tag, a.seq, a.id) {
			t.Fatal("reuse allowed")
		}
	}
	for name, change := range map[string]func(*reservationObservations){
		"missing eighth": func(o *reservationObservations) { o.Releases = o.Releases[:7] },
		"published":      func(o *reservationObservations) { o.Releases[7].Draft = false },
		"immutable":      func(o *reservationObservations) { o.Releases[7].Immutable = true },
		"prerelease":     func(o *reservationObservations) { o.Releases[7].Prerelease = true },
		"commit":         func(o *reservationObservations) { o.Releases[7].Commit = strings.Repeat("a", 40) },
		"asset identity": func(o *reservationObservations) { o.Releases[7].Assets[0].ID++ },
		"asset bytes":    func(o *reservationObservations) { o.Releases[7].Assets[0].Digest = strings.Repeat("a", 64) },
		"asset size":     func(o *reservationObservations) { o.Releases[7].Assets[0].Size++ },
		"body":           func(o *reservationObservations) { o.Releases[7].Body = "Qualified" },
		"tag present":    func(o *reservationObservations) { o.Refs[7].Release.State = "present" },
		"burn present":   func(o *reservationObservations) { o.Refs[7].Burn.State = "present" },
		"unknown ref":    func(o *reservationObservations) { o.Refs[7].Release.State = "unavailable" },
		"duplicate":      func(o *reservationObservations) { o.Releases = append(o.Releases, o.Releases[7]) },
		"unrelated draft": func(o *reservationObservations) {
			o.Releases = append(o.Releases, reservationRelease{ID: 8, Tag: "v9.9.9", Draft: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			o := reservationFixture()
			change(&o)
			if checkCandidateReservations(o, nil) {
				t.Fatal("unsafe eighth admitted")
			}
		})
	}
	if checkCandidateReservations(reservationFixture(), []string{"v3.1.136"}) {
		t.Fatal("reserved allowlist admitted")
	}
}

func TestQ210ReservationCannotBeOmittedOrRelabeled(t *testing.T) {
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.139", 213
	for name, mutate := range map[string]func(*qualificationFacts){
		"old seven only": func(f *qualificationFacts) { f.ReservedIdentities = f.ReservedIdentities[:7] },
		"unsigned":       func(f *qualificationFacts) { f.ReservedIdentities[7].SigningState = "unsigned" },
		"manifest": func(f *qualificationFacts) {
			f.ReservedIdentities[7].QualificationManifestSHA256 = strings.Repeat("a", 64)
		},
		"tag reuse":      func(f *qualificationFacts) { f.Candidate.BTag = "v3.1.136" },
		"sequence reuse": func(f *qualificationFacts) { f.Candidate.BSequence = 210 },
	} {
		t.Run(name, func(t *testing.T) {
			f := facts
			f.ReservedIdentities = approvedCandidateReservations()
			mutate(&f)
			if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
				t.Fatal("q210 reservation bypassed")
			}
		})
	}
}
