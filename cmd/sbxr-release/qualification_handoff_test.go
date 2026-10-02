package main

import (
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestPreparedLinkNotificationPausesOnlyActualAttendedWait(t *testing.T) {
	start := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	stamp := func(d time.Duration) string { return start.Add(d).Format(time.RFC3339) }
	attempt := v3QualificationAttempt{StartedAt: stamp(0), KaringResponseLimitSeconds: 3600, AttendedFinishBy: stamp(6 * time.Hour), EvidencePolicy: softwarelifecycle.MVPHTTPRecurringEvidencePolicy, Support: &v3ReleaseSupport{Scope: softwarelifecycle.RecurringSubscriptionUpgrade}}
	scenario := v3ScenarioEvidence{ScenarioID: "source-v3.1.81-upgrade", KaringHandoffs: []v3KaringHandoff{{Phase: "http-profile-refresh", PreparedAt: stamp(time.Minute), NotifiedAt: stamp(20 * time.Minute), RespondedAt: stamp(80 * time.Minute)}}}
	paused, ok := validKaringHandoffs(scenario, attempt, start, start.Add(90*time.Minute), 30*time.Minute)
	if !ok || paused != time.Hour {
		t.Fatalf("full hour after 19-minute preparation refused: %v %s", ok, paused)
	}
	if valid := 90*time.Minute-paused <= 30*time.Minute; !valid {
		t.Fatal("technical budget differs")
	}
	for _, test := range []struct {
		name   string
		mutate func(*v3ScenarioEvidence, *v3QualificationAttempt)
	}{
		{"undeclared", func(s *v3ScenarioEvidence, a *v3QualificationAttempt) {
			a.KaringResponseLimitSeconds = 0
			a.AttendedFinishBy = ""
		}},
		{"late response", func(s *v3ScenarioEvidence, a *v3QualificationAttempt) {
			s.KaringHandoffs[0].RespondedAt = stamp(80*time.Minute + time.Second)
		}},
		{"preparation after announcement", func(s *v3ScenarioEvidence, a *v3QualificationAttempt) {
			s.KaringHandoffs[0].PreparedAt = stamp(21 * time.Minute)
		}},
		{"expired technical request", func(s *v3ScenarioEvidence, a *v3QualificationAttempt) {
			s.KaringHandoffs[0].NotifiedAt = stamp(31 * time.Minute)
		}},
		{"insufficient attendance", func(s *v3ScenarioEvidence, a *v3QualificationAttempt) { a.AttendedFinishBy = stamp(79 * time.Minute) }},
		{"wrong phase", func(s *v3ScenarioEvidence, a *v3QualificationAttempt) {
			s.KaringHandoffs[0].Phase = "unrelated-profile"
		}},
		{"replayed phase", func(s *v3ScenarioEvidence, a *v3QualificationAttempt) {
			s.KaringHandoffs = append(s.KaringHandoffs, s.KaringHandoffs[0])
		}},
		{"pending response", func(s *v3ScenarioEvidence, a *v3QualificationAttempt) { s.KaringHandoffs[0].RespondedAt = "" }},
		{"extended signed limit", func(s *v3ScenarioEvidence, a *v3QualificationAttempt) { a.KaringResponseLimitSeconds = 3601 }},
		{"extended session", func(s *v3ScenarioEvidence, a *v3QualificationAttempt) {
			a.AttendedFinishBy = stamp(6*time.Hour + time.Second)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := attempt
			s := scenario
			s.KaringHandoffs = append([]v3KaringHandoff(nil), scenario.KaringHandoffs...)
			test.mutate(&s, &a)
			if _, ok := validKaringHandoffs(s, a, start, start.Add(90*time.Minute), 30*time.Minute); ok {
				t.Fatal("invalid handoff accepted")
			}
		})
	}
}
