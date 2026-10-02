package main

import (
	"strings"
	"time"
)

func validKaringResponseDeclaration(attempt v3QualificationAttempt) bool {
	if attempt.KaringResponseLimitSeconds == 0 {
		return attempt.AttendedFinishBy == ""
	}
	started, ok := qualificationTime(attempt.StartedAt)
	finish, finishOK := qualificationTime(attempt.AttendedFinishBy)
	return ordinaryLiveAttempt(attempt) && httpLiveAttempt(attempt) && attempt.OwnerException == "" &&
		attempt.KaringResponseLimitSeconds == 3600 && ok && finishOK &&
		!finish.Before(started.Add(time.Hour)) && !finish.After(started.Add(6*time.Hour))
}

func karingHandoffPhases(scenario string) []string {
	if strings.HasPrefix(scenario, "source-") && (strings.HasSuffix(scenario, "-upgrade") || strings.HasSuffix(scenario, "-postcommit")) {
		return []string{"source-profile-import", "http-profile-refresh"}
	}
	switch scenario {
	case "mvp-subscription":
		return []string{"profile-import", "profile-refresh"}
	case "mvp-credentials":
		return []string{"credential-refresh", "rotated-link-refresh"}
	case "mvp-removal":
		return []string{"test-profile-removal"}
	}
	return nil
}

// Only actual attended waits are excluded from the unchanged technical budget.
// The signed attendance cutoff and six-hour transport/job ceiling still apply.
func validKaringHandoffs(scenario v3ScenarioEvidence, attempt v3QualificationAttempt, started, completed time.Time, limit time.Duration) (time.Duration, bool) {
	if attempt.KaringResponseLimitSeconds == 0 {
		return 0, len(scenario.KaringHandoffs) == 0
	}
	if !validKaringResponseDeclaration(attempt) || attempt.KaringResponseLimitSeconds != 3600 {
		return 0, false
	}
	finish, _ := qualificationTime(attempt.AttendedFinishBy)
	if completed.After(finish) {
		return 0, false
	}
	previous, paused, seen := started, time.Duration(0), map[string]bool{}
	for _, h := range scenario.KaringHandoffs {
		allowed := false
		for _, phase := range karingHandoffPhases(scenario.ScenarioID) {
			if phase == h.Phase {
				allowed = true
			}
		}
		prepared, pOK := qualificationTime(h.PreparedAt)
		notified, nOK := qualificationTime(h.NotifiedAt)
		responded, rOK := qualificationTime(h.RespondedAt)
		if !allowed || seen[h.Phase] || !pOK || !nOK || !rOK || prepared.After(notified) || notified.Before(previous) ||
			notified.After(started.Add(limit+paused)) || notified.Add(time.Hour).After(finish) ||
			responded.Before(notified) || responded.After(notified.Add(time.Hour)) || responded.After(completed) {
			return 0, false
		}
		seen[h.Phase] = true
		paused += responded.Sub(notified)
		previous = responded
	}
	return paused, true
}
