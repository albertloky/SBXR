package certificatelifecycle_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
)

type scheduledChange string

func (change scheduledChange) Identity() string { return string(change) }

type ipDue struct {
	calls []certificatelifecycle.Lineage
}

func (*ipDue) Record(certificatelifecycle.Lineage, certificatelifecycle.ApplyResult) error {
	return nil
}

type memoryAttemptHistory struct {
	at      time.Time
	outcome certificatelifecycle.RenewalAttempt
	found   bool
}

func (history *memoryAttemptHistory) LoadIPAttempt() (time.Time, certificatelifecycle.RenewalAttempt, bool, error) {
	return history.at, history.outcome, history.found, nil
}
func (history *memoryAttemptHistory) StoreIPAttempt(at time.Time, outcome certificatelifecycle.RenewalAttempt) error {
	history.at, history.outcome, history.found = at, outcome, true
	return nil
}
func (history *memoryAttemptHistory) ClearIPAttempt() error {
	history.at, history.outcome, history.found = time.Time{}, "", false
	return nil
}

func (policy *ipDue) Due(lineage certificatelifecycle.Lineage) bool {
	policy.calls = append(policy.calls, lineage)
	return true
}

type renewalPlanner struct {
	calls []certificatelifecycle.Lineage
}

func (planner *renewalPlanner) BuildFresh(lineage certificatelifecycle.Lineage) (certificatelifecycle.ChangeSet, error) {
	planner.calls = append(planner.calls, lineage)
	if lineage != certificatelifecycle.IPLineage {
		return nil, errors.New("domain branch belongs to issue #98")
	}
	return scheduledChange("renew-ip-8"), nil
}

type busySystemChanges struct{ calls int }

func (changes *busySystemChanges) ApplyFresh(func() (certificatelifecycle.ChangeSet, error)) certificatelifecycle.ApplyResult {
	changes.calls++
	return certificatelifecycle.ApplyResult{Outcome: certificatelifecycle.Deferred, PlanConsumed: true, RebuildPlan: true, Code: "SYSTEM-CHANGES-BUSY"}
}

type failedSystemChanges struct{}

func (failedSystemChanges) ApplyFresh(build func() (certificatelifecycle.ChangeSet, error)) certificatelifecycle.ApplyResult {
	if _, err := build(); err != nil {
		return certificatelifecycle.ApplyResult{Outcome: certificatelifecycle.Refused, Code: "SYSTEM-CHANGES-RENEWAL-PLAN"}
	}
	return certificatelifecycle.ApplyResult{Outcome: certificatelifecycle.Refused, PlanConsumed: true, Code: "CERTIFICATE-ORDER-FAILED"}
}

func TestSystemdUnitsOwnOnePersistentRandomizedTwiceDailyRenewal(t *testing.T) {
	units, err := certificatelifecycle.SystemdUnits()
	if err != nil || len(units) != 2 || units["sbxr-cert-renew.service"] == "" || strings.Count(units["sbxr-cert-renew.timer"], "OnCalendar=") != 1 || !strings.Contains(units["sbxr-cert-renew.timer"], "00,12:00:00") || !strings.Contains(units["sbxr-cert-renew.timer"], "RandomizedDelaySec=1m") || !strings.Contains(units["sbxr-cert-renew.timer"], "Persistent=true") || !strings.Contains(units["sbxr-cert-renew.timer"], "OnUnitInactiveSec=13m") || !strings.Contains(units["sbxr-cert-renew.timer"], "AccuracySec=1s") {
		t.Fatalf("persistent renewal units = %+v, %v", units, err)
	}
	for name, content := range units {
		if strings.Contains(name+content, "certbot.timer") || strings.Contains(name+content, "sbxr-ip") || strings.Contains(name+content, "sbxr-domain") {
			t.Fatalf("competing renewal owner in %s: %s", name, content)
		}
	}
}

func TestIPRenewalPolicyControlsDueAndRetryWindows(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		facts   certificatelifecycle.IPRenewalFacts
		due     bool
		outcome certificatelifecycle.Outcome
		code    string
	}{
		{name: "standing policy missing", facts: certificatelifecycle.IPRenewalFacts{Now: now, NotAfter: now.Add(48 * time.Hour)}, outcome: certificatelifecycle.Failed, code: "CERTIFICATE-RENEWAL-POLICY"},
		{name: "outside renewal window", facts: certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(72*time.Hour + time.Second)}, outcome: certificatelifecycle.Healthy, code: "CERTIFICATE-RENEWAL-NOT-DUE"},
		{name: "at threshold", facts: certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(72 * time.Hour)}, due: true, outcome: certificatelifecycle.Healthy, code: "CERTIFICATE-RENEWAL-DUE"},
		{name: "below one day warns", facts: certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(23 * time.Hour)}, due: true, outcome: certificatelifecycle.NeedsAttention, code: "CERTIFICATE-IP-EXPIRY-WARNING"},
		{name: "ordinary failure waits six hours", facts: certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(48 * time.Hour), LastAttempt: now.Add(-5 * time.Hour), LastOutcome: certificatelifecycle.RenewalFailed}, outcome: certificatelifecycle.NeedsAttention, code: "CERTIFICATE-RENEWAL-RETRY"},
		{name: "ordinary failure retry reached", facts: certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(48 * time.Hour), LastAttempt: now.Add(-6 * time.Hour), LastOutcome: certificatelifecycle.RenewalFailed}, due: true, outcome: certificatelifecycle.NeedsAttention, code: "CERTIFICATE-RENEWAL-DUE"},
		{name: "busy does not retry in same evaluation", facts: certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(24 * time.Hour), LastAttempt: now, LastOutcome: certificatelifecycle.RenewalBusy}, outcome: certificatelifecycle.NeedsAttention, code: "CERTIFICATE-RENEWAL-BUSY"},
		{name: "busy retries at next bounded timer evaluation", facts: certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(24 * time.Hour), LastAttempt: now.Add(-14 * time.Minute), LastOutcome: certificatelifecycle.RenewalBusy}, due: true, outcome: certificatelifecycle.NeedsAttention, code: "CERTIFICATE-RENEWAL-DUE"},
		{name: "urgent busy retries within fifteen minutes", facts: certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(23 * time.Hour), LastAttempt: now.Add(-14 * time.Minute), LastOutcome: certificatelifecycle.RenewalBusy}, due: true, outcome: certificatelifecycle.NeedsAttention, code: "CERTIFICATE-RENEWAL-DUE"},
		{name: "expiry is failed and immediately due", facts: certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now, LastAttempt: now.Add(-time.Minute), LastOutcome: certificatelifecycle.RenewalFailed}, due: true, outcome: certificatelifecycle.Failed, code: "CERTIFICATE-IP-EXPIRED"},
		{name: "future attempt is unknown", facts: certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(48 * time.Hour), LastAttempt: now.Add(time.Minute), LastOutcome: certificatelifecycle.RenewalBusy}, outcome: certificatelifecycle.Unknown, code: "CERTIFICATE-RENEWAL-TIME"},
		{name: "outcome without attempt is unknown", facts: certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(48 * time.Hour), LastOutcome: certificatelifecycle.RenewalBusy}, outcome: certificatelifecycle.Unknown, code: "CERTIFICATE-RENEWAL-TIME"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := certificatelifecycle.EvaluateIPRenewal(test.facts)
			if decision.Due != test.due || decision.Outcome != test.outcome || decision.Code != test.code {
				t.Fatalf("decision = %+v", decision)
			}
		})
	}
}

func TestSchedulerRunsOnlyOneFreshIPAttemptPerEvaluation(t *testing.T) {
	due, planner, changes := &ipDue{}, &renewalPlanner{}, &busySystemChanges{}
	results := certificatelifecycle.NewScheduler(due, planner, changes).Run()
	if len(results) != 1 || results[0].Lineage != certificatelifecycle.IPLineage || results[0].ChangeSetID != "" || results[0].Apply.Code != "SYSTEM-CHANGES-BUSY" {
		t.Fatalf("results = %+v", results)
	}
	if len(due.calls) != 1 || due.calls[0] != certificatelifecycle.IPLineage || len(planner.calls) != 0 || changes.calls != 1 {
		t.Fatalf("calls = due %v planner %v apply %d", due.calls, planner.calls, changes.calls)
	}
}

func TestStandingIPPolicyPersistsFailureAcrossSchedulerProcesses(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	history := &memoryAttemptHistory{}
	first := certificatelifecycle.NewStandingIPPolicy(certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(48 * time.Hour)}, history)
	planner := &renewalPlanner{}
	results := certificatelifecycle.NewScheduler(first, planner, failedSystemChanges{}).Run()
	if len(results) != 1 || results[0].Error != nil || history.outcome != certificatelifecycle.RenewalFailed || len(planner.calls) != 1 {
		t.Fatalf("first scheduler process = results %+v history %+v calls %v", results, history, planner.calls)
	}
	fiveHoursLater := certificatelifecycle.NewStandingIPPolicy(certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now.Add(5 * time.Hour), NotAfter: now.Add(48 * time.Hour)}, history)
	if fiveHoursLater.Due(certificatelifecycle.IPLineage) || fiveHoursLater.Decision().Code != "CERTIFICATE-RENEWAL-RETRY" {
		t.Fatalf("five-hour decision = %+v", fiveHoursLater.Decision())
	}
	sixHoursLater := certificatelifecycle.NewStandingIPPolicy(certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now.Add(6 * time.Hour), NotAfter: now.Add(48 * time.Hour)}, history)
	if !sixHoursLater.Due(certificatelifecycle.IPLineage) {
		t.Fatalf("six-hour decision = %+v", sixHoursLater.Decision())
	}
}
