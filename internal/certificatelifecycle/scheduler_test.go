package certificatelifecycle_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
)

type scheduledChange string

func (change scheduledChange) Identity() string { return string(change) }

type ipDue struct {
	calls []certificatelifecycle.Lineage
	both  bool
}

func (*ipDue) Record(certificatelifecycle.Lineage, certificatelifecycle.ApplyResult) error {
	return nil
}

type memoryAttemptHistory struct {
	lineage certificatelifecycle.Lineage
	at      time.Time
	outcome certificatelifecycle.RenewalAttempt
	found   bool
	loads   []certificatelifecycle.Lineage
}

func (history *memoryAttemptHistory) LoadAttempt(lineage certificatelifecycle.Lineage) (time.Time, certificatelifecycle.RenewalAttempt, bool, error) {
	history.loads = append(history.loads, lineage)
	if history.lineage != lineage {
		return time.Time{}, "", false, nil
	}
	return history.at, history.outcome, history.found, nil
}

func TestRevisionOneSchedulerChecksOnlyTheIPLineage(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	history := &memoryAttemptHistory{}
	policy := certificatelifecycle.NewStandingPolicy(
		certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(100 * time.Hour)},
		certificatelifecycle.DomainRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(24 * time.Hour), RenewalInformation: certificatelifecycle.RenewalInformation{Status: certificatelifecycle.RenewalInformationUnavailable}},
		history,
	)
	results := certificatelifecycle.NewScheduler(policy, serialPlanner{events: &[]string{}}, failedSystemChanges{}).Run()
	if len(results) != 0 || fmt.Sprint(history.loads) != fmt.Sprint([]certificatelifecycle.Lineage{certificatelifecycle.IPLineage}) {
		t.Fatalf("revision 1 renewal = results %+v checks %v", results, history.loads)
	}
}
func (history *memoryAttemptHistory) StoreAttempt(lineage certificatelifecycle.Lineage, at time.Time, outcome certificatelifecycle.RenewalAttempt) error {
	history.lineage, history.at, history.outcome, history.found = lineage, at, outcome, true
	return nil
}
func (history *memoryAttemptHistory) ClearAttempt(lineage certificatelifecycle.Lineage) error {
	if history.lineage == lineage {
		history.lineage, history.at, history.outcome, history.found = "", time.Time{}, "", false
	}
	return nil
}

func (policy *ipDue) Due(lineage certificatelifecycle.Lineage) bool {
	policy.calls = append(policy.calls, lineage)
	return policy.both || lineage == certificatelifecycle.IPLineage
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

type serialPlanner struct{ events *[]string }

func (planner serialPlanner) BuildFresh(lineage certificatelifecycle.Lineage) (certificatelifecycle.ChangeSet, error) {
	identity := "renew-ip"
	if lineage == certificatelifecycle.DomainLineage {
		identity = "renew-domain"
	}
	*planner.events = append(*planner.events, "build "+identity)
	return scheduledChange(identity), nil
}

type serialSystemChanges struct{ events *[]string }

func (changes serialSystemChanges) ApplyFresh(build func() (certificatelifecycle.ChangeSet, error)) certificatelifecycle.ApplyResult {
	change, err := build()
	if err != nil {
		return certificatelifecycle.ApplyResult{Outcome: certificatelifecycle.Refused, Code: "SYSTEM-CHANGES-RENEWAL-PLAN"}
	}
	*changes.events = append(*changes.events, "apply "+change.Identity())
	return certificatelifecycle.ApplyResult{Outcome: certificatelifecycle.Applied, PlanConsumed: true}
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

func TestDomainRenewalPolicyUsesARIOrFifteenDayFallback(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		facts   certificatelifecycle.DomainRenewalFacts
		due     bool
		outcome certificatelifecycle.Outcome
		code    string
	}{
		{name: "ARI window not reached", facts: certificatelifecycle.DomainRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(30 * 24 * time.Hour), RenewalInformation: certificatelifecycle.RenewalInformation{Status: certificatelifecycle.RenewalInformationAvailable, WindowStart: now.Add(time.Hour), WindowEnd: now.Add(2 * time.Hour)}}, outcome: certificatelifecycle.Healthy, code: "CERTIFICATE-RENEWAL-NOT-DUE"},
		{name: "ARI window reached", facts: certificatelifecycle.DomainRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(30 * 24 * time.Hour), RenewalInformation: certificatelifecycle.RenewalInformation{Status: certificatelifecycle.RenewalInformationAvailable, WindowStart: now.Add(-time.Second), WindowEnd: now.Add(time.Hour)}}, due: true, outcome: certificatelifecycle.Healthy, code: "CERTIFICATE-RENEWAL-DUE"},
		{name: "fallback outside fifteen days", facts: certificatelifecycle.DomainRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(15*24*time.Hour + time.Second), RenewalInformation: certificatelifecycle.RenewalInformation{Status: certificatelifecycle.RenewalInformationUnavailable}}, outcome: certificatelifecycle.Healthy, code: "CERTIFICATE-RENEWAL-NOT-DUE"},
		{name: "fallback at fifteen days", facts: certificatelifecycle.DomainRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(15 * 24 * time.Hour), RenewalInformation: certificatelifecycle.RenewalInformation{Status: certificatelifecycle.RenewalInformationUnavailable}}, due: true, outcome: certificatelifecycle.Healthy, code: "CERTIFICATE-RENEWAL-DUE"},
		{name: "malformed ARI fails closed", facts: certificatelifecycle.DomainRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(30 * 24 * time.Hour), RenewalInformation: certificatelifecycle.RenewalInformation{Status: certificatelifecycle.RenewalInformationAvailable, WindowStart: now.Add(time.Hour), WindowEnd: now}}, outcome: certificatelifecycle.Unknown, code: "CERTIFICATE-DOMAIN-ARI"},
		{name: "expired domain is failed and due", facts: certificatelifecycle.DomainRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now, RenewalInformation: certificatelifecycle.RenewalInformation{Status: certificatelifecycle.RenewalInformationUnavailable}}, due: true, outcome: certificatelifecycle.Failed, code: "CERTIFICATE-DOMAIN-EXPIRED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := certificatelifecycle.EvaluateDomainRenewal(test.facts)
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
	if fmt.Sprint(due.calls) != fmt.Sprint([]certificatelifecycle.Lineage{certificatelifecycle.IPLineage, certificatelifecycle.DomainLineage}) || len(planner.calls) != 0 || changes.calls != 1 {
		t.Fatalf("calls = due %v planner %v apply %d", due.calls, planner.calls, changes.calls)
	}
}

func TestSchedulerEvaluatesBothDueLineagesSerially(t *testing.T) {
	var events []string
	due := &ipDue{both: true}
	results := certificatelifecycle.NewScheduler(due, serialPlanner{events: &events}, serialSystemChanges{events: &events}).Run()
	if len(results) != 2 || results[0].Lineage != certificatelifecycle.IPLineage || results[0].ChangeSetID != "renew-ip" || results[1].Lineage != certificatelifecycle.DomainLineage || results[1].ChangeSetID != "renew-domain" {
		t.Fatalf("results = %+v", results)
	}
	if fmt.Sprint(due.calls) != fmt.Sprint([]certificatelifecycle.Lineage{certificatelifecycle.IPLineage, certificatelifecycle.DomainLineage}) || fmt.Sprint(events) != "[build renew-ip apply renew-ip build renew-domain apply renew-domain]" {
		t.Fatalf("serial calls = due %v events %v", due.calls, events)
	}
}

func TestStandingIPPolicyPersistsFailureAcrossSchedulerProcesses(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	history := &memoryAttemptHistory{}
	first := certificatelifecycle.NewStandingPolicy(certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(48 * time.Hour)}, certificatelifecycle.DomainRenewalFacts{}, history)
	planner := &renewalPlanner{}
	results := certificatelifecycle.NewScheduler(first, planner, failedSystemChanges{}).Run()
	if len(results) != 1 || results[0].Error != nil || history.outcome != certificatelifecycle.RenewalFailed || len(planner.calls) != 1 {
		t.Fatalf("first scheduler process = results %+v history %+v calls %v", results, history, planner.calls)
	}
	fiveHoursLater := certificatelifecycle.NewStandingPolicy(certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now.Add(5 * time.Hour), NotAfter: now.Add(48 * time.Hour)}, certificatelifecycle.DomainRenewalFacts{}, history)
	if fiveHoursLater.Due(certificatelifecycle.IPLineage) || fiveHoursLater.Decision(certificatelifecycle.IPLineage).Code != "CERTIFICATE-RENEWAL-RETRY" {
		t.Fatalf("five-hour decision = %+v", fiveHoursLater.Decision(certificatelifecycle.IPLineage))
	}
	sixHoursLater := certificatelifecycle.NewStandingPolicy(certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now.Add(6 * time.Hour), NotAfter: now.Add(48 * time.Hour)}, certificatelifecycle.DomainRenewalFacts{}, history)
	if !sixHoursLater.Due(certificatelifecycle.IPLineage) {
		t.Fatalf("six-hour decision = %+v", sixHoursLater.Decision(certificatelifecycle.IPLineage))
	}
}

func TestStandingPolicyPersistsDomainFailureSeparately(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	history := &memoryAttemptHistory{}
	domainFacts := certificatelifecycle.DomainRenewalFacts{LineageExists: true, StandingPolicyApproved: true, Now: now, NotAfter: now.Add(20 * 24 * time.Hour), RenewalInformation: certificatelifecycle.RenewalInformation{Status: certificatelifecycle.RenewalInformationAvailable, WindowStart: now.Add(-time.Hour), WindowEnd: now.Add(time.Hour)}}
	first := certificatelifecycle.NewStandingPolicy(certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: now, NotAfter: now.Add(100 * time.Hour)}, domainFacts, history)
	results := certificatelifecycle.NewScheduler(first, serialPlanner{events: &[]string{}}, failedSystemChanges{}).Run()
	if len(results) != 1 || results[0].Lineage != certificatelifecycle.DomainLineage || history.lineage != certificatelifecycle.DomainLineage || history.outcome != certificatelifecycle.RenewalFailed {
		t.Fatalf("domain failure = results %+v history %+v", results, history)
	}
	domainFacts.Now = now.Add(5 * time.Hour)
	fiveHoursLater := certificatelifecycle.NewStandingPolicy(certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: domainFacts.Now, NotAfter: now.Add(100 * time.Hour)}, domainFacts, history)
	if fiveHoursLater.Due(certificatelifecycle.DomainLineage) || fiveHoursLater.Decision(certificatelifecycle.DomainLineage).Code != "CERTIFICATE-RENEWAL-RETRY" {
		t.Fatalf("five-hour domain decision = %+v", fiveHoursLater.Decision(certificatelifecycle.DomainLineage))
	}
	domainFacts.Now = now.Add(6 * time.Hour)
	sixHoursLater := certificatelifecycle.NewStandingPolicy(certificatelifecycle.IPRenewalFacts{StandingPolicyApproved: true, Now: domainFacts.Now, NotAfter: now.Add(100 * time.Hour)}, domainFacts, history)
	if !sixHoursLater.Due(certificatelifecycle.DomainLineage) {
		t.Fatalf("six-hour domain decision = %+v", sixHoursLater.Decision(certificatelifecycle.DomainLineage))
	}
}
