// Package certificatelifecycle owns certificate due and retry policy.
package certificatelifecycle

import (
	"errors"
	"time"
)

type Lineage string

const (
	IPLineage     Lineage = "IP certificate"
	DomainLineage Lineage = "Domain certificate"
)

type ChangeSet interface {
	Identity() string
}

type ApplyOutcome string

const (
	Applied  ApplyOutcome = "Completed"
	Deferred ApplyOutcome = "Deferred"
	Refused  ApplyOutcome = "Refused"
)

type ApplyResult struct {
	Outcome      ApplyOutcome
	PlanConsumed bool
	QueueCreated bool
	RebuildPlan  bool
	Code         string
}

type RenewalAttempt string

const (
	RenewalFailed RenewalAttempt = "failed"
	RenewalBusy   RenewalAttempt = "busy"
)

type IPRenewalFacts struct {
	StandingPolicyApproved bool
	Now, NotAfter          time.Time
	LastAttempt            time.Time
	LastOutcome            RenewalAttempt
}

type RenewalInformationStatus string

const (
	RenewalInformationAvailable   RenewalInformationStatus = "available"
	RenewalInformationUnavailable RenewalInformationStatus = "unavailable"
	RenewalInformationInvalid     RenewalInformationStatus = "invalid"
)

type RenewalInformation struct {
	Status                 RenewalInformationStatus
	WindowStart, WindowEnd time.Time
}

type DomainRenewalFacts struct {
	LineageExists          bool
	StandingPolicyApproved bool
	Now, NotAfter          time.Time
	RenewalInformation     RenewalInformation
	LastAttempt            time.Time
	LastOutcome            RenewalAttempt
}

type RenewalDecision struct {
	Due     bool
	Outcome Outcome
	Code    string
}

type AttemptHistory interface {
	LoadAttempt(Lineage) (time.Time, RenewalAttempt, bool, error)
	StoreAttempt(Lineage, time.Time, RenewalAttempt) error
	ClearAttempt(Lineage) error
}

type StandingPolicy struct {
	lineages map[Lineage]*standingLineagePolicy
	history  AttemptHistory
}

type standingLineagePolicy struct {
	now      time.Time
	evaluate func(time.Time, RenewalAttempt, bool) RenewalDecision
	decision RenewalDecision
}

func NewStandingPolicy(ip IPRenewalFacts, domain DomainRenewalFacts, history AttemptHistory) *StandingPolicy {
	policy := &StandingPolicy{history: history, lineages: map[Lineage]*standingLineagePolicy{
		IPLineage: {now: ip.Now, evaluate: func(last time.Time, outcome RenewalAttempt, found bool) RenewalDecision {
			if found {
				ip.LastAttempt, ip.LastOutcome = last, outcome
			}
			return EvaluateIPRenewal(ip)
		}},
	}}
	if domain.LineageExists {
		policy.lineages[DomainLineage] = &standingLineagePolicy{now: domain.Now, evaluate: func(last time.Time, outcome RenewalAttempt, found bool) RenewalDecision {
			if found {
				domain.LastAttempt, domain.LastOutcome = last, outcome
			}
			return EvaluateDomainRenewal(domain)
		}}
	}
	return policy
}

func (policy *StandingPolicy) Due(lineage Lineage) bool {
	if policy == nil || policy.history == nil {
		return false
	}
	lineagePolicy := policy.lineages[lineage]
	if lineagePolicy == nil {
		return false
	}
	last, outcome, found, err := policy.history.LoadAttempt(lineage)
	if err != nil {
		lineagePolicy.decision = RenewalDecision{Outcome: Unknown, Code: "CERTIFICATE-RENEWAL-HISTORY"}
		return false
	}
	lineagePolicy.decision = lineagePolicy.evaluate(last, outcome, found)
	return lineagePolicy.decision.Due
}

func (policy *StandingPolicy) Record(lineage Lineage, result ApplyResult) error {
	if policy == nil || policy.history == nil || policy.lineages[lineage] == nil {
		return errors.New("certificate renewal history unavailable")
	}
	if result.Outcome == Applied {
		return policy.history.ClearAttempt(lineage)
	}
	outcome := RenewalFailed
	if result.Outcome == Deferred && result.Code == "SYSTEM-CHANGES-BUSY" {
		outcome = RenewalBusy
	}
	return policy.history.StoreAttempt(lineage, policy.lineages[lineage].now, outcome)
}

func (policy *StandingPolicy) Decision(lineage Lineage) RenewalDecision {
	if policy == nil || policy.lineages[lineage] == nil {
		return RenewalDecision{Outcome: Unknown, Code: "CERTIFICATE-RENEWAL-POLICY"}
	}
	return policy.lineages[lineage].decision
}

func EvaluateIPRenewal(facts IPRenewalFacts) RenewalDecision {
	if !facts.StandingPolicyApproved {
		return RenewalDecision{Outcome: Failed, Code: "CERTIFICATE-RENEWAL-POLICY"}
	}
	remaining := facts.NotAfter.Sub(facts.Now)
	if facts.Now.IsZero() || facts.NotAfter.IsZero() || facts.LastAttempt.After(facts.Now) || facts.LastAttempt.IsZero() != (facts.LastOutcome == "") || facts.LastOutcome != "" && facts.LastOutcome != RenewalFailed && facts.LastOutcome != RenewalBusy {
		return RenewalDecision{Outcome: Unknown, Code: "CERTIFICATE-RENEWAL-TIME"}
	}
	if remaining <= 0 {
		return RenewalDecision{Due: true, Outcome: Failed, Code: "CERTIFICATE-IP-EXPIRED"}
	}
	if !ipRenewalDue(facts.Now, facts.NotAfter) {
		return RenewalDecision{Outcome: Healthy, Code: "CERTIFICATE-RENEWAL-NOT-DUE"}
	}
	if remaining < 24*time.Hour && facts.LastOutcome == "" {
		return RenewalDecision{Due: true, Outcome: NeedsAttention, Code: "CERTIFICATE-IP-EXPIRY-WARNING"}
	}
	return renewalDueDecision(facts.Now, facts.LastAttempt, facts.LastOutcome)
}

func EvaluateDomainRenewal(facts DomainRenewalFacts) RenewalDecision {
	if !facts.StandingPolicyApproved {
		return RenewalDecision{Outcome: Failed, Code: "CERTIFICATE-RENEWAL-POLICY"}
	}
	if facts.Now.IsZero() || facts.NotAfter.IsZero() || facts.LastAttempt.After(facts.Now) || facts.LastAttempt.IsZero() != (facts.LastOutcome == "") || facts.LastOutcome != "" && facts.LastOutcome != RenewalFailed && facts.LastOutcome != RenewalBusy {
		return RenewalDecision{Outcome: Unknown, Code: "CERTIFICATE-RENEWAL-TIME"}
	}
	if !facts.Now.Before(facts.NotAfter) {
		return RenewalDecision{Due: true, Outcome: Failed, Code: "CERTIFICATE-DOMAIN-EXPIRED"}
	}
	due := false
	switch facts.RenewalInformation.Status {
	case RenewalInformationAvailable:
		window := facts.RenewalInformation
		if window.WindowStart.IsZero() || window.WindowEnd.IsZero() || !window.WindowStart.Before(window.WindowEnd) {
			return RenewalDecision{Outcome: Unknown, Code: "CERTIFICATE-DOMAIN-ARI"}
		}
		due = !facts.Now.Before(window.WindowStart)
	case RenewalInformationUnavailable:
		due = facts.NotAfter.Sub(facts.Now) <= 15*24*time.Hour
	default:
		return RenewalDecision{Outcome: Unknown, Code: "CERTIFICATE-DOMAIN-ARI"}
	}
	if !due {
		return RenewalDecision{Outcome: Healthy, Code: "CERTIFICATE-RENEWAL-NOT-DUE"}
	}
	return renewalDueDecision(facts.Now, facts.LastAttempt, facts.LastOutcome)
}

func renewalDueDecision(now, lastAttempt time.Time, lastOutcome RenewalAttempt) RenewalDecision {
	if lastOutcome == RenewalFailed && now.Sub(lastAttempt) < 6*time.Hour {
		return RenewalDecision{Outcome: NeedsAttention, Code: "CERTIFICATE-RENEWAL-RETRY"}
	}
	if lastOutcome == RenewalBusy && !now.After(lastAttempt) {
		return RenewalDecision{Outcome: NeedsAttention, Code: "CERTIFICATE-RENEWAL-BUSY"}
	}
	outcome := Healthy
	if lastOutcome != "" {
		outcome = NeedsAttention
	}
	return RenewalDecision{Due: true, Outcome: outcome, Code: "CERTIFICATE-RENEWAL-DUE"}
}

func ipRenewalDue(now, notAfter time.Time) bool {
	return notAfter.Sub(now) <= 72*time.Hour
}

type DuePolicy interface {
	Due(Lineage) bool
	Record(Lineage, ApplyResult) error
}

type Planner interface {
	BuildFresh(Lineage) (ChangeSet, error)
}

type SystemChanges interface {
	ApplyFresh(func() (ChangeSet, error)) ApplyResult
}

type Scheduler struct {
	due     DuePolicy
	planner Planner
	apply   SystemChanges
}

func NewScheduler(due DuePolicy, planner Planner, apply SystemChanges) Scheduler {
	return Scheduler{due: due, planner: planner, apply: apply}
}

type LineageResult struct {
	Lineage     Lineage
	ChangeSetID string
	Apply       ApplyResult
	Error       error
}

// Run evaluates both fixed lineages serially. Each due lineage obtains the
// System Changes lock separately and builds only after that lock is held.
func (scheduler Scheduler) Run() []LineageResult {
	if scheduler.due == nil || scheduler.planner == nil || scheduler.apply == nil {
		return []LineageResult{{Error: errors.New("certificate renewal scheduler is incomplete")}}
	}
	var results []LineageResult
	for _, lineage := range []Lineage{IPLineage, DomainLineage} {
		if !scheduler.due.Due(lineage) {
			continue
		}
		changeSetID := ""
		result := scheduler.apply.ApplyFresh(func() (ChangeSet, error) {
			changeSet, err := scheduler.planner.BuildFresh(lineage)
			if err != nil || changeSet == nil || changeSet.Identity() == "" {
				return nil, errors.New("fresh renewal Plan unavailable")
			}
			changeSetID = changeSet.Identity()
			return changeSet, nil
		})
		recordErr := scheduler.due.Record(lineage, result)
		results = append(results, LineageResult{Lineage: lineage, ChangeSetID: changeSetID, Apply: result, Error: recordErr})
	}
	return results
}
