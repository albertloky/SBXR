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

type RenewalDecision struct {
	Due     bool
	Outcome Outcome
	Code    string
}

type AttemptHistory interface {
	LoadIPAttempt() (time.Time, RenewalAttempt, bool, error)
	StoreIPAttempt(time.Time, RenewalAttempt) error
	ClearIPAttempt() error
}

type StandingIPPolicy struct {
	facts    IPRenewalFacts
	history  AttemptHistory
	decision RenewalDecision
}

func NewStandingIPPolicy(facts IPRenewalFacts, history AttemptHistory) *StandingIPPolicy {
	return &StandingIPPolicy{facts: facts, history: history}
}

func (policy *StandingIPPolicy) Due(lineage Lineage) bool {
	if policy == nil || lineage != IPLineage || policy.history == nil {
		return false
	}
	last, outcome, found, err := policy.history.LoadIPAttempt()
	if err != nil {
		policy.decision = RenewalDecision{Outcome: Unknown, Code: "CERTIFICATE-RENEWAL-HISTORY"}
		return false
	}
	facts := policy.facts
	if found {
		facts.LastAttempt, facts.LastOutcome = last, outcome
	}
	policy.decision = EvaluateIPRenewal(facts)
	return policy.decision.Due
}

func (policy *StandingIPPolicy) Record(lineage Lineage, result ApplyResult) error {
	if policy == nil || lineage != IPLineage || policy.history == nil {
		return errors.New("IP renewal history unavailable")
	}
	if result.Outcome == Applied {
		return policy.history.ClearIPAttempt()
	}
	outcome := RenewalFailed
	if result.Outcome == Deferred && result.Code == "SYSTEM-CHANGES-BUSY" {
		outcome = RenewalBusy
	}
	return policy.history.StoreIPAttempt(policy.facts.Now, outcome)
}

func (policy *StandingIPPolicy) Decision() RenewalDecision {
	if policy == nil {
		return RenewalDecision{Outcome: Unknown, Code: "CERTIFICATE-RENEWAL-POLICY"}
	}
	return policy.decision
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
	retry := time.Duration(0)
	code := "CERTIFICATE-RENEWAL-RETRY"
	switch facts.LastOutcome {
	case RenewalFailed:
		retry = 6 * time.Hour
	case RenewalBusy:
		if !facts.Now.After(facts.LastAttempt) {
			return RenewalDecision{Outcome: NeedsAttention, Code: "CERTIFICATE-RENEWAL-BUSY"}
		}
	}
	if retry > 0 && !facts.LastAttempt.IsZero() {
		if facts.Now.Sub(facts.LastAttempt) < retry {
			return RenewalDecision{Outcome: NeedsAttention, Code: code}
		}
	}
	outcome := Healthy
	if facts.LastOutcome != "" {
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

// Run evaluates the IP lineage once. The one persistent timer calls Run again
// when Certificate Lifecycle's retry policy permits another fresh attempt.
func (scheduler Scheduler) Run() []LineageResult {
	if scheduler.due == nil || scheduler.planner == nil || scheduler.apply == nil {
		return []LineageResult{{Error: errors.New("certificate renewal scheduler is incomplete")}}
	}
	if !scheduler.due.Due(IPLineage) {
		return nil
	}
	changeSetID := ""
	result := scheduler.apply.ApplyFresh(func() (ChangeSet, error) {
		changeSet, err := scheduler.planner.BuildFresh(IPLineage)
		if err != nil || changeSet == nil || changeSet.Identity() == "" {
			return nil, errors.New("fresh renewal Plan unavailable")
		}
		changeSetID = changeSet.Identity()
		return changeSet, nil
	})
	recordErr := scheduler.due.Record(IPLineage, result)
	return []LineageResult{{Lineage: IPLineage, ChangeSetID: changeSetID, Apply: result, Error: recordErr}}
}
