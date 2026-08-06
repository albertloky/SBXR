// Package certificatelifecycle owns certificate due and retry policy.
package certificatelifecycle

import (
	"errors"
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

type DuePolicy interface {
	Due(Lineage) bool
	WaitWithinRetryPolicy(Lineage) bool
}

type Planner interface {
	BuildFresh(Lineage) (ChangeSet, error)
}

type SystemChanges interface {
	Apply(ChangeSet) ApplyResult
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

// Run evaluates the two lineages serially. Waiting and retry permission remain
// entirely inside Certificate Lifecycle; each Apply receives a newly built Change Set.
func (scheduler Scheduler) Run() []LineageResult {
	if scheduler.due == nil || scheduler.planner == nil || scheduler.apply == nil {
		return []LineageResult{{Error: errors.New("certificate renewal scheduler is incomplete")}}
	}
	results := make([]LineageResult, 0, 2)
	for _, lineage := range []Lineage{IPLineage, DomainLineage} {
		if !scheduler.due.Due(lineage) {
			continue
		}
		changeSet, err := scheduler.planner.BuildFresh(lineage)
		if err != nil || changeSet == nil || changeSet.Identity() == "" {
			results = append(results, LineageResult{Lineage: lineage, Error: errors.New("fresh renewal Plan unavailable")})
			continue
		}
		result := scheduler.apply.Apply(changeSet)
		if result.Outcome == Deferred && result.RebuildPlan && scheduler.due.WaitWithinRetryPolicy(lineage) {
			rebuilt, rebuildErr := scheduler.planner.BuildFresh(lineage)
			if rebuildErr != nil || rebuilt == nil || rebuilt.Identity() == "" || rebuilt.Identity() == changeSet.Identity() {
				results = append(results, LineageResult{Lineage: lineage, ChangeSetID: changeSet.Identity(), Apply: result, Error: errors.New("contention did not produce a fresh Plan")})
				continue
			}
			changeSet, result = rebuilt, scheduler.apply.Apply(rebuilt)
		}
		results = append(results, LineageResult{Lineage: lineage, ChangeSetID: changeSet.Identity(), Apply: result})
	}
	return results
}
