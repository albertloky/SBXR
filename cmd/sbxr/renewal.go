package main

import (
	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type renewalSystemChanges struct{ changes systemchanges.Interface }

func (adapter renewalSystemChanges) Apply(changeSet certificatelifecycle.ChangeSet) certificatelifecycle.ApplyResult {
	change, ok := changeSet.(*systemchanges.ChangeSet)
	if !ok {
		return certificatelifecycle.ApplyResult{Outcome: certificatelifecycle.Refused, Code: "SYSTEM-CHANGES-CHANGE-SET-REQUIRED"}
	}
	result := adapter.changes.Apply(change)
	code := ""
	if result.Finding != nil {
		code = result.Finding.Code
	}
	return certificatelifecycle.ApplyResult{
		Outcome: certificatelifecycle.ApplyOutcome(result.Outcome), PlanConsumed: result.PlanConsumed,
		QueueCreated: result.QueueCreated, RebuildPlan: result.RebuildPlan, Code: code,
	}
}
