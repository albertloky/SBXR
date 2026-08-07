package main

import (
	"errors"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type renewalSystemChanges struct{ changes systemchanges.Interface }

func (adapter renewalSystemChanges) ApplyFresh(build func() (certificatelifecycle.ChangeSet, error)) certificatelifecycle.ApplyResult {
	result := adapter.changes.ApplyFreshCertificateRenewal(func() (*systemchanges.ChangeSet, error) {
		changeSet, err := build()
		if err != nil {
			return nil, err
		}
		change, ok := changeSet.(*systemchanges.ChangeSet)
		if !ok {
			return nil, errors.New("Certificate Lifecycle Change Set unavailable")
		}
		return change, nil
	})
	code := ""
	if result.Finding != nil {
		code = result.Finding.Code
	}
	return certificatelifecycle.ApplyResult{
		Outcome: certificatelifecycle.ApplyOutcome(result.Outcome), PlanConsumed: result.PlanConsumed,
		QueueCreated: result.QueueCreated, RebuildPlan: result.RebuildPlan, Code: code,
	}
}
