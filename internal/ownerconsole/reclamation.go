package ownerconsole

import (
	"context"
	"fmt"
	"sync/atomic"
)

const ReclamationPhrase = "RECLAIM THIS VPS"

type ReclamationOutcomeModule interface {
	ConfirmReclamation(context.Context, PlanIdentity, ReclamationApproval) ChangeReview
}

// ReclamationApproval is opaque, digest-bound, and one-use. Only the genuine
// interactive Owner Console path can construct an approved value.
type ReclamationApproval struct{ cell *reclamationApprovalCell }
type reclamationApprovalCell struct {
	identity PlanIdentity
	digest   string
	used     atomic.Bool
}

func (ReclamationApproval) String() string   { return "Owner Console reclamation approval: redacted" }
func (ReclamationApproval) GoString() string { return "Owner Console reclamation approval: redacted" }
func (ReclamationApproval) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("Owner Console reclamation approval cannot be rendered")
}

func (approval ReclamationApproval) NetworkPolicyReclamationApproval(identity PlanIdentity, digest string) bool {
	return approval.cell != nil && approval.cell.identity == identity && approval.cell.digest == digest && approval.cell.used.CompareAndSwap(false, true)
}
