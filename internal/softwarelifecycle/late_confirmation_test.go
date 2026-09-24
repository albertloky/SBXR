package softwarelifecycle

import (
	"strings"
	"testing"
)

func TestLateConfirmationOneTargetAndReview(t *testing.T) {
	support := &ReleaseSupport{Scope: SubscriptionCleanInstallRepair, Contract: SubscriptionUpdateContract, Sources: []ReleaseIdentity{}}
	if p, ok := QualificationException(LateConfirmationTag, LateConfirmationSequence, support); !ok || p.ID != LateConfirmationID {
		t.Fatal("approved target refused")
	}
	for _, tag := range []string{"v3.1.80", "v3.1.82", ""} {
		if _, ok := QualificationException(tag, LateConfirmationSequence, support); ok {
			t.Fatal("other tag")
		}
	}
	for _, seq := range []uint64{0, 158, 160} {
		if _, ok := QualificationException(LateConfirmationTag, seq, support); ok {
			t.Fatal("other sequence")
		}
	}
	if _, ok := QualificationException(LateConfirmationTag, LateConfirmationSequence, nil); ok {
		t.Fatal("missing support")
	}
	support.Scope = FirstSubscriptionCleanInstall
	if _, ok := QualificationException(LateConfirmationTag, LateConfirmationSequence, support); ok {
		t.Fatal("wrong scope")
	}
	r := LateConfirmationReview{BaseCommit: LateConfirmationBase, PolicyDiffSHA256: strings.Repeat("b", 64), Reviewer: "Codex source comparison; Owner-approved exception", RuntimeTreeSHA256: LateConfirmationRuntimeTree, SupplementSHA256: LateConfirmationSupplement, TargetCommit: strings.Repeat("a", 40), TargetSequence: LateConfirmationSequence, TargetTag: LateConfirmationTag}
	if !r.Valid(r.TargetCommit) {
		t.Fatal("review refused")
	}
	if r.Valid(LateConfirmationBase) || r.Valid(strings.Repeat("c", 40)) {
		t.Fatal("unbound source")
	}
	for name, mutate := range map[string]func(*LateConfirmationReview){
		"runtime":  func(v *LateConfirmationReview) { v.RuntimeTreeSHA256 = strings.Repeat("c", 64) },
		"evidence": func(v *LateConfirmationReview) { v.SupplementSHA256 = strings.Repeat("c", 64) },
		"target":   func(v *LateConfirmationReview) { v.TargetTag = "v3.1.82" },
		"reviewer": func(v *LateConfirmationReview) { v.Reviewer = "Owner signed" },
		"diff":     func(v *LateConfirmationReview) { v.PolicyDiffSHA256 = "" },
	} {
		t.Run(name, func(t *testing.T) {
			v := r
			mutate(&v)
			if v.Valid(r.TargetCommit) {
				t.Fatal("invalid review")
			}
		})
	}
}
