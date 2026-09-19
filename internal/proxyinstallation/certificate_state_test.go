package proxyinstallation

import (
	"context"
	"fmt"
	"strings"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
)

// Carry the protected serving state independently of the accepted ownership,
// just as the filesystem adapter does. Older doubles omitted this boundary.
type certificateStateHost struct {
	*repairTestHost
	stored           hostadapter.ServingAuthority
	stateFailure     bool
	lateStateFailure bool
}

func (h *certificateStateHost) PublishCertificateServingState(_ hostadapter.RenewalAuthority, source, target hostadapter.ServingAuthority) bool {
	if h.stored != source && h.stored != target {
		return false
	}
	if h.stateFailure {
		return false
	}
	h.stored = target
	return !h.lateStateFailure
}

func TestAcceptedCertificateStatePublicationResumesWithoutAnotherCertificateOrRestart(t *testing.T) {
	for _, action := range []Action{ReplaceSubscriptionCertificateAction, FinishSubscriptionChangeAction} {
		for _, late := range []bool{false, true} {
			t.Run(string(action)+fmt.Sprint(late), func(t *testing.T) {
				_, renewal, lifecycle := renewalInstallation(t)
				record, _ := decodeOwnership(renewal.ownership)
				h := &certificateStateHost{repairTestHost: &repairTestHost{activationTestHost: &activationTestHost{renewalTestHost: renewal, published: *record.Serving, loaded: *record.Serving}}, stored: *record.Serving, stateFailure: !late, lateStateFailure: late}
				if action == FinishSubscriptionChangeAction {
					h.published.CertificateGeneration++
				}
				m := newInstalledInterface(lifecycle, h, acceptedSingBox{})
				review := m.Review(t.Context(), action)
				if review.Prepared == nil {
					t.Fatalf("review: %#v", review.Result)
				}
				if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeNeedsCompletion {
					t.Fatalf("publication failure lost finish authority: %#v", result)
				}
				pending, valid := decodeOwnership(h.ownership)
				if !valid || pending.Serving.CertificateGeneration != 2 || pending.Activation == nil && pending.Repair == nil {
					t.Fatal("accepted checkpoint not retained")
				}
				restarts, requests := h.restarts, h.repairs
				h.stateFailure, h.lateStateFailure = false, false
				m = newInstalledInterface(lifecycle, h, acceptedSingBox{})
				review = m.Review(t.Context(), FinishSubscriptionChangeAction)
				if review.Prepared == nil {
					t.Fatalf("finish review: %#v", review.Result)
				}
				if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeFinished {
					t.Fatalf("finish: %#v", result)
				}
				if h.restarts != restarts || h.repairs != requests || h.stored != *pending.Serving {
					t.Fatal("finishing repeated runtime/certificate work or missed state")
				}
			})
		}
	}
}

func TestExistingAcceptedGenerationMismatchHasReviewedRecovery(t *testing.T) {
	_, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	source := *record.Serving
	record.Serving.CertificateGeneration++
	updateSubscriptionResources(&record, record.Release)
	renewal.ownership = ownershipBytes(record)
	h := &certificateStateHost{repairTestHost: &repairTestHost{activationTestHost: &activationTestHost{renewalTestHost: renewal, published: *record.Serving, loaded: *record.Serving}}, stored: source}
	m := newInstalledInterface(lifecycle, h, acceptedSingBox{})
	before := string(h.ownership)
	review := m.Review(t.Context(), FinishSubscriptionChangeAction)
	if review.Prepared == nil || review.SubscriptionStatus != SubscriptionChangeIncomplete || !strings.Contains(strings.Join(review.Plan, " "), "snapshot for generation 1") {
		t.Fatalf("recovery review: %#v", review)
	}
	if string(h.ownership) != before || h.stored != source {
		t.Fatal("review mutated state")
	}
	if result := m.Execute(t.Context(), *review.Prepared, Declined, nil); result.Code != ActionCancelled || string(h.ownership) != before {
		t.Fatal("decline mutated state")
	}
	review = m.Review(t.Context(), FinishSubscriptionChangeAction)
	h.stored.LinkID = strings.Repeat("f", 32)
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != ActionRefused || string(h.ownership) != before {
		t.Fatal("changed snapshot accepted")
	}
	h.stored = source
	review = m.Review(t.Context(), FinishSubscriptionChangeAction)
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeFinished {
		t.Fatalf("recovery: %#v", result)
	}
	if h.stored != *record.Serving || h.repairs != 0 || h.restarts != 0 {
		t.Fatal("recovery changed certificate/runtime or missed snapshot")
	}
	review = m.Review(t.Context(), CompleteRemovalAction)
	if review.Prepared == nil {
		t.Fatalf("removal review: %#v", review.Result)
	}
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted {
		t.Fatalf("removal: %#v", result)
	}
}

func TestAcceptedRepairFinishRevalidatesLoadedCertificate(t *testing.T) {
	_, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	h := &certificateStateHost{repairTestHost: &repairTestHost{activationTestHost: &activationTestHost{renewalTestHost: renewal, published: *record.Serving, loaded: *record.Serving}}, stored: *record.Serving, stateFailure: true}
	m := newInstalledInterface(lifecycle, h, acceptedSingBox{})
	review := m.Review(t.Context(), ReplaceSubscriptionCertificateAction)
	if review.Prepared == nil {
		t.Fatalf("review: %#v", review.Result)
	}
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeNeedsCompletion {
		t.Fatalf("publication: %#v", result)
	}
	before := string(h.ownership)
	h.stateFailure = false
	h.loaded = hostadapter.ServingAuthority{}
	m = newInstalledInterface(lifecycle, h, acceptedSingBox{})
	review = m.Review(t.Context(), FinishSubscriptionChangeAction)
	if review.Prepared == nil {
		t.Fatalf("finish review: %#v", review.Result)
	}
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeNeedsCompletion || result.FailedCheck != "Accepted certificate verification" || string(h.ownership) != before {
		t.Fatalf("changed runtime was accepted: %#v", result)
	}
	if h.stored != *record.Serving || h.repairs != 1 || h.restarts != 1 {
		t.Fatal("failed finish repeated effects or wrote state")
	}
}

func (h *certificateStateHost) InspectCertificateServingState(target hostadapter.ServingAuthority, _ bool) (hostadapter.ServingAuthority, bool) {
	return h.stored, compatibleCertificateTarget(h.stored, target)
}

func (h *certificateStateHost) InspectServingFiles(a hostadapter.ServingAuthority, _ bool) hostadapter.Observation {
	return hostadapter.Observation{Observed: true, Accepted: a == h.stored}
}

func (h *certificateStateHost) ReadSubscriptionLink(a hostadapter.ServingAuthority, _ string) ([]byte, bool) {
	return []byte("test link"), a == h.stored
}

func TestCertificateAcceptancePublishesStateBeforeLinkAndRemoval(t *testing.T) {
	for _, action := range []Action{ReplaceSubscriptionCertificateAction, FinishSubscriptionChangeAction} {
		t.Run(string(action), func(t *testing.T) {
			_, renewal, lifecycle := renewalInstallation(t)
			record, _ := decodeOwnership(renewal.ownership)
			h := &certificateStateHost{repairTestHost: &repairTestHost{activationTestHost: &activationTestHost{renewalTestHost: renewal, published: *record.Serving, loaded: *record.Serving}}, stored: *record.Serving}
			if action == FinishSubscriptionChangeAction {
				h.published.CertificateGeneration++
			}
			m := newInstalledInterface(lifecycle, h, acceptedSingBox{})
			review := m.Review(t.Context(), action)
			if review.Prepared == nil {
				t.Fatalf("review refused: %#v", review.Result)
			}
			result := m.Execute(context.Background(), *review.Prepared, Approved, nil)
			if result.Code != SubscriptionCertificateReplaced && result.Code != SubscriptionChangeFinished {
				t.Fatalf("execute: %#v", result)
			}
			accepted, _ := decodeOwnership(h.ownership)
			if h.stored != *accepted.Serving {
				t.Fatal("accepted certificate left obsolete serving state")
			}
			if _, ok := h.ReadSubscriptionLink(*accepted.Serving, accepted.PublicIPv4); !ok {
				t.Fatal("accepted link refused")
			}
			review = m.Review(t.Context(), CompleteRemovalAction)
			if review.Prepared == nil {
				t.Fatalf("removal review: %#v", review.Result)
			}
			if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted {
				t.Fatalf("removal: %#v", result)
			}
		})
	}
}
