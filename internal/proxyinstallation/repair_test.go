package proxyinstallation

import (
	"context"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
)

type repairTestHost struct {
	*activationTestHost
	repairs            int
	repairFails        bool
	repairInvalid      bool
	resolveFails       bool
	removalRepairFails bool
	removedRepair      *hostadapter.ServingAuthority
}

func (h *repairTestHost) RepairSubscriptionCertificate(context.Context, hostadapter.RenewalAuthority) bool {
	h.repairs++
	if h.repairFails {
		return false
	}
	h.published.CertificateGeneration++
	for index := range h.published.CertificateSHA256 {
		h.published.CertificateSHA256[index] = strings.Repeat(string(rune('6'+index)), 64)
	}
	if h.repairInvalid {
		h.published.LinkID = strings.Repeat("f", 32)
	}
	return true
}

func (h *repairTestHost) ResolveRenewalFailure(hostadapter.RenewalAuthority, hostadapter.ServingAuthority) bool {
	if h.resolveFails {
		return false
	}
	h.renewal = &hostadapter.RenewalInspection{Observation: hostadapter.Observation{Observed: true, Accepted: true}, State: hostadapter.RenewalAttemptHealthy}
	return true
}

func (h *repairTestHost) RemoveSubscriptionRepair(_ context.Context, _ hostadapter.ServingAuthority, target hostadapter.ServingAuthority, _ *hostadapter.ServingExclusion) bool {
	if h.removalRepairFails {
		return false
	}
	h.removed = true
	h.removedRepair = &target
	return true
}

func TestOwnerReviewsAndExecutesOneRuntimeRepair(t *testing.T) {
	_, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	host := &repairTestHost{activationTestHost: &activationTestHost{renewalTestHost: renewal, published: *record.Serving}}
	host.subscriptionServing = *record.Serving
	host.subscriptionCredential = []byte(strings.Repeat("A", 43))
	m := newInstalledInterface(lifecycle, host, acceptedSingBox{})

	review := m.Review(t.Context(), RepairSubscriptionAction)
	if review.Prepared == nil || !reflect.DeepEqual(review.LegalActions, []Action{RepairSubscriptionAction, ViewDetailsAction, ShowClientConfigurationAction, CompleteRemovalAction, RotateSubscriptionLinkAction}) {
		t.Fatalf("Review() = %#v", review)
	}
	plan := strings.Join(review.Plan, "\n")
	for _, want := range []string{"Action: Repair subscription", "owned Subscription Serving runtime", "restart", "Subscription Link", "Proxy Profile", "Client Identity"} {
		if !strings.Contains(plan, want) {
			t.Fatalf("Plan does not contain %q: %s", want, plan)
		}
	}
	var phases []string
	result := m.Execute(t.Context(), *review.Prepared, Approved, func(progress Progress) { phases = append(phases, progress.Phase) })
	committed, ok := decodeOwnership(host.ownership)
	if !ok || committed.Repair != nil || result.Code != SubscriptionRepaired || result.SubscriptionStatus != SubscriptionAvailable || host.restarts != 1 || host.repairs != 0 {
		t.Fatalf("Execute() = %#v record=%#v restarts=%d repairs=%d", result, committed, host.restarts, host.repairs)
	}
	if strings.Join(phases, "|") != "Checking subscription safety|Repairing subscription serving|Verifying subscription result" {
		t.Fatalf("phases = %q", phases)
	}
}

func TestRepairConfirmationIsSingleUseAndRevalidatesDiagnosedFacts(t *testing.T) {
	_, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	healthy := hostadapter.RenewalInspection{Observation: hostadapter.Observation{Observed: true, Accepted: true}, State: hostadapter.RenewalAttemptHealthy}
	host := &repairTestHost{activationTestHost: &activationTestHost{renewalTestHost: renewal, published: *record.Serving, renewal: &healthy}}
	host.subscriptionServing = *record.Serving
	host.subscriptionCredential = []byte(strings.Repeat("A", 43))
	m := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	review := m.Review(t.Context(), RepairSubscriptionAction)
	if result := m.Execute(t.Context(), *review.Prepared, Declined, nil); result.Code != ActionCancelled || host.restarts != 0 {
		t.Fatalf("declined Execute() = %#v restarts=%d", result, host.restarts)
	}
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != ActionRefused || host.restarts != 0 {
		t.Fatalf("reused Execute() = %#v restarts=%d", result, host.restarts)
	}
	review = m.Review(t.Context(), RepairSubscriptionAction)
	failed := hostadapter.RenewalInspection{Observation: hostadapter.Observation{Observed: true}, State: hostadapter.RenewalAttemptFailed}
	host.renewal = &failed
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != ActionRefused || host.restarts != 0 || host.repairs != 0 {
		t.Fatalf("stale Execute() = %#v restarts=%d repairs=%d", result, host.restarts, host.repairs)
	}
}

func TestOwnerRepairsOneFailedManagedCertificateAttempt(t *testing.T) {
	_, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	for index := range record.ResourceCreatingReleases {
		record.ResourceCreatingReleases[index] = legacyProxyCreator
	}
	renewal.ownership = ownershipBytes(record)
	failed := hostadapter.RenewalInspection{Observation: hostadapter.Observation{Observed: true}, State: hostadapter.RenewalAttemptFailed}
	host := &repairTestHost{activationTestHost: &activationTestHost{renewalTestHost: renewal, published: *record.Serving, loaded: *record.Serving, renewal: &failed}}
	host.subscriptionServing = *record.Serving
	host.subscriptionCredential = []byte(strings.Repeat("A", 43))
	m := newInstalledInterface(lifecycle, host, acceptedSingBox{})

	review := m.Review(t.Context(), RepairSubscriptionAction)
	if review.Prepared == nil || !strings.Contains(strings.Join(review.Plan, "\n"), "Owner-driven managed Certbot replacement attempt") {
		t.Fatalf("Review() = %#v", review)
	}
	var phases []string
	result := m.Execute(t.Context(), *review.Prepared, Approved, func(progress Progress) { phases = append(phases, progress.Phase) })
	committed, ok := decodeOwnership(host.ownership)
	if !ok || committed.Repair != nil || committed.Serving == nil || committed.Serving.CertificateGeneration != 2 || result.Code != SubscriptionRepaired || host.repairs != 1 || host.restarts != 1 {
		t.Fatalf("Execute() = %#v record=%#v repairs=%d restarts=%d", result, committed, host.repairs, host.restarts)
	}
	if strings.Join(phases, "|") != "Checking subscription safety|Renewing subscription certificate|Repairing subscription serving|Verifying subscription result" {
		t.Fatalf("phases = %q", phases)
	}
	for index, resource := range committed.Resources {
		creator := committed.ResourceCreatingReleases[index]
		if strings.Contains(resource, "2.pem") && creator != committed.Release {
			t.Fatalf("replacement resource creator = %#v for %q", creator, resource)
		}
		if strings.Contains(resource, "1.pem") {
			t.Fatalf("obsolete certificate resource retained: %q", resource)
		}
	}
}

func TestRepairEffectFailuresRemainForwardAndRecoverable(t *testing.T) {
	for _, test := range []struct {
		name string
		fail func(*repairTestHost)
		fix  func(*repairTestHost)
	}{
		{"certificate command", func(h *repairTestHost) { h.repairFails = true }, func(h *repairTestHost) { h.repairFails = false }},
		{"renewal evidence resolution", func(h *repairTestHost) { h.resolveFails = true }, func(h *repairTestHost) { h.resolveFails = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, renewal, lifecycle := renewalInstallation(t)
			record, _ := decodeOwnership(renewal.ownership)
			failed := hostadapter.RenewalInspection{Observation: hostadapter.Observation{Observed: true}, State: hostadapter.RenewalAttemptFailed}
			host := &repairTestHost{activationTestHost: &activationTestHost{renewalTestHost: renewal, published: *record.Serving, loaded: *record.Serving, renewal: &failed}}
			host.subscriptionServing = *record.Serving
			host.subscriptionCredential = []byte(strings.Repeat("A", 43))
			test.fail(host)
			module := newInstalledInterface(lifecycle, host, acceptedSingBox{})
			review := module.Review(t.Context(), RepairSubscriptionAction)
			if result := module.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeNeedsCompletion || result.ProxyTraffic != ProvedWorking {
				t.Fatalf("failed Execute() = %#v", result)
			}
			test.fix(host)
			module = newInstalledInterface(lifecycle, host, acceptedSingBox{})
			review = module.Review(t.Context(), FinishSubscriptionChangeAction)
			if result := module.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeFinished {
				t.Fatalf("finished Execute() = %#v", result)
			}
		})
	}
}

func TestRuntimeRepairRefusesRenewalContentionBeforeRestart(t *testing.T) {
	_, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	host := &repairTestHost{activationTestHost: &activationTestHost{renewalTestHost: renewal, published: *record.Serving}}
	host.subscriptionServing = *record.Serving
	host.subscriptionCredential = []byte(strings.Repeat("A", 43))
	host.renewalBusy = true
	module := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	review := module.Review(t.Context(), RepairSubscriptionAction)
	if result := module.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeNeedsCompletion || result.FailedCheck != "Renewal exclusion" || host.restarts != 0 {
		t.Fatalf("Execute() = %#v restarts=%d", result, host.restarts)
	}
}

func TestInvalidPublishedCertificateDoesNotDisturbLoadedGeneration(t *testing.T) {
	_, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	failed := hostadapter.RenewalInspection{Observation: hostadapter.Observation{Observed: true}, State: hostadapter.RenewalAttemptFailed}
	host := &repairTestHost{activationTestHost: &activationTestHost{renewalTestHost: renewal, published: *record.Serving, loaded: *record.Serving, renewal: &failed}, repairInvalid: true}
	host.subscriptionServing = *record.Serving
	host.subscriptionCredential = []byte(strings.Repeat("A", 43))
	module := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	review := module.Review(t.Context(), RepairSubscriptionAction)
	result := module.Execute(t.Context(), *review.Prepared, Approved, nil)
	if result.Code != SubscriptionChangeNeedsCompletion || host.restarts != 0 || host.loaded != *record.Serving || result.ProxyTraffic != ProvedWorking {
		t.Fatalf("Execute() = %#v restarts=%d loaded=%#v", result, host.restarts, host.loaded)
	}
}

func TestFinishRepairCleansPreparationButFinishesCommittedCorrection(t *testing.T) {
	t.Run("prepared", func(t *testing.T) {
		_, renewal, lifecycle := renewalInstallation(t)
		record, _ := decodeOwnership(renewal.ownership)
		host := &repairTestHost{activationTestHost: &activationTestHost{renewalTestHost: renewal, published: *record.Serving, failPublishAt: 2}}
		host.subscriptionServing = *record.Serving
		host.subscriptionCredential = []byte(strings.Repeat("A", 43))
		m := newInstalledInterface(lifecycle, host, acceptedSingBox{})
		review := m.Review(t.Context(), RepairSubscriptionAction)
		if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeNeedsCompletion {
			t.Fatalf("interrupted Execute() = %#v", result)
		}
		host.failPublishAt = 0
		m = newInstalledInterface(lifecycle, host, acceptedSingBox{})
		review = m.Review(t.Context(), FinishSubscriptionChangeAction)
		if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeCleanedUp || host.restarts != 0 || host.repairs != 0 {
			t.Fatalf("cleanup Execute() = %#v restarts=%d repairs=%d", result, host.restarts, host.repairs)
		}
	})

	t.Run("committed", func(t *testing.T) {
		_, renewal, lifecycle := renewalInstallation(t)
		record, _ := decodeOwnership(renewal.ownership)
		host := &repairTestHost{activationTestHost: &activationTestHost{renewalTestHost: renewal, published: *record.Serving, activationFails: true}}
		host.subscriptionServing = *record.Serving
		host.subscriptionCredential = []byte(strings.Repeat("A", 43))
		m := newInstalledInterface(lifecycle, host, acceptedSingBox{})
		review := m.Review(t.Context(), RepairSubscriptionAction)
		if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeNeedsCompletion {
			t.Fatalf("interrupted Execute() = %#v", result)
		}
		host.activationFails = false
		m = newInstalledInterface(lifecycle, host, acceptedSingBox{})
		review = m.Review(t.Context(), FinishSubscriptionChangeAction)
		if review.Prepared == nil || !strings.Contains(strings.Join(review.Plan, "\n"), "finish forward") {
			t.Fatalf("finish Review() = %#v", review)
		}
		if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeFinished || host.restarts != 2 {
			t.Fatalf("finish Execute() = %#v restarts=%d", result, host.restarts)
		}
	})
}

func TestEveryRepairPublicationFailureKeepsOneLegalRecoveryDirection(t *testing.T) {
	for failAt := 1; failAt <= 5; failAt++ {
		t.Run(strconv.Itoa(failAt), func(t *testing.T) {
			_, renewal, lifecycle := renewalInstallation(t)
			record, _ := decodeOwnership(renewal.ownership)
			host := &repairTestHost{activationTestHost: &activationTestHost{renewalTestHost: renewal, published: *record.Serving, failPublishAt: failAt}}
			host.subscriptionServing = *record.Serving
			host.subscriptionCredential = []byte(strings.Repeat("A", 43))
			m := newInstalledInterface(lifecycle, host, acceptedSingBox{})
			review := m.Review(t.Context(), RepairSubscriptionAction)
			_ = m.Execute(t.Context(), *review.Prepared, Approved, nil)
			host.failPublishAt = 0
			for attempt := 0; attempt < 3; attempt++ {
				m = newInstalledInterface(lifecycle, host, acceptedSingBox{})
				status := m.Review(t.Context(), StatusAction)
				if status.SubscriptionStatus == SubscriptionAvailable {
					break
				}
				action := RepairSubscriptionAction
				if status.SubscriptionStatus == SubscriptionChangeIncomplete {
					action = FinishSubscriptionChangeAction
				}
				review = m.Review(t.Context(), action)
				if review.Prepared == nil {
					t.Fatalf("no recovery action after publication %d: %#v", failAt, review)
				}
				_ = m.Execute(t.Context(), *review.Prepared, Approved, nil)
			}
			final := newInstalledInterface(lifecycle, host, acceptedSingBox{}).Review(t.Context(), StatusAction)
			committed, ok := decodeOwnership(host.ownership)
			if !ok || committed.Repair != nil || final.SubscriptionStatus != SubscriptionAvailable || !host.active {
				t.Fatalf("publication %d final=%#v record=%#v active=%v", failAt, final, committed, host.active)
			}
		})
	}
}

func TestCompleteRemovalTakesOverCommittedRepairWithoutStartingIt(t *testing.T) {
	_, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	host := &repairTestHost{activationTestHost: &activationTestHost{renewalTestHost: renewal, published: *record.Serving, activationFails: true}}
	host.subscriptionServing = *record.Serving
	host.subscriptionCredential = []byte(strings.Repeat("A", 43))
	m := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	review := m.Review(t.Context(), RepairSubscriptionAction)
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeNeedsCompletion {
		t.Fatalf("repair Execute() = %#v", result)
	}
	restarts := host.restarts
	m = newInstalledInterface(lifecycle, host, acceptedSingBox{})
	review = m.Review(t.Context(), CompleteRemovalAction)
	if review.Prepared == nil {
		t.Fatalf("removal Review() = %#v", review)
	}
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted || !host.removed || !host.renewalRemoved || host.restarts != restarts {
		t.Fatalf("removal Execute() = %#v serving=%v renewal=%v restarts=%d", result, host.removed, host.renewalRemoved, host.restarts)
	}
}

func TestCompleteRemovalTakesOverPublishedCertificateRepairWithoutActivation(t *testing.T) {
	for _, failAt := range []int{4, 5} {
		t.Run(strconv.Itoa(failAt), func(t *testing.T) {
			_, renewal, lifecycle := renewalInstallation(t)
			record, _ := decodeOwnership(renewal.ownership)
			failed := hostadapter.RenewalInspection{Observation: hostadapter.Observation{Observed: true}, State: hostadapter.RenewalAttemptFailed}
			host := &repairTestHost{activationTestHost: &activationTestHost{renewalTestHost: renewal, published: *record.Serving, loaded: *record.Serving, renewal: &failed, failPublishAt: failAt}}
			host.subscriptionServing = *record.Serving
			host.subscriptionCredential = []byte(strings.Repeat("A", 43))
			module := newInstalledInterface(lifecycle, host, acceptedSingBox{})
			review := module.Review(t.Context(), RepairSubscriptionAction)
			if result := module.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeNeedsCompletion && result.Code != SubscriptionStatusProblemDetected {
				t.Fatalf("repair Execute() = %#v", result)
			}
			pending, ok := decodeOwnership(host.ownership)
			if !ok || pending.Repair == nil || pending.Repair.Target == nil || pending.Repair.Target.CertificateGeneration != 2 {
				t.Fatalf("pending repair = %#v", pending.Repair)
			}
			restarts := host.restarts
			host.failPublishAt = 0
			module = newInstalledInterface(lifecycle, host, acceptedSingBox{})
			review = module.Review(t.Context(), CompleteRemovalAction)
			if result := module.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted || host.removedRepair == nil || host.removedRepair.CertificateGeneration != 2 || host.restarts != restarts {
				t.Fatalf("removal Execute() = %#v target=%#v restarts=%d", result, host.removedRepair, host.restarts)
			}
		})
	}
}

func TestRepairAuthorityValidationRejectsChangedEffectsAndTargets(t *testing.T) {
	_, renewal, _ := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	target := *record.Serving
	operation := subscriptionRepair{OperationID: strings.Repeat("1", 32), Kind: "repair subscription", Direction: "forward", Correction: repairRuntime, Effects: []string{"restart owned serving runtime"}, Checkpoint: repairCommitted, Source: *record.Serving, Target: &target}
	record.Repair = &operation
	if _, ok := decodeOwnership(ownershipBytes(record)); !ok {
		t.Fatal("valid repair authority refused")
	}
	for _, mutate := range []func(*subscriptionRepair){
		func(repair *subscriptionRepair) { repair.Effects = []string{"restart proxy"} },
		func(repair *subscriptionRepair) { repair.Direction = "cleanup" },
		func(repair *subscriptionRepair) { repair.Target.CertificateGeneration++ },
	} {
		changed := operation
		changed.Effects = slices.Clone(operation.Effects)
		copyTarget := *operation.Target
		changed.Target = &copyTarget
		mutate(&changed)
		record.Repair = &changed
		if _, ok := decodeOwnership(ownershipBytes(record)); ok {
			t.Fatalf("changed repair authority accepted: %#v", changed)
		}
	}
}
