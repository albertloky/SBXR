package proxyinstallation

import (
	"context"
	"errors"
	"strings"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
)

type renewalTestHost struct {
	*servingTestHost
	runs, hooks                int
	renewalRemoved             bool
	renewalBusy, renewalUnsafe bool
}

func (h *renewalTestHost) InspectRenewal(hostadapter.RenewalAuthority) hostadapter.RenewalInspection {
	if h.renewalUnsafe {
		return hostadapter.RenewalInspection{State: hostadapter.RenewalAttemptUnsafe}
	}
	return hostadapter.RenewalInspection{Observation: hostadapter.Observation{Observed: true}, State: hostadapter.RenewalAttemptFailed}
}

type activationTestHost struct {
	*renewalTestHost
	published       hostadapter.ServingAuthority
	loaded          hostadapter.ServingAuthority
	activationFails bool
	restarts        int
	publishCalls    int
	failPublishAt   int
	latePublishAt   int
	failSyncAt      int
	renewal         *hostadapter.RenewalInspection
}

func (h *activationTestHost) InspectRenewal(hostadapter.RenewalAuthority) hostadapter.RenewalInspection {
	if h.renewal != nil {
		return *h.renewal
	}
	return hostadapter.RenewalInspection{Observation: hostadapter.Observation{Observed: true, Accepted: true}, State: hostadapter.RenewalAttemptHealthy}
}

func (h *activationTestHost) InspectCertificateActivation(context.Context, hostadapter.RenewalAuthority, hostadapter.ServingAuthority) hostadapter.CertificateActivationInspection {
	return hostadapter.CertificateActivationInspection{
		Published: h.published,
		Loaded:    h.loaded,
		Observed:  true,
		Accepted:  h.published.Valid(),
	}
}

func (h *activationTestHost) ActivateServing(_ context.Context, _ hostadapter.RenewalAuthority, target hostadapter.ServingAuthority) bool {
	h.restarts++
	if h.activationFails {
		return false
	}
	h.loaded = target
	return true
}

func (h *activationTestHost) PublishOwnership(current, next string, expected, body []byte) error {
	h.publishCalls++
	if h.publishCalls == h.failPublishAt {
		return errors.New("activation checkpoint failed")
	}
	err := h.controlledHost.PublishOwnership(current, next, expected, body)
	if err == nil && h.publishCalls == h.latePublishAt {
		if h.publishCalls == h.failSyncAt {
			h.failOwnershipSync = true
		}
		return errors.New("late activation checkpoint failure")
	}
	return err
}

type testRenewalRunner struct{ host *renewalTestHost }

func (r testRenewalRunner) Run(context.Context) int { r.host.runs++; return 0 }
func (testRenewalRunner) Abort()                    {}
func (h *renewalTestHost) PrepareRenewalRecorder(hostadapter.RenewalAuthority) (hostadapter.RenewalAttemptRunner, bool) {
	return testRenewalRunner{host: h}, true
}
func (h *renewalTestHost) RecordRenewalHook(hostadapter.RenewalAuthority, string, map[string]string) bool {
	h.hooks++
	return true
}
func (h *renewalTestHost) AcquireRenewalExclusion(hostadapter.RenewalAuthority) (*hostadapter.RenewalExclusion, bool) {
	return &hostadapter.RenewalExclusion{}, !h.renewalBusy
}
func (h *renewalTestHost) RemoveRenewalIntegration(context.Context, hostadapter.RenewalAuthority, *hostadapter.RenewalExclusion) bool {
	h.renewalRemoved = true
	return true
}
func (h *renewalTestHost) RenewalIntegrationAbsent(hostadapter.RenewalAuthority) bool {
	return h.renewalRemoved
}

func renewalInstallation(t *testing.T) (Interface, *renewalTestHost, *controlledRemovalLifecycle) {
	t.Helper()
	_, serving, lifecycle := servingInstallation(t)
	record, ok := decodeOwnership(serving.ownership)
	if !ok {
		t.Fatal("serving authority invalid")
	}
	record.Renewal = &hostadapter.RenewalAuthority{RecorderID: strings.Repeat("a", 32), Lineage: "sbxr-subscription", PublicIPv4: record.PublicIPv4, Invocation: hostadapter.OfficialRenewalInvocation}
	record.Resources = recordResources(record, false)
	record.ResourceCreatingReleases = nil
	for range record.Resources {
		record.ResourceCreatingReleases = append(record.ResourceCreatingReleases, record.Release)
	}
	serving.ownership = ownershipBytes(record)
	host := &renewalTestHost{servingTestHost: serving}
	return newInstalledInterface(lifecycle, host, acceptedSingBox{}), host, lifecycle
}

func TestManagedRenewalDispatchRequiresExactDurableAuthority(t *testing.T) {
	_, host, lifecycle := renewalInstallation(t)
	if code := recordRenewal(t.Context(), lifecycle, host); code != 0 || host.runs != 1 {
		t.Fatalf("recordRenewal() = %d runs=%d", code, host.runs)
	}
	host.stagedOwnership = []byte("conflicting transaction")
	if code := recordRenewal(t.Context(), lifecycle, host); code != hostadapter.RenewalRecorderRefused || host.runs != 1 {
		t.Fatalf("conflicting recordRenewal() = %d runs=%d", code, host.runs)
	}
}

func TestRenewalEvidenceIsVisibleAndRemovalExcludesWritersBeforeCommit(t *testing.T) {
	m, host, _ := renewalInstallation(t)
	status := m.Review(t.Context(), StatusAction)
	if status.Status != Running || status.SubscriptionStatus != SubscriptionProblemDetected || !strings.Contains(strings.Join(status.Details, "\n"), "Renewal Attempt Evidence: failed") {
		t.Fatalf("Review() = %#v", status)
	}
	review := m.Review(t.Context(), CompleteRemovalAction)
	if review.Prepared == nil {
		t.Fatal("Complete removal not offered")
	}
	before := string(host.ownership)
	host.renewalBusy = true
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != ActionRefused || string(host.ownership) != before {
		t.Fatalf("busy Execute() = %#v", result)
	}
	host.renewalBusy = false
	review = m.Review(t.Context(), CompleteRemovalAction)
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted || !host.renewalRemoved || !host.removed {
		t.Fatalf("Execute() = %#v renewal=%v serving=%v", result, host.renewalRemoved, host.removed)
	}
}

func TestPublishedCertificateReplacementIsReviewedAndFinishedForward(t *testing.T) {
	m, renewal, lifecycle := renewalInstallation(t)
	record, ok := decodeOwnership(renewal.ownership)
	if !ok {
		t.Fatal("renewal authority invalid")
	}
	target := *record.Serving
	target.CertificateGeneration++
	for index := range target.CertificateSHA256 {
		target.CertificateSHA256[index] = strings.Repeat(string(rune('1'+index)), 64)
	}
	host := &activationTestHost{renewalTestHost: renewal, published: target, loaded: *record.Serving}
	m = newInstalledInterface(lifecycle, host, acceptedSingBox{})

	review := m.Review(t.Context(), FinishSubscriptionChangeAction)
	if review.Status != Running || review.SubscriptionStatus != SubscriptionChangeIncomplete || review.Prepared == nil || len(review.LegalActions) != 2 || review.LegalActions[0] != FinishSubscriptionChangeAction {
		t.Fatalf("Review() = %#v", review)
	}
	for _, want := range []string{"generation 1", "generation 2", "Ownership Record", "proved usable"} {
		if !strings.Contains(strings.Join(review.Plan, "\n"), want) {
			t.Fatalf("Plan does not contain %q: %#v", want, review.Plan)
		}
	}
	if result := m.Execute(t.Context(), *review.Prepared, Declined, nil); result.Code != ActionCancelled || host.restarts != 0 {
		t.Fatalf("declined Execute() = %#v restarts=%d", result, host.restarts)
	}

	review = m.Review(t.Context(), FinishSubscriptionChangeAction)
	var phases []string
	result := m.Execute(t.Context(), *review.Prepared, Approved, func(progress Progress) { phases = append(phases, progress.Phase) })
	committed, ok := decodeOwnership(host.ownership)
	if !ok || result.Code != SubscriptionChangeFinished || result.Status != Running || result.SubscriptionStatus != SubscriptionAvailable || result.ProxyTraffic != ProvedWorking || result.SubscriptionServing != ProvedWorking || committed.Serving == nil || *committed.Serving != target || committed.Activation != nil || host.restarts != 1 {
		t.Fatalf("Execute() = %#v record=%#v restarts=%d", result, committed, host.restarts)
	}
	if strings.Join(phases, "|") != "Finishing subscription change|Activating subscription|Verifying subscription result" {
		t.Fatalf("phases = %q", phases)
	}
}

func TestCertificateActivationRefusesAChangedPreparedTarget(t *testing.T) {
	m, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	target := *record.Serving
	target.CertificateGeneration++
	for index := range target.CertificateSHA256 {
		target.CertificateSHA256[index] = strings.Repeat(string(rune('1'+index)), 64)
	}
	host := &activationTestHost{renewalTestHost: renewal, published: target, loaded: *record.Serving}
	m = newInstalledInterface(lifecycle, host, acceptedSingBox{})
	review := m.Review(t.Context(), FinishSubscriptionChangeAction)
	host.published.CertificateGeneration++
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != ActionRefused || host.restarts != 0 {
		t.Fatalf("changed target Execute() = %#v restarts=%d", result, host.restarts)
	}
}

func TestCertificateActivationRequiresDurableLateCheckpointProof(t *testing.T) {
	m, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	target := *record.Serving
	target.CertificateGeneration++
	for index := range target.CertificateSHA256 {
		target.CertificateSHA256[index] = strings.Repeat(string(rune('5'+index)), 64)
	}
	host := &activationTestHost{renewalTestHost: renewal, published: target, loaded: *record.Serving, latePublishAt: 1, failSyncAt: 1}
	m = newInstalledInterface(lifecycle, host, acceptedSingBox{})
	review := m.Review(t.Context(), FinishSubscriptionChangeAction)
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeNeedsCompletion || host.restarts != 0 {
		t.Fatalf("unsynchronized Execute() = %#v restarts=%d", result, host.restarts)
	}
	review = m.Review(t.Context(), FinishSubscriptionChangeAction)
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeNeedsCompletion || host.restarts != 0 {
		t.Fatalf("unsynchronized retry Execute() = %#v restarts=%d", result, host.restarts)
	}
	host.failOwnershipSync = false
	review = m.Review(t.Context(), FinishSubscriptionChangeAction)
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeFinished || host.restarts != 1 {
		t.Fatalf("durable Execute() = %#v restarts=%d", result, host.restarts)
	}
}

func TestLateFinalActivationCheckpointRestoresFinishingAuthority(t *testing.T) {
	m, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	target := *record.Serving
	target.CertificateGeneration++
	for index := range target.CertificateSHA256 {
		target.CertificateSHA256[index] = strings.Repeat(string(rune('1'+index)), 64)
	}
	host := &activationTestHost{renewalTestHost: renewal, published: target, loaded: *record.Serving, latePublishAt: 2, failSyncAt: 2}
	m = newInstalledInterface(lifecycle, host, acceptedSingBox{})
	review := m.Review(t.Context(), FinishSubscriptionChangeAction)
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeNeedsCompletion || host.restarts != 1 {
		t.Fatalf("late final Execute() = %#v restarts=%d", result, host.restarts)
	}
	pending, ok := decodeOwnership(host.ownership)
	if !ok || pending.Activation == nil || pending.Activation.Checkpoint != activationTargetAccepted || pending.Serving == nil || pending.Serving.CertificateGeneration != 2 {
		t.Fatalf("finishing authority = %#v", pending)
	}
	if fresh := newInstalledInterface(lifecycle, host, acceptedSingBox{}).Review(t.Context(), StatusAction); fresh.SubscriptionStatus != SubscriptionChangeIncomplete {
		t.Fatalf("fresh Review() = %#v", fresh)
	}
}

func TestLateActivationMarkerCleanupRequiresDurableProof(t *testing.T) {
	m, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	target := *record.Serving
	target.CertificateGeneration++
	for index := range target.CertificateSHA256 {
		target.CertificateSHA256[index] = strings.Repeat(string(rune('5'+index)), 64)
	}
	host := &activationTestHost{renewalTestHost: renewal, published: target, loaded: *record.Serving, latePublishAt: 3, failSyncAt: 3}
	m = newInstalledInterface(lifecycle, host, acceptedSingBox{})
	review := m.Review(t.Context(), FinishSubscriptionChangeAction)
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionStatusProblemDetected || result.Message != "A subscription problem was detected. View details before continuing." || result.SubscriptionStatus != SubscriptionProblemDetected || result.ProxyTraffic != ProvedWorking || result.SubscriptionServing != ProvedWorking || host.restarts != 1 {
		t.Fatalf("late cleanup Execute() = %#v restarts=%d", result, host.restarts)
	}
}

func TestCertificateActivationRecoversWithoutRepeatingTheLoadedEffect(t *testing.T) {
	m, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	target := *record.Serving
	target.CertificateGeneration++
	for index := range target.CertificateSHA256 {
		target.CertificateSHA256[index] = strings.Repeat(string(rune('5'+index)), 64)
	}
	host := &activationTestHost{renewalTestHost: renewal, published: target, loaded: *record.Serving, failPublishAt: 2}
	m = newInstalledInterface(lifecycle, host, acceptedSingBox{})
	review := m.Review(t.Context(), FinishSubscriptionChangeAction)
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeNeedsCompletion || host.restarts != 1 {
		t.Fatalf("interrupted Execute() = %#v restarts=%d", result, host.restarts)
	}
	pending, ok := decodeOwnership(host.ownership)
	if !ok || pending.Activation == nil || pending.Serving == nil || pending.Serving.CertificateGeneration != 1 {
		t.Fatalf("pending record = %#v", pending)
	}

	host.failPublishAt = 0
	m = newInstalledInterface(lifecycle, host, acceptedSingBox{})
	review = m.Review(t.Context(), FinishSubscriptionChangeAction)
	if review.Prepared == nil {
		t.Fatalf("recovery Review() = %#v", review)
	}
	if !strings.Contains(strings.Join(review.Plan, "\n"), "Do not restart Subscription Serving") {
		t.Fatalf("recovery Plan = %#v", review.Plan)
	}
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeFinished || host.restarts != 1 {
		t.Fatalf("recovery Execute() = %#v restarts=%d", result, host.restarts)
	}
}

func TestExistingActivationRetargetsOneNewerCompatiblePublication(t *testing.T) {
	m, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	second := *record.Serving
	second.CertificateGeneration++
	third := second
	third.CertificateGeneration++
	for index := range second.CertificateSHA256 {
		second.CertificateSHA256[index] = strings.Repeat(string(rune('1'+index)), 64)
		third.CertificateSHA256[index] = strings.Repeat(string(rune('5'+index)), 64)
	}
	record.Activation = &certificateActivation{Source: *record.Serving, Target: second, Checkpoint: activationTargetRecorded}
	renewal.ownership = ownershipBytes(record)
	host := &activationTestHost{renewalTestHost: renewal, published: third, loaded: *record.Serving}
	m = newInstalledInterface(lifecycle, host, acceptedSingBox{})
	review := m.Review(t.Context(), FinishSubscriptionChangeAction)
	if review.Prepared == nil || review.SubscriptionStatus != SubscriptionChangeIncomplete {
		t.Fatalf("retarget Review() = %#v", review)
	}
	if result := m.Execute(t.Context(), *review.Prepared, Approved, nil); result.Code != SubscriptionChangeFinished || host.restarts != 1 {
		t.Fatalf("retarget Execute() = %#v restarts=%d", result, host.restarts)
	}
	committed, ok := decodeOwnership(host.ownership)
	if !ok || committed.Serving == nil || *committed.Serving != third || committed.Activation != nil {
		t.Fatalf("retarget ownership = %#v", committed)
	}
}

func TestDeployHookAttemptsTheProtectedCertificateActivationPath(t *testing.T) {
	_, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	target := *record.Serving
	target.CertificateGeneration++
	for index := range target.CertificateSHA256 {
		target.CertificateSHA256[index] = strings.Repeat(string(rune('9'-index)), 64)
	}
	host := &activationTestHost{renewalTestHost: renewal, published: target, loaded: *record.Serving}
	if !recordRenewalHook(t.Context(), lifecycle, host, hostadapter.RenewalDeployRole, map[string]string{}) {
		t.Fatal("deploy hook refused valid activation")
	}
	committed, ok := decodeOwnership(host.ownership)
	if !ok || host.hooks != 1 || host.restarts != 1 || committed.Serving == nil || *committed.Serving != target || committed.Activation != nil {
		t.Fatalf("hooks=%d restarts=%d record=%#v", host.hooks, host.restarts, committed)
	}
}

func TestLiveRenewalTakesStatusPrecedenceButDeployHookStillActivates(t *testing.T) {
	_, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	target := *record.Serving
	target.CertificateGeneration++
	for index := range target.CertificateSHA256 {
		target.CertificateSHA256[index] = strings.Repeat(string(rune('4'+index)), 64)
	}
	live := hostadapter.RenewalInspection{Observation: hostadapter.Observation{Observed: true, Accepted: true}, State: hostadapter.RenewalAttemptLive}
	host := &activationTestHost{renewalTestHost: renewal, published: target, loaded: *record.Serving, renewal: &live}
	m := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	if review := m.Review(t.Context(), StatusAction); review.SubscriptionStatus != SubscriptionChangeInProgress {
		t.Fatalf("live Review() = %#v", review)
	}
	if !recordRenewalHook(t.Context(), lifecycle, host, hostadapter.RenewalDeployRole, map[string]string{}) || host.restarts != 1 {
		t.Fatalf("deploy hook refused: restarts=%d", host.restarts)
	}
}

func TestStoppedAcceptedSubscriptionIsAProblemNotMissedActivation(t *testing.T) {
	_, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	host := &activationTestHost{renewalTestHost: renewal, published: *record.Serving}
	m := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	if review := m.Review(t.Context(), FinishSubscriptionChangeAction); review.SubscriptionStatus != SubscriptionProblemDetected || review.Prepared != nil {
		t.Fatalf("stopped Review() = %#v", review)
	}
}

func TestSuccessfulOwnedRenewalAndActivationClearsAnEarlierFailure(t *testing.T) {
	_, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	failed := hostadapter.RenewalAttempt{Completion: &hostadapter.RenewalCompletion{ExitCode: 1, OwnedOutcome: "incomplete", LineageAfter: "../../archive/sbxr-subscription/cert1.pem"}}
	renewed := hostadapter.RenewalAttempt{Completion: &hostadapter.RenewalCompletion{OwnedOutcome: "renewed", LineageAfter: "../../archive/sbxr-subscription/cert1.pem"}, DeployHook: &hostadapter.RenewalHookOutcome{Outcome: "succeeded"}, PostHook: &hostadapter.RenewalHookOutcome{Outcome: "succeeded"}}
	inspection := hostadapter.RenewalInspection{Observation: hostadapter.Observation{Observed: true}, State: hostadapter.RenewalAttemptFailed, Evidence: hostadapter.RenewalEvidence{Attempts: []hostadapter.RenewalAttempt{failed, renewed}}}
	host := &activationTestHost{renewalTestHost: renewal, published: *record.Serving, loaded: *record.Serving, renewal: &inspection}
	m := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	if review := m.Review(t.Context(), StatusAction); review.SubscriptionStatus != SubscriptionAvailable {
		t.Fatalf("successful owned renewal remained failed: %#v", review)
	}
	inspection.Evidence.Attempts[1].Completion.OwnedOutcome = "no-op"
	if review := m.Review(t.Context(), StatusAction); review.SubscriptionStatus != SubscriptionProblemDetected {
		t.Fatalf("unrelated no-op cleared failure: %#v", review)
	}
}

func TestInvalidReplacementPreservesTheValidLoadedGeneration(t *testing.T) {
	_, renewal, lifecycle := renewalInstallation(t)
	record, _ := decodeOwnership(renewal.ownership)
	invalid := *record.Serving
	invalid.CertificateSHA256[0] = strings.Repeat("7", 64)
	host := &activationTestHost{renewalTestHost: renewal, published: invalid, loaded: *record.Serving}
	m := newInstalledInterface(lifecycle, host, acceptedSingBox{})
	review := m.Review(t.Context(), FinishSubscriptionChangeAction)
	if review.SubscriptionStatus != SubscriptionProblemDetected || review.SubscriptionServing != ProvedWorking || review.Prepared != nil || host.restarts != 0 {
		t.Fatalf("Review() = %#v restarts=%d", review, host.restarts)
	}
}
