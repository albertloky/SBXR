package proxyinstallation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
)

func (h *controlledHost) ClientIdentitySubscriptionReady(_ context.Context, source hostadapter.ServingAuthority, renewal hostadapter.RenewalAuthority) bool {
	return source == h.subscriptionServing && renewal == h.subscriptionRenewal && len(h.subscriptionCredential) == 43 && !h.publicIPDrift
}
func (*controlledHost) UpgradeClientIdentityServingStartup() bool               { return true }
func (*controlledHost) VerifyClientIdentityServingStartup(context.Context) bool { return true }
func (h *controlledHost) PrepareClientIdentitySubscription(s hostadapter.ClientIdentitySubscription, artifact []byte) bool {
	sum := sha256.Sum256(artifact)
	if !s.Valid() || hex.EncodeToString(sum[:]) != s.TargetArtifactSHA256 {
		return false
	}
	h.clientSubscriptionArtifact = bytes.Clone(artifact)
	return true
}
func (h *controlledHost) InspectClientIdentitySubscription(s hostadapter.ClientIdentitySubscription, _ string, required, _ bool) hostadapter.Observation {
	sum := sha256.Sum256(h.clientSubscriptionArtifact)
	return hostadapter.Observation{Observed: true, Accepted: s.Valid() && (!required && len(h.clientSubscriptionArtifact) == 0 || hex.EncodeToString(sum[:]) == s.TargetArtifactSHA256)}
}
func (h *controlledHost) StopClientIdentitySubscription(context.Context) bool {
	h.subscriptionStopped = true
	return true
}
func (h *controlledHost) PublishClientIdentitySubscription(source, target hostadapter.ServingAuthority) bool {
	if h.subscriptionServing != source && h.subscriptionServing != target {
		return false
	}
	h.subscriptionServing = target
	return true
}
func (h *controlledHost) RemoveClientIdentitySubscription(hostadapter.ClientIdentitySubscription) bool {
	h.clientSubscriptionArtifact = nil
	return true
}
func (h *controlledHost) RemoveSubscriptionRepair(context.Context, hostadapter.ServingAuthority, hostadapter.ServingAuthority, *hostadapter.ServingExclusion) bool {
	h.subscriptionPrepared = false
	h.subscriptionStopped = true
	return true
}
func (h *controlledHost) ClientIdentitySubscriptionArtifactMatches(s hostadapter.ClientIdentitySubscription, artifact []byte) bool {
	sum := sha256.Sum256(artifact)
	return hex.EncodeToString(sum[:]) == s.TargetArtifactSHA256 && (len(h.clientSubscriptionArtifact) == 0 || bytes.Equal(artifact, h.clientSubscriptionArtifact))
}

func TestClientIdentityRotationPreservesEnabledSubscription(t *testing.T) {
	host := acceptedHost()
	installation := newInstalledInterface(readyLifecycle{}, host, singboxadapter.New())
	setup := installation.Review(t.Context(), StartSetupAction)
	if result := installation.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Code != SetupComplete {
		t.Fatalf("setup: %s", result.Code)
	}
	enable := installation.Review(t.Context(), EnableSubscriptionAction)
	if result := installation.Execute(t.Context(), *enable.Prepared, Approved, nil); result.Code != SubscriptionEnabled {
		t.Fatalf("enable: %s", result.Code)
	}
	host.subscriptionAbsence = &hostadapter.Observation{Observed: true}
	source, _ := decodeOwnership(host.ownership)
	link := bytes.Clone(installation.Review(t.Context(), ViewDetailsAction).SubscriptionLink)
	configuration := bytes.Clone(host.configuration)
	rotate := installation.Review(t.Context(), RotateClientIdentityAction)
	if rotate.Prepared == nil || !slices.Contains(rotate.LegalActions, RotateClientIdentityAction) {
		t.Fatalf("enabled rotation refused: %s / %s", rotate.Result.Code, rotate.Result.FailedCheck)
	}
	result := installation.Execute(t.Context(), *rotate.Prepared, Approved, func(progress Progress) {
		if len(progress.SubscriptionLink) != 0 || len(progress.ClientConfiguration) != 0 {
			t.Fatal("rotation disclosed credentials")
		}
	})
	if result.Code != ClientIdentityRotated || result.SubscriptionStatus != SubscriptionAvailable || result.ProxyTraffic != ProvedWorking || result.SubscriptionServing != ProvedWorking {
		t.Fatalf("rotation: %s / %s / %s", result.Code, result.FailedCheck, result.SubscriptionStatus)
	}
	target, ok := decodeOwnership(host.ownership)
	if !ok || target.ClientRotation != nil || *source.Serving != *target.Serving || source.Package != target.Package || source.Release != target.Release || bytes.Equal(configuration, host.configuration) {
		t.Fatal("rotation did not preserve subscription and provenance or replace identity")
	}
	if got := installation.Review(t.Context(), ViewDetailsAction).SubscriptionLink; len(link) == 0 || !bytes.Equal(link, got) {
		t.Fatal("Subscription Link changed")
	}
}

func enabledIdentityInstallation(t *testing.T) (Interface, *controlledHost) {
	t.Helper()
	host := acceptedHost()
	m := newInstalledInterface(readyLifecycle{}, host, singboxadapter.New())
	setup := m.Review(t.Context(), StartSetupAction)
	if got := m.Execute(t.Context(), *setup.Prepared, Approved, nil); got.Code != SetupComplete {
		t.Fatal(got.Code)
	}
	enable := m.Review(t.Context(), EnableSubscriptionAction)
	if got := m.Execute(t.Context(), *enable.Prepared, Approved, nil); got.Code != SubscriptionEnabled {
		t.Fatal(got.Code)
	}
	host.subscriptionAbsence = &hostadapter.Observation{Observed: true}
	return m, host
}

func TestEnabledIdentityRotationRecoversEveryDurableCheckpoint(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		for _, checkpoint := range clientIdentityCheckpointPolicies[1:] {
			t.Run(string(checkpoint.checkpoint)+map[bool]string{false: "/available", true: "/renewal-fault"}[unavailable], func(t *testing.T) {
				m, host := enabledIdentityInstallation(t)
				host.renewalProblem = unavailable
				source := bytes.Clone(host.configuration)
				credential := bytes.Clone(host.subscriptionCredential)
				host.failClientCheckpoint = checkpoint.checkpoint
				rotate := m.Review(t.Context(), RotateClientIdentityAction)
				if rotate.Prepared == nil {
					t.Fatal("safe rotation refused")
				}
				if got := m.Execute(t.Context(), *rotate.Prepared, Approved, nil); got.Code != ClientIdentityRotationNeedsFinish {
					t.Fatal(got.Code)
				}
				pending, _ := decodeOwnership(host.ownership)
				for _, action := range []Action{ShowClientConfigurationAction, RotateClientIdentityAction, FinishSubscriptionChangeAction, RotateSubscriptionLinkAction, RepairSubscriptionAction} {
					if got := m.Review(t.Context(), action); got.Prepared != nil {
						t.Fatalf("pending rotation admitted %s", action)
					}
				}
				if got := m.Review(t.Context(), ViewDetailsAction); len(got.SubscriptionLink) == 0 || got.SubscriptionStatus != SubscriptionChangeIncomplete {
					t.Fatal("pending rotation hid consistent link or lost status")
				}
				restarted := newInstalledInterface(readyLifecycle{}, host, singboxadapter.New())
				finish := restarted.Review(t.Context(), FinishClientIdentityAction)
				if finish.Prepared == nil {
					t.Fatalf("finish refused: %s", finish.Result.FailedCheck)
				}
				got := restarted.Execute(t.Context(), *finish.Prepared, Approved, nil)
				want := ClientIdentityRotationCleanedUp
				if pending.ClientRotation.Direction == "forward" {
					want = ClientIdentityRotationFinished
				}
				if got.Code != want {
					t.Fatalf("finish: %s / %s", got.Code, got.FailedCheck)
				}
				if !bytes.Equal(credential, host.subscriptionCredential) || host.subscriptionCredentialCount != 1 || host.renewalProblem != unavailable || len(host.clientSubscriptionArtifact) != 0 {
					t.Fatal("rotation changed link, renewal evidence, or retained staging")
				}
				if (want == ClientIdentityRotationCleanedUp) != bytes.Equal(source, host.configuration) {
					t.Fatal("wrong credential recovery direction")
				}
			})
		}
	}
}

func TestEnabledIdentityRotationPreservesIndependentRenewalFailure(t *testing.T) {
	m, host := enabledIdentityInstallation(t)
	host.renewalProblem = true
	rotate := m.Review(t.Context(), RotateClientIdentityAction)
	if rotate.Prepared == nil || rotate.SubscriptionStatus != SubscriptionProblemDetected {
		t.Fatal("independent fault blocked rotation")
	}
	got := m.Execute(t.Context(), *rotate.Prepared, Approved, nil)
	if got.Code != ClientIdentityRotated || got.SubscriptionStatus != SubscriptionProblemDetected || got.ProxyTraffic != ProvedWorking || !host.renewalProblem {
		t.Fatalf("rotation: %s / %s", got.Code, got.SubscriptionStatus)
	}
}

func TestEnabledIdentityRotationRefusesMissingArtifactAndAllowsRemovalOnBothSides(t *testing.T) {
	for _, effect := range []string{"stop", "start"} {
		t.Run(effect, func(t *testing.T) {
			m, host := enabledIdentityInstallation(t)
			host.renewalProblem = true
			host.clientIdentityFail = effect
			rotate := m.Review(t.Context(), RotateClientIdentityAction)
			m.Execute(t.Context(), *rotate.Prepared, Approved, nil)
			artifact := bytes.Clone(host.clientSubscriptionArtifact)
			host.clientSubscriptionArtifact = []byte("wrong artifact")
			if got := m.Review(t.Context(), FinishClientIdentityAction); got.Prepared != nil {
				t.Fatal("uncertain artifact admitted finishing")
			}
			host.clientSubscriptionArtifact = artifact
			lifecycle := &controlledRemovalLifecycle{ready: true}
			remover := newInstalledInterface(lifecycle, host, singboxadapter.New())
			remove := remover.Review(t.Context(), CompleteRemovalAction)
			if remove.Prepared == nil {
				t.Fatalf("takeover refused: %s", remove.Result.FailedCheck)
			}
			starts := host.subscriptionStarts
			result := remover.Execute(t.Context(), *remove.Prepared, Approved, nil)
			if result.Code != CompleteRemovalCompleted || host.subscriptionStarts != starts || len(host.clientSubscriptionArtifact) != 0 {
				t.Fatalf("removal: %s / %s", result.Code, result.FailedCheck)
			}
		})
	}
}

func TestEnabledIdentityRotationPlanNamesPreservationAndDirectRefresh(t *testing.T) {
	m, _ := enabledIdentityInstallation(t)
	review := m.Review(t.Context(), RotateClientIdentityAction)
	plan := strings.Join(review.Plan, "\n")
	for _, want := range []string{"same Subscription Link", "leaked Subscription Link", "direct connection", "persistent Karing DNS", "renewal failures"} {
		if !strings.Contains(plan, want) {
			t.Fatalf("missing plan instruction %q", want)
		}
	}
}

func TestEnabledIdentityRotationIncorporatesStandingCertificatePublication(t *testing.T) {
	m, host := enabledIdentityInstallation(t)
	certificate := host.subscriptionServing
	certificate.CertificateGeneration++
	certificate.CertificateSHA256 = [4]string{strings.Repeat("6", 64), strings.Repeat("7", 64), strings.Repeat("8", 64), strings.Repeat("9", 64)}
	host.clientPublishedCertificate = &certificate
	rotate := m.Review(t.Context(), RotateClientIdentityAction)
	if rotate.Prepared == nil {
		t.Fatal("standing activation blocked safe rotation")
	}
	got := m.Execute(t.Context(), *rotate.Prepared, Approved, nil)
	if got.Code != ClientIdentityRotated {
		t.Fatalf("rotation: %s / %s", got.Code, got.FailedCheck)
	}
	record, ok := decodeOwnership(host.ownership)
	if !ok || *record.Serving != certificate || record.Activation != nil || record.ClientRotation != nil {
		t.Fatal("certificate publication not incorporated into the single rotation")
	}
	for _, body := range host.checkpoints {
		if _, valid := decodeOwnership(body); !valid {
			t.Fatal("invalid intermediate durable authority")
		}
	}
}

func TestEnabledIdentityRotationCompletesWithExpiredCertificateButNotUncertainArtifact(t *testing.T) {
	m, host := enabledIdentityInstallation(t)
	host.clientCertificateInvalid = true
	rotate := m.Review(t.Context(), RotateClientIdentityAction)
	if rotate.Prepared == nil {
		t.Fatal("independent certificate fault blocked rotation")
	}
	got := m.Execute(t.Context(), *rotate.Prepared, Approved, nil)
	if got.Code != ClientIdentityRotated || got.SubscriptionStatus != SubscriptionProblemDetected || got.ProxyTraffic != ProvedWorking || !host.subscriptionStopped || !host.active {
		t.Fatalf("rotation: %s / %s", got.Code, got.SubscriptionStatus)
	}
}
