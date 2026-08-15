package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type clientAccessProfilePlanStub struct {
	identity, sha string
	steps         []systemchanges.Step
	checks        []systemchanges.Check
}

func (stub clientAccessProfilePlanStub) Identity() string { return stub.identity }
func (stub clientAccessProfilePlanStub) SHA256() string   { return stub.sha }
func (stub clientAccessProfilePlanStub) Steps() []systemchanges.Step {
	return append([]systemchanges.Step(nil), stub.steps...)
}
func (stub clientAccessProfilePlanStub) Checks() []systemchanges.Check {
	return append([]systemchanges.Check(nil), stub.checks...)
}
func (clientAccessProfilePlanStub) ValidateConnectionProfiles(state.ConnectionProfiles, state.ConnectionProfileSecretReader) error {
	return nil
}
func (clientAccessProfilePlanStub) PrepareConnectionProfiles(state.ConnectionProfiles, state.ConnectionProfileSecretReader) ([]byte, []byte, error) {
	return []byte(`{"inbounds":[]}`), []byte(`{"inbounds":[]}`), nil
}

type clientAccessPublicationPlanStub struct {
	identity, sha string
	steps         []systemchanges.Step
	checks        []systemchanges.Check
}

func (stub clientAccessPublicationPlanStub) Identity() string { return stub.identity }
func (stub clientAccessPublicationPlanStub) SHA256() string   { return stub.sha }
func (stub clientAccessPublicationPlanStub) Steps() []systemchanges.Step {
	return append([]systemchanges.Step(nil), stub.steps...)
}
func (stub clientAccessPublicationPlanStub) Checks() []systemchanges.Check {
	return append([]systemchanges.Check(nil), stub.checks...)
}
func (clientAccessPublicationPlanStub) ValidateSubscription(state.SubscriptionSettings, state.ClientAccessReader) error {
	return nil
}
func (clientAccessPublicationPlanStub) PrepareSubscriptionPublication() ([]byte, error) {
	return []byte("bundle"), nil
}

func TestClientAccessPlanBindsCorePublicationAndStateIntoOneChangeSet(t *testing.T) {
	profileStep, err := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	publicationStep, err := systemchanges.NewStep(systemchanges.SubscriptionModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	profile := clientAccessProfilePlanStub{"profile-plan", strings.Repeat("a", 64), []systemchanges.Step{profileStep}, []systemchanges.Check{{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-AGREEMENT"}}}
	publication := clientAccessPublicationPlanStub{"publication-plan", strings.Repeat("b", 64), []systemchanges.Step{publicationStep}, []systemchanges.Check{{Owner: systemchanges.SubscriptionModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "SUBSCRIPTION-PUBLICATION-AGREEMENT"}}}

	plan, err := newClientAccessPlan("change-0008", clientAccessRotateAllProfiles, profile, publication)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Identity() == profile.Identity() || plan.Identity() == publication.Identity() || len(plan.Steps()) != 2 || len(plan.Checks()) != 4 || len(plan.SHA256()) != 64 {
		t.Fatalf("umbrella Plan = identity %q sha %q steps %d checks %d", plan.Identity(), plan.SHA256(), len(plan.Steps()), len(plan.Checks()))
	}
	prepared := &clientAccessPreparedStub{changeSet: "change-0008", revision: 8, starting: strings.Repeat("c", 64), candidate: strings.Repeat("d", 64), identity: plan.Identity(), sha: plan.SHA256()}
	changeSet, err := plan.changeSet(prepared, systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: prepared.starting}, strings.Repeat("a", 64), systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1})
	if err != nil || changeSet == nil {
		t.Fatalf("global Change Set = (%v, %v)", changeSet, err)
	}

	prepared.identity = profile.Identity()
	if changed, err := plan.changeSet(prepared, systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: prepared.starting}, strings.Repeat("a", 64), systemchanges.DiskRequirement{PreparationBytes: 1}); err == nil || changed != nil {
		t.Fatal("partial child Plan identity was accepted")
	}
}

func TestClientAccessFirewallPlanRefusesMissingSSHPreservationProof(t *testing.T) {
	firewall, err := systemchanges.NewFirewallPolicyStep("table inet sbxr {\n chain input {\n  type filter hook input priority filter\n  policy drop\n  tcp dport 2222 accept\n }\n}", 2222)
	if err != nil {
		t.Fatal(err)
	}
	profile := clientAccessProfilePlanStub{"profile-plan", strings.Repeat("a", 64), nil, []systemchanges.Check{{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-AGREEMENT"}}}
	publication := clientAccessPublicationPlanStub{"publication-plan", strings.Repeat("b", 64), nil, []systemchanges.Check{{Owner: systemchanges.SubscriptionModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "SUBSCRIPTION-PUBLICATION-AGREEMENT"}}}
	effect := clientAccessPlanEffects{SHA256: strings.Repeat("c", 64), Steps: []systemchanges.Step{firewall}, Checks: []systemchanges.Check{{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-CLIENT-ACCESS-CANDIDATE"}}}
	if plan, err := newClientAccessPlan("change-0008", clientAccessEnableProfile, profile, publication, effect); err == nil || plan != nil {
		t.Fatal("firewall-changing Client Access Plan accepted missing SSH Preservation Proof")
	}
	effect.SSHPreservation = clientAccessTestSSHPreservation(t)
	if plan, err := newClientAccessPlan("change-0008", clientAccessEnableProfile, profile, publication, effect); err != nil || plan == nil {
		t.Fatalf("SSH-protected Client Access firewall Plan = (%v, %v)", plan, err)
	}
}

type clientAccessSSHObserver struct{ observed networkpolicy.Observations }

func (observer clientAccessSSHObserver) Observe(networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	return observer.observed, nil
}

func clientAccessTestSSHPreservation(t *testing.T) systemchanges.SSHPreservationAuthority {
	t.Helper()
	identity := "203.0.113.9 50000 203.0.113.10 2222"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(identity)))
	proof, failure := networkpolicy.New(clientAccessSSHObserver{networkpolicy.Observations{
		SSH:       networkpolicy.SSHFacts{DetectedPort: 2222, ServerAddress: "203.0.113.10", CurrentSessions: []string{digest}, SessionsComplete: true, Service: "ssh.service", Listener: "0.0.0.0:2222/tcp"},
		Listeners: []networkpolicy.Listener{{Address: "0.0.0.0", Port: 2222, Protocol: networkpolicy.TCP, Service: "ssh.service"}},
	}}).ProveSSHPreservation(identity)
	if failure != nil {
		t.Fatal("test SSH Preservation Proof unavailable")
	}
	return systemchanges.NewSSHPreservationAuthority(proof)
}

type clientAccessPreparedStub struct {
	changeSet, starting, candidate, identity, sha string
	revision                                      uint64
}

func (prepared *clientAccessPreparedStub) SystemChangesPreparedState() (string, uint64, string, string, string, string, bool) {
	return prepared.changeSet, prepared.revision, prepared.starting, prepared.candidate, prepared.identity, prepared.sha, true
}
func (*clientAccessPreparedStub) SystemChangesConsume(any, string, string) (any, error) {
	return nil, errors.New("not used")
}
