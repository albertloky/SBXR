package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type clientAccessAction string

const (
	clientAccessEnableProfile      clientAccessAction = "enable-profile"
	clientAccessDisableProfile     clientAccessAction = "disable-profile"
	clientAccessRotateProfile      clientAccessAction = "rotate-profile"
	clientAccessRotateAllProfiles  clientAccessAction = "rotate-all-profiles"
	clientAccessRotateSubscription clientAccessAction = "rotate-subscription"
	clientAccessRevokeAll          clientAccessAction = "revoke-all"
)

type clientAccessProfilePlan interface {
	state.ConnectionProfilesReviewedPreparer
	Steps() []systemchanges.Step
	Checks() []systemchanges.Check
}

type clientAccessPublicationPlan interface {
	state.SubscriptionValidator
	state.SubscriptionPublicationPreparer
	Steps() []systemchanges.Step
	Checks() []systemchanges.Check
}

type clientAccessPlanEffects struct {
	SHA256          string
	Steps           []systemchanges.Step
	Checks          []systemchanges.Check
	SSHPreservation systemchanges.SSHPreservationAuthority
}

// clientAccessPlan is the application-level umbrella Plan. Its one identity is
// the only identity State and System Changes accept for the coordinated work.
type clientAccessPlan struct {
	changeSetID     string
	action          clientAccessAction
	identity        string
	sha256          string
	profile         clientAccessProfilePlan
	publication     clientAccessPublicationPlan
	steps           []systemchanges.Step
	checks          []systemchanges.Check
	sshPreservation systemchanges.SSHPreservationAuthority
}

func newClientAccessPlan(changeSet string, action clientAccessAction, profile clientAccessProfilePlan, publication clientAccessPublicationPlan, effects ...clientAccessPlanEffects) (*clientAccessPlan, error) {
	if changeSet == "" || !validClientAccessAction(action) || profile == nil || publication == nil || profile.Identity() == "" || publication.Identity() == "" || len(profile.SHA256()) != 64 || len(publication.SHA256()) != 64 {
		return nil, errors.New("complete Client Access Plan inputs are required")
	}
	extra := clientAccessPlanEffects{SHA256: hex.EncodeToString(sha256.New().Sum(nil))}
	if len(effects) > 1 {
		return nil, errors.New("Client Access Plan effects are ambiguous")
	}
	if len(effects) == 1 {
		extra = effects[0]
		if len(extra.SHA256) != 64 || len(extra.Steps) == 0 || len(extra.Checks) == 0 {
			return nil, errors.New("Client Access Plan effects are incomplete")
		}
	}
	bound, _ := json.Marshal(struct {
		ChangeSet                           string
		Action                              clientAccessAction
		ProfileIdentity, ProfileSHA256      string
		PublicationIdentity, PublicationSHA string
		EffectsSHA256                       string
	}{changeSet, action, profile.Identity(), profile.SHA256(), publication.Identity(), publication.SHA256(), extra.SHA256})
	digest := sha256.Sum256(bound)
	checksum := hex.EncodeToString(digest[:])
	steps := append(append(append([]systemchanges.Step(nil), extra.Steps...), profile.Steps()...), publication.Steps()...)
	for _, step := range steps {
		if step.Forward() == systemchanges.ApplyApprovedNetworkPolicy && extra.SSHPreservation == (systemchanges.SSHPreservationAuthority{}) {
			return nil, errors.New("Client Access firewall Plan requires SSH Preservation Proof")
		}
	}
	checks := append(append(append([]systemchanges.Check(nil), extra.Checks...), profile.Checks()...), publication.Checks()...)
	checks = append(checks,
		systemchanges.Check{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-CLIENT-ACCESS-LISTENERS"},
		systemchanges.Check{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-CLIENT-ACCESS-LISTENERS"},
	)
	if len(steps) == 0 || len(checks) == 0 {
		return nil, errors.New("complete Client Access effects and gates are required")
	}
	return &clientAccessPlan{changeSetID: changeSet, action: action, identity: changeSet + "-client-access-" + checksum[:12], sha256: checksum, profile: profile, publication: publication, steps: steps, checks: checks, sshPreservation: extra.SSHPreservation}, nil
}

func validClientAccessAction(action clientAccessAction) bool {
	switch action {
	case clientAccessEnableProfile, clientAccessDisableProfile, clientAccessRotateProfile, clientAccessRotateAllProfiles, clientAccessRotateSubscription, clientAccessRevokeAll:
		return true
	default:
		return false
	}
}

func clientAccessChangesFirewall(action clientAccessAction) bool {
	return action == clientAccessEnableProfile || action == clientAccessDisableProfile
}

func (plan *clientAccessPlan) Identity() string {
	if plan == nil {
		return ""
	}
	return plan.identity
}

func (plan *clientAccessPlan) SHA256() string {
	if plan == nil {
		return ""
	}
	return plan.sha256
}

func (plan *clientAccessPlan) Steps() []systemchanges.Step {
	if plan == nil {
		return nil
	}
	return append([]systemchanges.Step(nil), plan.steps...)
}

func (plan *clientAccessPlan) Checks() []systemchanges.Check {
	if plan == nil {
		return nil
	}
	return append([]systemchanges.Check(nil), plan.checks...)
}

func (plan *clientAccessPlan) ValidateConnectionProfiles(profiles state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) error {
	if plan == nil || plan.profile == nil {
		return errors.New("Connection Profiles Client Access Plan unavailable")
	}
	return plan.profile.ValidateConnectionProfiles(profiles, secrets)
}

func (plan *clientAccessPlan) PrepareConnectionProfiles(profiles state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) ([]byte, []byte, error) {
	if plan == nil || plan.profile == nil {
		return nil, nil, errors.New("Connection Profiles Client Access Plan unavailable")
	}
	return plan.profile.PrepareConnectionProfiles(profiles, secrets)
}

func (plan *clientAccessPlan) ValidateSubscription(settings state.SubscriptionSettings, secrets state.ClientAccessReader) error {
	if plan == nil || plan.publication == nil {
		return errors.New("Subscription Client Access Plan unavailable")
	}
	return plan.publication.ValidateSubscription(settings, secrets)
}

func (plan *clientAccessPlan) PrepareSubscriptionPublication() ([]byte, error) {
	if plan == nil || plan.publication == nil {
		return nil, errors.New("Subscription Client Access Plan unavailable")
	}
	return plan.publication.PrepareSubscriptionPublication()
}

func (plan *clientAccessPlan) changeSet(prepared systemchanges.PreparedStateCommit, starting systemchanges.StateLineage, volatileSHA256 string, disk systemchanges.DiskRequirement) (*systemchanges.ChangeSet, error) {
	if plan == nil || prepared == nil || len(volatileSHA256) != 64 {
		return nil, errors.New("prepared Client Access Plan unavailable")
	}
	changeSet, revision, startingSHA256, candidateSHA256, identity, checksum, valid := prepared.SystemChangesPreparedState()
	if !valid || changeSet != plan.changeSetID || identity != plan.identity || checksum != plan.sha256 || starting.Status != systemchanges.Managed || revision != starting.Revision+1 || startingSHA256 != starting.SHA256 || len(candidateSHA256) != 64 {
		return nil, errors.New("prepared Client Access Plan changed")
	}
	mutation := systemchanges.SettingChangeMutation
	if plan.action == clientAccessRotateProfile || plan.action == clientAccessRotateAllProfiles || plan.action == clientAccessRotateSubscription || plan.action == clientAccessRevokeAll {
		mutation = systemchanges.RotationMutation
	}
	return systemchanges.NewChangeSet(systemchanges.ChangeSetSpec{
		Identity: plan.changeSetID, Mutation: mutation, OutcomeOwner: systemchanges.StateModule,
		StartingState: starting, TargetStateSHA256: candidateSHA256,
		Plan:          systemchanges.PlanBinding{Identity: plan.identity, SHA256: plan.sha256, VolatileSHA256: volatileSHA256},
		PreparedState: prepared, SSHPreservation: plan.sshPreservation, Steps: plan.steps, Checks: plan.checks,
		Timeouts: systemchanges.Timeouts{Step: time.Minute, Check: time.Minute}, Disk: disk,
	})
}
