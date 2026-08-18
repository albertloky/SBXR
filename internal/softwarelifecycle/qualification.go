package softwarelifecycle

import (
	"bytes"
	"errors"
	"strings"

	lifecyclecontract "github.com/albertloky/SBXR/internal/softwarelifecycle/contract"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

// ControlledSecretMarker identifies one staged-onboarding protected value and
// its exact controlled owning artifact.
type ControlledSecretMarker struct {
	Class string
	Owner string
	Value []byte
	Proof string
}

// ControlledStagedOnboardingSecretMarkers returns one unique marker per
// required protected value class.
func ControlledStagedOnboardingSecretMarkers() []ControlledSecretMarker {
	return []ControlledSecretMarker{
		{Class: "management token", Owner: "protected/state/cloudflare-management-token", Value: controlledSecretMarker("SBXR_USER_TOKEN_", "MARKER_00000000000000abcd"), Proof: "RELEASE-STAGED-ONBOARDING-MARKER-MANAGEMENT-TOKEN"},
		{Class: "token identifiers", Owner: "protected/state/cloudflare-token-identifiers", Value: []byte(strings.Repeat("9f", 16)), Proof: "RELEASE-STAGED-ONBOARDING-MARKER-TOKEN-IDENTIFIERS"},
		{Class: "Tunnel run token", Owner: "protected/cloudflared/run-token", Value: controlledSecretMarker("CLOUDFLARE-ROTATED-RUN-", "TOKEN-MARKER"), Proof: "RELEASE-STAGED-ONBOARDING-MARKER-TUNNEL-RUN-TOKEN"},
		{Class: "profile credentials", Owner: "protected/state/profile-credentials", Value: controlledSecretMarker("profile-secret-", "marker"), Proof: "RELEASE-STAGED-ONBOARDING-MARKER-PROFILE-CREDENTIALS"},
		{Class: "subscription token", Owner: "protected/state/subscription-token", Value: controlledSecretMarker("subscription-secret-", "marker"), Proof: "RELEASE-STAGED-ONBOARDING-MARKER-SUBSCRIPTION-TOKEN"},
		{Class: "complete subscription URLs", Owner: "protected/subscription/complete-url", Value: controlledSecretMarker("COMPLETE-SUBSCRIPTION-", "URL-MARKER"), Proof: "RELEASE-STAGED-ONBOARDING-MARKER-COMPLETE-URL"},
		{Class: "private keys", Owner: "protected/service/private-key", Value: controlledSecretMarker("U0JYUi1RVUFMSUZZLVBSSVZBVEUt", "S0VZLTAwMDAwMDc"), Proof: "RELEASE-STAGED-ONBOARDING-MARKER-PRIVATE-KEY"},
		{Class: "setup entropy", Owner: "protected/transaction/setup-entropy", Value: controlledSecretMarker("QUALIFICATION-SETUP-ENTROPY-", "00000000000000000008"), Proof: "RELEASE-STAGED-ONBOARDING-MARKER-SETUP-ENTROPY"},
		{Class: "setup approval", Owner: "protected/transaction/setup-approval", Value: controlledSecretMarker("QUALIFICATION-SETUP-APPROVAL-", "00000000000000000009"), Proof: "RELEASE-STAGED-ONBOARDING-MARKER-SETUP-APPROVAL"},
		{Class: "raw provider responses", Owner: "protected/transaction/provider-response", Value: controlledSecretMarker("PROVIDER-FIELD-", "MARKER"), Proof: "RELEASE-STAGED-ONBOARDING-MARKER-PROVIDER-RESPONSE"},
		{Class: "external errors", Owner: "protected/transaction/external-error", Value: controlledSecretMarker("PROVIDER-ERROR-", "MARKER"), Proof: "RELEASE-STAGED-ONBOARDING-MARKER-EXTERNAL-ERROR"},
	}
}

func controlledSecretMarker(parts ...string) []byte { return []byte(strings.Join(parts, "")) }

// QualifyControlledStagedOnboardingSurfaces rejects a marker on every named
// output surface. It returns only fixed errors and no scanned bytes.
func QualifyControlledStagedOnboardingSurfaces(surfaces map[string][]byte, required []string) error {
	if len(surfaces) != len(required) {
		return errors.New("controlled staged-onboarding secret scan is incomplete")
	}
	for _, name := range required {
		body, ok := surfaces[name]
		if !ok {
			return errors.New("controlled staged-onboarding secret scan is incomplete")
		}
		for _, marker := range ControlledStagedOnboardingSecretMarkers() {
			if bytes.Contains(body, marker.Value) {
				return errors.New("controlled staged-onboarding secret scan found a marker")
			}
		}
	}
	return nil
}

type controlledQualificationContribution struct{ proof InstallContributionProof }

func (contribution controlledQualificationContribution) SoftwareLifecycleUpdateContribution() lifecyclecontract.UpdateContribution {
	return contribution.proof
}

// ControlledReleaseChangeSummaries runs the real update and downgrade planners
// with one genuine State capability and deterministic no-live contributions.
func ControlledReleaseChangeSummaries(capability ManagedCapability) (UpdateSummary, UpdateSummary, error) {
	revision, stateSHA, cloudflareProfilesSetUp, valid := capability.SoftwareLifecycleManagedCapability()
	if !valid {
		return UpdateSummary{}, UpdateSummary{}, errors.New("controlled Software Lifecycle capability unavailable")
	}
	disk := systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}
	desiredSHA := strings.Repeat("b", 64)
	installed := controlledQualificationRelease("v1.0.0", 1)
	candidate := controlledQualificationRelease("v2.0.0", 2)
	updateChange := "controlled-update-capability"
	update, finding := PlanUpdate(UpdatePlanRequest{Installed: installed, InstalledCandidate: controlledQualificationCandidate(installed), Candidate: controlledQualificationCandidate(candidate), StartingRevision: revision, StartingStateSHA256: stateSHA, ChangeSet: updateChange, DesiredStateSHA256: desiredSHA, Contributions: controlledQualificationContributions(updateChange, desiredSHA, cloudflareProfilesSetUp), Capability: capability, Disk: disk})
	if finding != nil || update == nil {
		return UpdateSummary{}, UpdateSummary{}, errors.New("controlled update capability unavailable")
	}
	downgradeChange := "controlled-downgrade-capability"
	downgrade, finding := PlanDowngrade(DowngradePlanRequest(UpdatePlanRequest{Installed: candidate, InstalledCandidate: controlledQualificationCandidate(candidate), Candidate: controlledQualificationCandidate(installed), StartingRevision: revision, StartingStateSHA256: stateSHA, ChangeSet: downgradeChange, DesiredStateSHA256: desiredSHA, Contributions: controlledQualificationContributions(downgradeChange, desiredSHA, cloudflareProfilesSetUp), Capability: capability, Disk: disk}))
	if finding != nil || downgrade == nil {
		return UpdateSummary{}, UpdateSummary{}, errors.New("controlled downgrade capability unavailable")
	}
	return update.Summary(), downgrade.Summary(), nil
}

func controlledQualificationRelease(tag string, sequence uint64) VerifiedRelease {
	commit := strings.Repeat(string('a'+rune(sequence-1)), 40)
	return VerifiedRelease{Identity: ReleaseIdentity{Repository: Repository, Tag: tag, Commit: commit, IndexSHA256: strings.Repeat("a", 64)}, Version: strings.TrimPrefix(tag, "v"), Sequence: sequence, StateSchema: 2, MinimumUpdaterSchema: 1}
}

func controlledQualificationCandidate(release VerifiedRelease) InstallCandidate {
	staged := StagedRelease{Identity: release.Identity, Build: EmbeddedBuildIdentity{Repository: release.Identity.Repository, Tag: release.Identity.Tag, Commit: release.Identity.Commit, PayloadSHA256: strings.Repeat("c", 64)}, Architecture: AMD64, ExecutableSHA256: strings.Repeat("d", 64), ComponentsSHA256: strings.Repeat("e", 64), InstallPath: ReleaseInstallPath(release.Identity), StateSchema: release.StateSchema}
	return InstallCandidate{cell: &installCandidateCell{verified: release, staged: staged, archive: []byte("controlled application"), components: []byte("controlled components")}}
}

func controlledQualificationContributions(changeSet, desiredSHA string, cloudflareProfilesSetUp bool) []UpdateContribution {
	types := []struct {
		name  InstallContributionName
		owner systemchanges.Module
	}{
		{ProfilesInstallContribution, systemchanges.ConnectionProfilesModule},
	}
	if cloudflareProfilesSetUp {
		types = append(types, struct {
			name  InstallContributionName
			owner systemchanges.Module
		}{CloudflareInstallContribution, systemchanges.CloudflareModule})
	}
	types = append(types, struct {
		name  InstallContributionName
		owner systemchanges.Module
	}{SubscriptionInstallContribution, systemchanges.SubscriptionModule})
	result := make([]UpdateContribution, 0, len(types))
	for index, contribution := range types {
		step, _ := systemchanges.NewStep(contribution.owner, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
		proof := InstallContributionProof{Name: string(contribution.name), Owner: contribution.owner, Identity: "controlled-" + strings.ToLower(strings.ReplaceAll(string(contribution.name), " ", "-")), SHA256: strings.Repeat(string('1'+rune(index)), 64), StableSHA256: strings.Repeat(string('6'+rune(index)), 64), ChangeSet: changeSet, DesiredStateSHA256: desiredSHA, Steps: []systemchanges.Step{step}, Checks: []systemchanges.Check{{Owner: contribution.owner, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONTROLLED-CAPABILITY-PRE"}, {Owner: contribution.owner, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONTROLLED-CAPABILITY-POST"}}, Details: []string{"controlled capability effects"}}
		result = append(result, controlledQualificationContribution{proof: proof})
	}
	return result
}
