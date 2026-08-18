package softwarelifecycle

import (
	"errors"
	"strings"

	lifecyclecontract "github.com/albertloky/SBXR/internal/softwarelifecycle/contract"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

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
