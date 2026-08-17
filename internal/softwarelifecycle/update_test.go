package softwarelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type controlledUpdateApproval struct {
	recheck UpdateRecheck
	calls   int
}

type controlledUpdatePrepared struct {
	changeSet                string
	revision                 uint64
	starting, candidate      string
	planIdentity, planSHA256 string
	release                  ReleaseIdentity
	from, to                 uint64
	steps                    int
}

func (prepared controlledUpdatePrepared) SystemChangesPreparedState() (string, uint64, string, string, string, string, bool) {
	return prepared.changeSet, prepared.revision, prepared.starting, prepared.candidate, prepared.planIdentity, prepared.planSHA256, true
}
func (controlledUpdatePrepared) SystemChangesConsume(any, string, string) (any, error) {
	return nil, nil
}
func (prepared controlledUpdatePrepared) SoftwareLifecyclePreparedRelease() (string, string, string, string, bool) {
	return prepared.release.Repository, prepared.release.Tag, prepared.release.Commit, prepared.release.IndexSHA256, true
}
func (prepared controlledUpdatePrepared) SoftwareLifecyclePreparedMigration() (uint64, uint64, int, bool) {
	return prepared.from, prepared.to, prepared.steps, true
}

func (approval *controlledUpdateApproval) AuthorizeAndRecheck(context.Context) (UpdateRecheck, error) {
	approval.calls++
	return approval.recheck, nil
}

func TestPlanUpdateDisclosesOneCompleteManagedToManagedTransaction(t *testing.T) {
	installed, candidate := controlledUpdateReleases()
	capability, startingStateSHA256 := controlledManagedCapability(t, true)
	disk := systemchanges.DiskRequirement{PreparationBytes: 10, TemporaryBytes: 20, SnapshotBytes: 30, JournalBytes: 40, RollbackBytes: 50, OverheadBytes: 60}
	plan, finding := PlanUpdate(UpdatePlanRequest{
		Installed: installed, InstalledCandidate: controlledInstalledCandidate(installed), Candidate: candidate, StartingRevision: 7, StartingStateSHA256: startingStateSHA256,
		ChangeSet: "update-revision-8", DesiredStateSHA256: strings.Repeat("b", 64), Contributions: controlledUpdateContributions(t, "update-revision-8", strings.Repeat("b", 64)), Capability: capability, Disk: disk,
	})
	if finding != nil || plan == nil {
		t.Fatalf("PlanUpdate() = (%+v, %+v)", plan, finding)
	}
	summary := plan.Summary()
	if summary.CurrentRelease != installed.Identity || summary.CandidateRelease != candidate.cell.staged.Identity || summary.CurrentRevision != 7 || summary.CandidateRevision != 8 || summary.Disk != disk || !summary.OneUse || !summary.PrivilegedMutationAfterApproval {
		t.Fatalf("summary = %+v", summary)
	}
	if !reflect.DeepEqual(summary.MigrationPath, []string{"State schema 1 -> 2: preserve all Owner meaning; regenerate release-bound material"}) || !reflect.DeepEqual(summary.AffectedServices, []string{"cloudflared.service", "sbxr-subscription.service", "sing-box.service", "xray.service"}) || len(summary.SubscriptionRepresentations) != 7 || summary.Compatibility == "" || summary.Interruption == "" || summary.Cancellation == "" || summary.Rollback == "" {
		t.Fatalf("incomplete update review = %+v", summary)
	}
}

func TestPlanUpdatePreservesRealityOnlyCapabilityWithoutCloudflareWork(t *testing.T) {
	installed, candidate := controlledUpdateReleases()
	installed.StateSchema, candidate.cell.verified.StateSchema, candidate.cell.verified.Migrations = 2, 2, nil
	capability, stateSHA256 := controlledManagedCapability(t, false)
	desired := strings.Repeat("b", 64)
	contributions := controlledUpdateContributions(t, "update-reality-only", desired)
	plan, finding := PlanUpdate(UpdatePlanRequest{
		Installed: installed, InstalledCandidate: controlledInstalledCandidate(installed), Candidate: candidate,
		StartingRevision: 7, StartingStateSHA256: stateSHA256, ChangeSet: "update-reality-only", DesiredStateSHA256: desired,
		Contributions: []UpdateContribution{contributions[0], contributions[2]}, Capability: capability,
		Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1},
	})
	if finding != nil || plan == nil {
		t.Fatalf("PlanUpdate() = (%+v, %+v)", plan, finding)
	}
	if got := plan.Summary().AffectedServices; !reflect.DeepEqual(got, []string{"sbxr-subscription.service", "xray.service"}) {
		t.Fatalf("AffectedServices = %v", got)
	}
	prepared := controlledUpdatePrepared{changeSet: "update-reality-only", revision: 8, starting: stateSHA256, candidate: desired, planIdentity: plan.Identity(), planSHA256: plan.SHA256(), release: candidate.cell.staged.Identity, from: 2, to: 2}
	realityOnly := []UpdateContribution{contributions[0], contributions[2]}
	approval := &controlledUpdateApproval{recheck: UpdateRecheck{Installed: installed, InstalledCandidate: controlledInstalledCandidate(installed), Candidate: candidate, StartingRevision: 7, StartingStateSHA256: stateSHA256, Contributions: realityOnly, Capability: capability}}
	result := plan.Apply(t.Context(), UpdateApplyRequest{Approval: approval, PreparedState: prepared, SystemChanges: systemchanges.New(nil)})
	if result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE" || approval.calls != 1 {
		t.Fatalf("reality-only Apply() = %+v; calls=%d", result, approval.calls)
	}
}

type capabilityStorage struct{ document []byte }

func (storage capabilityStorage) Read() ([]byte, error) { return storage.document, nil }
func (capabilityStorage) Publish([]byte, []byte, string) ([]byte, error) {
	return nil, errors.New("not used")
}

func controlledManagedCapability(t *testing.T, cloudflareProfilesSetUp bool) (*state.SoftwareLifecycleCapability, string) {
	t.Helper()
	document, err := os.ReadFile("../state/testdata/complete-state.json")
	if err != nil {
		t.Fatal(err)
	}
	if !cloudflareProfilesSetUp {
		var envelope map[string]any
		if err := json.Unmarshal(document, &envelope); err != nil {
			t.Fatal(err)
		}
		payload := envelope["payload"].(map[string]any)
		payload["installation"].(map[string]any)["domain"] = ""
		profiles := payload["connection_profiles"].(map[string]any)
		for name, value := range profiles {
			profile := value.(map[string]any)
			if name == "vless_reality_vision" {
				profile["lifecycle"] = "Enabled"
				continue
			}
			for field, current := range profile {
				switch current.(type) {
				case string:
					profile[field] = ""
				case bool:
					profile[field] = false
				case float64:
					profile[field] = float64(0)
				}
			}
			profile["lifecycle"] = "Not set up"
		}
		for field, current := range payload["cloudflare"].(map[string]any) {
			switch current.(type) {
			case string:
				payload["cloudflare"].(map[string]any)[field] = ""
			case bool:
				payload["cloudflare"].(map[string]any)[field] = false
			}
		}
		certificates := payload["certificates"].(map[string]any)
		for _, field := range []string{"domain_certificate_id", "domain_serving_pointer", "domain_hostname"} {
			certificates[field] = ""
		}
		envelope["schema_version"] = float64(2)
		encodedPayload, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		digest := sha256.Sum256(encodedPayload)
		envelope["checksum"] = hex.EncodeToString(digest[:])
		document, err = json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
	}
	release := state.ReleaseIdentity{Repository: "https://github.com/albertloky/SBXR", Tag: "v1.0.0", Commit: "0123456789abcdef0123456789abcdef01234567", ReleaseIndexSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	module := state.New(capabilityStorage{document: document})
	result, err := module.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: 7, LastCompletedChangeSet: "change-0007", ReleaseIdentity: release}})
	if err != nil {
		t.Fatal(err)
	}
	capability := module.SoftwareLifecycleCapability(result)
	_, stateSHA256, _, valid := capability.SoftwareLifecycleManagedCapability()
	if !valid {
		t.Fatal("managed capability unavailable")
	}
	return capability, stateSHA256
}

func TestPlanDowngradeDisclosesAndReusesTheManagedTransaction(t *testing.T) {
	installed, candidate := controlledUpdateReleases()
	installed.Sequence, installed.StateSchema = 2, 2
	installed.Identity.Tag = "v2.0.0"
	installedCandidate := controlledInstalledCandidate(installed)
	candidate.cell.verified.Sequence = 1
	candidate.cell.verified.StateSchema = 2
	candidate.cell.verified.Migrations = nil
	capability, startingStateSHA256 := controlledManagedCapability(t, true)
	request := DowngradePlanRequest(UpdatePlanRequest{
		Installed: installed, InstalledCandidate: installedCandidate, Candidate: candidate, StartingRevision: 7, StartingStateSHA256: startingStateSHA256,
		ChangeSet: "downgrade-revision-8", DesiredStateSHA256: strings.Repeat("b", 64), Contributions: controlledUpdateContributions(t, "downgrade-revision-8", strings.Repeat("b", 64)), Capability: capability, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1},
	})
	plan, finding := PlanDowngrade(request)
	if finding != nil || plan == nil {
		t.Fatalf("PlanDowngrade() = (%+v, %+v)", plan, finding)
	}
	summary := plan.Summary()
	if summary.Operation != ReviewDowngrade || summary.CurrentRelease != installed.Identity || summary.CandidateRelease != candidate.cell.staged.Identity || summary.Compatibility != "Current Desired State schema 2 is supported by the selected release" || len(summary.MigrationPath) != 0 || !summary.OneUse {
		t.Fatalf("downgrade summary = %+v", summary)
	}

	same := request
	same.Candidate = installedCandidate
	if plan, finding := PlanDowngrade(same); plan != nil || finding == nil {
		t.Fatalf("same-identity downgrade = (%+v, %+v)", plan, finding)
	}
	incompatible := request
	incompatible.Candidate = candidate
	incompatible.Candidate.cell.verified.StateSchema = 1
	if plan, finding := PlanDowngrade(incompatible); plan != nil || finding == nil {
		t.Fatalf("incompatible downgrade = (%+v, %+v)", plan, finding)
	}
}

func TestApplyDowngradeHandsOneExactlyBoundChangeSetToSystemChanges(t *testing.T) {
	installed, candidate := controlledUpdateReleases()
	installed.Sequence, installed.StateSchema, installed.Identity.Tag = 2, 2, "v2.0.0"
	installedCandidate := controlledInstalledCandidate(installed)
	candidate.cell.verified.Sequence, candidate.cell.verified.StateSchema, candidate.cell.verified.Migrations = 1, 2, nil
	capability, starting := controlledManagedCapability(t, false)
	desired := strings.Repeat("b", 64)
	contributions := controlledUpdateContributions(t, "downgrade-revision-8-success", desired)
	realityOnly := []UpdateContribution{contributions[0], contributions[2]}
	request := DowngradePlanRequest(UpdatePlanRequest{Installed: installed, InstalledCandidate: installedCandidate, Candidate: candidate, StartingRevision: 7, StartingStateSHA256: starting, ChangeSet: "downgrade-revision-8-success", DesiredStateSHA256: desired, Contributions: realityOnly, Capability: capability, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}})
	plan, finding := PlanDowngrade(request)
	if finding != nil {
		t.Fatal(finding)
	}
	prepared := controlledUpdatePrepared{changeSet: request.ChangeSet, revision: 8, starting: starting, candidate: desired, planIdentity: plan.Identity(), planSHA256: plan.SHA256(), release: candidate.cell.staged.Identity, from: 2, to: 2}
	approval := &controlledUpdateApproval{recheck: UpdateRecheck{Installed: installed, InstalledCandidate: installedCandidate, Candidate: candidate, StartingRevision: 7, StartingStateSHA256: starting, Contributions: realityOnly, Capability: capability}}
	result := plan.Apply(t.Context(), UpdateApplyRequest{Approval: approval, PreparedState: prepared, SystemChanges: systemchanges.New(nil)})
	if result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE" || approval.calls != 1 {
		t.Fatalf("Apply() = %+v; calls=%d", result, approval.calls)
	}
}

func TestApplyDowngradeRejectsStaleFactsAndReuse(t *testing.T) {
	installed, candidate := controlledUpdateReleases()
	installed.Sequence, installed.StateSchema, installed.Identity.Tag = 2, 2, "v2.0.0"
	installedCandidate := controlledInstalledCandidate(installed)
	candidate.cell.verified.Sequence, candidate.cell.verified.StateSchema, candidate.cell.verified.Migrations = 1, 2, nil
	desired := strings.Repeat("b", 64)
	capability, starting := controlledManagedCapability(t, true)
	request := DowngradePlanRequest(UpdatePlanRequest{Installed: installed, InstalledCandidate: installedCandidate, Candidate: candidate, StartingRevision: 7, StartingStateSHA256: starting, ChangeSet: "downgrade-revision-8-stale", DesiredStateSHA256: desired, Contributions: controlledUpdateContributions(t, "downgrade-revision-8-stale", desired), Capability: capability, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}})
	plan, finding := PlanDowngrade(request)
	if finding != nil {
		t.Fatal(finding)
	}
	approval := &controlledUpdateApproval{recheck: UpdateRecheck{Installed: installed, InstalledCandidate: installedCandidate, Candidate: candidate, StartingRevision: 8, StartingStateSHA256: request.StartingStateSHA256, Contributions: request.Contributions, Capability: capability}}
	result := plan.Apply(t.Context(), UpdateApplyRequest{Approval: approval})
	if result.Finding == nil || result.Finding.Code != "SOFTWARE-LIFECYCLE-UPDATE-STALE" || !result.NothingChanged {
		t.Fatalf("stale Apply() = %+v", result)
	}
	if repeated := plan.Apply(t.Context(), UpdateApplyRequest{Approval: approval}); repeated.Finding == nil || repeated.Finding.Code != "SOFTWARE-LIFECYCLE-UPDATE-PLAN-USED" || approval.calls != 1 {
		t.Fatalf("reused Apply() = %+v; calls=%d", repeated, approval.calls)
	}
}

func controlledUpdateReleases() (VerifiedRelease, InstallCandidate) {
	installed := VerifiedRelease{Identity: ReleaseIdentity{Repository: Repository, Tag: "v1.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("a", 64)}, Sequence: 1, StateSchema: 1, MinimumUpdaterSchema: 1}
	candidate := controlledInstallCandidate()
	candidate.cell.verified = VerifiedRelease{Identity: candidate.cell.staged.Identity, Sequence: 2, StateSchema: 2, MinimumUpdaterSchema: 1, Migrations: []EmbeddedMigration{{Name: "state-v1-to-v2.json", From: 1, To: 2, Document: state.ReleaseMigrations()["state-v1-to-v2.json"]}}}
	return installed, candidate
}

func controlledInstalledCandidate(installed VerifiedRelease) InstallCandidate {
	candidate := controlledInstallCandidate()
	candidate.cell.staged.Identity = installed.Identity
	candidate.cell.staged.Build.Repository = installed.Identity.Repository
	candidate.cell.staged.Build.Tag = installed.Identity.Tag
	candidate.cell.staged.Build.Commit = installed.Identity.Commit
	candidate.cell.staged.InstallPath = ReleaseInstallPath(installed.Identity)
	candidate.cell.staged.StateSchema = installed.StateSchema
	candidate.cell.verified = installed
	return candidate
}

func controlledUpdateContributions(t *testing.T, changeSet, desired string) []UpdateContribution {
	t.Helper()
	all := controlledInstallContributions(t, changeSet, desired)
	result := []UpdateContribution{all[1].(UpdateContribution)}
	step, err := systemchanges.NewStep(systemchanges.CloudflareModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	result = append(result, controlledInstallContribution{InstallContributionProof{Name: string(CloudflareInstallContribution), Owner: systemchanges.CloudflareModule, Identity: "component-plan-cloudflare", SHA256: strings.Repeat("5", 64), StableSHA256: strings.Repeat("a", 64), ChangeSet: changeSet, DesiredStateSHA256: desired, Steps: []systemchanges.Step{step}, Checks: []systemchanges.Check{{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "UPDATE-CLOUDFLARE-PRE"}, {Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "UPDATE-CLOUDFLARE-POST"}}, Details: []string{"Cloudflare Tunnel exact update effects"}}})
	result = append(result, all[3].(UpdateContribution))
	return result
}

func TestApplyUpdateRejectsAChangedOrReusedReviewedPlan(t *testing.T) {
	installed, candidate := controlledUpdateReleases()
	desired := strings.Repeat("b", 64)
	installedCandidate := controlledInstalledCandidate(installed)
	capability, starting := controlledManagedCapability(t, true)
	request := UpdatePlanRequest{Installed: installed, InstalledCandidate: installedCandidate, Candidate: candidate, StartingRevision: 7, StartingStateSHA256: starting, ChangeSet: "update-revision-8", DesiredStateSHA256: desired, Contributions: controlledUpdateContributions(t, "update-revision-8", desired), Capability: capability, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}}
	plan, finding := PlanUpdate(request)
	if finding != nil {
		t.Fatal(finding)
	}
	changed := controlledUpdateContributions(t, request.ChangeSet, desired)
	proof := changed[0].SoftwareLifecycleUpdateContribution()
	proof.StableSHA256 = strings.Repeat("e", 64)
	changed[0] = controlledInstallContribution{proof}
	approval := &controlledUpdateApproval{recheck: UpdateRecheck{Installed: installed, InstalledCandidate: installedCandidate, Candidate: candidate, StartingRevision: 7, StartingStateSHA256: request.StartingStateSHA256, Contributions: changed, Capability: capability}}
	result := plan.Apply(t.Context(), UpdateApplyRequest{Approval: approval})
	if approval.calls != 1 || result.Finding == nil || result.Finding.Code != "SOFTWARE-LIFECYCLE-UPDATE-STALE" || !result.NothingChanged {
		t.Fatalf("Apply() = %+v; calls=%d", result, approval.calls)
	}
	if repeated := plan.Apply(t.Context(), UpdateApplyRequest{Approval: approval}); repeated.Finding == nil || repeated.Finding.Code != "SOFTWARE-LIFECYCLE-UPDATE-PLAN-USED" || approval.calls != 1 {
		t.Fatalf("repeated Apply() = %+v; calls=%d", repeated, approval.calls)
	}
}

func TestApplyUpdateHandsOneExactlyBoundChangeSetToSystemChanges(t *testing.T) {
	installed, candidate := controlledUpdateReleases()
	capability, starting := controlledManagedCapability(t, true)
	desired := strings.Repeat("b", 64)
	installedCandidate := controlledInstalledCandidate(installed)
	request := UpdatePlanRequest{Installed: installed, InstalledCandidate: installedCandidate, Candidate: candidate, StartingRevision: 7, StartingStateSHA256: starting, ChangeSet: "update-revision-8-success", DesiredStateSHA256: desired, Contributions: controlledUpdateContributions(t, "update-revision-8-success", desired), Capability: capability, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}}
	plan, finding := PlanUpdate(request)
	if finding != nil {
		t.Fatal(finding)
	}
	prepared := controlledUpdatePrepared{changeSet: request.ChangeSet, revision: 8, starting: starting, candidate: desired, planIdentity: plan.Identity(), planSHA256: plan.SHA256(), release: candidate.cell.staged.Identity, from: 1, to: 2, steps: 1}
	approval := &controlledUpdateApproval{recheck: UpdateRecheck{Installed: installed, InstalledCandidate: installedCandidate, Candidate: candidate, StartingRevision: 7, StartingStateSHA256: starting, Contributions: controlledUpdateContributions(t, request.ChangeSet, desired), Capability: capability}}
	result := plan.Apply(t.Context(), UpdateApplyRequest{Approval: approval, PreparedState: prepared, SystemChanges: systemchanges.New(nil)})
	if result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE" || approval.calls != 1 {
		t.Fatalf("Apply() = %+v; calls=%d", result, approval.calls)
	}
}
