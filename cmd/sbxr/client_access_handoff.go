package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

const maxClientAccessHandoffBytes = 16 << 10

type clientAccessHandoffRequest struct {
	Schema               int                            `json:"schema"`
	Mode                 string                         `json:"mode"`
	Action               clientAccessAction             `json:"action,omitempty"`
	ProviderAction       managedProviderAction          `json:"provider_action,omitempty"`
	Profile              string                         `json:"profile,omitempty"`
	ChangeSet            string                         `json:"change_set"`
	Token                string                         `json:"token,omitempty"`
	OwnerEmail           string                         `json:"owner_email,omitempty"`
	Agreement            bool                           `json:"agreement,omitempty"`
	DiagnosticsAction    string                         `json:"diagnostics_action,omitempty"`
	SoftwareAction       string                         `json:"software_action,omitempty"`
	ReleaseTag           string                         `json:"release_tag,omitempty"`
	ReviewedPlanIdentity string                         `json:"reviewed_plan_identity,omitempty"`
	ReviewedPlanSHA256   string                         `json:"reviewed_plan_sha256,omitempty"`
	BundleReplacement    ownerconsole.BundleReplacement `json:"bundle_replacement,omitempty"`
}

func (clientAccessHandoffRequest) String() string { return "Client Access handoff request: protected" }
func (clientAccessHandoffRequest) GoString() string {
	return "Client Access handoff request: protected"
}

type clientAccessHandoffReview struct {
	Identity, SHA256, DesiredStateSHA256, VolatileSHA256 string
	CandidateTag, CandidateCommit, CandidateIndexSHA256  string
	StartingRevision, CandidateRevision                  uint64
	TotalSteps                                           uint16
	Plan                                                 ownerconsole.PlanPresentation
	SSHFailureCause                                      networkpolicy.SSHPreservationFailureCause `json:"ssh_failure_cause,omitempty"`
}

type clientAccessSSHReviewError struct {
	Cause networkpolicy.SSHPreservationFailureCause
}

func (*clientAccessSSHReviewError) Error() string {
	return "Managed Client Access SSH Preservation Proof unavailable"
}

type clientAccessRecoveryResult struct {
	Status          systemchanges.InstallationStatus
	SSHFailureCause networkpolicy.SSHPreservationFailureCause `json:"ssh_failure_cause,omitempty"`
}

type clientAccessHandoffSession struct {
	mu                                           sync.Mutex
	socket                                       *os.File
	wait                                         func() error
	used, applying, cancellable, removalApproved bool
	review                                       clientAccessHandoffReview
}

func validClientAccessHandoff(request clientAccessHandoffRequest) bool {
	if request.Schema != 1 || request.Mode != "change" && request.Mode != "provider" && request.Mode != "view" && request.Mode != "recover" && request.Mode != "diagnostics" && request.Mode != "software-review" && request.Mode != "software-apply" && request.Mode != "removal-review" && request.Mode != "removal-apply" {
		return false
	}
	removal := request.Mode == "removal-review" || request.Mode == "removal-apply"
	if removal {
		if request.Action != "" || request.ProviderAction != "" || request.Profile != "" || request.Token != "" || request.OwnerEmail != "" || request.Agreement || request.DiagnosticsAction != "" || request.SoftwareAction != "" || request.ReleaseTag != "" || request.BundleReplacement.Archive != "" || !validClientAccessChangeSet(request.ChangeSet) {
			return false
		}
		if request.Mode == "removal-review" {
			return request.ReviewedPlanIdentity == "" && request.ReviewedPlanSHA256 == ""
		}
		return validClientAccessChangeSet(request.ReviewedPlanIdentity) && clientAccessSHA256.MatchString(request.ReviewedPlanSHA256)
	}
	software := request.Mode == "software-review" || request.Mode == "software-apply"
	if !software && (request.SoftwareAction != "" || request.ReleaseTag != "" || request.ReviewedPlanIdentity != "" || request.ReviewedPlanSHA256 != "") {
		return false
	}
	if software {
		if request.Action != "" || request.ProviderAction != "" || request.Profile != "" || request.Token != "" || request.OwnerEmail != "" || request.Agreement || request.DiagnosticsAction != "" || request.BundleReplacement.Archive != "" {
			return false
		}
		binding := request.ReviewedPlanIdentity == "" && request.ReviewedPlanSHA256 == ""
		if request.Mode == "software-apply" {
			binding = validClientAccessChangeSet(request.ReviewedPlanIdentity) && clientAccessSHA256.MatchString(request.ReviewedPlanSHA256)
		}
		switch request.SoftwareAction {
		case "update":
			return validClientAccessChangeSet(request.ChangeSet) && softwareReleaseTag.MatchString(request.ReleaseTag) && binding
		case "repair":
			return validClientAccessChangeSet(request.ChangeSet) && request.ReleaseTag == "" && binding
		case "downgrade":
			return validClientAccessChangeSet(request.ChangeSet) && softwarelifecycle.ValidDowngradeTag(request.ReleaseTag) && binding
		default:
			return false
		}
	}
	if request.Mode != "diagnostics" && (request.DiagnosticsAction != "" || request.BundleReplacement.Archive != "") {
		return false
	}
	if request.Mode == "diagnostics" {
		if request.Action != "" || request.ProviderAction != "" || request.Profile != "" || request.ChangeSet != "" || request.Token != "" || request.OwnerEmail != "" || request.Agreement {
			return false
		}
		if request.DiagnosticsAction == "view" {
			return request.BundleReplacement.Archive == ""
		}
		return request.DiagnosticsAction == "bundle" && (request.BundleReplacement.Archive == "" || validSupportBundleName(request.BundleReplacement.Archive))
	}
	if request.Mode == "view" {
		return request.Action == "" && request.Profile == "" && request.ChangeSet == ""
	}
	if !validClientAccessChangeSet(request.ChangeSet) {
		return false
	}
	if request.Mode == "recover" {
		return request.Action == "" && request.ProviderAction == "" && request.Profile == "" && request.Token == "" && request.OwnerEmail == "" && !request.Agreement
	}
	if request.Mode == "provider" {
		if request.Action != "" || request.Profile != "" || !validManagedProviderAction(request.ProviderAction) {
			return false
		}
		switch request.ProviderAction {
		case managedCloudflareReplace:
			_, err := cloudflaretunnel.NewManagementToken(request.Token)
			return err == nil && request.OwnerEmail == "" && !request.Agreement
		case managedCloudflareRemove, managedCloudflareRotate:
			return request.Token == "" && request.OwnerEmail == "" && !request.Agreement
		case managedCertificateIP, managedCertificateDomain:
			return request.Token == "" && request.Agreement && certificatelifecycle.ValidOwnerEmail(request.OwnerEmail)
		}
	}
	if !validClientAccessAction(request.Action) {
		return false
	}
	profile := connectionprofiles.ProfileID(request.Profile)
	profileAction := request.Action == clientAccessEnableProfile || request.Action == clientAccessDisableProfile || request.Action == clientAccessRotateProfile
	if !profileAction {
		return request.Profile == ""
	}
	switch profile {
	case connectionprofiles.VLESSRealityVisionProfileID, connectionprofiles.VLESSXHTTPProfileID, connectionprofiles.VLESSWebSocketProfileID, connectionprofiles.Hysteria2ProfileID, connectionprofiles.TUICProfileID, connectionprofiles.AnyTLSProfileID:
		return true
	default:
		return false
	}
}

var softwareReleaseTag = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
var clientAccessSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validSupportBundleName(name string) bool {
	const prefix, suffix = "sbxr-support-", ".tar.gz"
	if len(name) != len(prefix)+len("20060102T150405Z")+len(suffix) || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return false
	}
	_, err := time.Parse("20060102T150405Z", strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix))
	return err == nil
}

func validClientAccessChangeSet(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func softwareUpdatePlanPresentation(built *builtSoftwareChange, desiredSHA string) ownerconsole.PlanPresentation {
	summary := built.plan.Summary()
	effects := append([]string{}, summary.MigrationPath...)
	effects = append(effects, "Affected services: "+strings.Join(summary.AffectedServices, ", "), "Regenerated subscription representations: "+strings.Join(summary.SubscriptionRepresentations, ", "), diskPresentation(summary.Disk))
	return ownerconsole.PlanPresentation{
		Identity: ownerconsole.PlanIdentity(built.plan.Identity()), DesiredStateRevision: summary.CandidateRevision, DesiredStateSHA256: desiredSHA,
		RelevantChecksums:      []string{"Software Lifecycle Plan SHA-256 " + built.plan.SHA256(), "Reviewed volatile state SHA-256 " + built.plan.VolatileSHA256()},
		ObservedState:          "Proven Managed Desired State revision " + fmt.Sprint(summary.CurrentRevision),
		VerifiedExternalInputs: []string{"Installed release " + summary.CurrentRelease.Tag + " " + summary.CurrentRelease.Commit + " " + summary.CurrentRelease.IndexSHA256, "Candidate release " + summary.CandidateRelease.Tag + " " + summary.CandidateRelease.Commit + " " + summary.CandidateRelease.IndexSHA256, summary.Compatibility},
		Effects:                effects, RequiredChecks: append([]string{}, summary.Checks...), AdvisoryChecks: []string{"Outside-client and provider acceptance remains pending until performed"},
		Interruption: summary.Interruption, Cancellation: summary.Cancellation, Rollback: summary.Rollback,
	}
}

func softwareRepairPlanPresentation(built *builtSoftwareRepair) ownerconsole.PlanPresentation {
	summary := built.plan.Summary()
	effects := []string{"Owning Module: " + string(summary.OwningModule)}
	effects = append(effects, summary.Steps...)
	effects = append(effects, summary.Details...)
	effects = append(effects, summary.StateEffect, diskPresentation(summary.Disk))
	return ownerconsole.PlanPresentation{
		Identity: ownerconsole.PlanIdentity(built.plan.Identity()), DesiredStateRevision: summary.CandidateRevision, DesiredStateSHA256: summary.CurrentStateSHA256,
		RelevantChecksums: []string{"Current-State repair Plan SHA-256 " + built.plan.SHA256(), "Fresh drift SHA-256 " + built.inspection.VolatileSHA256},
		ObservedState:     "Current proven Desired State revision " + fmt.Sprint(summary.CurrentRevision), VerifiedExternalInputs: []string{"Exactly one repair contribution owned by " + string(summary.OwningModule)},
		Effects: effects, RequiredChecks: append([]string{}, summary.Checks...), AdvisoryChecks: []string{"No resource adoption and no missing State or secret recreation"},
		Interruption: "Only the affected service may restart.", Cancellation: "Cancellation waits for a safe rollback checkpoint.", Rollback: summary.Rollback,
	}
}

func completeRemovalPlanPresentation(built *builtCompleteRemoval) ownerconsole.PlanPresentation {
	summary := built.plan.Summary()
	revision := summary.StateRevision + 1
	lineageUnavailable := summary.StartingStatus == softwarelifecycle.RecoveryRequired && summary.StateRevision == 0
	if lineageUnavailable {
		revision = 0
	}
	effects := append([]string{}, summary.OwnedLocalCategories...)
	effects = append(effects, summary.CloudflareCategories...)
	effects = append(effects, diskPresentation(summary.Disk))
	return ownerconsole.PlanPresentation{
		Identity: ownerconsole.PlanIdentity(built.plan.Identity()), DesiredStateRevision: revision, DesiredStateSHA256: built.starting.StateSHA256, LineageUnavailable: lineageUnavailable,
		RelevantChecksums: []string{"Complete removal Plan SHA-256 " + built.plan.SHA256(), "Reviewed volatile state SHA-256 " + built.starting.VolatileSHA256},
		ObservedState:     "Proven " + string(summary.StartingStatus) + " starting status", VerifiedExternalInputs: append([]string{}, summary.IrreversibleRemnants...), Effects: effects,
		RequiredChecks: []string{"Exact owned external resources absent", "Final Not installed with no recovery material"}, AdvisoryChecks: []string{"Copied client configurations and provider caches may remain"},
		Interruption: "Restart continues from the exact durable checkpoint.", Cancellation: summary.CancellationBoundary, Rollback: summary.Rollback,
	}
}

func diskPresentation(disk systemchanges.DiskRequirement) string {
	return fmt.Sprintf("Disk bytes: preparation=%d temporary=%d snapshot=%d journal=%d rollback=%d overhead=%d", disk.PreparationBytes, disk.TemporaryBytes, disk.SnapshotBytes, disk.JournalBytes, disk.RollbackBytes, disk.OverheadBytes)
}

func validSoftwarePlanPresentation(review clientAccessHandoffReview) bool {
	plan := review.Plan
	lineage := plan.DesiredStateSHA256 == review.DesiredStateSHA256 && plan.DesiredStateRevision == review.CandidateRevision || plan.LineageUnavailable && plan.DesiredStateSHA256 == "" && review.DesiredStateSHA256 == "" && plan.DesiredStateRevision == 0 && review.CandidateRevision == 0
	return string(plan.Identity) == review.Identity && lineage && len(plan.RelevantChecksums) >= 2 && plan.ObservedState != "" && len(plan.VerifiedExternalInputs) > 0 && len(plan.Effects) > 0 && len(plan.RequiredChecks) > 0 && plan.Interruption != "" && plan.Cancellation != "" && plan.Rollback != ""
}

func writeClientAccessMessage(writer io.Writer, value any) error {
	body, err := json.Marshal(value)
	if err != nil || len(body) == 0 || len(body) > maxClientAccessHandoffBytes {
		return errors.New("Client Access handoff refused")
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(body)))
	if _, err = io.Copy(writer, bytes.NewReader(append(header, body...))); err != nil {
		return errors.New("Client Access handoff unavailable")
	}
	return nil
}

func readClientAccessMessage(reader io.Reader, value any) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return errors.New("Client Access handoff unavailable")
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 || size > maxClientAccessHandoffBytes {
		return errors.New("Client Access handoff refused")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(reader, body); err != nil || softwarelifecycle.ValidateUniqueJSON(body) != nil {
		return errors.New("Client Access handoff refused")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("Client Access handoff refused")
	}
	return nil
}

func serveSoftwareApply(socket *os.File, apply func(*systemchanges.Cancellation) systemchanges.ApplyResult) error {
	cancellation := systemchanges.NewCancellation()
	results := make(chan systemchanges.ApplyResult, 1)
	go func() { results <- apply(cancellation) }()
	cancelRequest := make(chan bool, 1)
	go func() {
		message := make([]byte, 7)
		_, err := io.ReadFull(socket, message)
		cancelRequest <- err == nil && string(message) == "CANCEL\n"
	}()
	var result systemchanges.ApplyResult
	select {
	case result = <-results:
	case accepted := <-cancelRequest:
		if accepted {
			cancellation.Request()
		}
		result = <-results
	}
	terminal := byte('X')
	if result.Outcome == systemchanges.Completed {
		terminal = 'C'
	} else if result.Outcome == systemchanges.RollbackSucceeded {
		terminal = 'R'
	} else if result.Outcome == systemchanges.AwaitingTokenRevocation {
		terminal = 'D'
	} else if result.Outcome == systemchanges.RemovalForwardOnly {
		terminal = 'P'
	}
	_, err := socket.Write([]byte{terminal})
	return err
}

func serveClientAccess(ctx context.Context, socket, executable *os.File, verify func(*os.File, *os.File) error) error {
	if ctx == nil || socket == nil || executable == nil || verify == nil || verify(socket, executable) != nil {
		return errors.New("privileged Client Access process refused")
	}
	var request clientAccessHandoffRequest
	if readClientAccessMessage(socket, &request) != nil || !validClientAccessHandoff(request) {
		return errors.New("Client Access request refused")
	}
	if request.Mode == "diagnostics" {
		if request.DiagnosticsAction == "view" {
			presentation, err := productionDiagnosticsPresentation(ctx)
			if err != nil {
				return err
			}
			return writeClientAccessMessage(socket, presentation)
		}
		return writeClientAccessMessage(socket, productionSupportBundle(ctx, request.BundleReplacement))
	}
	if request.Mode == "removal-review" || request.Mode == "removal-apply" {
		apply := request.Mode == "removal-apply"
		built, err := buildCompleteRemoval(ctx, request.ChangeSet, apply)
		if err != nil {
			return err
		}
		if apply && (built.plan.Identity() != request.ReviewedPlanIdentity || built.plan.SHA256() != request.ReviewedPlanSHA256) {
			return errors.New("approved Complete removal Plan changed")
		}
		candidateRevision := built.starting.StateRevision + 1
		if built.starting.Status == systemchanges.RecoveryRequired && built.starting.StateRevision == 0 {
			candidateRevision = 0
		}
		review := clientAccessHandoffReview{Identity: built.plan.Identity(), SHA256: built.plan.SHA256(), DesiredStateSHA256: built.starting.StateSHA256, VolatileSHA256: built.starting.VolatileSHA256, StartingRevision: built.starting.StateRevision, CandidateRevision: candidateRevision, TotalSteps: completeRemovalTotalSteps, Plan: completeRemovalPlanPresentation(built)}
		if writeClientAccessMessage(socket, review) != nil {
			return errors.New("Complete removal review unavailable")
		}
		if !apply {
			return nil
		}
		typed := make([]byte, len("COMPLETE REMOVAL\n"))
		permanent := make([]byte, len("PERMANENTLY REMOVE SBXR\n"))
		applyMessage := make([]byte, len("APPLY\n"))
		if _, err := io.ReadFull(socket, typed); err != nil || string(typed) != "COMPLETE REMOVAL\n" {
			return errors.New("Complete removal typed confirmation unavailable")
		}
		built.typedConfirmed = true
		if _, err := io.ReadFull(socket, permanent); err != nil || string(permanent) != "PERMANENTLY REMOVE SBXR\n" {
			return errors.New("Complete removal permanent selection unavailable")
		}
		built.permanentSelected = true
		if _, err := io.ReadFull(socket, applyMessage); err != nil || string(applyMessage) != "APPLY\n" {
			return errors.New("Complete removal approval unavailable")
		}
		return serveSoftwareApply(socket, func(cancellation *systemchanges.Cancellation) systemchanges.ApplyResult {
			return applyCompleteRemoval(ctx, built, cancellation)
		})
	}
	if request.Mode == "software-review" || request.Mode == "software-apply" {
		apply := request.Mode == "software-apply"
		if request.SoftwareAction == "repair" {
			built, err := recheckSoftwareRepair(ctx, request.ChangeSet)
			if apply {
				built, err = prepareSoftwareRepair(ctx, request.ChangeSet)
			}
			if err != nil {
				return err
			}
			proof := built.contribution.SoftwareLifecycleRepairContribution()
			if apply && (built.plan.Identity() != request.ReviewedPlanIdentity || built.plan.SHA256() != request.ReviewedPlanSHA256) {
				return errors.New("approved Software Lifecycle repair Plan changed")
			}
			review := clientAccessHandoffReview{Identity: built.plan.Identity(), SHA256: built.plan.SHA256(), DesiredStateSHA256: built.starting.SHA256, VolatileSHA256: built.inspection.VolatileSHA256, StartingRevision: built.starting.Revision, CandidateRevision: built.starting.Revision + 1, TotalSteps: uint16(len(proof.Steps))}
			review.Plan = softwareRepairPlanPresentation(built)
			if writeClientAccessMessage(socket, review) != nil {
				return errors.New("Software Lifecycle repair review unavailable")
			}
			if !apply {
				return nil
			}
			approval := make([]byte, 6)
			if _, err := io.ReadFull(socket, approval); err != nil || string(approval) != "APPLY\n" {
				return errors.New("Software Lifecycle repair approval unavailable")
			}
			return serveSoftwareApply(socket, func(cancellation *systemchanges.Cancellation) systemchanges.ApplyResult {
				return applySoftwareRepair(ctx, built, cancellation)
			})
		}
		action := softwareUpdate
		if request.SoftwareAction == "downgrade" {
			action = softwareDowngrade
		}
		built, err := prepareSoftwareChange(ctx, action, request.ReleaseTag, request.ChangeSet)
		if err != nil {
			return err
		}
		if apply && (built.plan.Identity() != request.ReviewedPlanIdentity || built.plan.SHA256() != request.ReviewedPlanSHA256) {
			return errors.New("approved Software Lifecycle Plan changed")
		}
		_, _, _, targetSHA, _, _, valid := built.prepared.SystemChangesPreparedState()
		if !valid {
			return errors.New("Software Lifecycle prepared State unavailable")
		}
		review := clientAccessHandoffReview{Identity: built.plan.Identity(), SHA256: built.plan.SHA256(), DesiredStateSHA256: targetSHA, VolatileSHA256: built.plan.VolatileSHA256(), CandidateTag: built.candidate.Identity.Tag, CandidateCommit: built.candidate.Identity.Commit, CandidateIndexSHA256: built.candidate.Identity.IndexSHA256, StartingRevision: built.starting.Revision, CandidateRevision: built.starting.Revision + 1, TotalSteps: uint16(built.totalSteps)}
		review.Plan = softwareUpdatePlanPresentation(built, targetSHA)
		if writeClientAccessMessage(socket, review) != nil {
			return errors.New("Software Lifecycle review unavailable")
		}
		if !apply {
			return nil
		}
		approval := make([]byte, 6)
		if _, err := io.ReadFull(socket, approval); err != nil || string(approval) != "APPLY\n" {
			return errors.New("Software Lifecycle approval unavailable")
		}
		return serveSoftwareApply(socket, func(cancellation *systemchanges.Cancellation) systemchanges.ApplyResult {
			return applySoftwareChange(ctx, built, cancellation)
		})
	}
	if request.Mode == "view" {
		presentation, err := managedClientAccessPresentation(ctx)
		if err != nil {
			return err
		}
		return writeClientAccessMessage(socket, presentation)
	}
	if request.Mode == "provider" {
		disk := systemchanges.DiskRequirement{PreparationBytes: 8 << 20, TemporaryBytes: 8 << 20, SnapshotBytes: 32 << 20, JournalBytes: 8 << 20, RollbackBytes: 8 << 20, OverheadBytes: 256 << 20}
		built, module, err := prepareManagedProvider(ctx, managedProviderBuildRequest{Action: request.ProviderAction, ChangeSet: request.ChangeSet, Token: request.Token, OwnerEmail: request.OwnerEmail, Agreement: request.Agreement, Disk: disk})
		if err != nil {
			return err
		}
		_, _, _, targetSHA, _, _, valid := built.prepared.SystemChangesPreparedState()
		if !valid {
			return errors.New("managed provider prepared State unavailable")
		}
		review := clientAccessHandoffReview{Identity: built.plan.Identity(), SHA256: built.plan.SHA256(), DesiredStateSHA256: targetSHA, VolatileSHA256: built.volatileSHA, StartingRevision: built.starting.Revision, CandidateRevision: built.starting.Revision + 1, TotalSteps: uint16(built.totalSteps)}
		if writeClientAccessMessage(socket, review) != nil {
			return errors.New("managed provider review unavailable")
		}
		approval := make([]byte, 6)
		if _, err := io.ReadFull(socket, approval); err != nil || string(approval) != "APPLY\n" {
			return errors.New("managed provider approval unavailable")
		}
		result := applyManagedProvider(ctx, built, module)
		terminal := byte('X')
		if result.Outcome == systemchanges.Completed {
			terminal = 'C'
		} else if result.Outcome == systemchanges.RollbackSucceeded {
			terminal = 'R'
		} else if result.Outcome == systemchanges.AwaitingRunTokenRotation {
			terminal = 'A'
		}
		_, err = socket.Write([]byte{terminal})
		return err
	}
	if request.Mode == "recover" {
		pending, found, err := productionPendingChangeSetReader().PendingChangeSet()
		if err != nil || !found || pending.Identity != request.ChangeSet {
			return errors.New("Client Access recovery request refused")
		}
		if recoveryErr := runStartupRecovery(); recoveryErr != nil {
			var sshFailure *clientAccessSSHReviewError
			if errors.As(recoveryErr, &sshFailure) {
				return writeClientAccessMessage(socket, clientAccessRecoveryResult{SSHFailureCause: sshFailure.Cause})
			}
			return errors.New("Client Access recovery failed")
		}
		observed, err := installRecoveryObservation()
		stillPending, pendingErr := pendingStartupRecovery()
		status := systemchanges.InstallationStatus("")
		if err == nil && pendingErr == nil && !stillPending && (observed.Status == systemchanges.Managed || observed.Status == systemchanges.NotInstalled) {
			status = observed.Status
		}
		return writeClientAccessMessage(socket, clientAccessRecoveryResult{Status: status})
	}
	disk := systemchanges.DiskRequirement{PreparationBytes: 8 << 20, TemporaryBytes: 8 << 20, SnapshotBytes: 32 << 20, JournalBytes: 8 << 20, RollbackBytes: 8 << 20, OverheadBytes: 256 << 20}
	built, module, err := prepareManagedClientAccess(ctx, clientAccessBuildRequest{Action: request.Action, Profile: connectionprofiles.ProfileID(request.Profile), ChangeSet: request.ChangeSet, Disk: disk})
	if err != nil {
		var sshFailure *clientAccessSSHReviewError
		if errors.As(err, &sshFailure) {
			return writeClientAccessMessage(socket, clientAccessHandoffReview{SSHFailureCause: sshFailure.Cause})
		}
		return err
	}
	review := clientAccessHandoffReview{Identity: built.plan.Identity(), SHA256: built.plan.SHA256(), DesiredStateSHA256: built.candidateSHA, VolatileSHA256: built.volatileSHA, StartingRevision: built.starting.Revision, CandidateRevision: built.starting.Revision + 1, TotalSteps: uint16(built.totalSteps)}
	if writeClientAccessMessage(socket, review) != nil {
		return errors.New("Client Access review unavailable")
	}
	approval := make([]byte, 6)
	if _, err := io.ReadFull(socket, approval); err != nil || string(approval) != "APPLY\n" {
		return errors.New("Client Access approval unavailable")
	}
	result := applyClientAccess(ctx, built, module)
	terminal := byte('X')
	if result.Outcome == systemchanges.Completed {
		terminal = 'C'
	} else if result.Outcome == systemchanges.RollbackSucceeded {
		terminal = 'R'
	}
	_, err = socket.Write([]byte{terminal})
	return err
}

func loadDiagnosticsPresentation(ctx context.Context) ownerconsole.DiagnosticsPresentation {
	request := clientAccessHandoffRequest{Schema: 1, Mode: "diagnostics", DiagnosticsAction: "view"}
	var presentation ownerconsole.DiagnosticsPresentation
	if requestClientAccessResult(ctx, request, &presentation) != nil {
		return ownerconsole.DiagnosticsPresentation{}
	}
	return presentation
}

func createSupportBundle(ctx context.Context, replacement ownerconsole.BundleReplacement) ownerconsole.SupportBundleResult {
	request := clientAccessHandoffRequest{Schema: 1, Mode: "diagnostics", DiagnosticsAction: "bundle", BundleReplacement: replacement}
	var result ownerconsole.SupportBundleResult
	if requestClientAccessResult(ctx, request, &result) != nil {
		return ownerconsole.SupportBundleResult{}
	}
	return result
}

func requestClientAccessResult(ctx context.Context, request clientAccessHandoffRequest, result any) error {
	if ctx == nil || !validClientAccessHandoff(request) || result == nil {
		return errors.New("Client Access request launch refused")
	}
	executable, err := openCurrentClientAccessExecutable()
	if err != nil {
		return err
	}
	parent, wait, err := startClientAccessProcess(ctx, executable)
	executable.Close()
	if err != nil {
		return err
	}
	defer parent.Close()
	if writeClientAccessMessage(parent, request) != nil || readClientAccessMessage(parent, result) != nil || wait() != nil {
		return errors.New("privileged Client Access result unavailable")
	}
	return nil
}

func retryClientAccessRecovery(ctx context.Context, changeSet string) (systemchanges.InstallationStatus, error) {
	request := clientAccessHandoffRequest{Schema: 1, Mode: "recover", ChangeSet: changeSet}
	if ctx == nil || !validClientAccessHandoff(request) {
		return "", errors.New("Client Access recovery launch refused")
	}
	pending, found, pendingErr := productionPendingChangeSetReader().PendingChangeSet()
	if pendingErr != nil || !found || pending.Identity != changeSet {
		return "", errors.New("Client Access recovery launch refused")
	}
	executable, err := openCurrentClientAccessExecutable()
	if err != nil {
		return "", err
	}
	parent, wait, err := startClientAccessProcess(ctx, executable)
	executable.Close()
	if err != nil {
		return "", err
	}
	defer wait()
	defer parent.Close()
	if writeClientAccessMessage(parent, request) != nil {
		return "", errors.New("Client Access recovery unavailable")
	}
	var result clientAccessRecoveryResult
	if readClientAccessMessage(parent, &result) != nil || result.Status != "" && result.Status != systemchanges.Managed && result.Status != systemchanges.NotInstalled || result.SSHFailureCause != "" && (!pending.ForwardFirewallPending || result.Status != "" || !validClientAccessSSHFailureCause(result.SSHFailureCause)) {
		return "", errors.New("Client Access recovery did not prove a terminal installation status")
	}
	if result.SSHFailureCause != "" {
		return "", &clientAccessSSHReviewError{Cause: result.SSHFailureCause}
	}
	return result.Status, nil
}

func launchClientAccessReview(ctx context.Context, request clientAccessHandoffRequest) (*clientAccessHandoffSession, error) {
	if ctx == nil || !validClientAccessHandoff(request) {
		return nil, errors.New("Client Access launch refused")
	}
	executable, err := openCurrentClientAccessExecutable()
	if err != nil {
		return nil, err
	}
	parent, wait, err := startClientAccessProcess(ctx, executable)
	executable.Close()
	if err != nil {
		return nil, err
	}
	if err := writeClientAccessMessage(parent, request); err != nil {
		parent.Close()
		_ = wait()
		return nil, err
	}
	var review clientAccessHandoffReview
	if err := readClientAccessMessage(parent, &review); err != nil {
		parent.Close()
		_ = wait()
		return nil, errors.New("privileged Client Access review unavailable")
	}
	if validClientAccessSSHFailureReview(request, review) {
		parent.Close()
		if wait() != nil {
			return nil, errors.New("privileged Client Access review unavailable")
		}
		return nil, &clientAccessSSHReviewError{Cause: review.SSHFailureCause}
	}
	unprovenRemoval := (request.Mode == "removal-review" || request.Mode == "removal-apply") && review.StartingRevision == 0 && review.CandidateRevision == 0 && review.DesiredStateSHA256 == "" && review.Plan.LineageUnavailable
	if review.SSHFailureCause != "" || review.Identity == "" || len(review.SHA256) != 64 || len(review.VolatileSHA256) != 64 || !unprovenRemoval && (len(review.DesiredStateSHA256) != 64 || review.CandidateRevision != review.StartingRevision+1) || review.TotalSteps == 0 || (request.Mode == "software-review" || request.Mode == "software-apply" || request.Mode == "removal-review" || request.Mode == "removal-apply") && !validSoftwarePlanPresentation(review) {
		parent.Close()
		_ = wait()
		return nil, errors.New("privileged Client Access review unavailable")
	}
	if request.Mode == "software-review" || request.Mode == "removal-review" {
		parent.Close()
		if wait() != nil {
			return nil, errors.New("privileged Software Lifecycle planning failed")
		}
		return &clientAccessHandoffSession{used: true, review: review}, nil
	}
	return &clientAccessHandoffSession{socket: parent, wait: wait, review: review, cancellable: request.Mode == "software-apply" || request.Mode == "removal-apply"}, nil
}

func validClientAccessSSHFailureCause(cause networkpolicy.SSHPreservationFailureCause) bool {
	return cause == networkpolicy.SSHLaunchIdentityInvalid || cause == networkpolicy.SSHOriginalSessionLost || cause == networkpolicy.SSHObservationUnavailable
}

func validClientAccessSSHFailureReview(request clientAccessHandoffRequest, review clientAccessHandoffReview) bool {
	return request.Mode == "change" && clientAccessChangesFirewall(request.Action) && validClientAccessSSHFailureCause(review.SSHFailureCause)
}

func loadClientAccessPresentation(ctx context.Context) clientAccessPresentation {
	request := clientAccessHandoffRequest{Schema: 1, Mode: "view"}
	executable, err := openCurrentClientAccessExecutable()
	if err != nil {
		return clientAccessPresentation{}
	}
	parent, wait, err := startClientAccessProcess(ctx, executable)
	executable.Close()
	if err != nil {
		return clientAccessPresentation{}
	}
	defer wait()
	defer parent.Close()
	if writeClientAccessMessage(parent, request) != nil {
		return clientAccessPresentation{}
	}
	var presentation clientAccessPresentation
	if readClientAccessMessage(parent, &presentation) != nil || wait() != nil {
		return clientAccessPresentation{}
	}
	return presentation
}

func (session *clientAccessHandoffSession) discard() {
	if session == nil {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.used {
		return
	}
	session.used = true
	if session.socket != nil {
		_ = session.socket.Close()
	}
	if session.wait != nil {
		_ = session.wait()
	}
}

func (session *clientAccessHandoffSession) apply() (byte, error) {
	if session == nil {
		return 0, errors.New("Client Access review is unavailable")
	}
	session.mu.Lock()
	if session.used || session.socket == nil || session.wait == nil {
		session.mu.Unlock()
		return 0, errors.New("Client Access review is unavailable")
	}
	session.used = true
	socket, wait := session.socket, session.wait
	approval := "APPLY\n"
	if session.removalApproved {
		approval = "COMPLETE REMOVAL\nPERMANENTLY REMOVE SBXR\nAPPLY\n"
	}
	if _, err := socket.Write([]byte(approval)); err != nil {
		session.mu.Unlock()
		return 0, err
	}
	session.applying = true
	session.mu.Unlock()
	defer socket.Close()
	terminal := []byte{0}
	_, readErr := io.ReadFull(socket, terminal)
	waitErr := wait()
	session.mu.Lock()
	session.applying = false
	session.mu.Unlock()
	if readErr != nil || waitErr != nil || terminal[0] != 'A' && terminal[0] != 'C' && terminal[0] != 'D' && terminal[0] != 'P' && terminal[0] != 'R' && terminal[0] != 'X' {
		return 0, errors.New("privileged Client Access result unavailable")
	}
	return terminal[0], nil
}

func (session *clientAccessHandoffSession) cancel() error {
	if session == nil {
		return errors.New("Software Lifecycle cancellation unavailable")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.cancellable || !session.applying || session.socket == nil {
		return errors.New("Software Lifecycle cancellation unavailable")
	}
	session.cancellable = false
	if _, err := session.socket.Write([]byte("CANCEL\n")); err != nil {
		return errors.New("Software Lifecycle cancellation unavailable")
	}
	return nil
}

func servePrivateClientAccess(ctx context.Context) error {
	executable := os.NewFile(3, "verified-sbxr")
	if executable == nil {
		return errors.New("verified executable descriptor unavailable")
	}
	defer executable.Close()
	return serveClientAccess(ctx, os.Stdin, executable, verifyClientAccessProcess)
}
