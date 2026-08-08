package subscriptionpublication_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestPlanBindsOneCompleteValidatedArtifactSetWithoutRenderingSecrets(t *testing.T) {
	source, reader := sixProfileSource(t, "198.51.100.10")
	token := access(reader, "SUBSCRIPTION-TOKEN-MARKER")
	release := state.ReleaseIdentity{Repository: "github.com/albertloky/SBXR", Tag: "v1.0.0", Commit: strings.Repeat("a", 40), ReleaseIndexSHA256: strings.Repeat("b", 64)}
	result := newAcceptingTestModule().Plan(t.Context(), subscriptionpublication.PlanRequest{
		Source: source, Secrets: reader, Subscription: state.SubscriptionSettings{Token: token, ListenPort: 10443, CertificateID: "ip-certificate"},
		ChangeSet: "change-0008", StartingState: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: strings.Repeat("c", 64)},
		DesiredStateRevision: 8, DesiredStateSHA256: strings.Repeat("d", 64), ManagedInputsSHA256: strings.Repeat("e", 64),
		RelevantChecksums:       subscriptionpublication.RelevantChecksums{ConnectionProfiles: strings.Repeat("f", 64), Subscription: strings.Repeat("1", 64)},
		CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, SelectedAddress: "198.51.100.10", ReleaseIdentity: release,
	})
	if result.Plan == nil || result.Finding != nil {
		t.Fatalf("Plan() = %+v", result)
	}
	if result.Plan.Identity() == "" || len(result.Plan.SHA256()) != 64 || len(result.Plan.Steps()) != 1 || len(result.Plan.Checks()) != 3 {
		t.Fatalf("Plan bindings are incomplete: %s %s steps=%d checks=%d", result.Plan.Identity(), result.Plan.SHA256(), len(result.Plan.Steps()), len(result.Plan.Checks()))
	}
	summary := result.Plan.Summary()
	if summary.ProfileCount != 6 || len(summary.Representations) != 7 || summary.ChangeSet != "change-0008" || summary.DesiredStateRevision != 8 || summary.ReleaseIdentity != release || summary.SelectedAddress != "198.51.100.10" || summary.CompatibilityDefinition != string(subscriptionpublication.CurrentCompatibilityDefinition) || !validSummaryChecksums(summary.RelevantChecksums) || !summary.ValidationComplete || summary.Replacement != "complete artifact set N to N+1" || summary.Rollback != "restore the exact prior complete artifact set" {
		t.Fatalf("Plan summary = %+v", summary)
	}
	for _, rendered := range []string{fmt.Sprint(result.Plan), fmt.Sprintf("%+v", result.Plan), fmt.Sprintf("%#v", result.Plan)} {
		if strings.Contains(rendered, "SUBSCRIPTION-TOKEN-MARKER") || strings.Contains(rendered, "11111111-1111-4111-8111-111111111111") {
			t.Fatalf("Plan formatting exposed a Client Access Value: %s", rendered)
		}
	}
	if encoded, err := json.Marshal(result.Plan); err == nil || bytes.Contains(encoded, []byte("SUBSCRIPTION-TOKEN-MARKER")) {
		t.Fatalf("json.Marshal(Plan) = %s, %v", encoded, err)
	}
	bundle, err := result.Plan.PrepareSubscriptionPublication()
	set, decodeErr := subscriptionpublication.DecodePreparedArtifactSet(bytes.NewReader(bundle))
	if err != nil || decodeErr != nil || len(set.Files()) != 8 {
		t.Fatalf("PrepareSubscriptionPublication() = %d bytes, %v, decode %v", len(bundle), err, decodeErr)
	}
	if _, err := result.Plan.PrepareSubscriptionPublication(); err == nil {
		t.Fatal("prepared artifact authority was reusable")
	}
	prepared := &preparedPlanBinding{changeSet: "change-0008", revision: 8, starting: strings.Repeat("c", 64), candidate: strings.Repeat("d", 64), identity: result.Plan.Identity(), sha256: result.Plan.SHA256()}
	disk := systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}
	firstApply := result.Plan.Apply(systemchanges.New(nil), prepared, systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: strings.Repeat("c", 64)}, strings.Repeat("e", 64), disk)
	secondApply := result.Plan.Apply(systemchanges.New(nil), prepared, systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: strings.Repeat("c", 64)}, strings.Repeat("e", 64), disk)
	if firstApply.Outcome != systemchanges.Refused || secondApply.Outcome != systemchanges.Refused || prepared.bindings != 1 {
		t.Fatalf("one-use Plan.Apply = first %+v, second %+v, prepared bindings %d", firstApply, secondApply, prepared.bindings)
	}
}

type preparedPlanBinding struct {
	changeSet, starting, candidate, identity, sha256 string
	revision                                         uint64
	bindings                                         int
}

func (prepared *preparedPlanBinding) SystemChangesPreparedState() (string, uint64, string, string, string, string, bool) {
	prepared.bindings++
	return prepared.changeSet, prepared.revision, prepared.starting, prepared.candidate, prepared.identity, prepared.sha256, true
}

func (*preparedPlanBinding) SystemChangesConsume(any, string, string) (any, error) {
	return nil, errors.New("unavailable test Adapter")
}

func validSummaryChecksums(checksums subscriptionpublication.RelevantChecksums) bool {
	return len(checksums.ConnectionProfiles) == 64 && len(checksums.Subscription) == 64
}

func TestPlanRefusesStaleIncompleteAndSecretBearingInputs(t *testing.T) {
	source, reader := sixProfileSource(t, "198.51.100.10")
	base := subscriptionpublication.PlanRequest{
		Source: source, Secrets: reader, Subscription: state.SubscriptionSettings{Token: access(reader, "SUBSCRIPTION-TOKEN-MARKER"), ListenPort: 10443, CertificateID: "ip-certificate"},
		ChangeSet: "change-0008", StartingState: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: strings.Repeat("c", 64)},
		DesiredStateRevision: 8, DesiredStateSHA256: strings.Repeat("d", 64), ManagedInputsSHA256: strings.Repeat("e", 64),
		RelevantChecksums:       subscriptionpublication.RelevantChecksums{ConnectionProfiles: strings.Repeat("f", 64), Subscription: strings.Repeat("1", 64)},
		CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, SelectedAddress: "198.51.100.10",
		ReleaseIdentity: state.ReleaseIdentity{Repository: "github.com/albertloky/SBXR", Tag: "v1.0.0", Commit: strings.Repeat("a", 40), ReleaseIndexSHA256: strings.Repeat("b", 64)},
	}
	for _, mutate := range []func(*subscriptionpublication.PlanRequest){
		func(request *subscriptionpublication.PlanRequest) { request.DesiredStateRevision = 7 },
		func(request *subscriptionpublication.PlanRequest) {
			request.CompatibilityDefinition = "stale-definition"
		},
		func(request *subscriptionpublication.PlanRequest) {
			request.ManagedInputsSHA256 = "SUBSCRIPTION-TOKEN-MARKER"
		},
		func(request *subscriptionpublication.PlanRequest) { request.Secrets = nil },
	} {
		request := base
		mutate(&request)
		result := newAcceptingTestModule().Plan(t.Context(), request)
		if result.Plan != nil || result.Finding == nil || strings.Contains(fmt.Sprintf("%+v", result.Finding), "SUBSCRIPTION-TOKEN-MARKER") {
			t.Fatalf("invalid Plan request was accepted or leaked: %+v", result)
		}
	}
}
