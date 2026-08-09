package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type mutableStateStorage struct {
	mu                 sync.Mutex
	document           string
	err                error
	publishBeforeError bool
	publishAfterError  bool
	readback           []byte
}

func (storage *mutableStateStorage) Read() ([]byte, error) {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	return []byte(storage.document), storage.err
}

func (storage *mutableStateStorage) set(document string, err error) {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	storage.document = document
	storage.err = err
}

func (storage *mutableStateStorage) Publish(expectedPrior, candidate []byte, _ string) ([]byte, error) {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	missing := errors.Is(storage.err, fs.ErrNotExist)
	if storage.publishBeforeError || storage.err != nil && !missing || missing && len(expectedPrior) != 0 || !missing && !bytes.Equal([]byte(storage.document), expectedPrior) {
		return nil, errors.New("publication baseline changed")
	}
	storage.document = string(candidate)
	storage.err = nil
	if storage.publishAfterError {
		return nil, errors.New("interrupted after replacement")
	}
	if storage.readback != nil {
		return append([]byte(nil), storage.readback...), nil
	}
	return append([]byte(nil), candidate...), nil
}

func (storage *mutableStateStorage) Restore(expectedCurrent, prior []byte) ([]byte, error) {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	if storage.err != nil || !bytes.Equal([]byte(storage.document), expectedCurrent) {
		return nil, errors.New("rollback baseline changed")
	}
	storage.document = string(prior)
	if len(prior) == 0 {
		storage.err = fs.ErrNotExist
	}
	return append([]byte(nil), prior...), nil
}

func TestPrepareCommitDerivesRevisionFromExactLoad(t *testing.T) {
	candidate := completeDesiredState()

	t.Run("fresh installation is revision 1", func(t *testing.T) {
		storage := &mutableStateStorage{err: fs.ErrNotExist}
		stateModule := New(storage)
		loaded, err := stateModule.Load(LoadRequest{Baseline: CleanVPS})
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := stateModule.PrepareCommit(preparedRequest(t, loaded, candidate, "change-0001"))
		if err != nil {
			t.Fatal(err)
		}
		if prepared.Revision() != 1 || prepared.MigrationReview() != nil {
			t.Fatalf("fresh prepared commit = (revision %d, migration %#v), want revision 1 without a fictional predecessor", prepared.Revision(), prepared.MigrationReview())
		}
	})

	t.Run("managed revision N prepares N plus 1", func(t *testing.T) {
		storage := &mutableStateStorage{document: documentFor(t, candidate)}
		stateModule := New(storage)
		loaded, err := stateModule.Load(intentManagedRequest())
		if err != nil {
			t.Fatal(err)
		}
		request := preparedRequest(t, loaded, candidate, "change-0008")
		prepared, err := stateModule.PrepareCommit(request)
		if err != nil {
			t.Fatal(err)
		}
		if prepared.Revision() != 8 {
			t.Fatalf("prepared revision = %d, want 8", prepared.Revision())
		}
	})
}

func TestPrepareCommitReportsSchemaOneToTwoReleaseCompatibility(t *testing.T) {
	candidate := completeDesiredState()
	storage := &mutableStateStorage{document: documentFor(t, candidate)}
	stateModule := New(storage)
	loaded, err := stateModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	request := preparedRequest(t, loaded, candidate, "change-0008")
	request.CandidateReleaseIdentity.Tag = "v1.1.0"
	request.CandidateReleaseIdentity.Commit = strings.Repeat("1", 40)
	request.SubscriptionPublication = request.SemanticValidators.Subscription.(*validatingSeams)
	prepared, err := stateModule.PrepareCommit(request)
	if err != nil {
		t.Fatal(err)
	}
	review := prepared.MigrationReview()
	if review == nil || review.StartingSchema != 1 || review.TargetSchema != 2 || len(review.Steps) != 1 || review.Steps[0].FromSchema != 1 || review.Steps[0].ToSchema != 2 || review.StartingRelease != testRelease || review.TargetRelease != request.CandidateReleaseIdentity || review.StartingReleaseCanReadCandidate {
		t.Fatalf("PrepareCommit() migration review = %#v, want complete schema 1 to 2 path and incompatible starting release", review)
	}
	from, to, steps, networkFree := prepared.SoftwareLifecyclePreparedMigration()
	if from != 0 || to != 0 || steps != 0 || networkFree {
		t.Fatalf("generic SoftwareLifecyclePreparedMigration() = (%d, %d, %d, %t), want no update authority", from, to, steps, networkFree)
	}
}

func TestPrepareCommitRequiresOneFreshExactLoad(t *testing.T) {
	candidate := completeDesiredState()

	t.Run("one Load prepares at most once", func(t *testing.T) {
		storage := &mutableStateStorage{document: documentFor(t, candidate)}
		stateModule := New(storage)
		loaded, err := stateModule.Load(intentManagedRequest())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stateModule.PrepareCommit(preparedRequest(t, loaded, candidate, "change-0008")); err != nil {
			t.Fatal(err)
		}
		_, err = stateModule.PrepareCommit(preparedRequest(t, loaded, candidate, "change-0008"))
		assertFinding(t, err, "STATE-LOAD-USED")
	})

	t.Run("changed persisted starting bytes are stale", func(t *testing.T) {
		document := documentFor(t, candidate)
		storage := &mutableStateStorage{document: document}
		stateModule := New(storage)
		loaded, err := stateModule.Load(intentManagedRequest())
		if err != nil {
			t.Fatal(err)
		}
		storage.set("\n"+document, nil)
		request := preparedRequest(t, loaded, candidate, "change-0008")
		_, err = stateModule.PrepareCommit(request)
		assertFinding(t, err, "STATE-LOAD-STALE")
		loadedAgain, err := stateModule.Load(intentManagedRequest())
		if err != nil {
			t.Fatal(err)
		}
		replayed := preparedRequest(t, loadedAgain, candidate, "change-0008")
		replayed.ReviewedInputs = request.ReviewedInputs
		_, err = stateModule.PrepareCommit(replayed)
		assertFinding(t, err, "STATE-PLAN-USED")
	})

	t.Run("Change in progress remains read-only", func(t *testing.T) {
		document := documentFor(t, candidate)
		storage := &mutableStateStorage{document: document}
		stateModule := New(storage)
		request := intentManagedRequest()
		request.Lineage.ActiveChangeSet = "change-0008"
		loaded, err := stateModule.Load(request)
		if err != nil || loaded.Status != ChangeInProgress || loaded.Snapshot == nil || loaded.Snapshot.Revision != 7 || loaded.Snapshot.DesiredState != candidate || loaded.CurrentOperation == nil || loaded.CurrentOperation.ChangeSet != "change-0008" {
			t.Fatalf("Load() = (%+v, %v), want last committed revision and typed operation status", loaded, err)
		}
		_, err = stateModule.PrepareCommit(preparedRequest(t, loaded, candidate, "change-0009"))
		assertFinding(t, err, "STATE-CHANGE-IN-PROGRESS")
	})
}

func TestPreparedCommitIsOpaqueAndConsumedByFirstApply(t *testing.T) {
	candidate := completeDesiredState()
	document := documentFor(t, candidate)
	storage := &mutableStateStorage{document: document}
	stateModule := New(storage)
	loaded, err := stateModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	request := preparedRequest(t, loaded, candidate, "change-0008")
	prepared, err := stateModule.PrepareCommit(request)
	if err != nil {
		t.Fatal(err)
	}

	transaction, err := prepared.ConsumeForApply(request.ReviewedInputs)
	if err != nil {
		t.Fatal(err)
	}
	if transaction == nil || transaction.startingRevision != 7 || transaction.candidateRevision != 8 || !bytes.Equal(transaction.priorState, []byte(document)) {
		t.Fatal("transaction handoff did not preserve exact opaque prior State and N to N+1")
	}
	assertFinding(t, consumeAgain(prepared, reviewedInputs(t, '1')), "STATE-PREPARED-USED")

	for name, protected := range map[string]any{"prepared commit": prepared, "transaction material": transaction} {
		rendered, renderErr := json.Marshal(protected)
		formatted := fmt.Sprintf("%+v %#v", protected, protected)
		if renderErr == nil || strings.Contains(string(rendered), "SECRET-MARKER") || !strings.Contains(formatted, "redacted") || len(formatted) > 160 {
			t.Fatalf("%s exposed protected transaction material", name)
		}
	}
}

func TestFirstApplyAttemptBurnsChangedOrStaleAuthority(t *testing.T) {
	candidate := completeDesiredState()
	document := documentFor(t, candidate)

	bindings := []struct {
		name   string
		change func(*ReviewedInputs)
	}{
		{name: "changed Plan identity", change: func(current *ReviewedInputs) { current.planIdentity = "plan-other" }},
		{name: "changed Plan checksum", change: func(current *ReviewedInputs) { current.planSHA256 = testSHA('8') }},
		{name: "changed Connection Profiles observation", change: func(current *ReviewedInputs) { current.managed.connectionProfiles = testSHA('8') }},
		{name: "changed subscription observation", change: func(current *ReviewedInputs) { current.managed.subscription = testSHA('8') }},
		{name: "changed Cloudflare observation", change: func(current *ReviewedInputs) { current.managed.cloudflare = testSHA('8') }},
		{name: "changed certificate observation", change: func(current *ReviewedInputs) { current.managed.certificates = testSHA('8') }},
		{name: "changed Network Policy observation", change: func(current *ReviewedInputs) { current.managed.networkPolicy = testSHA('8') }},
		{name: "changed software observation", change: func(current *ReviewedInputs) { current.managed.softwareLifecycle = testSHA('8') }},
	}
	for _, tt := range bindings {
		t.Run(tt.name, func(t *testing.T) {
			storage := &mutableStateStorage{document: document}
			stateModule := New(storage)
			loaded, err := stateModule.Load(intentManagedRequest())
			if err != nil {
				t.Fatal(err)
			}
			request := preparedRequest(t, loaded, candidate, "change-0008")
			prepared, err := stateModule.PrepareCommit(request)
			if err != nil {
				t.Fatal(err)
			}
			current := request.ReviewedInputs
			tt.change(&current)
			_, err = prepared.ConsumeForApply(current)
			assertFinding(t, err, "STATE-PREPARED-BINDING")
			assertFinding(t, consumeAgain(prepared, reviewedInputs(t, '1')), "STATE-PREPARED-USED")
		})
	}

	t.Run("different persisted starting State", func(t *testing.T) {
		storage := &mutableStateStorage{document: document}
		stateModule := New(storage)
		loaded, err := stateModule.Load(intentManagedRequest())
		if err != nil {
			t.Fatal(err)
		}
		request := preparedRequest(t, loaded, candidate, "change-0008")
		prepared, err := stateModule.PrepareCommit(request)
		if err != nil {
			t.Fatal(err)
		}
		changed := candidate
		changed.Software.XrayVersion = "25.9.0"
		storage.set(documentFor(t, changed), nil)
		_, err = prepared.ConsumeForApply(request.ReviewedInputs)
		assertFinding(t, err, "STATE-PREPARED-STALE")
		storage.set(document, nil)
		assertFinding(t, consumeAgain(prepared, reviewedInputs(t, '1')), "STATE-PREPARED-USED")
	})
}

func TestEveryApprovedChangeKindPreparesExactlyNToNPlusOne(t *testing.T) {
	base := completeDesiredState()
	tests := []struct {
		name   string
		change func(*DesiredState)
	}{
		{name: "setting change", change: func(candidate *DesiredState) { candidate.ConnectionProfiles.AnyTLS.PaddingScheme = "stop=16" }},
		{name: "repair", change: func(*DesiredState) {}},
		{name: "credential rotation", change: func(candidate *DesiredState) { candidate.Subscription.Token = NewClientAccessValue(testSHA('a')) }},
		{name: "software migration", change: func(candidate *DesiredState) { candidate.Software.XrayVersion = "25.9.0" }},
		{name: "automatic certificate renewal", change: func(candidate *DesiredState) {
			candidate.Certificates.IPCertificateID = "ip-certificate-renewed"
			candidate.Certificates.DomainCertificateID = "domain-certificate-renewed"
			candidate.Subscription.CertificateID = candidate.Certificates.IPCertificateID
			candidate.ConnectionProfiles.Hysteria2.CertificateID = candidate.Certificates.DomainCertificateID
			candidate.ConnectionProfiles.TUIC.CertificateID = candidate.Certificates.DomainCertificateID
			candidate.ConnectionProfiles.AnyTLS.CertificateID = candidate.Certificates.DomainCertificateID
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := base
			tt.change(&candidate)
			stateModule, request, _ := managedPrepareRequest(t, candidate)
			prepared, err := stateModule.PrepareCommit(request)
			if err != nil {
				t.Fatal(err)
			}
			if prepared.Revision() != 8 {
				t.Fatalf("prepared revision = %d, want 8", prepared.Revision())
			}
			if _, err := prepared.ConsumeForApply(request.ReviewedInputs); err != nil {
				t.Fatal(err)
			}
			loaded, err := stateModule.Load(intentManagedRequest())
			if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 7 {
				t.Fatalf("planning advanced current revision: Load() = (%+v, %v)", loaded, err)
			}
		})
	}
}

func TestEveryApplyOutcomeRequiresFreshAuthority(t *testing.T) {
	for _, outcome := range []string{"failure", "cancellation", "rollback", "success", "retry"} {
		t.Run(outcome, func(t *testing.T) {
			candidate := completeDesiredState()
			stateModule, request, _ := managedPrepareRequest(t, candidate)
			prepared, err := stateModule.PrepareCommit(request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := prepared.ConsumeForApply(request.ReviewedInputs); err != nil {
				t.Fatal(err)
			}
			assertFinding(t, consumeAgain(prepared, request.ReviewedInputs), "STATE-PREPARED-USED")
		})
	}
}

func TestPreparedCommitAllowsOnlyOneConcurrentConsumer(t *testing.T) {
	candidate := completeDesiredState()
	stateModule, request, _ := managedPrepareRequest(t, candidate)
	prepared, err := stateModule.PrepareCommit(request)
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var replays atomic.Int32
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, consumeErr := prepared.ConsumeForApply(request.ReviewedInputs)
			if consumeErr == nil {
				successes.Add(1)
				return
			}
			var finding *Finding
			if errors.As(consumeErr, &finding) && finding.Code == "STATE-PREPARED-USED" {
				replays.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || replays.Load() != 15 {
		t.Fatalf("concurrent consumers = (%d success, %d replay), want (1, 15)", successes.Load(), replays.Load())
	}
}

func TestPreparedTransactionMaterialIsByteStableAndBindsChecksums(t *testing.T) {
	candidate := completeDesiredState()
	stateModule, firstRequest, _ := managedPrepareRequest(t, candidate)
	first, err := stateModule.PrepareCommit(firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	loadedAgain, err := stateModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	secondRequest := preparedRequest(t, loadedAgain, candidate, "change-0008")
	secondRequest.ReviewedInputs = reviewedInputs(t, '1')
	second, err := stateModule.PrepareCommit(secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.preparedState, second.preparedState) || first.preparedSHA256 != second.preparedSHA256 || first.candidateSHA256 != second.candidateSHA256 || first.manifestSHA256 != second.manifestSHA256 || !reflect.DeepEqual(first.serviceCopies, second.serviceCopies) {
		t.Fatal("same exact lineage and candidate produced different transaction material")
	}
	transaction, err := first.ConsumeForApply(firstRequest.ReviewedInputs)
	if err != nil {
		t.Fatal(err)
	}
	if transaction.startingChecksum == "" || transaction.candidateChecksum == "" || transaction.manifestChecksum == "" || transaction.preparedChecksum == "" || transaction.changeSet != "change-0008" || !bytes.Equal(transaction.preparedState, first.preparedState) {
		t.Fatal("transaction material omitted a required checksum or Change Set binding")
	}
}

func TestPreparedTransactionPublishesExactlyOnceAndReturnsAgreementInputs(t *testing.T) {
	candidate := completeDesiredState()
	stateModule, request, _ := managedPrepareRequest(t, candidate)
	prepared, err := stateModule.PrepareCommit(request)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := prepared.ConsumeForApply(request.ReviewedInputs)
	if err != nil {
		t.Fatal(err)
	}
	var prior bytes.Buffer
	present, err := transaction.PreservePriorState(&prior)
	if err != nil || !present || prior.String() != documentFor(t, completeDesiredState()) {
		t.Fatalf("PreservePriorState() = (present %t, %v), want exact opaque revision 7", present, err)
	}
	copyOfTransaction := *transaction
	agreement, err := transaction.Publish()
	if err != nil {
		t.Fatal(err)
	}
	if agreement.PublishedRevision() != 8 || agreement.ChangeSet() != "change-0008" || agreement.PublishedChecksum() == "" || agreement.PublishedDocumentSHA256() == "" || agreement.PreparedManifestChecksum() == "" || agreement.ReleaseIdentity() != testRelease || agreement.ConnectionProfiles() != candidate.ConnectionProfiles || agreement.Subscription() != candidate.Subscription || agreement.Cloudflare() != candidate.Cloudflare || agreement.Certificates() != candidate.Certificates || agreement.NetworkPolicy() != candidate.NetworkPolicy || agreement.SoftwareLifecycle() != (SoftwareLifecycleIntent{Installation: candidate.Installation, Software: candidate.Software}) || len(agreement.ServiceManifests()) != 4 {
		t.Fatal("publication agreement omitted the published State or prepared manifests")
	}
	loaded, err := stateModule.Load(LoadRequest{Baseline: ManagedEvidence, SupportedRelease: testRelease, Lineage: &LineageProof{Revision: 8, LastCompletedChangeSet: "change-0008", ReleaseIdentity: testRelease}})
	if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 8 {
		t.Fatalf("Load() after publication = (%+v, %v), want exact revision 8", loaded, err)
	}
	_, err = copyOfTransaction.Publish()
	assertFinding(t, err, "STATE-PUBLICATION-USED")
}

func TestFreshInstallationPublishesRevisionOneOnlyAtPublication(t *testing.T) {
	candidate := completeDesiredState()
	storage := &mutableStateStorage{err: fs.ErrNotExist}
	stateModule := New(storage)
	loaded, err := stateModule.Load(LoadRequest{Baseline: CleanVPS})
	if err != nil {
		t.Fatal(err)
	}
	request := preparedRequest(t, loaded, candidate, "change-0001")
	prepared, err := stateModule.PrepareCommit(request)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := prepared.ConsumeForApply(request.ReviewedInputs)
	if err != nil {
		t.Fatal(err)
	}
	if result, loadErr := stateModule.Load(LoadRequest{Baseline: CleanVPS}); loadErr != nil || result.Status != NotInstalled {
		t.Fatalf("State before Publish() = (%+v, %v), want Not installed", result, loadErr)
	}
	if before, readErr := storage.Read(); !errors.Is(readErr, fs.ErrNotExist) || bytes.Contains(before, []byte("CLOUDFLARE-MANAGEMENT-SECRET-MARKER")) {
		t.Fatal("fresh Cloudflare management token was stored before revision 1 publication")
	}
	var prior bytes.Buffer
	if present, preserveErr := transaction.PreservePriorState(&prior); preserveErr != nil || present || prior.Len() != 0 {
		t.Fatalf("fresh prior handoff = (present %t, bytes %d, %v), want proven absence", present, prior.Len(), preserveErr)
	}
	agreement, err := transaction.Publish()
	if err != nil || agreement.PublishedRevision() != 1 {
		t.Fatalf("Publish() = (%+v, %v), want revision 1", agreement, err)
	}
	if published, readErr := storage.Read(); readErr != nil || !bytes.Contains(published, []byte("CLOUDFLARE-MANAGEMENT-SECRET-MARKER")) {
		t.Fatal("revision 1 omitted the verified Cloudflare management token")
	}
}

func TestPublicationInterruptionKeepsWholeStateAndOpaquePrior(t *testing.T) {
	candidate := completeDesiredState()
	prior := documentFor(t, candidate)
	tests := []struct {
		name      string
		configure func(*mutableStateStorage)
		code      string
		wantPrior bool
	}{
		{name: "before replacement", configure: func(storage *mutableStateStorage) { storage.publishBeforeError = true }, code: "STATE-PUBLICATION-STORAGE", wantPrior: true},
		{name: "after replacement", configure: func(storage *mutableStateStorage) { storage.publishAfterError = true }, code: "STATE-PUBLICATION-STORAGE"},
		{name: "wrong readback", configure: func(storage *mutableStateStorage) { storage.readback = []byte(`{"partial":true}`) }, code: "STATE-PUBLICATION-READBACK"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := &mutableStateStorage{document: prior}
			tt.configure(storage)
			stateModule := New(storage)
			loaded, err := stateModule.Load(intentManagedRequest())
			if err != nil {
				t.Fatal(err)
			}
			request := preparedRequest(t, loaded, candidate, "change-0008")
			prepared, err := stateModule.PrepareCommit(request)
			if err != nil {
				t.Fatal(err)
			}
			transaction, err := prepared.ConsumeForApply(request.ReviewedInputs)
			if err != nil {
				t.Fatal(err)
			}
			_, err = transaction.Publish()
			assertFinding(t, err, tt.code)
			var restored bytes.Buffer
			present, preserveErr := transaction.PreservePriorState(&restored)
			if preserveErr != nil || !present || restored.String() != prior {
				t.Fatalf("prior handoff after interruption = (present %t, %v), want exact prior bytes", present, preserveErr)
			}
			current, readErr := storage.Read()
			if readErr != nil || tt.wantPrior && !bytes.Equal(current, []byte(prior)) || !tt.wantPrior && !bytes.Equal(current, transaction.preparedState) {
				t.Fatal("interruption left neither the whole prior State nor the whole prepared State")
			}
			_, err = transaction.Publish()
			assertFinding(t, err, "STATE-PUBLICATION-USED")
		})
	}
}

func TestPublicationRefusesAChangedStartingStateAndBurnsAuthority(t *testing.T) {
	candidate := completeDesiredState()
	prior := documentFor(t, candidate)
	storage := &mutableStateStorage{document: prior}
	stateModule := New(storage)
	loaded, err := stateModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	request := preparedRequest(t, loaded, candidate, "change-0008")
	prepared, err := stateModule.PrepareCommit(request)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := prepared.ConsumeForApply(request.ReviewedInputs)
	if err != nil {
		t.Fatal(err)
	}
	storage.set("\n"+prior, nil)
	_, err = transaction.Publish()
	assertFinding(t, err, "STATE-PUBLICATION-STALE")
	_, err = transaction.Publish()
	assertFinding(t, err, "STATE-PUBLICATION-USED")
	var restored bytes.Buffer
	if present, preserveErr := transaction.PreservePriorState(&restored); preserveErr != nil || !present || restored.String() != prior {
		t.Fatalf("stale publication lost exact prior handoff: present=%t err=%v", present, preserveErr)
	}
}

func TestTransactionAllowsOnlyOneConcurrentPublication(t *testing.T) {
	candidate := completeDesiredState()
	stateModule, request, _ := managedPrepareRequest(t, candidate)
	prepared, err := stateModule.PrepareCommit(request)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := prepared.ConsumeForApply(request.ReviewedInputs)
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var replays atomic.Int32
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, publishErr := transaction.Publish()
			if publishErr == nil {
				successes.Add(1)
				return
			}
			var finding *Finding
			if errors.As(publishErr, &finding) && finding.Code == "STATE-PUBLICATION-USED" {
				replays.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || replays.Load() != 15 {
		t.Fatalf("concurrent publication = (%d success, %d replay), want (1, 15)", successes.Load(), replays.Load())
	}
}

func TestPostPublicationAgreementIsProtectedAndCannotBecomeComplete(t *testing.T) {
	candidate := completeDesiredState()
	stateModule, request, _ := managedPrepareRequest(t, candidate)
	prepared, err := stateModule.PrepareCommit(request)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := prepared.ConsumeForApply(request.ReviewedInputs)
	if err != nil {
		t.Fatal(err)
	}
	agreement, err := transaction.Publish()
	if err != nil {
		t.Fatal(err)
	}
	manifest := agreement.ServiceManifests()
	manifest[0] = ServiceAgreement{}
	if agreement.ServiceManifests()[0].Service() == "" {
		t.Fatal("caller changed protected agreement inputs")
	}
	for name, protected := range map[string]any{"agreement": agreement, "service manifest": agreement.ServiceManifests()[0]} {
		data, renderErr := json.Marshal(protected)
		formatted := fmt.Sprintf("%+v %#v", protected, protected)
		if renderErr == nil || strings.Contains(string(data), "SECRET-MARKER") || !strings.Contains(formatted, "redacted") || strings.Contains(strings.ToLower(formatted), "complete") {
			t.Fatalf("%s was renderable or claimed Complete", name)
		}
	}
}

func TestPreparationRefusalBurnsLoadedAuthority(t *testing.T) {
	candidate := completeDesiredState()
	stateModule, request, _ := managedPrepareRequest(t, candidate)
	request.Candidate.Subscription.Token = ClientAccessValue{}
	_, err := stateModule.PrepareCommit(request)
	assertFinding(t, err, "STATE-INTENT-INCOMPLETE")
	request.Candidate = candidate
	request.ServiceMaterials = serviceMaterialsFor(candidate)
	_, err = stateModule.PrepareCommit(request)
	assertFinding(t, err, "STATE-PLAN-USED")
	freshPlan := preparedRequest(t, request.Loaded, candidate, "change-0008")
	freshPlan.ReviewedInputs = reviewedInputs(t, '1')
	_, err = stateModule.PrepareCommit(freshPlan)
	assertFinding(t, err, "STATE-LOAD-USED")
	loadedAgain, err := stateModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	replayedPlan := preparedRequest(t, loadedAgain, candidate, "change-0008")
	replayedPlan.ReviewedInputs = request.ReviewedInputs
	_, err = stateModule.PrepareCommit(replayedPlan)
	assertFinding(t, err, "STATE-PLAN-USED")
}

func TestReviewedPlanCannotPrepareTwice(t *testing.T) {
	candidate := completeDesiredState()
	stateModule, firstRequest, _ := managedPrepareRequest(t, candidate)
	if _, err := stateModule.PrepareCommit(firstRequest); err != nil {
		t.Fatal(err)
	}
	loadedAgain, err := stateModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	replayed := preparedRequest(t, loadedAgain, candidate, "change-0008")
	replayed.ReviewedInputs = firstRequest.ReviewedInputs
	_, err = stateModule.PrepareCommit(replayed)
	assertFinding(t, err, "STATE-PLAN-USED")

	loadedFresh, err := stateModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	fresh := preparedRequest(t, loadedFresh, candidate, "change-0008")
	fresh.ReviewedInputs = reviewedInputs(t, '1')
	if _, err := stateModule.PrepareCommit(fresh); err != nil {
		t.Fatal(err)
	}
}

func TestReviewedPlanAuthoritySurvivesInterfaceReconstruction(t *testing.T) {
	candidate := completeDesiredState()
	storage := &mutableStateStorage{document: documentFor(t, candidate)}
	firstModule := New(storage)
	loaded, err := firstModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	request := preparedRequest(t, loaded, candidate, "change-0008")
	if _, err := firstModule.PrepareCommit(request); err != nil {
		t.Fatal(err)
	}
	secondModule := New(storage)
	loadedAgain, err := secondModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	replayed := preparedRequest(t, loadedAgain, candidate, "change-0008")
	replayed.ReviewedInputs = request.ReviewedInputs
	_, err = secondModule.PrepareCommit(replayed)
	assertFinding(t, err, "STATE-PLAN-USED")
}

func TestReviewedPlanIdentityCannotMintAnotherAuthority(t *testing.T) {
	candidate := completeDesiredState()
	storage := &mutableStateStorage{document: documentFor(t, candidate)}
	firstModule := New(storage)
	loaded, err := firstModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	request := preparedRequest(t, loaded, candidate, "change-0008")
	if _, err := firstModule.PrepareCommit(request); err != nil {
		t.Fatal(err)
	}
	secondModule := New(storage)
	loadedAgain, err := secondModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	replayed := preparedRequest(t, loadedAgain, candidate, "change-0008")
	replayed.ReviewedInputs, err = NewReviewedInputs(request.ReviewedInputs.planIdentity, request.ReviewedInputs.planSHA256, request.ReviewedInputs.managed)
	if err != nil {
		t.Fatal(err)
	}
	_, err = secondModule.PrepareCommit(replayed)
	assertFinding(t, err, "STATE-PLAN-USED")
}

func preparedRequest(t *testing.T, loaded Result, candidate DesiredState, changeSet ChangeSetIdentity) PrepareRequest {
	t.Helper()
	reviewed := reviewedInputs(t, '1')
	validator := &validatingSeams{want: candidate, calls: map[string]int{}, planIdentity: string(reviewed.planIdentity), planSHA256: reviewed.planSHA256}
	request := PrepareRequest{
		Loaded:                   loaded,
		CandidateReleaseIdentity: testRelease,
		ChangeSet:                changeSet,
		Candidate:                candidate,
		SemanticValidators:       validatorsFor(validator),
		ServiceMaterials:         serviceMaterialsFor(candidate),
		ReviewedInputs:           reviewed,
	}
	if subscriptionPublicationRequired(loaded.loaded, candidate, testRelease) {
		request.SubscriptionPublication = validator
	}
	return request
}

func managedPrepareRequest(t *testing.T, candidate DesiredState) (Interface, PrepareRequest, *validatingSeams) {
	t.Helper()
	storage := &mutableStateStorage{document: documentFor(t, completeDesiredState())}
	stateModule := New(storage)
	loaded, err := stateModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	request := preparedRequest(t, loaded, candidate, "change-0008")
	validator := request.SemanticValidators.ConnectionProfiles.(*validatingSeams)
	return stateModule, request, validator
}

func reviewedInputs(t *testing.T, firstChecksumCharacter byte) ReviewedInputs {
	t.Helper()
	plan := PlanIdentity(fmt.Sprintf("plan-test-%d", testPlanSequence.Add(1)))
	return reviewedInputsWith(t, plan, '7', [6]byte{firstChecksumCharacter, '2', '3', '4', '5', '6'})
}

var testPlanSequence atomic.Uint64

func reviewedInputsWith(t *testing.T, plan PlanIdentity, planChecksumCharacter byte, checksums [6]byte) ReviewedInputs {
	t.Helper()
	inputs, err := NewManagedInputChecksums(testSHA(checksums[0]), testSHA(checksums[1]), testSHA(checksums[2]), testSHA(checksums[3]), testSHA(checksums[4]), testSHA(checksums[5]))
	if err != nil {
		t.Fatal(err)
	}
	reviewed, err := NewReviewedInputs(plan, testSHA(planChecksumCharacter), inputs)
	if err != nil {
		t.Fatal(err)
	}
	return reviewed
}

func consumeAgain(prepared *PreparedCommit, reviewed ReviewedInputs) error {
	_, err := prepared.ConsumeForApply(reviewed)
	return err
}

func testSHA(character byte) string {
	value := make([]byte, 64)
	for index := range value {
		value[index] = character
	}
	return string(value)
}

func assertFinding(t *testing.T, err error, code string) {
	t.Helper()
	var finding *Finding
	if !errors.As(err, &finding) || finding.Code != code {
		t.Fatalf("error = %#v, want %s", err, code)
	}
	if strings.Contains(err.Error(), "SECRET-MARKER") {
		t.Fatal("finding exposed a protected value")
	}
}
