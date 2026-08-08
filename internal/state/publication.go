package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"reflect"
	"sync/atomic"
)

// TransactionMaterial is the opaque State-owned handoff for one System
// Changes attempt, prior-State preservation, and atomic State publication.
type TransactionMaterial struct {
	startingRevision           uint64
	candidateRevision          uint64
	startingChecksum           string
	candidateChecksum          string
	manifestChecksum           string
	preparedChecksum           string
	changeSet                  ChangeSetIdentity
	reviewed                   ReviewedInputs
	priorState                 []byte
	preparedState              []byte
	serviceCopies              PreparedServiceCopies
	subscriptionArtifactBundle []byte
	storage                    Storage
	publication                *publicationAuthority
	startingRelease            ReleaseIdentity
	candidateRelease           ReleaseIdentity
	deferred                   *deferredCloudflare
	forwardRecovery            bool
}

type publicationAuthority struct{ used atomic.Bool }

type rollbackStorage interface {
	Restore(expectedCurrent, prior []byte) ([]byte, error)
}

func (TransactionMaterial) MarshalJSON() ([]byte, error) { return nil, errProtectedValueRendering }
func (TransactionMaterial) String() string               { return "[redacted transaction material]" }
func (TransactionMaterial) GoString() string             { return "[redacted transaction material]" }

// SystemChangesBindings returns only exact non-secret transaction lineage.
type systemChangesTransactionBinding struct {
	StartingRevision       uint64            `json:"starting_revision"`
	CandidateRevision      uint64            `json:"candidate_revision"`
	StartingSHA256         string            `json:"starting_sha256"`
	CandidateSHA256        string            `json:"candidate_sha256"`
	PreparedStateSHA256    string            `json:"prepared_state_sha256"`
	PreparedManifestSHA256 string            `json:"prepared_manifest_sha256"`
	ChangeSet              ChangeSetIdentity `json:"change_set"`
	StartingRelease        ReleaseIdentity   `json:"starting_release"`
	CandidateRelease       ReleaseIdentity   `json:"candidate_release"`
}

func (transaction *TransactionMaterial) SystemChangesBindings(lease any) ([]byte, error) {
	if !validSystemChangesLease(lease) || transaction == nil || transaction.publication == nil {
		return nil, finding("STATE-TRANSACTION-LEASE", "transaction material", "no authorized System Changes lease", "the one active Apply lease", "protected lineage cannot leave State", "use System Changes Apply")
	}
	return json.Marshal(systemChangesTransactionBinding{
		StartingRevision: transaction.startingRevision, CandidateRevision: transaction.candidateRevision,
		StartingSHA256: transaction.startingChecksum, CandidateSHA256: transaction.candidateChecksum,
		PreparedStateSHA256: transaction.preparedChecksum, PreparedManifestSHA256: transaction.manifestChecksum,
		ChangeSet: transaction.changeSet, StartingRelease: transaction.startingRelease, CandidateRelease: transaction.candidateRelease,
	})
}

func (transaction *TransactionMaterial) SystemChangesDeferred(lease any) bool {
	return validSystemChangesLease(lease) && transaction != nil && transaction.deferred != nil
}

type deferredStepEvidence struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
}

// SystemChangesFinalizeCloudflare consumes the provider-issued run token only
// after all referenced IDs are durable, then rebuilds and validates the exact
// candidate and its protected service copies before publication.
func (transaction *TransactionMaterial) SystemChangesFinalizeCloudflare(lease any, evidenceJSON []byte) ([]byte, error) {
	if !validSystemChangesLease(lease) || transaction == nil || transaction.deferred == nil || !transaction.deferred.used.CompareAndSwap(false, true) {
		return nil, finding("STATE-CLOUDFLARE-FINALIZATION", "deferred Cloudflare finalization", "no fresh authorized finalization", "one active System Changes lease and one-use deferred commit", "State cannot accept provider results outside the transaction", "roll back the active Change Set")
	}
	var evidence []deferredStepEvidence
	if json.Unmarshal(evidenceJSON, &evidence) != nil {
		return nil, finding("STATE-CLOUDFLARE-EVIDENCE", "Cloudflare provider evidence", "the durable evidence could not be decoded", "exact typed identifiers for every planned create", "State never guesses provider identities", "roll back the active Change Set")
	}
	resource := func(step int, kind string) (string, bool) {
		if step < 1 || step > len(evidence) {
			return "", false
		}
		item := evidence[step-1]
		return item.ResourceID, item.ResourceType == kind && item.ResourceID != ""
	}
	deferred := transaction.deferred
	candidate := deferred.candidate
	var ok bool
	if candidate.Cloudflare.TunnelID, ok = resource(deferred.binding.TunnelStep, "cloudflare-tunnel"); !ok {
		return nil, deferredEvidenceFinding()
	}
	if candidate.Cloudflare.XHTTPDNSRecordID, ok = resource(deferred.binding.XHTTPDNSRecordStep, "cloudflare-dns-record"); !ok {
		return nil, deferredEvidenceFinding()
	}
	if candidate.Cloudflare.WebSocketDNSRecordID, ok = resource(deferred.binding.WebSocketDNSRecordStep, "cloudflare-dns-record"); !ok {
		return nil, deferredEvidenceFinding()
	}
	if deferred.binding.DirectIPv4RecordStep > 0 {
		if candidate.Cloudflare.DirectIPv4RecordID, ok = resource(deferred.binding.DirectIPv4RecordStep, "cloudflare-dns-record"); !ok {
			return nil, deferredEvidenceFinding()
		}
	}
	if deferred.binding.DirectIPv6RecordStep > 0 {
		if candidate.Cloudflare.DirectIPv6RecordID, ok = resource(deferred.binding.DirectIPv6RecordStep, "cloudflare-dns-record"); !ok {
			return nil, deferredEvidenceFinding()
		}
	}
	if candidate.Cloudflare.TunnelRunToken, ok = NewInfrastructureSecretFrom(deferred.runToken); !ok {
		return nil, finding("STATE-CLOUDFLARE-RUN-TOKEN", "Tunnel run token", "the one-use protected token was unavailable", "the provider-issued token from the created Tunnel", "State alone may consume this Infrastructure Secret", "roll back the active Change Set")
	}
	if problem := validateDesiredState(candidate); problem != nil || !validateSemantics(candidate, deferred.validators) {
		return nil, finding("STATE-CLOUDFLARE-CANDIDATE", "final Cloudflare candidate", "the completed candidate failed structural or owning-Module validation", "one complete internally consistent Desired State", "provider results cannot bypass State validation", "roll back the active Change Set")
	}
	materials := expectedServiceMaterials(candidate)
	copies, err := prepareServiceCopies(transaction.candidateRevision, transaction.changeSet, materials)
	if err != nil {
		return nil, err
	}
	preparedState, candidateChecksum, err := prepareStateDocument(transaction.candidateRevision, transaction.candidateRelease, transaction.changeSet, candidate)
	if err != nil {
		return nil, finding("STATE-CLOUDFLARE-SERIALIZATION", "final Cloudflare candidate", "the final candidate could not be serialized", "one byte-stable complete candidate", "publication bytes must be exact", "roll back the active Change Set")
	}
	manifestChecksum, err := checksumServiceManifests(copies)
	if err != nil {
		return nil, err
	}
	preparedDigest := sha256.Sum256(preparedState)
	transaction.candidateChecksum = candidateChecksum
	transaction.manifestChecksum = manifestChecksum
	transaction.preparedChecksum = hex.EncodeToString(preparedDigest[:])
	transaction.preparedState = preparedState
	transaction.serviceCopies = copies
	transaction.deferred = nil
	return transaction.SystemChangesBindings(lease)
}

func deferredEvidenceFinding() error {
	return finding("STATE-CLOUDFLARE-EVIDENCE", "Cloudflare provider evidence", "a planned immutable identifier is missing or has the wrong type", "every returned identifier journaled before later work", "State never guesses or adopts provider resources", "roll back the active Change Set")
}

func prepareServiceCopies(revision uint64, changeSet ChangeSetIdentity, materials ServiceMaterials) (PreparedServiceCopies, error) {
	var copies PreparedServiceCopies
	for _, item := range []struct {
		service, module, group string
		material               any
		target                 **PreparedServiceCopy
	}{
		{"xray.service", "connectionprofiles", "xray", materials.Xray, &copies.Xray},
		{"sing-box.service", "connectionprofiles", "sing-box", materials.SingBox, &copies.SingBox},
		{"cloudflared.service", "cloudflaretunnel", "cloudflared", materials.Cloudflared, &copies.Cloudflared},
	} {
		if item.material == nil || reflect.ValueOf(item.material).IsNil() {
			continue
		}
		prepared, err := prepareServiceCopy(item.service, item.module, item.group, revision, changeSet, item.material)
		if err != nil {
			return PreparedServiceCopies{}, err
		}
		*item.target = &prepared
	}
	subscription, err := prepareServiceCopy("sbxr-subscription.service", "subscriptionserving", "sbxr-subscription", revision, changeSet, materials.Subscription)
	if err != nil {
		return PreparedServiceCopies{}, err
	}
	copies.Subscription = &subscription
	return copies, nil
}

// SystemChangesWriteArtifacts streams protected bytes without interpreting them.
func (transaction *TransactionMaterial) SystemChangesWriteArtifacts(lease any, write func(name string, mode uint32, source io.Reader) error) error {
	if !validSystemChangesLease(lease) || transaction == nil || transaction.publication == nil || write == nil {
		return finding("STATE-TRANSACTION-ARTIFACTS", "transaction artifacts", "no complete protected handoff", "one exact opaque artifact stream", "durable preparation cannot be proven", "prepare State again")
	}
	if len(transaction.priorState) > 0 && !transaction.forwardRecovery {
		if err := write("snapshot/prior-state.json", 0o600, bytes.NewReader(transaction.priorState)); err != nil {
			return err
		}
	}
	if err := write("prepared/state.json", 0o600, bytes.NewReader(transaction.preparedState)); err != nil {
		return err
	}
	for _, artifact := range []struct {
		name string
		copy *PreparedServiceCopy
	}{
		{"prepared/xray.json", transaction.serviceCopies.Xray}, {"prepared/sing-box.json", transaction.serviceCopies.SingBox},
		{"prepared/cloudflared.json", transaction.serviceCopies.Cloudflared}, {"prepared/subscription.json", transaction.serviceCopies.Subscription},
	} {
		if artifact.copy != nil {
			if err := write(artifact.name, 0o600, bytes.NewReader(artifact.copy.bytes)); err != nil {
				return err
			}
		}
	}
	if len(transaction.subscriptionArtifactBundle) > 0 {
		if err := write("prepared/subscriptions.bundle", 0o600, bytes.NewReader(transaction.subscriptionArtifactBundle)); err != nil {
			return err
		}
	}
	manifests, err := json.Marshal(preparedManifestSet{
		Xray: manifestPointer(transaction.serviceCopies.Xray), SingBox: manifestPointer(transaction.serviceCopies.SingBox),
		Cloudflared: manifestPointer(transaction.serviceCopies.Cloudflared), Subscription: manifestPointer(transaction.serviceCopies.Subscription),
	})
	if err != nil {
		return err
	}
	return write("prepared/manifests.json", 0o600, bytes.NewReader(manifests))
}

func manifestPointer(copy *PreparedServiceCopy) *ServiceManifest {
	if copy == nil {
		return nil
	}
	manifest := copy.manifest
	return &manifest
}

func (transaction *TransactionMaterial) SystemChangesPublish(lease any) (any, error) {
	if !validSystemChangesLease(lease) {
		return nil, finding("STATE-TRANSACTION-LEASE", "Desired State publication", "no authorized System Changes lease", "the one active Apply lease", "State cannot publish outside Apply", "use System Changes Apply")
	}
	if transaction != nil && transaction.forwardRecovery {
		current, err := transaction.storage.Read()
		if err == nil && bytes.Equal(current, transaction.preparedState) {
			if !transaction.publication.used.CompareAndSwap(false, true) {
				return nil, finding("STATE-PUBLICATION-USED", "Desired State publication", "the publication authority was already consumed", "one recovery publication proof", "forward recovery cannot invent a second publication", "continue the active recovery runner")
			}
			return transaction.publicationAgreement()
		}
	}
	return transaction.Publish()
}

type systemChangesRollbackAgreement struct {
	Status   InstallationStatus `json:"status"`
	Revision uint64             `json:"revision"`
	SHA256   string             `json:"sha256"`
	Release  ReleaseIdentity    `json:"release_identity"`
}

const maxRecoveryStateArtifactBytes = 8 << 20

// SystemChangesRestoreDurable is State's restart-only recovery seam. System
// Changes transports the protected bytes, while State alone validates and
// restores Desired State through its storage boundary.
func (i Interface) SystemChangesRestoreDurable(lease any, bindingJSON []byte, priorSource, candidateSource io.Reader) ([]byte, error) {
	if !validSystemChangesRecoveryLease(lease) || i.implementation == nil || i.implementation.storage == nil || priorSource == nil || candidateSource == nil {
		return nil, finding("STATE-RECOVERY-LEASE", "restart Desired State rollback", "no authorized State recovery handoff", "the one active System Changes recovery lease", "Desired State cannot be restored outside restart recovery", "keep affected services stopped")
	}
	var binding systemChangesTransactionBinding
	if json.Unmarshal(bindingJSON, &binding) != nil || binding.CandidateRevision != binding.StartingRevision+1 || !validSHA256(binding.CandidateSHA256) || !validSHA256(binding.PreparedStateSHA256) || !validReleaseIdentity(binding.CandidateRelease) {
		return nil, finding("STATE-RECOVERY-BINDING", "restart Desired State rollback", "an invalid durable State binding", "the exact transaction-bound starting and candidate lineage", "State never guesses recovery lineage", "use the Recovery Required flow")
	}
	prior, err := readRecoveryStateArtifact(priorSource)
	if err != nil {
		return nil, err
	}
	candidate, err := readRecoveryStateArtifact(candidateSource)
	if err != nil {
		return nil, err
	}
	candidateDigest := sha256.Sum256(candidate)
	candidateDocument, problem := decode(candidate)
	if problem != nil || hex.EncodeToString(candidateDigest[:]) != binding.PreparedStateSHA256 || candidateDocument.Revision != binding.CandidateRevision || candidateDocument.Checksum != binding.CandidateSHA256 || candidateDocument.ReleaseIdentity != binding.CandidateRelease || candidateDocument.LastCompletedChangeSet != ChangeSetIdentity(binding.ChangeSet) {
		return nil, finding("STATE-RECOVERY-CANDIDATE", "restart Desired State rollback", "candidate State disagrees with its durable binding", "the exact protected candidate State", "State cannot restore across ambiguous lineage", "use the Recovery Required flow")
	}
	if len(prior) == 0 {
		if binding.StartingRevision != 0 || binding.StartingSHA256 != "" || binding.StartingRelease != (ReleaseIdentity{}) {
			return nil, finding("STATE-RECOVERY-PRIOR", "restart Desired State rollback", "the absent prior State disagrees with its durable binding", "one proven Not installed baseline", "State cannot invent a prior document", "use the Recovery Required flow")
		}
	} else {
		priorDocument, problem := decode(prior)
		if problem != nil || priorDocument.Revision != binding.StartingRevision || priorDocument.Checksum != binding.StartingSHA256 || priorDocument.ReleaseIdentity != binding.StartingRelease {
			return nil, finding("STATE-RECOVERY-PRIOR", "restart Desired State rollback", "prior State disagrees with its durable binding", "the exact protected prior State", "State cannot restore across ambiguous lineage", "use the Recovery Required flow")
		}
	}
	transaction := &TransactionMaterial{storage: i.implementation.storage, priorState: prior, preparedState: candidate, startingRelease: binding.StartingRelease}
	return transaction.SystemChangesRestore(lease)
}

func readRecoveryStateArtifact(source io.Reader) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(source, maxRecoveryStateArtifactBytes+1))
	if err != nil || len(content) > maxRecoveryStateArtifactBytes {
		return nil, finding("STATE-RECOVERY-SIZE", "restart Desired State rollback", "a State artifact is unreadable or too large", "one bounded protected State document", "unbounded or partial recovery input is unsafe", "use the Recovery Required flow")
	}
	return content, nil
}

// SystemChangesFinalizeRunTokenRotation replaces only the deferred run-token
// slot in the protected candidate and rebuilds its exact service artifacts.
func (i Interface) SystemChangesFinalizeRunTokenRotation(lease any, bindingJSON []byte, candidateSource io.Reader, source any) (any, error) {
	if !validSystemChangesRecoveryLease(lease) || i.implementation == nil || i.implementation.storage == nil || candidateSource == nil {
		return nil, finding("STATE-RUN-TOKEN-RECOVERY", "Tunnel run-token recovery", "no authorized protected handoff", "the active System Changes recovery lease", "State cannot accept a run token outside forward recovery", "keep cloudflared stopped")
	}
	secret, ok := source.(VerifiedInfrastructureSecret)
	if !ok || secret == nil {
		return nil, finding("STATE-RUN-TOKEN-RECOVERY", "Tunnel run-token recovery", "the Cloudflare token handoff is invalid", "one opaque one-use Infrastructure Secret", "callers cannot supply token text", "check Cloudflare again")
	}
	var binding systemChangesTransactionBinding
	if json.Unmarshal(bindingJSON, &binding) != nil || binding.CandidateRevision != binding.StartingRevision+1 || !validSHA256(binding.PreparedStateSHA256) {
		return nil, finding("STATE-RUN-TOKEN-BINDING", "Tunnel run-token recovery", "the durable State binding is invalid", "the exact active transaction lineage", "State never guesses recovery lineage", "use Recovery Required")
	}
	candidateBytes, err := readRecoveryStateArtifact(candidateSource)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(candidateBytes)
	document, problem := decode(candidateBytes)
	if problem != nil || hex.EncodeToString(digest[:]) != binding.PreparedStateSHA256 || document.Revision != binding.CandidateRevision || document.LastCompletedChangeSet != ChangeSetIdentity(binding.ChangeSet) || document.desiredState.Cloudflare.TunnelRunToken.value != "deferred-cloudflare-run-token" {
		return nil, finding("STATE-RUN-TOKEN-CANDIDATE", "Tunnel run-token recovery", "the deferred candidate is invalid", "one transaction-bound deferred token slot", "the old token cannot be reused", "use Recovery Required")
	}
	newToken, consumed := NewInfrastructureSecretFrom(secret)
	if !consumed {
		return nil, finding("STATE-RUN-TOKEN-CANDIDATE", "Tunnel run-token recovery", "the new token was unavailable or already used", "one fresh Cloudflare token", "State accepts no replayed credential", "check Cloudflare again")
	}
	document.desiredState.Cloudflare.TunnelRunToken = newToken
	if problem := validateDesiredState(document.desiredState); problem != nil {
		return nil, problem
	}
	return i.forwardRunTokenMaterial(binding, document.desiredState)
}

func (i Interface) forwardRunTokenMaterial(binding systemChangesTransactionBinding, candidate DesiredState) (*TransactionMaterial, error) {
	copies, err := prepareServiceCopies(binding.CandidateRevision, binding.ChangeSet, expectedServiceMaterials(candidate))
	if err != nil {
		return nil, err
	}
	preparedState, candidateChecksum, err := prepareStateDocument(binding.CandidateRevision, binding.CandidateRelease, binding.ChangeSet, candidate)
	if err != nil {
		return nil, err
	}
	manifestChecksum, err := checksumServiceManifests(copies)
	if err != nil {
		return nil, err
	}
	preparedDigest := sha256.Sum256(preparedState)
	prior, readErr := i.implementation.storage.Read()
	if readErr != nil {
		return nil, finding("STATE-RUN-TOKEN-PRIOR", "Tunnel run-token recovery", "the current committed State is unavailable", "the exact starting revision", "forward recovery cannot guess its publication baseline", "use Recovery Required")
	}
	priorDocument, problem := decode(prior)
	if problem != nil || priorDocument.Revision != binding.StartingRevision || priorDocument.Checksum != binding.StartingSHA256 || priorDocument.ReleaseIdentity != binding.StartingRelease {
		return nil, finding("STATE-RUN-TOKEN-PRIOR", "Tunnel run-token recovery", "the current State disagrees with the rotation baseline", "the exact starting revision", "forward recovery cannot replace different State", "use Recovery Required")
	}
	return &TransactionMaterial{startingRevision: binding.StartingRevision, candidateRevision: binding.CandidateRevision, startingChecksum: binding.StartingSHA256, candidateChecksum: candidateChecksum, manifestChecksum: manifestChecksum, preparedChecksum: hex.EncodeToString(preparedDigest[:]), changeSet: binding.ChangeSet, priorState: prior, preparedState: preparedState, serviceCopies: copies, storage: i.implementation.storage, publication: &publicationAuthority{}, startingRelease: binding.StartingRelease, candidateRelease: binding.CandidateRelease, forwardRecovery: true}, nil
}

// SystemChangesLoadRunTokenRotation reconstructs only the State publication
// authority required by a later forward-recovery phase.
func (i Interface) SystemChangesLoadRunTokenRotation(lease any, bindingJSON []byte, candidateSource, manifestsSource io.Reader) (any, error) {
	if !validSystemChangesRecoveryLease(lease) || i.implementation == nil || i.implementation.storage == nil || candidateSource == nil || manifestsSource == nil {
		return nil, finding("STATE-RUN-TOKEN-RECOVERY", "Tunnel run-token recovery", "no complete durable handoff", "the active recovery lease and finalized artifacts", "State cannot reconstruct authority from partial evidence", "use Recovery Required")
	}
	var binding systemChangesTransactionBinding
	if json.Unmarshal(bindingJSON, &binding) != nil {
		return nil, finding("STATE-RUN-TOKEN-BINDING", "Tunnel run-token recovery", "the durable binding is invalid", "the exact finalized binding", "State never guesses recovery lineage", "use Recovery Required")
	}
	candidateBytes, err := readRecoveryStateArtifact(candidateSource)
	if err != nil {
		return nil, err
	}
	manifestBytes, err := readRecoveryStateArtifact(manifestsSource)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(candidateBytes)
	document, problem := decode(candidateBytes)
	var manifests preparedManifestSet
	if problem != nil || json.Unmarshal(manifestBytes, &manifests) != nil || hex.EncodeToString(digest[:]) != binding.PreparedStateSHA256 || document.Revision != binding.CandidateRevision || document.Checksum != binding.CandidateSHA256 || document.ReleaseIdentity != binding.CandidateRelease || document.LastCompletedChangeSet != ChangeSetIdentity(binding.ChangeSet) {
		return nil, finding("STATE-RUN-TOKEN-CANDIDATE", "Tunnel run-token recovery", "the finalized candidate disagrees with its binding", "the exact protected candidate and manifests", "forward recovery cannot publish ambiguous State", "use Recovery Required")
	}
	manifestDigest := sha256.Sum256(manifestBytes)
	if hex.EncodeToString(manifestDigest[:]) != binding.PreparedManifestSHA256 {
		return nil, finding("STATE-RUN-TOKEN-CANDIDATE", "Tunnel run-token recovery", "the finalized manifests disagree with their binding", "the exact protected service manifests", "forward recovery cannot publish ambiguous services", "use Recovery Required")
	}
	copies := copiesFromManifestSet(manifests)
	current, readErr := i.implementation.storage.Read()
	if readErr != nil {
		return nil, readErr
	}
	prior := current
	if bytes.Equal(current, candidateBytes) {
		prior = nil
	} else {
		priorDocument, priorProblem := decode(current)
		if priorProblem != nil || priorDocument.Revision != binding.StartingRevision || priorDocument.Checksum != binding.StartingSHA256 || priorDocument.ReleaseIdentity != binding.StartingRelease {
			return nil, finding("STATE-RUN-TOKEN-PRIOR", "Tunnel run-token recovery", "current State is neither the starting nor candidate revision", "one exact transaction lineage", "forward recovery cannot overwrite unrelated State", "use Recovery Required")
		}
	}
	return &TransactionMaterial{startingRevision: binding.StartingRevision, candidateRevision: binding.CandidateRevision, startingChecksum: binding.StartingSHA256, candidateChecksum: binding.CandidateSHA256, manifestChecksum: binding.PreparedManifestSHA256, preparedChecksum: binding.PreparedStateSHA256, changeSet: binding.ChangeSet, priorState: prior, preparedState: candidateBytes, serviceCopies: copies, storage: i.implementation.storage, publication: &publicationAuthority{}, startingRelease: binding.StartingRelease, candidateRelease: binding.CandidateRelease, forwardRecovery: true}, nil
}

func copiesFromManifestSet(manifests preparedManifestSet) PreparedServiceCopies {
	copyOf := func(manifest *ServiceManifest) *PreparedServiceCopy {
		if manifest == nil {
			return nil
		}
		return &PreparedServiceCopy{manifest: *manifest}
	}
	return PreparedServiceCopies{Xray: copyOf(manifests.Xray), SingBox: copyOf(manifests.SingBox), Cloudflared: copyOf(manifests.Cloudflared), Subscription: copyOf(manifests.Subscription)}
}

func (transaction *TransactionMaterial) SystemChangesRestore(lease any) ([]byte, error) {
	if !validSystemChangesLease(lease) || transaction == nil || transaction.storage == nil {
		return nil, finding("STATE-ROLLBACK-LEASE", "Desired State rollback", "no authorized transaction", "the one active System Changes lease", "State cannot restore outside automatic rollback", "use System Changes Apply")
	}
	current, err := transaction.storage.Read()
	priorCurrent := len(transaction.priorState) == 0 && errors.Is(err, fs.ErrNotExist) || err == nil && bytes.Equal(current, transaction.priorState)
	if !priorCurrent {
		if err != nil || !bytes.Equal(current, transaction.preparedState) {
			return nil, finding("STATE-ROLLBACK-LINEAGE", "Desired State rollback", "current State is neither the exact prior nor candidate bytes", "one exact transaction-bound State lineage", "automatic rollback cannot guess which State is current", "use the Recovery Required flow")
		}
		restorer, ok := transaction.storage.(rollbackStorage)
		if !ok {
			return nil, finding("STATE-ROLLBACK-STORAGE", "Desired State rollback", "storage has no rollback capability", "one exact atomic restore operation", "the prior State cannot be restored", "use the Recovery Required flow")
		}
		readback, restoreErr := restorer.Restore(transaction.preparedState, transaction.priorState)
		if restoreErr != nil || !bytes.Equal(readback, transaction.priorState) {
			return nil, finding("STATE-ROLLBACK-STORAGE", "Desired State rollback", "the prior bytes were not restored exactly", "the transaction-bound prior State", "rollback cannot be reported safe", "use the Recovery Required flow")
		}
	}
	agreement := systemChangesRollbackAgreement{Status: statusForPrior(transaction.priorState), Release: transaction.startingRelease}
	if len(transaction.priorState) > 0 {
		document, problem := decode(transaction.priorState)
		if problem != nil {
			return nil, problem
		}
		agreement.Revision, agreement.SHA256 = document.Revision, document.Checksum
	}
	return json.Marshal(agreement)
}

// PreservePriorState streams the exact prior bytes to System Changes without
// interpreting them. A false result represents the proven Not installed baseline.
func (transaction *TransactionMaterial) PreservePriorState(target io.Writer) (bool, error) {
	if transaction == nil || transaction.publication == nil || target == nil {
		return false, finding("STATE-PRIOR-UNAVAILABLE", "prior Desired State", "no complete opaque handoff", "the exact prior State or proven Not installed baseline", "rollback material cannot be inferred", "resolve the active Change Set through System Changes")
	}
	if len(transaction.priorState) == 0 {
		return false, nil
	}
	if _, err := io.Copy(target, bytes.NewReader(transaction.priorState)); err != nil {
		return false, finding("STATE-PRIOR-HANDOFF", "prior Desired State", "the opaque handoff did not complete", "the exact prior State bytes", "rollback requires a verified transaction-scoped snapshot", "resolve the active Change Set through System Changes")
	}
	return true, nil
}

// PostPublicationAgreement contains the exact State-side facts System Changes
// must compare with active files, services, and fresh owning-Module observations.
// It is not evidence that the Change Set is Complete.
type PostPublicationAgreement struct {
	publishedRevision uint64
	publishedChecksum string
	publishedDocument string
	manifestChecksum  string
	changeSet         ChangeSetIdentity
	releaseIdentity   ReleaseIdentity
	candidate         DesiredState
	serviceManifests  []ServiceAgreement
}

// ServiceAgreement is one protected prepared-manifest input for System Changes.
type ServiceAgreement struct{ manifest ServiceManifest }

func (agreement ServiceAgreement) Service() string      { return agreement.manifest.Service }
func (agreement ServiceAgreement) OwningModule() string { return agreement.manifest.OwningModule }
func (agreement ServiceAgreement) CandidateRevision() uint64 {
	return agreement.manifest.CandidateRevision
}
func (agreement ServiceAgreement) ChangeSet() ChangeSetIdentity { return agreement.manifest.ChangeSet }
func (agreement ServiceAgreement) Owner() string                { return agreement.manifest.Owner }
func (agreement ServiceAgreement) Group() string                { return agreement.manifest.Group }
func (agreement ServiceAgreement) DirectoryMode() uint32        { return agreement.manifest.DirectoryMode }
func (agreement ServiceAgreement) FileMode() uint32             { return agreement.manifest.FileMode }
func (agreement ServiceAgreement) SHA256() string               { return agreement.manifest.SHA256 }
func (ServiceAgreement) MarshalJSON() ([]byte, error)           { return nil, errProtectedValueRendering }
func (ServiceAgreement) String() string                         { return "[redacted service agreement]" }
func (ServiceAgreement) GoString() string                       { return "[redacted service agreement]" }

func (agreement *PostPublicationAgreement) PublishedRevision() uint64 {
	if agreement == nil {
		return 0
	}
	return agreement.publishedRevision
}

func (agreement *PostPublicationAgreement) PublishedChecksum() string {
	if agreement == nil {
		return ""
	}
	return agreement.publishedChecksum
}

func (agreement *PostPublicationAgreement) PublishedDocumentSHA256() string {
	if agreement == nil {
		return ""
	}
	return agreement.publishedDocument
}

func (agreement *PostPublicationAgreement) PreparedManifestChecksum() string {
	if agreement == nil {
		return ""
	}
	return agreement.manifestChecksum
}

func (agreement *PostPublicationAgreement) ChangeSet() ChangeSetIdentity {
	if agreement == nil {
		return ""
	}
	return agreement.changeSet
}

func (agreement *PostPublicationAgreement) ServiceManifests() []ServiceAgreement {
	if agreement == nil {
		return nil
	}
	return append([]ServiceAgreement(nil), agreement.serviceManifests...)
}

func (agreement *PostPublicationAgreement) ReleaseIdentity() ReleaseIdentity {
	if agreement == nil {
		return ReleaseIdentity{}
	}
	return agreement.releaseIdentity
}
func (agreement *PostPublicationAgreement) ConnectionProfiles() ConnectionProfiles {
	if agreement == nil {
		return ConnectionProfiles{}
	}
	return agreement.candidate.ConnectionProfiles
}
func (agreement *PostPublicationAgreement) Subscription() SubscriptionSettings {
	if agreement == nil {
		return SubscriptionSettings{}
	}
	return agreement.candidate.Subscription
}
func (agreement *PostPublicationAgreement) Cloudflare() CloudflareSettings {
	if agreement == nil {
		return CloudflareSettings{}
	}
	return agreement.candidate.Cloudflare
}
func (agreement *PostPublicationAgreement) Certificates() CertificateSettings {
	if agreement == nil {
		return CertificateSettings{}
	}
	return agreement.candidate.Certificates
}
func (agreement *PostPublicationAgreement) NetworkPolicy() NetworkPolicyInputs {
	if agreement == nil {
		return NetworkPolicyInputs{}
	}
	return agreement.candidate.NetworkPolicy
}
func (agreement *PostPublicationAgreement) SoftwareLifecycle() SoftwareLifecycleIntent {
	if agreement == nil {
		return SoftwareLifecycleIntent{}
	}
	return SoftwareLifecycleIntent{Installation: agreement.candidate.Installation, Software: agreement.candidate.Software}
}

func (*PostPublicationAgreement) MarshalJSON() ([]byte, error) {
	return nil, errProtectedValueRendering
}
func (*PostPublicationAgreement) String() string   { return "[redacted post-publication agreement]" }
func (*PostPublicationAgreement) GoString() string { return "[redacted post-publication agreement]" }

type systemChangesAgreement struct {
	Revision               uint64            `json:"revision"`
	CandidateSHA256        string            `json:"candidate_sha256"`
	PublishedStateSHA256   string            `json:"published_state_sha256"`
	PreparedManifestSHA256 string            `json:"prepared_manifest_sha256"`
	ChangeSet              ChangeSetIdentity `json:"change_set"`
	Release                ReleaseIdentity   `json:"release_identity"`
}

func (agreement *PostPublicationAgreement) SystemChangesAgreement(lease any) ([]byte, error) {
	if !validSystemChangesLease(lease) || agreement == nil || agreement.changeSet == "" || agreement.publishedRevision == 0 {
		return nil, finding("STATE-TRANSACTION-LEASE", "post-publication agreement", "no authorized complete handoff", "the one active Apply lease", "protected agreement cannot leave State", "use System Changes Apply")
	}
	return json.Marshal(systemChangesAgreement{Revision: agreement.publishedRevision, CandidateSHA256: agreement.publishedChecksum, PublishedStateSHA256: agreement.publishedDocument, PreparedManifestSHA256: agreement.manifestChecksum, ChangeSet: agreement.changeSet, Release: agreement.releaseIdentity})
}

// Publish performs the one State publication allowed by this transaction.
// System Changes still owns post-publication agreement and durable Complete.
func (transaction *TransactionMaterial) Publish() (*PostPublicationAgreement, error) {
	if transaction == nil || transaction.publication == nil || transaction.storage == nil {
		return nil, finding("STATE-PUBLICATION-UNAVAILABLE", "Desired State publication", "no complete transaction material", "one consumed prepared commit", "missing transaction authority cannot publish State", "run Load, create and review a fresh Plan, then prepare again")
	}
	if !transaction.publication.used.CompareAndSwap(false, true) {
		return nil, finding("STATE-PUBLICATION-USED", "Desired State publication", "the publication authority was already consumed", "one publication attempt", "a prepared revision cannot be published twice", "resolve the active Change Set through System Changes")
	}
	if !matchesLoadedState(transaction.storage, &loadedState{status: statusForPrior(transaction.priorState), bytes: transaction.priorState}) {
		return nil, finding("STATE-PUBLICATION-STALE", "Desired State publication", "current State changed before publication", "the exact prior State bound to this transaction", "publication cannot replace a different lineage", "resolve the active Change Set through System Changes")
	}
	readback, err := transaction.storage.Publish(transaction.priorState, transaction.preparedState, transaction.preparedChecksum)
	if err != nil {
		var problem *Finding
		if errors.As(err, &problem) {
			return nil, problem
		}
		return nil, finding("STATE-PUBLICATION-STORAGE", "Desired State publication", "the atomic storage operation did not complete", "one flushed atomic replacement and exact readback", "publication durability cannot be proven", "resolve the active Change Set through System Changes")
	}
	if !bytes.Equal(readback, transaction.preparedState) {
		return nil, finding("STATE-PUBLICATION-READBACK", "Desired State readback", "stored bytes differ from the prepared candidate", "the exact published revision and checksum", "publication alone cannot establish agreement", "resolve the active Change Set through System Changes")
	}
	document, problem := decode(readback)
	if problem != nil || document.Revision != transaction.candidateRevision || document.Checksum != transaction.candidateChecksum || document.LastCompletedChangeSet != transaction.changeSet {
		return nil, finding("STATE-PUBLICATION-READBACK", "Desired State readback", "published lineage differs from the prepared candidate", "the exact published revision and checksum", "publication alone cannot establish agreement", "resolve the active Change Set through System Changes")
	}
	return transaction.publicationAgreement()
}

func (transaction *TransactionMaterial) publicationAgreement() (*PostPublicationAgreement, error) {
	document, problem := decode(transaction.preparedState)
	if problem != nil || document.Revision != transaction.candidateRevision || document.Checksum != transaction.candidateChecksum || document.LastCompletedChangeSet != transaction.changeSet {
		return nil, finding("STATE-PUBLICATION-READBACK", "Desired State readback", "published lineage differs from the prepared candidate", "the exact published revision and checksum", "publication alone cannot establish agreement", "resolve the active Change Set through System Changes")
	}
	return &PostPublicationAgreement{publishedRevision: document.Revision, publishedChecksum: document.Checksum, publishedDocument: transaction.preparedChecksum, manifestChecksum: transaction.manifestChecksum, changeSet: transaction.changeSet, releaseIdentity: document.ReleaseIdentity, candidate: document.desiredState, serviceManifests: serviceManifests(transaction.serviceCopies)}, nil
}

func statusForPrior(prior []byte) InstallationStatus {
	if len(prior) == 0 {
		return NotInstalled
	}
	return Managed
}

func serviceManifests(copies PreparedServiceCopies) []ServiceAgreement {
	manifests := make([]ServiceAgreement, 0, 4)
	for _, copy := range []*PreparedServiceCopy{copies.Xray, copies.SingBox, copies.Cloudflared, copies.Subscription} {
		if copy != nil {
			manifests = append(manifests, ServiceAgreement{manifest: copy.manifest})
		}
	}
	return manifests
}

// ConsumeForApply burns this authority on the first attempt, then verifies
// the exact reviewed inputs and persisted starting State without mutation.
func (commit *PreparedCommit) ConsumeForApply(current ReviewedInputs) (*TransactionMaterial, error) {
	if commit == nil || commit.starting == nil || commit.storage == nil {
		return nil, finding("STATE-PREPARED-UNAVAILABLE", "prepared commit authority", "no complete prepared commit", "one fresh opaque prepared commit", "missing authority cannot start mutation", "run Load, create and review a fresh Plan, then prepare again")
	}
	if !commit.consumed.CompareAndSwap(false, true) {
		return nil, finding("STATE-PREPARED-USED", "prepared commit authority", "the authority was already consumed", "one use by the first Apply attempt", "no prior approval can be replayed", "run Load, create and review a fresh Plan, then prepare again")
	}
	if current != commit.reviewed {
		return nil, finding("STATE-PREPARED-BINDING", "prepared commit authority", "the reviewed Plan or managed inputs changed", "the exact Plan and managed-input checksums bound during preparation", "changed observations require fresh review", "run Load with fresh observations, review a fresh Plan, and prepare again")
	}
	if !matchesLoadedState(commit.storage, commit.starting) {
		return nil, finding("STATE-PREPARED-STALE", "prepared commit authority", "the persisted starting State changed", "the exact State bytes loaded before review", "a different starting lineage invalidates approval", "run Load with fresh observations, review a fresh Plan, and prepare again")
	}
	return &TransactionMaterial{
		startingRevision:           commit.starting.revision,
		candidateRevision:          commit.revision,
		startingChecksum:           commit.starting.payloadChecksum,
		candidateChecksum:          commit.candidateSHA256,
		manifestChecksum:           commit.manifestSHA256,
		preparedChecksum:           commit.preparedSHA256,
		changeSet:                  commit.changeSet,
		reviewed:                   commit.reviewed,
		priorState:                 append([]byte(nil), commit.starting.bytes...),
		preparedState:              append([]byte(nil), commit.preparedState...),
		serviceCopies:              commit.serviceCopies,
		subscriptionArtifactBundle: append([]byte(nil), commit.subscriptionArtifactBundle...),
		storage:                    commit.storage,
		publication:                &publicationAuthority{},
		startingRelease:            commit.starting.migration.StartingRelease,
		candidateRelease:           commit.releaseIdentity,
		deferred:                   commit.deferred,
	}, nil
}

// SystemChangesConsume burns the State authority while keeping managed-input
// checks private to State.
func (commit *PreparedCommit) SystemChangesConsume(lease any, planIdentity, planSHA256 string) (any, error) {
	if !validSystemChangesLease(lease) || commit == nil {
		return nil, finding("STATE-PREPARED-UNAVAILABLE", "prepared commit authority", "no prepared commit", "one fresh opaque prepared commit", "missing authority cannot start mutation", "prepare State again")
	}
	current := commit.reviewed
	current.planIdentity = PlanIdentity(planIdentity)
	current.planSHA256 = planSHA256
	return commit.ConsumeForApply(current)
}

func validSystemChangesLease(value any) bool {
	typeOf := reflect.TypeOf(value)
	lease, ok := value.(interface{ Authorized() bool })
	return ok && typeOf != nil && typeOf.PkgPath() == "github.com/albertloky/SBXR/internal/systemchanges" && typeOf.Name() == "ExecutionLease" && lease.Authorized()
}

func validSystemChangesRecoveryLease(value any) bool {
	typeOf := reflect.TypeOf(value)
	lease, ok := value.(interface{ RecoveryAuthorized() bool })
	return ok && typeOf != nil && typeOf.PkgPath() == "github.com/albertloky/SBXR/internal/systemchanges" && typeOf.Name() == "ExecutionLease" && lease.RecoveryAuthorized()
}
