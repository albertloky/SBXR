package state

import (
	"bytes"
	"errors"
	"io"
	"sync/atomic"
)

// TransactionMaterial is the opaque State-owned handoff for one System
// Changes attempt, prior-State preservation, and atomic State publication.
type TransactionMaterial struct {
	startingRevision  uint64
	candidateRevision uint64
	startingChecksum  string
	candidateChecksum string
	manifestChecksum  string
	preparedChecksum  string
	changeSet         ChangeSetIdentity
	reviewed          ReviewedInputs
	priorState        []byte
	preparedState     []byte
	serviceCopies     PreparedServiceCopies
	storage           Storage
	publication       *publicationAuthority
}

type publicationAuthority struct{ used atomic.Bool }

func (TransactionMaterial) MarshalJSON() ([]byte, error) { return nil, errProtectedValueRendering }
func (TransactionMaterial) String() string               { return "[redacted transaction material]" }
func (TransactionMaterial) GoString() string             { return "[redacted transaction material]" }

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
		startingRevision:  commit.starting.revision,
		candidateRevision: commit.revision,
		startingChecksum:  commit.starting.payloadChecksum,
		candidateChecksum: commit.candidateSHA256,
		manifestChecksum:  commit.manifestSHA256,
		preparedChecksum:  commit.preparedSHA256,
		changeSet:         commit.changeSet,
		reviewed:          commit.reviewed,
		priorState:        append([]byte(nil), commit.starting.bytes...),
		preparedState:     append([]byte(nil), commit.preparedState...),
		serviceCopies:     commit.serviceCopies,
		storage:           commit.storage,
		publication:       &publicationAuthority{},
	}, nil
}
