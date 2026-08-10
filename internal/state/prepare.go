package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"sync"
	"sync/atomic"
)

// SoftwareLifecycleIntent is the exact candidate section validated by Software
// Lifecycle without giving State an upward dependency.
type SoftwareLifecycleIntent struct {
	Installation InstallationIdentity `json:"installation"`
	Software     SoftwareSettings     `json:"software"`
}

// ClientAccessReader is supplied only while an owning validator checks its
// own Client Access Values. State never exposes this capability elsewhere.
type ClientAccessReader interface {
	ReadClientAccessValue(ClientAccessValue) string
}

// InfrastructureSecretReader is supplied only while an owning validator
// checks its own Infrastructure Secrets.
type InfrastructureSecretReader interface {
	ReadInfrastructureSecret(InfrastructureSecret) string
}

// ConnectionProfileSecretReader permits the Connection Profiles validator to
// inspect both secret categories owned by that Module.
type ConnectionProfileSecretReader interface {
	ClientAccessReader
	InfrastructureSecretReader
}

type secretReaderLease struct{ active atomic.Bool }

func newSecretReaderLease() *secretReaderLease {
	lease := &secretReaderLease{}
	lease.active.Store(true)
	return lease
}

func (lease *secretReaderLease) revoke() { lease.active.Store(false) }

type clientAccessReader struct{ lease *secretReaderLease }

func (reader *clientAccessReader) ReadClientAccessValue(value ClientAccessValue) string {
	if !reader.lease.active.Load() {
		return ""
	}
	return value.value
}

type infrastructureSecretReader struct{ lease *secretReaderLease }

func (reader *infrastructureSecretReader) ReadInfrastructureSecret(value InfrastructureSecret) string {
	if !reader.lease.active.Load() {
		return ""
	}
	return value.value
}

type connectionProfileSecretReader struct{ lease *secretReaderLease }

func (reader *connectionProfileSecretReader) ReadClientAccessValue(value ClientAccessValue) string {
	if !reader.lease.active.Load() {
		return ""
	}
	return value.value
}

func (reader *connectionProfileSecretReader) ReadInfrastructureSecret(value InfrastructureSecret) string {
	if !reader.lease.active.Load() {
		return ""
	}
	return value.value
}

// The validator Interfaces let State invoke each owning Module without an
// upward package dependency or accepting caller-made validation results.
type ConnectionProfilesValidator interface {
	ValidateConnectionProfiles(ConnectionProfiles, ConnectionProfileSecretReader) error
}

type ConnectionProfilesPreparer interface {
	PrepareConnectionProfiles(ConnectionProfiles, ConnectionProfileSecretReader) (xray, singBox []byte, err error)
}

type ConnectionProfilesReviewedPreparer interface {
	ConnectionProfilesValidator
	ConnectionProfilesPreparer
	Identity() string
	SHA256() string
}

type SubscriptionValidator interface {
	ValidateSubscription(SubscriptionSettings, ClientAccessReader) error
}

// SubscriptionPublicationPreparer is the reviewed owning-Module handoff for
// one complete validated artifact set. The bytes are protected transaction input.
type SubscriptionPublicationPreparer interface {
	Identity() string
	SHA256() string
	PrepareSubscriptionPublication() ([]byte, error)
}

type CloudflareValidator interface {
	ValidateCloudflare(CloudflareSettings, InfrastructureSecretReader) error
}

type CertificatesValidator interface {
	ValidateCertificates(CertificateSettings) error
}

type NetworkPolicyValidator interface {
	ValidateNetworkPolicy(NetworkPolicyInputs) error
}

type SoftwareLifecycleValidator interface {
	ValidateSoftwareLifecycle(SoftwareLifecycleIntent) error
}

// SemanticValidators contains every required owning-Module validation Seam.
type SemanticValidators struct {
	ConnectionProfiles ConnectionProfilesValidator
	Subscription       SubscriptionValidator
	Cloudflare         CloudflareValidator
	Certificates       CertificatesValidator
	NetworkPolicy      NetworkPolicyValidator
	SoftwareLifecycle  SoftwareLifecycleValidator
}

// XrayRealityMaterial contains only values read by the Xray REALITY listener.
type XrayRealityMaterial struct {
	Port        uint16               `json:"port"`
	UUID        ClientAccessValue    `json:"uuid"`
	PrivateKey  InfrastructureSecret `json:"private_key"`
	ShortID     ClientAccessValue    `json:"short_id"`
	Target      string               `json:"target"`
	ServerName  string               `json:"server_name"`
	Fingerprint string               `json:"fingerprint"`
}

// XrayXHTTPMaterial contains only values read by the loopback XHTTP listener.
type XrayXHTTPMaterial struct {
	UUID          ClientAccessValue `json:"uuid"`
	Path          ClientAccessValue `json:"path"`
	OriginAddress string            `json:"origin_address"`
	OriginPort    uint16            `json:"origin_port"`
	Mode          XHTTPMode         `json:"mode"`
}

// XrayWebSocketMaterial contains only values read by the loopback WebSocket listener.
type XrayWebSocketMaterial struct {
	UUID          ClientAccessValue `json:"uuid"`
	OriginAddress string            `json:"origin_address"`
	OriginPort    uint16            `json:"origin_port"`
	Path          ClientAccessValue `json:"path"`
}

// XrayServiceMaterial contains only enabled Xray listener values.
type XrayServiceMaterial struct {
	VLESSRealityVision *XrayRealityMaterial   `json:"vless_reality_vision,omitempty"`
	VLESSXHTTP         *XrayXHTTPMaterial     `json:"vless_xhttp,omitempty"`
	VLESSWebSocket     *XrayWebSocketMaterial `json:"vless_websocket,omitempty"`
}

// SingBoxHysteria2Material contains only values read by the Hysteria2 listener.
type SingBoxHysteria2Material struct {
	Port               uint16            `json:"port"`
	Password           ClientAccessValue `json:"password"`
	ServerName         string            `json:"server_name"`
	CertificatePointer string            `json:"certificate_pointer"`
	MasqueradeURL      string            `json:"masquerade_url"`
	Obfuscation        bool              `json:"obfuscation"`
	ObfuscationSecret  ClientAccessValue `json:"obfuscation_secret"`
}

// SingBoxTUICMaterial contains only values read by the TUIC listener.
type SingBoxTUICMaterial struct {
	Port               uint16            `json:"port"`
	UUID               ClientAccessValue `json:"uuid"`
	Password           ClientAccessValue `json:"password"`
	ServerName         string            `json:"server_name"`
	CertificatePointer string            `json:"certificate_pointer"`
	CongestionControl  CongestionControl `json:"congestion_control"`
	ZeroRTT            bool              `json:"zero_rtt"`
}

// SingBoxAnyTLSMaterial contains only values read by the AnyTLS listener.
type SingBoxAnyTLSMaterial struct {
	Port               uint16            `json:"port"`
	Password           ClientAccessValue `json:"password"`
	ServerName         string            `json:"server_name"`
	CertificatePointer string            `json:"certificate_pointer"`
	PaddingScheme      string            `json:"padding_scheme"`
}

// SingBoxServiceMaterial contains only enabled sing-box listener values.
type SingBoxServiceMaterial struct {
	Hysteria2 *SingBoxHysteria2Material `json:"hysteria2,omitempty"`
	TUIC      *SingBoxTUICMaterial      `json:"tuic,omitempty"`
	AnyTLS    *SingBoxAnyTLSMaterial    `json:"anytls,omitempty"`
}

// CloudflareRoute is one hostname-to-loopback mapping required by cloudflared.
type CloudflareRoute struct {
	Hostname string `json:"hostname"`
	Origin   string `json:"origin"`
}

// CloudflaredServiceMaterial omits the Cloudflare management token and carries
// only the run token, Tunnel identity, and enabled routes.
type CloudflaredServiceMaterial struct {
	TunnelID       string               `json:"tunnel_id"`
	TunnelRunToken InfrastructureSecret `json:"tunnel_run_token"`
	Routes         []CloudflareRoute    `json:"routes"`
}

// SubscriptionServiceMaterial contains only the public listener's credential,
// certificate binding, and selected address.
type SubscriptionServiceMaterial struct {
	Token              ClientAccessValue `json:"token"`
	ListenPort         uint16            `json:"listen_port"`
	CertificatePointer string            `json:"certificate_pointer"`
	PrimaryAddress     string            `json:"primary_address"`
}

// ServiceMaterials are the typed owning-Module outputs accepted by State.
type ServiceMaterials struct {
	Xray         *XrayServiceMaterial        `json:"-"`
	SingBox      *SingBoxServiceMaterial     `json:"-"`
	Cloudflared  *CloudflaredServiceMaterial `json:"-"`
	Subscription SubscriptionServiceMaterial `json:"-"`
}

// ServiceMaterialsFor derives the exact typed service inputs State expects
// from one complete Desired State candidate.
func ServiceMaterialsFor(candidate DesiredState) ServiceMaterials {
	return expectedServiceMaterials(candidate)
}

// PlanIdentity names one reviewed, one-use owning-Module Plan.
type PlanIdentity string

// ManagedInputChecksums bind the fresh observations used by every owning
// Module without exposing their secret-derived values through rendering.
type ManagedInputChecksums struct {
	connectionProfiles string
	subscription       string
	cloudflare         string
	certificates       string
	networkPolicy      string
	softwareLifecycle  string
}

func NewManagedInputChecksums(connectionProfiles, subscription, cloudflare, certificates, networkPolicy, softwareLifecycle string) (ManagedInputChecksums, error) {
	checksums := ManagedInputChecksums{connectionProfiles, subscription, cloudflare, certificates, networkPolicy, softwareLifecycle}
	if !validSHA256(connectionProfiles) || !validSHA256(subscription) || !validSHA256(cloudflare) || !validSHA256(certificates) || !validSHA256(networkPolicy) || !validSHA256(softwareLifecycle) {
		return ManagedInputChecksums{}, finding("STATE-MANAGED-INPUTS", "managed input checksums", "a required checksum is invalid", "one SHA-256 for every owning Module input", "changed observations must invalidate prepared authority", "refresh the managed inputs and review again")
	}
	return checksums, nil
}

func (ManagedInputChecksums) MarshalJSON() ([]byte, error) { return nil, errProtectedValueRendering }
func (ManagedInputChecksums) String() string               { return "[redacted managed input checksums]" }
func (ManagedInputChecksums) GoString() string             { return "[redacted managed input checksums]" }

// ReviewedInputs bind one approved Plan to the managed observations it reviewed.
type ReviewedInputs struct {
	planIdentity PlanIdentity
	planSHA256   string
	managed      ManagedInputChecksums
	authority    *reviewedPlanAuthority
}

type reviewedPlanAuthority struct{ used atomic.Bool }

// ponytail: process-lifetime interning keeps Plan identities one-use without
// forbidden preparation writes; replace it when a Plan Module owns this token.
var reviewedPlanAuthorities sync.Map

func NewReviewedInputs(planIdentity PlanIdentity, planSHA256 string, managed ManagedInputChecksums) (ReviewedInputs, error) {
	if !validPlanIdentity(planIdentity) || !validSHA256(planSHA256) || managed == (ManagedInputChecksums{}) {
		return ReviewedInputs{}, finding("STATE-REVIEW-BINDING", "reviewed Plan", "the Plan identity, checksum, or managed inputs are invalid", "one complete reviewed Plan binding", "unbound approval cannot authorize mutation", "create and review a fresh Plan")
	}
	authority, _ := reviewedPlanAuthorities.LoadOrStore(planIdentity, &reviewedPlanAuthority{})
	return ReviewedInputs{planIdentity: planIdentity, planSHA256: planSHA256, managed: managed, authority: authority.(*reviewedPlanAuthority)}, nil
}

func (ReviewedInputs) MarshalJSON() ([]byte, error) { return nil, errProtectedValueRendering }
func (ReviewedInputs) String() string               { return "[redacted reviewed inputs]" }
func (ReviewedInputs) GoString() string             { return "[redacted reviewed inputs]" }

func validPlanIdentity(value PlanIdentity) bool {
	return validChangeSetIdentity(ChangeSetIdentity(value))
}

// PrepareRequest binds one complete candidate to its loaded lineage and review.
type PrepareRequest struct {
	Loaded                   Result
	CandidateReleaseIdentity ReleaseIdentity
	ChangeSet                ChangeSetIdentity
	Candidate                DesiredState
	SemanticValidators       SemanticValidators
	ServiceMaterials         ServiceMaterials
	SubscriptionPublication  SubscriptionPublicationPreparer
	ReviewedInputs           ReviewedInputs
}

// ServiceManifest binds one prepared copy to its owner, bytes, narrow
// filesystem contract, candidate revision, and later Change Set. SHA256 is
// internal transaction material and must never be shown as Owner evidence.
type ServiceManifest struct {
	Service           string
	OwningModule      string
	CandidateRevision uint64
	ChangeSet         ChangeSetIdentity
	Owner             string
	Group             string
	DirectoryMode     uint32
	FileMode          uint32
	SHA256            string
}

// PreparedServiceCopy is opaque transaction input for later System Changes.
type PreparedServiceCopy struct {
	manifest ServiceManifest
	bytes    []byte
}

func (PreparedServiceCopy) MarshalJSON() ([]byte, error) { return nil, errProtectedValueRendering }
func (PreparedServiceCopy) String() string               { return "[redacted prepared service copy]" }
func (PreparedServiceCopy) GoString() string             { return "[redacted prepared service copy]" }

// PreparedServiceCopies omits services with no enabled Connection Profile.
type PreparedServiceCopies struct {
	Xray         *PreparedServiceCopy
	SingBox      *PreparedServiceCopy
	Cloudflared  *PreparedServiceCopy
	Subscription *PreparedServiceCopy
}

// PreparedCommit is one validated candidate and its byte-stable service material.
type PreparedCommit struct {
	releaseIdentity            ReleaseIdentity
	candidate                  DesiredState
	serviceCopies              PreparedServiceCopies
	subscriptionArtifactBundle []byte
	revision                   uint64
	changeSet                  ChangeSetIdentity
	reviewed                   ReviewedInputs
	starting                   *loadedState
	storage                    Storage
	candidateSHA256            string
	manifestSHA256             string
	preparedState              []byte
	preparedSHA256             string
	migration                  MigrationReview
	consumed                   atomic.Bool
	deferred                   *deferredCloudflare
	ipCertificateRenewal       bool
	domainCertificateRenewal   bool
	softwareUpdate             bool
	unprovenRemoval            bool
}

type CloudflareEvidenceBinding struct {
	TunnelStep             int
	XHTTPDNSRecordStep     int
	WebSocketDNSRecordStep int
	DirectIPv4RecordStep   int
	DirectIPv6RecordStep   int
}

type DeferredCloudflareAuthority interface {
	StateDeferredCloudflare() (source any, bindingJSON []byte, templateSHA256 string, valid bool)
}

type ManagementTokenChangeAuthority interface {
	StateManagementTokenChange() (source any, bindingJSON []byte, templateSHA256 string, valid bool)
}

type RunTokenRotationAuthority interface {
	StateRunTokenRotation() (source any, bindingJSON []byte, templateSHA256 string, valid bool)
}

type CloudflareRepairAuthority interface {
	StateCloudflareRepair() (source any, bindingJSON []byte, templateSHA256 string, valid bool)
}

type SoftwareUpdateAuthority interface {
	StateSoftwareUpdate() ([]byte, bool)
}

type SoftwareRepairAuthority interface {
	StateSoftwareRepair() (revision uint64, stateSHA256 string, valid bool)
}

type CompleteRemovalAuthority interface {
	StateCompleteRemoval() (revision uint64, stateSHA256 string, valid bool)
	StateUnprovenCompleteRemoval() (changeSet, identity, sha256 string, valid bool)
}

type ConnectionProfilesRepairAuthority interface {
	StateConnectionProfilesRepair() (revision uint64, stateSHA256 string, valid bool)
}

type deferredCloudflare struct {
	candidate  DesiredState
	validators SemanticValidators
	materials  ServiceMaterials
	runToken   VerifiedInfrastructureSecret
	binding    CloudflareEvidenceBinding
	rotation   bool
	used       atomic.Bool
}

type managementTokenChange struct{}

func (commit *PreparedCommit) Revision() uint64 {
	if commit == nil {
		return 0
	}
	return commit.revision
}

func (commit *PreparedCommit) MigrationReview() *MigrationReview {
	if commit == nil || commit.migration.StartingSchema == 0 {
		return nil
	}
	review := commit.migration
	review.TargetRelease = commit.releaseIdentity
	review.StartingReleaseCanReadCandidate = review.StartingRelease == review.TargetRelease
	return cloneMigrationReview(&review)
}

func (*PreparedCommit) MarshalJSON() ([]byte, error) { return nil, errProtectedValueRendering }
func (*PreparedCommit) String() string               { return "[redacted prepared commit]" }
func (*PreparedCommit) GoString() string             { return "[redacted prepared commit]" }

// SystemChangesPreparedState exposes only the non-secret binding needed to
// prove this opaque authority came from State for the exact Change Set.
func (commit *PreparedCommit) SystemChangesPreparedState() (changeSet string, revision uint64, startingSHA256, candidateSHA256, planIdentity, planSHA256 string, valid bool) {
	if commit != nil && commit.unprovenRemoval && commit.changeSet != "" && commit.reviewed.planIdentity != "" && validSHA256(commit.reviewed.planSHA256) {
		return string(commit.changeSet), 0, "", "", string(commit.reviewed.planIdentity), commit.reviewed.planSHA256, true
	}
	if commit == nil || commit.changeSet == "" || commit.revision == 0 || commit.candidateSHA256 == "" {
		return "", 0, "", "", "", "", false
	}
	return string(commit.changeSet), commit.revision, commit.starting.payloadChecksum, commit.candidateSHA256, string(commit.reviewed.planIdentity), commit.reviewed.planSHA256, true
}

func (commit *PreparedCommit) SystemChangesRemovalLineageUnavailable() bool {
	return commit != nil && commit.unprovenRemoval
}

func (commit *PreparedCommit) SoftwareLifecyclePreparedRelease() (repository, tag, revision, releaseIndexSHA256 string, valid bool) {
	if commit == nil {
		return "", "", "", "", false
	}
	identity := commit.releaseIdentity
	return identity.Repository, identity.Tag, identity.Commit, identity.ReleaseIndexSHA256, identity.Repository != "" && identity.Tag != "" && identity.Commit != "" && identity.ReleaseIndexSHA256 != ""
}

func (commit *PreparedCommit) SoftwareLifecyclePreparedMigration() (from, to uint64, steps int, networkFree bool) {
	if commit == nil || !commit.softwareUpdate || commit.migration.StartingSchema == 0 || commit.migration.TargetSchema < commit.migration.StartingSchema {
		return 0, 0, 0, false
	}
	return uint64(commit.migration.StartingSchema), uint64(commit.migration.TargetSchema), len(commit.migration.Steps), true
}

func (commit *PreparedCommit) SystemChangesIPCertificateRenewal() bool {
	return commit != nil && commit.ipCertificateRenewal
}

func (commit *PreparedCommit) SystemChangesDomainCertificateRenewal() bool {
	return commit != nil && commit.domainCertificateRenewal
}

// PrepareCommit validates one complete candidate and typed owning-Module
// outputs against the exact loaded bytes without mutating storage.
func (i Interface) PrepareCommit(request PrepareRequest) (*PreparedCommit, error) {
	return i.prepareCommit(request, nil, nil)
}

func (i Interface) PrepareSoftwareUpdateCommit(request PrepareRequest, authority SoftwareUpdateAuthority) (*PreparedCommit, error) {
	typeOf := reflect.TypeOf(authority)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || typeOf.Elem().PkgPath() != "github.com/albertloky/SBXR/internal/softwarelifecycle" || typeOf.Elem().Name() != "UpdatePlan" || request.Loaded.loaded == nil || request.Loaded.loaded.owner != i.implementation {
		return nil, finding("STATE-SOFTWARE-UPDATE-PLAN", "Software Lifecycle update", "the authority did not come from Software Lifecycle or current State", "one exact reviewed update Plan and fresh Managed Load", "an update cannot carry caller-made State changes", "reload State and rebuild the update Plan")
	}
	bindingJSON, valid := authority.StateSoftwareUpdate()
	var binding struct {
		StartingRevision                   uint64
		StartingStateSHA256, DesiredSHA256 string
		Current, Candidate                 struct{ Repository, Tag, Commit, IndexSHA256 string }
		FromSchema, ToSchema               uint64
	}
	current, problem := decode(request.Loaded.loaded.bytes)
	candidateBytes, candidateErr := marshalProtectedJSON(request.Candidate)
	candidateDigest := sha256.Sum256(candidateBytes)
	bindingErr := json.Unmarshal(bindingJSON, &binding)
	currentIdentity := binding.Current.Repository == current.ReleaseIdentity.Repository && binding.Current.Tag == current.ReleaseIdentity.Tag && binding.Current.Commit == current.ReleaseIdentity.Commit && binding.Current.IndexSHA256 == current.ReleaseIdentity.ReleaseIndexSHA256
	candidateIdentity := binding.Candidate.Repository == request.CandidateReleaseIdentity.Repository && binding.Candidate.Tag == request.CandidateReleaseIdentity.Tag && binding.Candidate.Commit == request.CandidateReleaseIdentity.Commit && binding.Candidate.IndexSHA256 == request.CandidateReleaseIdentity.ReleaseIndexSHA256
	if !valid || bindingErr != nil || problem != nil || candidateErr != nil || request.Loaded.Status != Managed || binding.StartingRevision != request.Loaded.loaded.revision || binding.StartingStateSHA256 != request.Loaded.loaded.payloadChecksum || binding.DesiredSHA256 != hex.EncodeToString(candidateDigest[:]) || !currentIdentity || !candidateIdentity || binding.FromSchema != uint64(current.SchemaVersion) || binding.ToSchema != uint64(supportedSchema) || !reflect.DeepEqual(current.desiredState, request.Candidate) {
		return nil, finding("STATE-SOFTWARE-UPDATE-PLAN", "Software Lifecycle update", "the release, migration, revision, or Desired State meaning differs from review", "the exact current Desired State with only its reviewed release/schema successor", "updates preserve all Owner values and secrets", "reload State and rebuild the update Plan")
	}
	commit, err := i.prepareCommit(request, nil, nil)
	if err == nil {
		commit.softwareUpdate = true
	}
	return commit, err
}

func (i Interface) PrepareSoftwareRepairCommit(request PrepareRequest, authority SoftwareRepairAuthority) (*PreparedCommit, error) {
	typeOf := reflect.TypeOf(authority)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || typeOf.Elem().PkgPath() != "github.com/albertloky/SBXR/internal/softwarelifecycle" || typeOf.Elem().Name() != "RepairPlan" || request.Loaded.loaded == nil || request.Loaded.loaded.owner != i.implementation {
		return nil, finding("STATE-SOFTWARE-REPAIR-PLAN", "current Desired State repair", "the authority did not come from Software Lifecycle or current State", "one exact reviewed repair Plan and fresh Managed Load", "repair cannot adopt caller-made or Observed State", "reload State and rebuild the repair Plan")
	}
	revision, stateSHA256, valid := authority.StateSoftwareRepair()
	current, problem := decode(request.Loaded.loaded.bytes)
	if !valid || problem != nil || request.Loaded.Status != Managed || request.Loaded.loaded.revision != revision || request.Loaded.loaded.payloadChecksum != stateSHA256 || current.ReleaseIdentity != request.CandidateReleaseIdentity || !reflect.DeepEqual(current.desiredState, request.Candidate) {
		return nil, finding("STATE-SOFTWARE-REPAIR-PLAN", "current Desired State repair", "the release, revision, checksum, or Desired State meaning differs from review", "the exact current valid Desired State and installed Release Identity", "repair only moves Observed State toward current intent", "reload State and rebuild the repair Plan")
	}
	return i.prepareCommit(request, nil, nil)
}

func (i Interface) PrepareCompleteRemovalCommit(request PrepareRequest, authority CompleteRemovalAuthority) (*PreparedCommit, error) {
	typeOf := reflect.TypeOf(authority)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || typeOf.Elem().PkgPath() != "github.com/albertloky/SBXR/internal/softwarelifecycle" || typeOf.Elem().Name() != "CompleteRemovalPlan" || request.Loaded.loaded == nil || request.Loaded.loaded.owner != i.implementation {
		return nil, finding("STATE-COMPLETE-REMOVAL-PLAN", "Complete removal rollback State", "the authority did not come from Software Lifecycle or current State", "one exact reviewed Complete removal Plan and fresh Managed Load", "removal cannot invent rollback lineage", "reload State and rebuild the Complete removal Plan")
	}
	revision, stateSHA256, valid := authority.StateCompleteRemoval()
	current, problem := decode(request.Loaded.loaded.bytes)
	if !valid || problem != nil || request.Loaded.Status != Managed || request.Loaded.loaded.revision != revision || request.Loaded.loaded.payloadChecksum != stateSHA256 || current.ReleaseIdentity != request.CandidateReleaseIdentity || !reflect.DeepEqual(current.desiredState, request.Candidate) {
		return nil, finding("STATE-COMPLETE-REMOVAL-PLAN", "Complete removal rollback State", "the release, revision, checksum, or Desired State meaning differs from review", "the exact unchanged current Desired State and installed Release Identity", "pre-checkpoint rollback must restore the proven starting intent", "reload State and rebuild the Complete removal Plan")
	}
	return i.prepareCommit(request, nil, nil)
}

func (i Interface) PrepareUnprovenCompleteRemovalCommit(authority CompleteRemovalAuthority) (*PreparedCommit, error) {
	typeOf := reflect.TypeOf(authority)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || typeOf.Elem().PkgPath() != "github.com/albertloky/SBXR/internal/softwarelifecycle" || typeOf.Elem().Name() != "CompleteRemovalPlan" || i.implementation == nil || i.implementation.storage == nil {
		return nil, finding("STATE-COMPLETE-REMOVAL-PLAN", "Complete removal rollback State", "the authority did not come from Software Lifecycle or State storage is unavailable", "one exact reviewed Complete removal Plan and State storage", "removal cannot invent missing lineage", "check again and rebuild the Complete removal Plan")
	}
	changeSet, planIdentity, planSHA256, valid := authority.StateUnprovenCompleteRemoval()
	if !valid || !validChangeSetIdentity(ChangeSetIdentity(changeSet)) || !validPlanIdentity(PlanIdentity(planIdentity)) || !validSHA256(planSHA256) {
		return nil, finding("STATE-COMPLETE-REMOVAL-PLAN", "Complete removal rollback State", "the unproven-lineage authority is invalid", "one exact Recovery Required Complete removal Plan", "missing lineage cannot be replaced by caller-authored facts", "check again and rebuild the Complete removal Plan")
	}
	prior, err := i.implementation.storage.Read()
	present := err == nil
	if errors.Is(err, fs.ErrNotExist) {
		prior = nil
	} else if err != nil {
		return nil, finding("STATE-COMPLETE-REMOVAL-BASELINE", "Complete removal rollback State", "the raw State baseline could not be preserved", "exact current bytes or proven absence", "rollback cannot guess unreadable material", "correct State storage access and check again")
	}
	manifests, _ := json.Marshal(preparedManifestSet{})
	manifestDigest, preparedDigest := sha256.Sum256(manifests), sha256.Sum256(prior)
	return &PreparedCommit{
		changeSet: ChangeSetIdentity(changeSet), reviewed: ReviewedInputs{planIdentity: PlanIdentity(planIdentity), planSHA256: planSHA256},
		starting: &loadedState{owner: i.implementation, status: RecoveryRequired, bytes: append([]byte(nil), prior...), present: present}, storage: i.implementation.storage,
		manifestSHA256: hex.EncodeToString(manifestDigest[:]), preparedState: append([]byte(nil), prior...), preparedSHA256: hex.EncodeToString(preparedDigest[:]), unprovenRemoval: true,
	}, nil
}

// PrepareIPCertificateRenewalCommit admits only the three Desired State facts
// changed by the Owner-approved IP renewal branch.
func (i Interface) PrepareIPCertificateRenewalCommit(request PrepareRequest) (*PreparedCommit, error) {
	if request.Loaded.loaded == nil || request.Loaded.loaded.owner != i.implementation {
		return nil, certificateRenewalScopeFinding()
	}
	prior, problem := decode(request.Loaded.loaded.bytes)
	if problem != nil || !validIPCertificateRenewal(prior.desiredState, request.Candidate) {
		return nil, certificateRenewalScopeFinding()
	}
	commit, err := i.prepareCommit(request, nil, nil)
	if err == nil {
		commit.ipCertificateRenewal = true
	}
	return commit, err
}

func validIPCertificateRenewal(prior, candidate DesiredState) bool {
	if !prior.Certificates.RenewalPolicy || !candidate.Certificates.RenewalPolicy ||
		candidate.Certificates.IPCertificateID == prior.Certificates.IPCertificateID ||
		candidate.Certificates.IPServingPointer == prior.Certificates.IPServingPointer ||
		candidate.Subscription.CertificateID != candidate.Certificates.IPCertificateID {
		return false
	}
	candidate.Certificates.IPCertificateID = prior.Certificates.IPCertificateID
	candidate.Certificates.IPServingPointer = prior.Certificates.IPServingPointer
	candidate.Subscription.CertificateID = prior.Subscription.CertificateID
	return reflect.DeepEqual(candidate, prior)
}

// PrepareDomainCertificateRenewalCommit admits only the shared domain
// certificate facts changed by the Owner-approved domain renewal branch.
func (i Interface) PrepareDomainCertificateRenewalCommit(request PrepareRequest) (*PreparedCommit, error) {
	if request.Loaded.loaded == nil || request.Loaded.loaded.owner != i.implementation {
		return nil, certificateRenewalScopeFinding()
	}
	prior, problem := decode(request.Loaded.loaded.bytes)
	if problem != nil || !validDomainCertificateRenewal(prior.desiredState, request.Candidate) {
		return nil, certificateRenewalScopeFinding()
	}
	commit, err := i.prepareCommit(request, nil, nil)
	if err == nil {
		commit.domainCertificateRenewal = true
	}
	return commit, err
}

func validDomainCertificateRenewal(prior, candidate DesiredState) bool {
	if !prior.Certificates.RenewalPolicy || !candidate.Certificates.RenewalPolicy ||
		candidate.Certificates.DomainCertificateID == prior.Certificates.DomainCertificateID ||
		candidate.Certificates.DomainServingPointer == prior.Certificates.DomainServingPointer ||
		candidate.ConnectionProfiles.Hysteria2.CertificateID != candidate.Certificates.DomainCertificateID ||
		candidate.ConnectionProfiles.TUIC.CertificateID != candidate.Certificates.DomainCertificateID ||
		candidate.ConnectionProfiles.AnyTLS.CertificateID != candidate.Certificates.DomainCertificateID {
		return false
	}
	candidate.Certificates.DomainCertificateID = prior.Certificates.DomainCertificateID
	candidate.Certificates.DomainServingPointer = prior.Certificates.DomainServingPointer
	candidate.ConnectionProfiles.Hysteria2.CertificateID = prior.ConnectionProfiles.Hysteria2.CertificateID
	candidate.ConnectionProfiles.TUIC.CertificateID = prior.ConnectionProfiles.TUIC.CertificateID
	candidate.ConnectionProfiles.AnyTLS.CertificateID = prior.ConnectionProfiles.AnyTLS.CertificateID
	return reflect.DeepEqual(candidate, prior)
}

func certificateRenewalScopeFinding() error {
	return finding("STATE-CERTIFICATE-RENEWAL-SCOPE", "standing certificate renewal", "the candidate changes facts outside one approved certificate lineage and its consumers", "only one certificate identifier, serving pointer, matching consumer bindings, and one revision", "unattended authority cannot expand into another setting or lineage", "create a fresh reviewed Plan")
}

// PrepareManagementTokenCommit lets only a reviewed Cloudflare Plan replace
// or deliberately remove the protected management token.
func (i Interface) PrepareManagementTokenCommit(request PrepareRequest, authority ManagementTokenChangeAuthority) (*PreparedCommit, error) {
	typeOf := reflect.TypeOf(authority)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || typeOf.Elem().PkgPath() != "github.com/albertloky/SBXR/internal/cloudflaretunnel" || typeOf.Elem().Name() != "Plan" {
		return nil, finding("STATE-CLOUDFLARE-TOKEN-PLAN", "Cloudflare management-token change", "the authority did not come from Cloudflare Tunnel", "one exact reviewed Cloudflare management-token Plan", "caller-made authority cannot change a stored Infrastructure Secret", "rebuild the management-token Plan")
	}
	source, bindingJSON, templateSHA256, valid := authority.StateManagementTokenChange()
	var binding struct {
		Action         string
		CurrentTokenID string
		AccountID      string
		ZoneID         string
		ZoneName       string
		Dependencies   []string
		Resolution     string
	}
	template, templateErr := marshalProtectedJSON(request.Candidate)
	digest := sha256.Sum256(template)
	bindingErr := json.Unmarshal(bindingJSON, &binding)
	resolved := len(binding.Dependencies) == 0 && binding.Resolution == "" || exactManagementTokenDependencies(binding.Dependencies) && binding.Resolution == "mark dependencies unmanaged"
	if binding.Action == "remove" && request.Loaded.Status == Managed && !exactManagementTokenDependencies(binding.Dependencies) {
		resolved = false
	}
	selectedAuthority := binding.AccountID == request.Candidate.Cloudflare.AccountID && binding.ZoneID == request.Candidate.Cloudflare.ZoneID && binding.ZoneName == request.Candidate.Cloudflare.ZoneName
	if request.Loaded.Snapshot != nil {
		current := request.Loaded.Snapshot.DesiredState.Cloudflare
		selectedAuthority = selectedAuthority && binding.AccountID == current.AccountID && binding.ZoneID == current.ZoneID && binding.ZoneName == current.ZoneName
	}
	if !valid || bindingErr != nil || templateErr != nil || hex.EncodeToString(digest[:]) != templateSHA256 || !selectedAuthority || binding.CurrentTokenID == "" || binding.Action == "replace" && (len(binding.Dependencies) != 0 || binding.Resolution != "") || binding.Action == "remove" && !resolved {
		return nil, finding("STATE-CLOUDFLARE-TOKEN-PLAN", "Cloudflare management-token change", "the reviewed token binding or dependency outcome is incomplete", "one exact dependency-free replacement or removal Plan", "State cannot guess which authority or dependencies were reviewed", "rebuild the management-token Plan")
	}
	switch binding.Action {
	case "replace":
		verified, ok := source.(VerifiedInfrastructureSecret)
		if !ok || request.Candidate.Cloudflare.ManagementToken.isSet() || request.Candidate.Cloudflare.ManagementTokenRemoved || request.Candidate.Cloudflare.ManagementTokenState != "" {
			return nil, finding("STATE-CLOUDFLARE-TOKEN-PLAN", "Cloudflare management-token replacement", "the protected replacement slot is not empty", "one empty slot filled only from the verified Cloudflare handoff", "a caller-supplied token cannot become Desired State", "rebuild the replacement Plan")
		}
		request.Candidate.Cloudflare.ManagementToken, ok = NewInfrastructureSecretFrom(verified)
		if !ok {
			return nil, finding("STATE-CLOUDFLARE-TOKEN-PLAN", "Cloudflare management-token replacement", "the verified replacement is unavailable or already used", "one fresh one-use verified replacement", "the stored token cannot change without fresh authority", "rebuild the replacement Plan")
		}
	case "remove":
		wantState := CloudflareManagementState("")
		if len(binding.Dependencies) != 0 {
			wantState = CloudflareManagementUnmanaged
		}
		if source != nil || request.Candidate.Cloudflare.ManagementToken.isSet() || !request.Candidate.Cloudflare.ManagementTokenRemoved || request.Candidate.Cloudflare.ManagementTokenState != wantState {
			return nil, finding("STATE-CLOUDFLARE-TOKEN-PLAN", "Cloudflare management-token removal", "the candidate is not the reviewed deliberate-absence state", "an empty token plus the explicit removed fact", "missing and deliberately removed authority must never be confused", "rebuild the removal Plan")
		}
	default:
		return nil, finding("STATE-CLOUDFLARE-TOKEN-PLAN", "Cloudflare management-token change", "the reviewed action is unsupported", "replace or remove", "State accepts no generic secret mutation", "rebuild the management-token Plan")
	}
	return i.prepareCommit(request, nil, &managementTokenChange{})
}

func exactManagementTokenDependencies(dependencies []string) bool {
	want := map[string]bool{"Tunnel": true, "DNS": true, "certificate": true, "profile": true, "repair": true, "update": true}
	if len(dependencies) != len(want) {
		return false
	}
	for _, dependency := range dependencies {
		if !want[dependency] {
			return false
		}
		delete(want, dependency)
	}
	return len(want) == 0
}

// PrepareDeferredCloudflareCommit binds every reviewed value known before
// mutation while reserving only provider-created IDs and the run token for
// State-owned finalization inside the active System Changes transaction.
func (i Interface) PrepareDeferredCloudflareCommit(request PrepareRequest, authority DeferredCloudflareAuthority) (*PreparedCommit, error) {
	typeOf := reflect.TypeOf(authority)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || typeOf.Elem().PkgPath() != "github.com/albertloky/SBXR/internal/cloudflaretunnel" || typeOf.Elem().Name() != "Plan" {
		return nil, finding("STATE-CLOUDFLARE-DEFERRED", "deferred Cloudflare finalization", "the authority did not come from Cloudflare Tunnel", "one exact reviewed Cloudflare Plan", "caller-made provider bindings cannot authorize State", "rebuild the Cloudflare Plan")
	}
	source, bindingJSON, templateSHA256, valid := authority.StateDeferredCloudflare()
	runToken, sourceOK := source.(VerifiedInfrastructureSecret)
	var planned struct {
		AccountID, ZoneID, TunnelName, XHTTPHostname, WebSocketHostname, DirectHostname string
		PublicIPv4, PublicIPv6                                                          string
		CloudflareEvidenceBinding
	}
	bindingErr := json.Unmarshal(bindingJSON, &planned)
	binding := planned.CloudflareEvidenceBinding
	template, templateErr := marshalProtectedJSON(request.Candidate)
	templateDigest := sha256.Sum256(template)
	candidate := request.Candidate
	fixedFactsMatch := planned.AccountID == candidate.Cloudflare.AccountID && planned.ZoneID == candidate.Cloudflare.ZoneID && planned.TunnelName == candidate.Cloudflare.TunnelName && planned.XHTTPHostname == candidate.Cloudflare.XHTTPHostname && planned.WebSocketHostname == candidate.Cloudflare.WebSocketHostname && planned.DirectHostname == candidate.Cloudflare.DirectHostname && planned.PublicIPv4 == candidate.NetworkPolicy.PublicIPv4 && planned.PublicIPv6 == candidate.NetworkPolicy.PublicIPv6
	if !valid || bindingErr != nil || !fixedFactsMatch || !sourceOK || runToken == nil || templateErr != nil || hex.EncodeToString(templateDigest[:]) != templateSHA256 || !validCloudflareEvidenceBinding(binding, request.Candidate.NetworkPolicy) {
		return nil, finding("STATE-CLOUDFLARE-DEFERRED", "deferred Cloudflare finalization", "the run-token handoff or evidence binding is incomplete", "one exact one-use State finalization binding", "provider-created values cannot be guessed", "rebuild the Cloudflare Plan")
	}
	original := request.Candidate
	staged, ok := stageDeferredCloudflare(original)
	if !ok {
		return nil, finding("STATE-CLOUDFLARE-DEFERRED", "deferred Cloudflare finalization", "the candidate already contains provider-created values or lacks reviewed fixed values", "only empty provider-created slots in one otherwise complete candidate", "preexisting identifiers cannot be adopted", "rebuild the Cloudflare Plan")
	}
	metadata := &deferredCloudflare{candidate: original, validators: request.SemanticValidators, materials: request.ServiceMaterials, runToken: runToken, binding: binding}
	request.Candidate = staged
	request.ServiceMaterials.Cloudflared = nil
	commit, err := i.prepareCommit(request, metadata, nil)
	if err == nil {
		commit.candidateSHA256 = templateSHA256
	}
	return commit, err
}

// PrepareRunTokenRotationCommit keeps the current run token only in the
// transaction's rollback snapshot. The candidate and cloudflared material stay
// deferred until Cloudflare returns a token different from that snapshot.
func (i Interface) PrepareRunTokenRotationCommit(request PrepareRequest, authority RunTokenRotationAuthority) (*PreparedCommit, error) {
	typeOf := reflect.TypeOf(authority)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || typeOf.Elem().PkgPath() != "github.com/albertloky/SBXR/internal/cloudflaretunnel" || typeOf.Elem().Name() != "Plan" {
		return nil, finding("STATE-CLOUDFLARE-RUN-TOKEN-PLAN", "Tunnel run-token rotation", "the authority did not come from Cloudflare Tunnel", "one exact reviewed run-token rotation Plan", "caller-made secret handoffs cannot authorize State", "rebuild the rotation Plan")
	}
	source, bindingJSON, templateSHA256, valid := authority.StateRunTokenRotation()
	runToken, sourceOK := source.(VerifiedInfrastructureSecret)
	var planned struct {
		AccountID, ZoneID, ZoneName, XHTTPHostname, WebSocketHostname, DirectHostname string
		PublicIPv4, PublicIPv6                                                        string
		TunnelID, XHTTPDNSRecordID, WebSocketDNSRecordID                              string
		DirectIPv4RecordID, DirectIPv6RecordID                                        string
	}
	bindingErr := json.Unmarshal(bindingJSON, &planned)
	template, templateErr := marshalProtectedJSON(request.Candidate)
	templateDigest := sha256.Sum256(template)
	candidate := request.Candidate
	cloudflare := candidate.Cloudflare
	fixedFactsMatch := planned.AccountID == cloudflare.AccountID && planned.ZoneID == cloudflare.ZoneID && planned.ZoneName == cloudflare.ZoneName && planned.TunnelID == cloudflare.TunnelID && planned.XHTTPHostname == cloudflare.XHTTPHostname && planned.WebSocketHostname == cloudflare.WebSocketHostname && planned.DirectHostname == cloudflare.DirectHostname && planned.XHTTPDNSRecordID == cloudflare.XHTTPDNSRecordID && planned.WebSocketDNSRecordID == cloudflare.WebSocketDNSRecordID && planned.DirectIPv4RecordID == cloudflare.DirectIPv4RecordID && planned.DirectIPv6RecordID == cloudflare.DirectIPv6RecordID && planned.PublicIPv4 == candidate.NetworkPolicy.PublicIPv4 && planned.PublicIPv6 == candidate.NetworkPolicy.PublicIPv6
	if !valid || bindingErr != nil || !fixedFactsMatch || !sourceOK || runToken == nil || templateErr != nil || hex.EncodeToString(templateDigest[:]) != templateSHA256 || !cloudflare.TunnelRunToken.isSet() || !validateSemantics(request.Candidate, request.SemanticValidators) {
		return nil, finding("STATE-CLOUDFLARE-RUN-TOKEN-PLAN", "Tunnel run-token rotation", "the protected handoff or committed ownership binding is incomplete", "one exact one-use rotation binding", "State never guesses provider ownership or credentials", "rebuild the rotation Plan")
	}
	original := request.Candidate
	request.Candidate.Cloudflare.TunnelRunToken = NewInfrastructureSecret("deferred-cloudflare-run-token")
	request.ServiceMaterials.Cloudflared = nil
	metadata := &deferredCloudflare{candidate: original, validators: request.SemanticValidators, materials: request.ServiceMaterials, runToken: runToken, rotation: true}
	commit, err := i.prepareCommit(request, metadata, nil)
	if err == nil {
		commit.candidateSHA256 = templateSHA256
	}
	return commit, err
}

// PrepareCloudflareRepairCommit admits an unchanged Desired State revision only
// when Cloudflare bound every repair target to the currently loaded ownership.
func (i Interface) PrepareCloudflareRepairCommit(request PrepareRequest, authority CloudflareRepairAuthority) (*PreparedCommit, error) {
	typeOf := reflect.TypeOf(authority)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || typeOf.Elem().PkgPath() != "github.com/albertloky/SBXR/internal/cloudflaretunnel" || typeOf.Elem().Name() != "Plan" {
		return nil, finding("STATE-CLOUDFLARE-REPAIR-PLAN", "Cloudflare managed repair", "the authority did not come from Cloudflare Tunnel", "one exact reviewed repair Plan", "caller-made ownership cannot authorize repair", "rebuild the repair Plan")
	}
	_, bindingJSON, templateSHA256, valid := authority.StateCloudflareRepair()
	var planned struct {
		AccountID, ZoneID, ZoneName, TunnelName, XHTTPHostname, WebSocketHostname, DirectHostname string
		PublicIPv4, PublicIPv6                                                                    string
		Owned                                                                                     struct {
			TunnelID, XHTTPDNSRecordID, WebSocketDNSRecordID, DirectIPv4RecordID, DirectIPv6RecordID string
		}
	}
	bindingErr := json.Unmarshal(bindingJSON, &planned)
	template, templateErr := marshalProtectedJSON(request.Candidate)
	templateDigest := sha256.Sum256(template)
	cloudflare := request.Candidate.Cloudflare
	fixed := planned.AccountID == cloudflare.AccountID && planned.ZoneID == cloudflare.ZoneID && planned.ZoneName == cloudflare.ZoneName && planned.TunnelName == cloudflare.TunnelName && planned.XHTTPHostname == cloudflare.XHTTPHostname && planned.WebSocketHostname == cloudflare.WebSocketHostname && planned.DirectHostname == cloudflare.DirectHostname && planned.PublicIPv4 == request.Candidate.NetworkPolicy.PublicIPv4 && planned.PublicIPv6 == request.Candidate.NetworkPolicy.PublicIPv6
	owned := planned.Owned.TunnelID == cloudflare.TunnelID && planned.Owned.XHTTPDNSRecordID == cloudflare.XHTTPDNSRecordID && planned.Owned.WebSocketDNSRecordID == cloudflare.WebSocketDNSRecordID && planned.Owned.DirectIPv4RecordID == cloudflare.DirectIPv4RecordID && planned.Owned.DirectIPv6RecordID == cloudflare.DirectIPv6RecordID
	if !valid || bindingErr != nil || !fixed || !owned || templateErr != nil || hex.EncodeToString(templateDigest[:]) != templateSHA256 {
		return nil, finding("STATE-CLOUDFLARE-REPAIR-PLAN", "Cloudflare managed repair", "the repair targets differ from current Desired State", "the exact loaded immutable ownership and unchanged candidate", "State never adopts provider identity", "reload State and rebuild the repair Plan")
	}
	return i.prepareCommit(request, nil, nil)
}

func (i Interface) PrepareConnectionProfilesRepairCommit(request PrepareRequest, authority ConnectionProfilesRepairAuthority) (*PreparedCommit, error) {
	typeOf := reflect.TypeOf(authority)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || typeOf.Elem().PkgPath() != "github.com/albertloky/SBXR/internal/connectionprofiles" || typeOf.Elem().Name() != "Plan" {
		return nil, finding("STATE-CONNECTION-PROFILES-REPAIR-PLAN", "Connection Profiles repair", "the authority did not come from Connection Profiles", "one exact reviewed repair Plan", "caller-made repair authority cannot replace proven configuration", "reload State and rebuild the repair Plan")
	}
	revision, stateSHA256, valid := authority.StateConnectionProfilesRepair()
	loaded := request.Loaded.loaded
	if !valid || loaded == nil || loaded.owner != i.implementation || loaded.revision != revision || loaded.payloadChecksum != stateSHA256 {
		return nil, finding("STATE-CONNECTION-PROFILES-REPAIR-PLAN", "Connection Profiles repair", "the repair authority differs from current State", "the exact loaded revision and checksum", "repair is only forward repair of the current proven lineage", "reload State and rebuild the repair Plan")
	}
	return i.prepareCommit(request, nil, nil)
}

func (i Interface) prepareCommit(request PrepareRequest, deferred *deferredCloudflare, tokenChange *managementTokenChange) (*PreparedCommit, error) {
	if i.implementation == nil || i.implementation.storage == nil {
		return nil, finding("STATE-STORAGE-UNAVAILABLE", "Desired State storage", "no storage Adapter", "the production State storage Adapter", "State cannot prepare trusted transaction material", "restore the State Adapter and review again")
	}
	if request.Loaded.loaded != nil {
		prior, problem := decode(request.Loaded.loaded.bytes)
		changed := problem == nil && (prior.desiredState.Cloudflare.ManagementToken.value != request.Candidate.Cloudflare.ManagementToken.value || prior.desiredState.Cloudflare.ManagementTokenRemoved != request.Candidate.Cloudflare.ManagementTokenRemoved || prior.desiredState.Cloudflare.ManagementTokenState != request.Candidate.Cloudflare.ManagementTokenState)
		if changed != (tokenChange != nil) {
			return nil, finding("STATE-CLOUDFLARE-TOKEN-PLAN", "Cloudflare management-token change", "the candidate token state does not match its reviewed authority", "every replacement or removal to use one Cloudflare-owned Plan", "generic setting Plans cannot change Infrastructure Secrets", "rebuild the management-token Plan")
		}
	}
	if request.ReviewedInputs.authority == nil {
		return nil, finding("STATE-REVIEW-BINDING", "reviewed Plan", "the reviewed binding is absent", "one complete fresh reviewed Plan", "unbound approval cannot authorize mutation", "create and review a fresh Plan")
	}
	if !request.ReviewedInputs.authority.used.CompareAndSwap(false, true) {
		return nil, finding("STATE-PLAN-USED", "reviewed Plan authority", "the Plan identity was already used for preparation", "one fresh one-use reviewed Plan", "prior approval cannot be replayed after any outcome", "create and review a fresh Plan")
	}
	loaded, problem := i.claimLoaded(request.Loaded)
	if problem != nil {
		return nil, problem
	}
	if problem := validateDesiredState(request.Candidate); problem != nil {
		return nil, problem
	}
	revision := loaded.revision + 1
	if revision == 0 || !validReleaseIdentity(request.CandidateReleaseIdentity) || !validChangeSetIdentity(request.ChangeSet) {
		return nil, finding("STATE-SERVICE-MANIFEST", "prepared service manifest", "the candidate revision, Release Identity, Change Set, or reviewed inputs are invalid", "one exact loaded revision and complete reviewed binding", "prepared bytes must be bound before mutation", "correct the manifest inputs and review again")
	}
	semanticsValid := validateSemantics(request.Candidate, request.SemanticValidators)
	if deferred != nil {
		semanticsValid = validateSemanticsExceptCloudflare(request.Candidate, request.SemanticValidators)
	}
	if !semanticsValid {
		return nil, finding("STATE-CANDIDATE-SEMANTIC", "Module-owned semantic validation", "an owning validator is missing or refused its typed section", "successful validation by every owning Module", "State cannot replace operational ownership or accept caller-made validation claims", "correct the candidate through the owning Module and review again")
	}
	expectedMaterials := expectedServiceMaterials(request.Candidate)
	if deferred != nil {
		expectedMaterials.Cloudflared = nil
	}
	if !reflect.DeepEqual(request.ServiceMaterials, expectedMaterials) {
		return nil, finding("STATE-SERVICE-MATERIAL-UNRELATED", "prepared service material", "material is missing, stale, or contains an unrelated value", "only each service's exact required candidate values", "runtime services must not receive complete Desired State or unrelated secrets", "regenerate the owning Module material and review again")
	}

	materials := request.ServiceMaterials
	subscriptionBundle, err := prepareSubscriptionPublication(request.SubscriptionPublication, request.ReviewedInputs, subscriptionPublicationRequired(loaded, request.Candidate, request.CandidateReleaseIdentity))
	if err != nil {
		return nil, finding("STATE-SUBSCRIPTION-PUBLICATION", "prepared Subscription Publication artifact set", "the owning Module handoff is missing, stale, incomplete, or invalid", "one reviewed byte-stable eight-file artifact set", "State cannot invent client representations or accept caller-made bytes", "regenerate the Subscription Publication Plan and review again")
	}
	connectionProfilesChanged := loaded.status == NotInstalled
	if !connectionProfilesChanged {
		current, problem := decode(loaded.bytes)
		connectionProfilesChanged = problem != nil || current.ReleaseIdentity != request.CandidateReleaseIdentity || !reflect.DeepEqual(current.desiredState.ConnectionProfiles, request.Candidate.ConnectionProfiles)
	}
	nativeXray, nativeSingBox, nativeErr := prepareConnectionProfileServices(request.SemanticValidators.ConnectionProfiles, request.Candidate.ConnectionProfiles, request.ReviewedInputs, connectionProfilesChanged)
	if nativeErr != nil {
		return nil, finding("STATE-SERVICE-SERIALIZATION", "prepared Connection Profiles configuration", "the owning Module refused native service bytes", "one complete deterministic Xray and sing-box configuration", "State cannot invent or repair proxy-core configuration", "regenerate the Connection Profiles Plan and review again")
	}
	var copies PreparedServiceCopies
	if materials.Xray != nil {
		prepared, err := prepareServiceCopy("xray.service", "connectionprofiles", "xray", revision, request.ChangeSet, materials.Xray)
		if nativeXray != nil {
			prepared, err = prepareServiceBytes("xray.service", "connectionprofiles", "xray", revision, request.ChangeSet, nativeXray)
		}
		if err != nil {
			return nil, err
		}
		copies.Xray = &prepared
	}
	if materials.SingBox != nil {
		prepared, err := prepareServiceCopy("sing-box.service", "connectionprofiles", "sing-box", revision, request.ChangeSet, materials.SingBox)
		if nativeSingBox != nil {
			prepared, err = prepareServiceBytes("sing-box.service", "connectionprofiles", "sing-box", revision, request.ChangeSet, nativeSingBox)
		}
		if err != nil {
			return nil, err
		}
		copies.SingBox = &prepared
	}
	if materials.Cloudflared != nil {
		prepared, err := prepareServiceCopy("cloudflared.service", "cloudflaretunnel", "cloudflared", revision, request.ChangeSet, materials.Cloudflared)
		if err != nil {
			return nil, err
		}
		copies.Cloudflared = &prepared
	}
	subscription, err := prepareServiceCopy("sbxr-subscription.service", "subscriptionserving", "sbxr-subscription", revision, request.ChangeSet, materials.Subscription)
	if err != nil {
		return nil, err
	}
	copies.Subscription = &subscription
	preparedState, candidateChecksum, err := prepareStateDocument(revision, request.CandidateReleaseIdentity, request.ChangeSet, request.Candidate)
	if err != nil {
		return nil, finding("STATE-CANDIDATE-SERIALIZATION", "prepared Desired State", "typed serialization failed", "one byte-stable complete candidate", "candidate bytes must be bound before mutation", "correct the candidate and review again")
	}
	manifestChecksum, err := checksumServiceManifests(copies)
	if err != nil {
		return nil, finding("STATE-SERVICE-SERIALIZATION", "prepared service manifests", "typed serialization failed", "one byte-stable manifest set", "service bytes must be bound before mutation", "regenerate the service material and review again")
	}
	preparedDigest := sha256.Sum256(preparedState)
	return &PreparedCommit{
		releaseIdentity: request.CandidateReleaseIdentity,
		candidate:       request.Candidate, serviceCopies: copies, subscriptionArtifactBundle: subscriptionBundle, revision: revision,
		changeSet: request.ChangeSet, reviewed: request.ReviewedInputs,
		starting: loaded, storage: i.implementation.storage,
		candidateSHA256: candidateChecksum, manifestSHA256: manifestChecksum,
		preparedState: preparedState, preparedSHA256: hex.EncodeToString(preparedDigest[:]),
		migration: loaded.migration, deferred: deferred,
	}, nil
}

func prepareSubscriptionPublication(preparer SubscriptionPublicationPreparer, reviewed ReviewedInputs, required bool) ([]byte, error) {
	if preparer == nil {
		if required {
			return nil, errors.New("reviewed Subscription Publication Plan required")
		}
		return nil, nil
	}
	if PlanIdentity(preparer.Identity()) != reviewed.planIdentity || preparer.SHA256() != reviewed.planSHA256 {
		return nil, errors.New("reviewed Subscription Publication Plan unavailable")
	}
	bundle, err := preparer.PrepareSubscriptionPublication()
	if err != nil || len(bundle) == 0 || len(bundle) > 32<<20 {
		return nil, errors.New("complete Subscription Publication artifact set unavailable")
	}
	return append([]byte(nil), bundle...), nil
}

func subscriptionPublicationRequired(loaded *loadedState, candidate DesiredState, release ReleaseIdentity) bool {
	if loaded == nil || loaded.status == NotInstalled {
		return true
	}
	current, problem := decode(loaded.bytes)
	if problem != nil {
		return true
	}
	prior := current.desiredState
	return prior.ConnectionProfiles != candidate.ConnectionProfiles ||
		prior.Subscription != candidate.Subscription ||
		prior.NetworkPolicy.PublicIPv4 != candidate.NetworkPolicy.PublicIPv4 ||
		prior.NetworkPolicy.PublicIPv6 != candidate.NetworkPolicy.PublicIPv6 ||
		prior.NetworkPolicy.PrimarySubscriptionAddress != candidate.NetworkPolicy.PrimarySubscriptionAddress ||
		prior.Certificates != candidate.Certificates ||
		prior.Software.XrayVersion != candidate.Software.XrayVersion ||
		prior.Software.SingBoxVersion != candidate.Software.SingBoxVersion ||
		prior.Software.CloudflaredVersion != candidate.Software.CloudflaredVersion ||
		prior.Software.CertbotVersion != candidate.Software.CertbotVersion ||
		current.ReleaseIdentity != release
}

func validateSemanticsExceptCloudflare(candidate DesiredState, validators SemanticValidators) bool {
	software := SoftwareLifecycleIntent{Installation: candidate.Installation, Software: candidate.Software}
	if missingValidator(validators.ConnectionProfiles) || missingValidator(validators.Subscription) || missingValidator(validators.Certificates) || missingValidator(validators.NetworkPolicy) || missingValidator(validators.SoftwareLifecycle) {
		return false
	}
	return validateConnectionProfiles(validators.ConnectionProfiles, candidate.ConnectionProfiles) &&
		validateSubscription(validators.Subscription, candidate.Subscription) &&
		validatorAccepted(func() error { return validators.Certificates.ValidateCertificates(candidate.Certificates) }) &&
		validatorAccepted(func() error { return validators.NetworkPolicy.ValidateNetworkPolicy(candidate.NetworkPolicy) }) &&
		validatorAccepted(func() error { return validators.SoftwareLifecycle.ValidateSoftwareLifecycle(software) })
}

func stageDeferredCloudflare(candidate DesiredState) (DesiredState, bool) {
	cloudflare := &candidate.Cloudflare
	if empty(cloudflare.AccountID, cloudflare.ZoneID, cloudflare.ZoneName, cloudflare.TunnelName, cloudflare.XHTTPHostname, cloudflare.WebSocketHostname, cloudflare.DirectHostname) || !cloudflare.ManagementToken.isSet() || cloudflare.TunnelID != "" || cloudflare.TunnelRunToken.isSet() || cloudflare.XHTTPDNSRecordID != "" || cloudflare.WebSocketDNSRecordID != "" || cloudflare.DirectIPv4RecordID != "" || cloudflare.DirectIPv6RecordID != "" {
		return DesiredState{}, false
	}
	cloudflare.TunnelID = "deferred-cloudflare-tunnel"
	cloudflare.TunnelRunToken = NewInfrastructureSecret("deferred-cloudflare-run-token")
	cloudflare.XHTTPDNSRecordID = "deferred-xhttp-dns"
	cloudflare.WebSocketDNSRecordID = "deferred-websocket-dns"
	if candidate.NetworkPolicy.PublicIPv4 != "" {
		cloudflare.DirectIPv4RecordID = "deferred-direct-ipv4-dns"
	}
	if candidate.NetworkPolicy.PublicIPv6 != "" {
		cloudflare.DirectIPv6RecordID = "deferred-direct-ipv6-dns"
	}
	return candidate, true
}

func validCloudflareEvidenceBinding(binding CloudflareEvidenceBinding, network NetworkPolicyInputs) bool {
	required := []int{binding.TunnelStep, binding.XHTTPDNSRecordStep, binding.WebSocketDNSRecordStep}
	if network.PublicIPv4 != "" {
		required = append(required, binding.DirectIPv4RecordStep)
	} else if binding.DirectIPv4RecordStep != 0 {
		return false
	}
	if network.PublicIPv6 != "" {
		required = append(required, binding.DirectIPv6RecordStep)
	} else if binding.DirectIPv6RecordStep != 0 {
		return false
	}
	seen := map[int]bool{}
	for _, step := range required {
		if step < 1 || seen[step] {
			return false
		}
		seen[step] = true
	}
	return true
}

func (i Interface) claimLoaded(result Result) (*loadedState, *Finding) {
	loaded := result.loaded
	if loaded == nil || loaded.owner != i.implementation {
		return nil, finding("STATE-LOAD-REQUIRED", "loaded State authority", "the result was absent or came from a different State Interface", "one exact fresh Load result", "preparation must bind the storage boundary that produced the lineage", "run Load again and create a fresh Plan")
	}
	if !loaded.used.CompareAndSwap(false, true) {
		return nil, finding("STATE-LOAD-USED", "loaded State authority", "the Load result was already used", "one fresh Load per preparation attempt", "retry cannot replay prior lineage authority", "run Load again and create a fresh Plan")
	}
	if loaded.status == ChangeInProgress {
		return nil, finding("STATE-CHANGE-IN-PROGRESS", "Desired State preparation", "a Change Set is already in progress", "read-only access to the last committed revision until the operation resolves", "the candidate cannot become current or authorize another mutation", "wait for transaction resolution and run Load again")
	}
	if loaded.status != Managed && loaded.status != NotInstalled {
		return nil, finding("STATE-LOAD-REQUIRED", "loaded State authority", "the loaded status cannot prepare a mutation", "one proven Managed or Not installed baseline", "unproven lineage cannot authorize mutation", "resolve the State finding and run Load again")
	}
	if matchesLoadedState(i.implementation.storage, loaded) {
		return loaded, nil
	}
	return nil, finding("STATE-LOAD-STALE", "loaded State authority", "the persisted starting State changed after Load", "the exact byte-stable loaded baseline", "stale lineage cannot authorize preparation", "run Load again with fresh observations and review a fresh Plan")
}

func matchesLoadedState(storage Storage, loaded *loadedState) bool {
	current, err := storage.Read()
	if loaded.status == NotInstalled || loaded.status == RecoveryRequired && !loaded.present {
		return errors.Is(err, fs.ErrNotExist)
	}
	return err == nil && bytes.Equal(current, loaded.bytes)
}

func prepareStateDocument(revision uint64, release ReleaseIdentity, changeSet ChangeSetIdentity, candidate DesiredState) ([]byte, string, error) {
	payload, err := marshalProtectedJSON(candidate)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(payload)
	checksum := hex.EncodeToString(digest[:])
	document, err := json.Marshal(persistedDocument{SchemaVersion: supportedSchema, Revision: revision, ReleaseIdentity: release, LastCompletedChangeSet: changeSet, Payload: payload, Checksum: checksum})
	return document, checksum, err
}

type preparedManifestSet struct {
	Xray         *ServiceManifest `json:"xray,omitempty"`
	SingBox      *ServiceManifest `json:"sing_box,omitempty"`
	Cloudflared  *ServiceManifest `json:"cloudflared,omitempty"`
	Subscription *ServiceManifest `json:"subscription"`
}

func checksumServiceManifests(copies PreparedServiceCopies) (string, error) {
	manifests := preparedManifestSet{}
	if copies.Xray != nil {
		manifest := copies.Xray.manifest
		manifests.Xray = &manifest
	}
	if copies.SingBox != nil {
		manifest := copies.SingBox.manifest
		manifests.SingBox = &manifest
	}
	if copies.Cloudflared != nil {
		manifest := copies.Cloudflared.manifest
		manifests.Cloudflared = &manifest
	}
	if copies.Subscription != nil {
		manifest := copies.Subscription.manifest
		manifests.Subscription = &manifest
	}
	data, err := json.Marshal(manifests)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func validateSemantics(candidate DesiredState, validators SemanticValidators) bool {
	software := SoftwareLifecycleIntent{Installation: candidate.Installation, Software: candidate.Software}
	if missingValidator(validators.ConnectionProfiles) || missingValidator(validators.Subscription) || missingValidator(validators.Cloudflare) || missingValidator(validators.Certificates) || missingValidator(validators.NetworkPolicy) || missingValidator(validators.SoftwareLifecycle) {
		return false
	}
	if !validateConnectionProfiles(validators.ConnectionProfiles, candidate.ConnectionProfiles) {
		return false
	}
	if !validateSubscription(validators.Subscription, candidate.Subscription) {
		return false
	}
	return validateCloudflare(validators.Cloudflare, candidate.Cloudflare) &&
		validatorAccepted(func() error { return validators.Certificates.ValidateCertificates(candidate.Certificates) }) &&
		validatorAccepted(func() error { return validators.NetworkPolicy.ValidateNetworkPolicy(candidate.NetworkPolicy) }) &&
		validatorAccepted(func() error { return validators.SoftwareLifecycle.ValidateSoftwareLifecycle(software) })
}

func validatorAccepted(validate func() error) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	return validate() == nil
}

func validateConnectionProfiles(validator ConnectionProfilesValidator, candidate ConnectionProfiles) (valid bool) {
	lease := newSecretReaderLease()
	defer func() {
		lease.revoke()
		if recover() != nil {
			valid = false
		}
	}()
	return validator.ValidateConnectionProfiles(candidate, &connectionProfileSecretReader{lease: lease}) == nil
}

func validateSubscription(validator SubscriptionValidator, candidate SubscriptionSettings) (valid bool) {
	lease := newSecretReaderLease()
	defer func() {
		lease.revoke()
		if recover() != nil {
			valid = false
		}
	}()
	return validator.ValidateSubscription(candidate, &clientAccessReader{lease: lease}) == nil
}

func validateCloudflare(validator CloudflareValidator, candidate CloudflareSettings) (valid bool) {
	lease := newSecretReaderLease()
	defer func() {
		lease.revoke()
		if recover() != nil {
			valid = false
		}
	}()
	return validator.ValidateCloudflare(candidate, &infrastructureSecretReader{lease: lease}) == nil
}

func missingValidator(validator any) bool {
	if validator == nil {
		return true
	}
	value := reflect.ValueOf(validator)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func expectedServiceMaterials(candidate DesiredState) ServiceMaterials {
	p := candidate.ConnectionProfiles
	xray := XrayServiceMaterial{}
	if p.VLESSRealityVision.Enabled {
		profile := p.VLESSRealityVision
		xray.VLESSRealityVision = &XrayRealityMaterial{Port: profile.Port, UUID: profile.UUID, PrivateKey: profile.PrivateKey, ShortID: profile.ShortID, Target: profile.Target, ServerName: profile.ServerName, Fingerprint: profile.Fingerprint}
	}
	if p.VLESSXHTTP.Enabled {
		profile := p.VLESSXHTTP
		xray.VLESSXHTTP = &XrayXHTTPMaterial{UUID: profile.UUID, Path: profile.Path, OriginAddress: profile.OriginAddress, OriginPort: profile.OriginPort, Mode: profile.Mode}
	}
	if p.VLESSWebSocket.Enabled {
		profile := p.VLESSWebSocket
		xray.VLESSWebSocket = &XrayWebSocketMaterial{UUID: profile.UUID, OriginAddress: profile.OriginAddress, OriginPort: profile.OriginPort, Path: profile.Path}
	}
	singBox := SingBoxServiceMaterial{}
	certificatePointer := candidate.Certificates.DomainServingPointer
	if p.Hysteria2.Enabled {
		profile := p.Hysteria2
		singBox.Hysteria2 = &SingBoxHysteria2Material{Port: profile.Port, Password: profile.Password, ServerName: profile.ServerName, CertificatePointer: certificatePointer, MasqueradeURL: profile.MasqueradeURL, Obfuscation: profile.Obfuscation, ObfuscationSecret: profile.ObfuscationSecret}
	}
	if p.TUIC.Enabled {
		profile := p.TUIC
		singBox.TUIC = &SingBoxTUICMaterial{Port: profile.Port, UUID: profile.UUID, Password: profile.Password, ServerName: profile.ServerName, CertificatePointer: certificatePointer, CongestionControl: profile.CongestionControl, ZeroRTT: profile.ZeroRTT}
	}
	if p.AnyTLS.Enabled {
		profile := p.AnyTLS
		singBox.AnyTLS = &SingBoxAnyTLSMaterial{Port: profile.Port, Password: profile.Password, ServerName: profile.ServerName, CertificatePointer: certificatePointer, PaddingScheme: profile.PaddingScheme}
	}
	routes := []CloudflareRoute{}
	if p.VLESSXHTTP.Enabled {
		routes = append(routes, CloudflareRoute{Hostname: p.VLESSXHTTP.Hostname, Origin: fmt.Sprintf("http://127.0.0.1:%d", p.VLESSXHTTP.OriginPort)})
	}
	if p.VLESSWebSocket.Enabled {
		routes = append(routes, CloudflareRoute{Hostname: p.VLESSWebSocket.Hostname, Origin: fmt.Sprintf("http://127.0.0.1:%d", p.VLESSWebSocket.OriginPort)})
	}
	materials := ServiceMaterials{
		Subscription: SubscriptionServiceMaterial{
			Token:              candidate.Subscription.Token,
			ListenPort:         candidate.Subscription.ListenPort,
			CertificatePointer: candidate.Certificates.IPServingPointer,
			PrimaryAddress:     candidate.NetworkPolicy.PrimarySubscriptionAddress,
		},
	}
	xrayConfigured := p.VLESSRealityVision != (VLESSRealityVision{}) || p.VLESSXHTTP != (VLESSXHTTP{}) || p.VLESSWebSocket != (VLESSWebSocket{})
	if xrayConfigured {
		materials.Xray = &xray
	}
	singBoxConfigured := p.Hysteria2 != (Hysteria2{}) || p.TUIC != (TUIC{}) || p.AnyTLS != (AnyTLS{})
	if singBoxConfigured {
		materials.SingBox = &singBox
	}
	if len(routes) > 0 {
		materials.Cloudflared = &CloudflaredServiceMaterial{
			TunnelID:       candidate.Cloudflare.TunnelID,
			TunnelRunToken: candidate.Cloudflare.TunnelRunToken,
			Routes:         routes,
		}
	}
	return materials
}

func prepareServiceCopy(service, module, group string, revision uint64, changeSet ChangeSetIdentity, material any) (PreparedServiceCopy, error) {
	data, err := marshalProtectedJSON(material)
	if err != nil {
		return PreparedServiceCopy{}, finding("STATE-SERVICE-SERIALIZATION", "prepared service material", "typed serialization failed", "one complete deterministic JSON copy", "transaction material must be byte-stable before mutation", "correct the typed material and review again")
	}
	return prepareServiceBytes(service, module, group, revision, changeSet, data)
}

func prepareServiceBytes(service, module, group string, revision uint64, changeSet ChangeSetIdentity, data []byte) (PreparedServiceCopy, error) {
	if len(data) == 0 || len(data) > 1<<20 || !json.Valid(data) {
		return PreparedServiceCopy{}, finding("STATE-SERVICE-SERIALIZATION", "prepared service material", "owning-Module bytes are empty, oversized, or invalid JSON", "one complete deterministic native configuration", "transaction material must be byte-stable before mutation", "correct the owning Module configuration and review again")
	}
	digest := sha256.Sum256(data)
	return PreparedServiceCopy{manifest: ServiceManifest{
		Service: service, OwningModule: module, CandidateRevision: revision, ChangeSet: changeSet,
		Owner: "root", Group: group, DirectoryMode: 0o750, FileMode: 0o640, SHA256: hex.EncodeToString(digest[:]),
	}, bytes: data}, nil
}

func prepareConnectionProfileServices(validator ConnectionProfilesValidator, candidate ConnectionProfiles, reviewed ReviewedInputs, requireReviewedPlan bool) (xray, singBox []byte, err error) {
	preparer, ok := validator.(ConnectionProfilesPreparer)
	if !ok {
		return nil, nil, errors.New("Connection Profiles native preparer unavailable")
	}
	if reviewedPreparer, reviewedOK := preparer.(ConnectionProfilesReviewedPreparer); requireReviewedPlan && (!reviewedOK || PlanIdentity(reviewedPreparer.Identity()) != reviewed.planIdentity || reviewedPreparer.SHA256() != reviewed.planSHA256) {
		return nil, nil, errors.New("reviewed Connection Profiles Plan preparer unavailable")
	}
	lease := newSecretReaderLease()
	defer func() {
		lease.revoke()
		if recover() != nil {
			xray, singBox, err = nil, nil, errors.New("Connection Profiles preparation panicked")
		}
	}()
	xray, singBox, err = preparer.PrepareConnectionProfiles(candidate, &connectionProfileSecretReader{lease: lease})
	if err != nil {
		return nil, nil, err
	}
	expected := expectedServiceMaterials(DesiredState{ConnectionProfiles: candidate})
	if expected.Xray != nil && len(xray) == 0 || expected.Xray == nil && len(xray) != 0 || expected.SingBox != nil && len(singBox) == 0 || expected.SingBox == nil && len(singBox) != 0 {
		return nil, nil, errors.New("Connection Profiles native service set is incomplete")
	}
	return xray, singBox, nil
}
