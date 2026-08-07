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

type SubscriptionValidator interface {
	ValidateSubscription(SubscriptionSettings, ClientAccessReader) error
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
	releaseIdentity ReleaseIdentity
	candidate       DesiredState
	serviceCopies   PreparedServiceCopies
	revision        uint64
	changeSet       ChangeSetIdentity
	reviewed        ReviewedInputs
	starting        *loadedState
	storage         Storage
	candidateSHA256 string
	manifestSHA256  string
	preparedState   []byte
	preparedSHA256  string
	migration       MigrationReview
	consumed        atomic.Bool
	deferred        *deferredCloudflare
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
	if commit == nil || commit.changeSet == "" || commit.revision == 0 || commit.candidateSHA256 == "" {
		return "", 0, "", "", "", "", false
	}
	return string(commit.changeSet), commit.revision, commit.starting.payloadChecksum, commit.candidateSHA256, string(commit.reviewed.planIdentity), commit.reviewed.planSHA256, true
}

// PrepareCommit validates one complete candidate and typed owning-Module
// outputs against the exact loaded bytes without mutating storage.
func (i Interface) PrepareCommit(request PrepareRequest) (*PreparedCommit, error) {
	return i.prepareCommit(request, nil, nil)
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
	var copies PreparedServiceCopies
	if materials.Xray != nil {
		prepared, err := prepareServiceCopy("xray.service", "connectionprofiles", "xray", revision, request.ChangeSet, materials.Xray)
		if err != nil {
			return nil, err
		}
		copies.Xray = &prepared
	}
	if materials.SingBox != nil {
		prepared, err := prepareServiceCopy("sing-box.service", "connectionprofiles", "sing-box", revision, request.ChangeSet, materials.SingBox)
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
		candidate:       request.Candidate, serviceCopies: copies, revision: revision,
		changeSet: request.ChangeSet, reviewed: request.ReviewedInputs,
		starting: loaded, storage: i.implementation.storage,
		candidateSHA256: candidateChecksum, manifestSHA256: manifestChecksum,
		preparedState: preparedState, preparedSHA256: hex.EncodeToString(preparedDigest[:]),
		migration: loaded.migration, deferred: deferred,
	}, nil
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
	if loaded.status == NotInstalled {
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
		xray.VLESSXHTTP = &XrayXHTTPMaterial{UUID: profile.UUID, OriginAddress: profile.OriginAddress, OriginPort: profile.OriginPort, Mode: profile.Mode}
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
	if xray != (XrayServiceMaterial{}) {
		materials.Xray = &xray
	}
	if singBox != (SingBoxServiceMaterial{}) {
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
	digest := sha256.Sum256(data)
	return PreparedServiceCopy{manifest: ServiceManifest{
		Service: service, OwningModule: module, CandidateRevision: revision, ChangeSet: changeSet,
		Owner: "root", Group: group, DirectoryMode: 0o750, FileMode: 0o640, SHA256: hex.EncodeToString(digest[:]),
	}, bytes: data}, nil
}
