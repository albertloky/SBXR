package state

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
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

// PrepareRequest is the candidate-validation portion of PrepareCommit. Issue
// #65 adds loaded-lineage, Plan, checksum, and one-use authority binding.
type PrepareRequest struct {
	CandidateRevision        uint64
	CandidateReleaseIdentity ReleaseIdentity
	ChangeSet                ChangeSetIdentity
	Candidate                DesiredState
	SemanticValidators       SemanticValidators
	ServiceMaterials         ServiceMaterials
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
// Issue #65 introduces the one-use handoff that can consume its private bytes.
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

// Preparation is a validated candidate and its byte-stable service material.
// It is not yet the one-use opaque prepared commit introduced by issue #65.
type Preparation struct {
	ReleaseIdentity ReleaseIdentity
	Candidate       DesiredState
	ServiceCopies   PreparedServiceCopies
}

// PrepareCommit validates one complete candidate and typed owning-Module
// outputs without reading or mutating the storage Adapter.
func (i Interface) PrepareCommit(request PrepareRequest) (Preparation, error) {
	if i.implementation == nil || i.implementation.storage == nil {
		return Preparation{}, finding("STATE-STORAGE-UNAVAILABLE", "Desired State storage", "no storage Adapter", "the production State storage Adapter", "State cannot prepare trusted transaction material", "restore the State Adapter and review again")
	}
	if problem := validateDesiredState(request.Candidate); problem != nil {
		return Preparation{}, problem
	}
	if request.CandidateRevision == 0 || !validReleaseIdentity(request.CandidateReleaseIdentity) || !validChangeSetIdentity(request.ChangeSet) {
		return Preparation{}, finding("STATE-SERVICE-MANIFEST", "prepared service manifest", "the candidate revision, Release Identity, or Change Set identity is invalid", "one positive candidate revision, exact Release Identity, and valid later Change Set", "prepared bytes must be bound before mutation", "correct the manifest inputs and review again")
	}
	if !validateSemantics(request.Candidate, request.SemanticValidators) {
		return Preparation{}, finding("STATE-CANDIDATE-SEMANTIC", "Module-owned semantic validation", "an owning validator is missing or refused its typed section", "successful validation by every owning Module", "State cannot replace operational ownership or accept caller-made validation claims", "correct the candidate through the owning Module and review again")
	}
	if !reflect.DeepEqual(request.ServiceMaterials, expectedServiceMaterials(request.Candidate)) {
		return Preparation{}, finding("STATE-SERVICE-MATERIAL-UNRELATED", "prepared service material", "material is missing, stale, or contains an unrelated value", "only each service's exact required candidate values", "runtime services must not receive complete Desired State or unrelated secrets", "regenerate the owning Module material and review again")
	}

	materials := request.ServiceMaterials
	var copies PreparedServiceCopies
	if materials.Xray != nil {
		prepared, err := prepareServiceCopy("xray.service", "connectionprofiles", "xray", request.CandidateRevision, request.ChangeSet, materials.Xray)
		if err != nil {
			return Preparation{}, err
		}
		copies.Xray = &prepared
	}
	if materials.SingBox != nil {
		prepared, err := prepareServiceCopy("sing-box.service", "connectionprofiles", "sing-box", request.CandidateRevision, request.ChangeSet, materials.SingBox)
		if err != nil {
			return Preparation{}, err
		}
		copies.SingBox = &prepared
	}
	if materials.Cloudflared != nil {
		prepared, err := prepareServiceCopy("cloudflared.service", "cloudflaretunnel", "cloudflared", request.CandidateRevision, request.ChangeSet, materials.Cloudflared)
		if err != nil {
			return Preparation{}, err
		}
		copies.Cloudflared = &prepared
	}
	subscription, err := prepareServiceCopy("sbxr-subscription.service", "subscriptionserving", "sbxr-subscription", request.CandidateRevision, request.ChangeSet, materials.Subscription)
	if err != nil {
		return Preparation{}, err
	}
	copies.Subscription = &subscription
	return Preparation{ReleaseIdentity: request.CandidateReleaseIdentity, Candidate: request.Candidate, ServiceCopies: copies}, nil
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
