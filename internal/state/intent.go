package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ClientAccessValue is a credential-bearing value used by an outside client.
// Its default text representation is always redacted.
type ClientAccessValue struct{ secretValue }

// InfrastructureSecret is root-only authority used to administer
// infrastructure or prove server identity. Its default text representation is
// always redacted.
type InfrastructureSecret struct{ secretValue }

type secretValue struct{ value string }

// NewClientAccessValue wraps a client credential without interpreting it.
func NewClientAccessValue(value string) ClientAccessValue {
	return ClientAccessValue{secretValue{value: value}}
}

// NewInfrastructureSecret wraps infrastructure authority without testing it.
func NewInfrastructureSecret(value string) InfrastructureSecret {
	return InfrastructureSecret{secretValue{value: value}}
}

type VerifiedInfrastructureSecret interface {
	ConsumeInfrastructureSecret() (string, bool)
}

// NewInfrastructureSecretFrom consumes one verified owning-Module handoff.
func NewInfrastructureSecretFrom(source VerifiedInfrastructureSecret) (InfrastructureSecret, bool) {
	if source == nil {
		return InfrastructureSecret{}, false
	}
	value, ok := source.ConsumeInfrastructureSecret()
	if !ok || value == "" {
		return InfrastructureSecret{}, false
	}
	return NewInfrastructureSecret(value), true
}

func (ClientAccessValue) MarshalJSON() ([]byte, error) {
	return nil, errProtectedValueRendering
}

func (InfrastructureSecret) MarshalJSON() ([]byte, error) {
	return nil, errProtectedValueRendering
}

func (v *ClientAccessValue) UnmarshalJSON(data []byte) error {
	return unmarshalSecret(data, &v.value)
}

func (v *InfrastructureSecret) UnmarshalJSON(data []byte) error {
	return unmarshalSecret(data, &v.value)
}

func unmarshalSecret(data []byte, destination *string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return nil
}

func (ClientAccessValue) String() string      { return "[redacted Client Access Value]" }
func (ClientAccessValue) GoString() string    { return "[redacted Client Access Value]" }
func (InfrastructureSecret) String() string   { return "[redacted Infrastructure Secret]" }
func (InfrastructureSecret) GoString() string { return "[redacted Infrastructure Secret]" }

func (v ClientAccessValue) isSet() bool    { return v.value != "" }
func (v InfrastructureSecret) isSet() bool { return v.value != "" }

// DesiredState contains only approved persistent installation intent. Observed
// State, Health Results, operations, recovery material, runtime copies, raw
// external output, extension maps, and acceptance evidence have no field here.
type DesiredState struct {
	Installation       InstallationIdentity `json:"installation"`
	ConnectionProfiles ConnectionProfiles   `json:"connection_profiles"`
	Subscription       SubscriptionSettings `json:"subscription"`
	Cloudflare         CloudflareSettings   `json:"cloudflare"`
	Certificates       CertificateSettings  `json:"certificates"`
	NetworkPolicy      NetworkPolicyInputs  `json:"network_policy"`
	Software           SoftwareSettings     `json:"software"`
}

// CandidateSHA256 returns the exact protected serialization checksum State
// will bind to a complete candidate. It never returns or renders the bytes.
func CandidateSHA256(candidate DesiredState) (string, error) {
	if finding := validateDesiredState(candidate); finding != nil {
		staged, ok := stageDeferredCloudflare(candidate)
		if !ok {
			return "", finding
		}
		if stagedFinding := validateDesiredState(staged); stagedFinding != nil {
			return "", stagedFinding
		}
	}
	document, err := marshalProtectedJSON(candidate)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(document)
	return hex.EncodeToString(digest[:]), nil
}

// ManagementTokenTemplateSHA256 binds the deliberately empty token slot used
// only by Cloudflare Tunnel's reviewed replacement or removal Plan.
func ManagementTokenTemplateSHA256(candidate DesiredState) (string, error) {
	if candidate.Cloudflare.ManagementToken.isSet() || candidate.Cloudflare.ManagementTokenRemoved && candidate.Cloudflare.ManagementTokenState != CloudflareManagementUnmanaged || !candidate.Cloudflare.ManagementTokenRemoved && candidate.Cloudflare.ManagementTokenState != "" {
		return "", errProtectedValueRendering
	}
	document, err := marshalProtectedJSON(candidate)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(document)
	return hex.EncodeToString(digest[:]), nil
}

// InstallationIdentity distinguishes this one managed SBXR installation.
type InstallationIdentity struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
}

// ConnectionProfiles contains the fixed six approved Connection Profiles.
type ConnectionProfiles struct {
	VLESSRealityVision VLESSRealityVision `json:"vless_reality_vision"`
	VLESSXHTTP         VLESSXHTTP         `json:"vless_xhttp"`
	VLESSWebSocket     VLESSWebSocket     `json:"vless_websocket"`
	Hysteria2          Hysteria2          `json:"hysteria2"`
	TUIC               TUIC               `json:"tuic"`
	AnyTLS             AnyTLS             `json:"anytls"`
}

// VLESSRealityVision is the direct Xray TCP Connection Profile.
type VLESSRealityVision struct {
	Enabled     bool                 `json:"enabled"`
	Port        uint16               `json:"port"`
	UUID        ClientAccessValue    `json:"uuid"`
	PrivateKey  InfrastructureSecret `json:"private_key"`
	PublicKey   string               `json:"public_key"`
	ShortID     ClientAccessValue    `json:"short_id"`
	Target      string               `json:"target"`
	ServerName  string               `json:"server_name"`
	Fingerprint string               `json:"fingerprint"`
}

// XHTTPMode is the fixed Xray XHTTP transport mode.
type XHTTPMode string

const XHTTPPacketUp XHTTPMode = "packet-up"

// VLESSXHTTP is the Xray Connection Profile behind Cloudflare Tunnel.
type VLESSXHTTP struct {
	Enabled       bool              `json:"enabled"`
	UUID          ClientAccessValue `json:"uuid"`
	Path          ClientAccessValue `json:"path"`
	Hostname      string            `json:"hostname"`
	OriginAddress string            `json:"origin_address"`
	OriginPort    uint16            `json:"origin_port"`
	Mode          XHTTPMode         `json:"mode"`
}

// VLESSWebSocket is the compatibility Xray profile behind Cloudflare Tunnel.
type VLESSWebSocket struct {
	Enabled       bool              `json:"enabled"`
	UUID          ClientAccessValue `json:"uuid"`
	Hostname      string            `json:"hostname"`
	OriginAddress string            `json:"origin_address"`
	OriginPort    uint16            `json:"origin_port"`
	Path          ClientAccessValue `json:"path"`
}

// Hysteria2 is the primary sing-box UDP Connection Profile.
type Hysteria2 struct {
	Enabled           bool              `json:"enabled"`
	Port              uint16            `json:"port"`
	Password          ClientAccessValue `json:"password"`
	ServerName        string            `json:"server_name"`
	CertificateID     string            `json:"certificate_id"`
	MasqueradeURL     string            `json:"masquerade_url"`
	Obfuscation       bool              `json:"obfuscation"`
	ObfuscationSecret ClientAccessValue `json:"obfuscation_secret"`
}

// CongestionControl is an approved TUIC congestion controller.
type CongestionControl string

const (
	CongestionBBR   CongestionControl = "bbr"
	CongestionCubic CongestionControl = "cubic"
)

// TUIC is the secondary sing-box UDP Connection Profile.
type TUIC struct {
	Enabled           bool              `json:"enabled"`
	Port              uint16            `json:"port"`
	UUID              ClientAccessValue `json:"uuid"`
	Password          ClientAccessValue `json:"password"`
	ServerName        string            `json:"server_name"`
	CertificateID     string            `json:"certificate_id"`
	CongestionControl CongestionControl `json:"congestion_control"`
	ZeroRTT           bool              `json:"zero_rtt"`
}

// AnyTLS is the direct sing-box TCP Connection Profile.
type AnyTLS struct {
	Enabled       bool              `json:"enabled"`
	Port          uint16            `json:"port"`
	Password      ClientAccessValue `json:"password"`
	ServerName    string            `json:"server_name"`
	CertificateID string            `json:"certificate_id"`
	PaddingScheme string            `json:"padding_scheme"`
}

// SubscriptionSettings owns the public subscription credential and listener.
type SubscriptionSettings struct {
	Token         ClientAccessValue `json:"token"`
	ListenPort    uint16            `json:"listen_port"`
	CertificateID string            `json:"certificate_id"`
}

// CloudflareSettings contains only the scoped account, immutable resource
// bindings, hostnames, and two Cloudflare Infrastructure Secrets.
type CloudflareManagementState string

const CloudflareManagementUnmanaged CloudflareManagementState = "Unmanaged"

type CloudflareSettings struct {
	AccountID              string                    `json:"account_id"`
	ZoneID                 string                    `json:"zone_id"`
	ZoneName               string                    `json:"zone_name"`
	TunnelID               string                    `json:"tunnel_id"`
	TunnelName             string                    `json:"tunnel_name"`
	ManagementToken        InfrastructureSecret      `json:"management_token"`
	ManagementTokenRemoved bool                      `json:"management_token_removed,omitempty"`
	ManagementTokenState   CloudflareManagementState `json:"management_token_state,omitempty"`
	TunnelRunToken         InfrastructureSecret      `json:"tunnel_run_token"`
	XHTTPHostname          string                    `json:"xhttp_hostname"`
	WebSocketHostname      string                    `json:"websocket_hostname"`
	DirectHostname         string                    `json:"direct_hostname"`
	XHTTPDNSRecordID       string                    `json:"xhttp_dns_record_id"`
	WebSocketDNSRecordID   string                    `json:"websocket_dns_record_id"`
	DirectIPv4RecordID     string                    `json:"direct_ipv4_record_id"`
	DirectIPv6RecordID     string                    `json:"direct_ipv6_record_id"`
}

// CertificateSettings identifies the two active certificate lineages and the
// standing renewal policy without storing certificate private keys here.
type CertificateSettings struct {
	RenewalPolicy        bool   `json:"renewal_policy"`
	OwnerEmail           string `json:"owner_email,omitempty"`
	ACMEAccountID        string `json:"acme_account_id"`
	IPCertificateID      string `json:"ip_certificate_id"`
	IPServingPointer     string `json:"ip_serving_pointer"`
	DomainCertificateID  string `json:"domain_certificate_id"`
	DomainServingPointer string `json:"domain_serving_pointer"`
	DomainHostname       string `json:"domain_hostname"`
}

// NetworkPolicyInputs are the persistent Owner-approved address and SSH facts.
type NetworkPolicyInputs struct {
	SSHPort                    uint16 `json:"ssh_port"`
	PublicIPv4                 string `json:"public_ipv4"`
	PublicIPv6                 string `json:"public_ipv6"`
	PrimarySubscriptionAddress string `json:"primary_subscription_address"`
}

// SoftwareSettings records the pinned managed component choices and update
// discovery preference. Applying an update remains review-only.
type SoftwareSettings struct {
	XrayVersion              string `json:"xray_version"`
	SingBoxVersion           string `json:"sing_box_version"`
	CloudflaredVersion       string `json:"cloudflared_version"`
	CertbotVersion           string `json:"certbot_version"`
	AutomaticUpdateDiscovery bool   `json:"automatic_update_discovery"`
}

func validateDesiredState(desired DesiredState) *Finding {
	profiles := desired.ConnectionProfiles
	if desired.Installation.ID == "" || desired.Installation.Domain == "" {
		return intentFinding("STATE-INTENT-INCOMPLETE", "installation identity", "a required identity value is absent", "one installation ID and domain", "the installation cannot be identified", "complete the installation identity and review again")
	}
	if !profiles.VLESSRealityVision.UUID.isSet() || !profiles.VLESSRealityVision.PrivateKey.isSet() || !profiles.VLESSRealityVision.ShortID.isSet() || profiles.VLESSRealityVision.Port == 0 || profiles.VLESSRealityVision.PublicKey == "" || profiles.VLESSRealityVision.Target == "" || profiles.VLESSRealityVision.ServerName == "" || profiles.VLESSRealityVision.Fingerprint == "" {
		return intentFinding("STATE-INTENT-INCOMPLETE", "VLESS REALITY Vision", "a required profile value is absent", "complete settings and independent credentials", "partial Connection Profiles cannot become Desired State", "complete the profile and review again")
	}
	if !profiles.VLESSXHTTP.UUID.isSet() || !profiles.VLESSXHTTP.Path.isSet() || profiles.VLESSXHTTP.Hostname == "" || profiles.VLESSXHTTP.OriginAddress == "" || profiles.VLESSXHTTP.OriginPort == 0 || profiles.VLESSXHTTP.Mode == "" {
		return intentFinding("STATE-INTENT-INCOMPLETE", "VLESS XHTTP", "a required profile value is absent", "complete settings and an independent credential", "partial Connection Profiles cannot become Desired State", "complete the profile and review again")
	}
	if !profiles.VLESSWebSocket.UUID.isSet() || !profiles.VLESSWebSocket.Path.isSet() || profiles.VLESSWebSocket.Hostname == "" || profiles.VLESSWebSocket.OriginAddress == "" || profiles.VLESSWebSocket.OriginPort == 0 {
		return intentFinding("STATE-INTENT-INCOMPLETE", "VLESS WebSocket", "a required profile value is absent", "complete settings and independent access values", "partial Connection Profiles cannot become Desired State", "complete the profile and review again")
	}
	if !profiles.Hysteria2.Password.isSet() || profiles.Hysteria2.Port == 0 || profiles.Hysteria2.ServerName == "" || profiles.Hysteria2.CertificateID == "" || profiles.Hysteria2.MasqueradeURL == "" {
		return intentFinding("STATE-INTENT-INCOMPLETE", "Hysteria2", "a required profile value is absent", "complete settings and an independent credential", "partial Connection Profiles cannot become Desired State", "complete the profile and review again")
	}
	if !profiles.TUIC.UUID.isSet() || !profiles.TUIC.Password.isSet() || profiles.TUIC.Port == 0 || profiles.TUIC.ServerName == "" || profiles.TUIC.CertificateID == "" || profiles.TUIC.CongestionControl == "" {
		return intentFinding("STATE-INTENT-INCOMPLETE", "TUIC", "a required profile value is absent", "complete settings and independent credentials", "partial Connection Profiles cannot become Desired State", "complete the profile and review again")
	}
	if !profiles.AnyTLS.Password.isSet() || profiles.AnyTLS.Port == 0 || profiles.AnyTLS.ServerName == "" || profiles.AnyTLS.CertificateID == "" || profiles.AnyTLS.PaddingScheme == "" {
		return intentFinding("STATE-INTENT-INCOMPLETE", "AnyTLS", "a required profile value is absent", "complete settings and an independent credential", "partial Connection Profiles cannot become Desired State", "complete the profile and review again")
	}
	if !desired.Subscription.Token.isSet() || desired.Subscription.ListenPort == 0 || desired.Subscription.CertificateID == "" {
		return intentFinding("STATE-INTENT-INCOMPLETE", "subscription", "a required subscription value is absent", "one token, listener, and certificate binding", "partial subscription intent cannot be served safely", "complete the subscription settings and review again")
	}
	cloudflare := desired.Cloudflare
	managementTokenValid := !cloudflare.ManagementTokenRemoved && cloudflare.ManagementToken.isSet() && cloudflare.ManagementTokenState == "" || cloudflare.ManagementTokenRemoved && !cloudflare.ManagementToken.isSet() && cloudflare.ManagementTokenState == CloudflareManagementUnmanaged
	if empty(cloudflare.AccountID, cloudflare.ZoneID, cloudflare.ZoneName, cloudflare.TunnelID, cloudflare.TunnelName, cloudflare.XHTTPHostname, cloudflare.WebSocketHostname, cloudflare.DirectHostname, cloudflare.XHTTPDNSRecordID, cloudflare.WebSocketDNSRecordID) || !managementTokenValid || !cloudflare.TunnelRunToken.isSet() {
		return intentFinding("STATE-INTENT-INCOMPLETE", "Cloudflare authority", "a required authority or immutable binding is absent", "scoped authority and every owned resource identity", "Cloudflare ownership cannot be proven", "complete the Cloudflare bindings and review again")
	}
	certificates := desired.Certificates
	if empty(certificates.ACMEAccountID, certificates.IPCertificateID, certificates.IPServingPointer, certificates.DomainCertificateID, certificates.DomainServingPointer, certificates.DomainHostname) {
		return intentFinding("STATE-INTENT-INCOMPLETE", "certificate settings", "a required certificate identity is absent", "both lineages and serving pointers", "active certificate material cannot be identified", "complete the certificate settings and review again")
	}
	network := desired.NetworkPolicy
	if network.SSHPort == 0 || network.PrimarySubscriptionAddress == "" || network.PublicIPv4 == "" && network.PublicIPv6 == "" {
		return intentFinding("STATE-INTENT-INCOMPLETE", "Network Policy inputs", "a required address or SSH value is absent", "SSH and at least one qualified public address", "network exposure cannot be evaluated completely", "complete Network Policy inputs and review again")
	}
	software := desired.Software
	if empty(software.XrayVersion, software.SingBoxVersion, software.CloudflaredVersion, software.CertbotVersion) {
		return intentFinding("STATE-INTENT-INCOMPLETE", "software settings", "a managed component version is absent", "one pinned version for every managed component", "the intended installation is incomplete", "complete the software settings and review again")
	}

	if cloudflare.ZoneName != desired.Installation.Domain || profiles.VLESSXHTTP.Hostname != cloudflare.XHTTPHostname || profiles.VLESSWebSocket.Hostname != cloudflare.WebSocketHostname {
		return crossSectionIntent("Cloudflare hostname bindings", "Connection Profiles and immutable Cloudflare bindings disagree")
	}
	if profiles.VLESSXHTTP.UUID.value == profiles.VLESSWebSocket.UUID.value || profiles.VLESSXHTTP.Path.value == profiles.VLESSWebSocket.Path.value || profiles.VLESSXHTTP.Hostname == profiles.VLESSWebSocket.Hostname {
		return crossSectionIntent("Cloudflare Connection Profile independence", "XHTTP and WebSocket share a credential or hostname")
	}
	if profiles.Hysteria2.ServerName != cloudflare.DirectHostname || profiles.TUIC.ServerName != cloudflare.DirectHostname || profiles.AnyTLS.ServerName != cloudflare.DirectHostname || certificates.DomainHostname != cloudflare.DirectHostname {
		return crossSectionIntent("direct TLS hostname", "profiles, certificate, and Cloudflare bindings disagree")
	}
	if profiles.Hysteria2.CertificateID != certificates.DomainCertificateID || profiles.TUIC.CertificateID != certificates.DomainCertificateID || profiles.AnyTLS.CertificateID != certificates.DomainCertificateID || desired.Subscription.CertificateID != certificates.IPCertificateID {
		return crossSectionIntent("certificate bindings", "a service refers to a different certificate identity")
	}
	if !validNetworkBindings(network, cloudflare) {
		return crossSectionIntent("Network Policy address bindings", "qualified addresses, primary address, and DNS identities disagree")
	}
	if portConflict(desired) {
		return crossSectionIntent("listener ports", "two TCP or UDP listeners conflict")
	}
	return nil
}

func empty(values ...string) bool {
	for _, value := range values {
		if value == "" {
			return true
		}
	}
	return false
}

func validNetworkBindings(network NetworkPolicyInputs, cloudflare CloudflareSettings) bool {
	if network.PrimarySubscriptionAddress != network.PublicIPv4 && network.PrimarySubscriptionAddress != network.PublicIPv6 {
		return false
	}
	return (network.PublicIPv4 == "") == (cloudflare.DirectIPv4RecordID == "") && (network.PublicIPv6 == "") == (cloudflare.DirectIPv6RecordID == "")
}

func portConflict(desired DesiredState) bool {
	p := desired.ConnectionProfiles
	tcp := []uint16{desired.NetworkPolicy.SSHPort, desired.Subscription.ListenPort}
	udp := []uint16{}
	if p.VLESSRealityVision.Enabled {
		tcp = append(tcp, p.VLESSRealityVision.Port)
	}
	if p.VLESSXHTTP.Enabled {
		tcp = append(tcp, p.VLESSXHTTP.OriginPort)
	}
	if p.VLESSWebSocket.Enabled {
		tcp = append(tcp, p.VLESSWebSocket.OriginPort)
	}
	if p.AnyTLS.Enabled {
		tcp = append(tcp, p.AnyTLS.Port)
	}
	if p.Hysteria2.Enabled {
		udp = append(udp, p.Hysteria2.Port)
	}
	if p.TUIC.Enabled {
		udp = append(udp, p.TUIC.Port)
	}
	return duplicatePort(tcp) || duplicatePort(udp)
}

func duplicatePort(ports []uint16) bool {
	seen := map[uint16]bool{}
	for _, port := range ports {
		if seen[port] {
			return true
		}
		seen[port] = true
	}
	return false
}

func intentFinding(code, concept, found, required, why, next string) *Finding {
	return finding(code, concept, found, required, why, next)
}

func crossSectionIntent(concept, found string) *Finding {
	return intentFinding("STATE-INTENT-CROSS-SECTION", concept, found, "one internally consistent complete candidate", "contradictory intent cannot be applied safely", "correct the conflicting sections and review again")
}
