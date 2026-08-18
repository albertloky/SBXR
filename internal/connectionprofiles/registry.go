package connectionprofiles

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type ProfileID string

const (
	VLESSRealityVisionProfileID ProfileID = "vless-reality-vision"
	VLESSXHTTPProfileID         ProfileID = "vless-xhttp"
	VLESSWebSocketProfileID     ProfileID = "vless-websocket"
	Hysteria2ProfileID          ProfileID = "hysteria2"
	TUICProfileID               ProfileID = "tuic"
	AnyTLSProfileID             ProfileID = "anytls"
)

type registryDefinition struct {
	id   ProfileID
	name string
}

var registryDefinitions = [...]registryDefinition{
	{VLESSRealityVisionProfileID, "VLESS REALITY Vision"},
	{VLESSXHTTPProfileID, "VLESS XHTTP"},
	{VLESSWebSocketProfileID, "VLESS WebSocket"},
	{Hysteria2ProfileID, "Hysteria2"},
	{TUICProfileID, "TUIC"},
	{AnyTLSProfileID, "AnyTLS"},
}

type RegistryCredentials struct {
	Reality   RealityCredentials
	XHTTP     XHTTPCredentials
	WebSocket WebSocketCredentials
	Hysteria2 Hysteria2Credentials
	TUIC      TUICCredentials
	AnyTLS    AnyTLSCredentials
}

type DeferredRegistryCredentials struct {
	XHTTP     XHTTPCredentials
	WebSocket WebSocketCredentials
	Hysteria2 Hysteria2Credentials
	TUIC      TUICCredentials
	AnyTLS    AnyTLSCredentials
}

func (RegistryCredentials) String() string {
	return "six independent Connection Profile credentials: ready"
}
func (RegistryCredentials) GoString() string {
	return "six independent Connection Profile credentials: ready"
}

func GenerateRegistryCredentials() (RegistryCredentials, error) {
	return GenerateRegistryCredentialsFrom(rand.Reader)
}

func GenerateRegistryCredentialsFrom(random io.Reader) (RegistryCredentials, error) {
	if random == nil {
		return RegistryCredentials{}, errors.New("credential entropy unavailable")
	}
	reality, realityErr := generateRealityCredentials(random)
	xhttp, xhttpErr := generateXHTTPCredentials(random)
	websocket, websocketErr := generateWebSocketCredentials(random)
	hysteria2, hysteria2Err := generateHysteria2Credentials(random)
	tuic, tuicErr := generateTUICCredentials(random)
	anyTLS, anyTLSErr := generateAnyTLSCredentials(random)
	credentials := RegistryCredentials{reality, xhttp, websocket, hysteria2, tuic, anyTLS}
	if errors.Join(realityErr, xhttpErr, websocketErr, hysteria2Err, tuicErr, anyTLSErr) != nil || !credentials.Independent() {
		return RegistryCredentials{}, errors.New("six independent Connection Profile credentials could not be generated")
	}
	return credentials, nil
}

func GenerateDeferredRegistryCredentials() (DeferredRegistryCredentials, error) {
	return GenerateDeferredRegistryCredentialsFrom(rand.Reader)
}

func GenerateDeferredRegistryCredentialsFrom(random io.Reader) (DeferredRegistryCredentials, error) {
	if random == nil {
		return DeferredRegistryCredentials{}, errors.New("credential entropy unavailable")
	}
	xhttp, xhttpErr := generateXHTTPCredentials(random)
	websocket, websocketErr := generateWebSocketCredentials(random)
	hysteria2, hysteria2Err := generateHysteria2Credentials(random)
	tuic, tuicErr := generateTUICCredentials(random)
	anyTLS, anyTLSErr := generateAnyTLSCredentials(random)
	credentials := DeferredRegistryCredentials{xhttp, websocket, hysteria2, tuic, anyTLS}
	if errors.Join(xhttpErr, websocketErr, hysteria2Err, tuicErr, anyTLSErr) != nil || !credentials.ready() {
		return DeferredRegistryCredentials{}, errors.New("five deferred Connection Profile credentials could not be generated")
	}
	return credentials, nil
}

func (credentials DeferredRegistryCredentials) ready() bool {
	return credentials.XHTTP.valid() && credentials.WebSocket.valid() && credentials.Hysteria2.valid() && credentials.TUIC.valid() && credentials.AnyTLS.valid()
}

func (credentials DeferredRegistryCredentials) independent(reality RealityCredentials) bool {
	if !credentials.ready() || !reality.valid() {
		return false
	}
	values := []string{reality.uuid.value, credentials.XHTTP.uuid.value, credentials.WebSocket.uuid.value, credentials.Hysteria2.password.value, credentials.TUIC.uuid.value, credentials.TUIC.password.value, credentials.AnyTLS.password.value, credentials.XHTTP.path.value, credentials.WebSocket.path.value}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

// RegistryRotation is a one-use, redacted handoff containing candidate
// Connection Profiles, their publication source, and leased render access.
type RegistryRotation struct {
	profiles state.ConnectionProfiles
	source   PublicationSource
	secrets  registryCredentialReader
	used     *atomic.Bool
}

type RegistryMutationAction string

const (
	EnableProfile                RegistryMutationAction = "Enable profile"
	DisableProfile               RegistryMutationAction = "Disable profile"
	RotateProfileCredential      RegistryMutationAction = "Rotate profile credential"
	RotateEveryProfileCredential RegistryMutationAction = "Rotate every profile credential"
)

type FreshRegistryInputs struct {
	profiles state.ConnectionProfiles
	source   PublicationSource
	secrets  registryCredentialReader
	used     *atomic.Bool
}

func (FreshRegistryInputs) String() string   { return "Fresh registry inputs: redacted" }
func (FreshRegistryInputs) GoString() string { return "Fresh registry inputs: redacted" }
func (FreshRegistryInputs) MarshalJSON() ([]byte, error) {
	return []byte(`"Fresh registry inputs: redacted"`), nil
}

func NewFreshRegistryInputs(request RegistryViewRequest) (*FreshRegistryInputs, error) {
	profiles, valid := DesiredProfiles(request)
	if !valid {
		return nil, errors.New("fresh registry inputs are invalid")
	}
	values := registryCredentialReader{
		profiles.VLESSRealityVision.UUID: request.Reality.Credentials.uuid.value, profiles.VLESSRealityVision.ShortID: request.Reality.Credentials.shortID.value,
		profiles.VLESSXHTTP.UUID: request.XHTTP.Credentials.uuid.value, profiles.VLESSXHTTP.Path: request.XHTTP.Credentials.path.value,
		profiles.VLESSWebSocket.UUID: request.WebSocket.Credentials.uuid.value, profiles.VLESSWebSocket.Path: request.WebSocket.Credentials.path.value,
		profiles.Hysteria2.Password: request.Hysteria2.Credentials.password.value,
		profiles.TUIC.UUID:          request.TUIC.Credentials.uuid.value, profiles.TUIC.Password: request.TUIC.Credentials.password.value,
		profiles.AnyTLS.Password: request.AnyTLS.Credentials.password.value,
	}
	if profiles.Hysteria2.Obfuscation {
		values[profiles.Hysteria2.ObfuscationSecret] = request.Hysteria2.Credentials.obfuscationSecret.value
	}
	return &FreshRegistryInputs{profiles: profiles, source: registryPublication(request), secrets: values, used: &atomic.Bool{}}, nil
}

func (inputs *FreshRegistryInputs) Profiles() state.ConnectionProfiles {
	if inputs == nil {
		return state.ConnectionProfiles{}
	}
	return inputs.profiles
}

func (inputs *FreshRegistryInputs) PublicationSource() PublicationSource {
	if inputs == nil {
		return PublicationSource{}
	}
	return inputs.source
}

func (inputs *FreshRegistryInputs) WithClientAccessReader(use func(state.ClientAccessReader) error) error {
	if inputs == nil || inputs.used == nil || use == nil || !inputs.used.CompareAndSwap(false, true) {
		return errors.New("fresh registry render authority unavailable")
	}
	lease := &registryCredentialLease{values: inputs.secrets}
	lease.active.Store(true)
	defer lease.active.Store(false)
	return use(lease)
}

func (RegistryRotation) String() string   { return "Connection Profile registry rotation: protected" }
func (RegistryRotation) GoString() string { return "Connection Profile registry rotation: protected" }
func (RegistryRotation) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Connection Profile registry rotation cannot be rendered")
}
func (rotation *RegistryRotation) ConnectionProfiles() state.ConnectionProfiles {
	if rotation == nil {
		return state.ConnectionProfiles{}
	}
	return rotation.profiles
}
func (rotation *RegistryRotation) PublicationSource() PublicationSource {
	if rotation == nil {
		return PublicationSource{}
	}
	return rotation.source
}

// WithClientAccessReader leases generated values only for one immediate owning-
// Module render. Retaining the reader after the callback yields no values.
func (rotation *RegistryRotation) WithClientAccessReader(use func(state.ClientAccessReader) error) error {
	if rotation == nil || rotation.used == nil || use == nil || !rotation.used.CompareAndSwap(false, true) {
		return errors.New("Connection Profile registry rotation render authority unavailable")
	}
	lease := &registryCredentialLease{values: rotation.secrets}
	lease.active.Store(true)
	defer lease.active.Store(false)
	return use(lease)
}

// RotateRegistryCredentials replaces every client credential while preserving
// Connection Profile settings, enablement, and non-credential publication facts.
func RotateRegistryCredentials(profiles state.ConnectionProfiles, source PublicationSource) (*RegistryRotation, error) {
	if !PublicationInputsMatch(source, profiles) {
		return nil, errors.New("Connection Profile publication source does not match current settings")
	}
	if hasNotSetUpProfile(profiles) {
		return nil, errors.New("Not set up profiles cannot rotate credentials")
	}
	credentials, err := GenerateRegistryCredentials()
	if err != nil {
		return nil, err
	}
	secrets := registryCredentialReader{}
	protect := func(value string) state.ClientAccessValue {
		protected := state.NewClientAccessValue(value)
		secrets[protected] = value
		return protected
	}
	profiles.VLESSRealityVision.UUID = protect(credentials.Reality.uuid.value)
	profiles.VLESSRealityVision.PrivateKey = state.NewInfrastructureSecret(credentials.Reality.privateKey.value)
	profiles.VLESSRealityVision.PublicKey = credentials.Reality.publicKey.value
	profiles.VLESSRealityVision.ShortID = protect(credentials.Reality.shortID.value)
	profiles.VLESSXHTTP.UUID = protect(credentials.XHTTP.uuid.value)
	profiles.VLESSXHTTP.Path = protect(credentials.XHTTP.path.value)
	profiles.VLESSWebSocket.UUID = protect(credentials.WebSocket.uuid.value)
	profiles.VLESSWebSocket.Path = protect(credentials.WebSocket.path.value)
	profiles.Hysteria2.Password = protect(credentials.Hysteria2.password.value)
	if profiles.Hysteria2.Obfuscation || profiles.Hysteria2.ObfuscationSecret != (state.ClientAccessValue{}) {
		obfuscationSecret, err := generateHexSecret()
		if err != nil {
			return nil, errors.New("Hysteria2 obfuscation secret generation failed")
		}
		profiles.Hysteria2.ObfuscationSecret = protect(obfuscationSecret)
	}
	profiles.TUIC.UUID = protect(credentials.TUIC.uuid.value)
	profiles.TUIC.Password = protect(credentials.TUIC.password.value)
	profiles.AnyTLS.Password = protect(credentials.AnyTLS.password.value)
	candidateSource, err := publicationSourceWithCandidateCredentials(source, profiles)
	if err != nil {
		return nil, err
	}
	return &RegistryRotation{profiles: profiles, source: candidateSource, secrets: secrets, used: &atomic.Bool{}}, nil
}

// PublicationSourceFor rebuilds the fixed publication handoff from one exact
// Desired State candidate without reading any protected value.
func PublicationSourceFor(address string, profiles state.ConnectionProfiles) (PublicationSource, error) {
	parsed, err := netip.ParseAddr(address)
	if err != nil || !parsed.IsGlobalUnicast() {
		return PublicationSource{}, errors.New("Connection Profile publication address is invalid")
	}
	all := []struct {
		enabled bool
		profile PublicationProfile
	}{
		{profiles.VLESSRealityVision.Enabled, PublicationProfile{ID: VLESSRealityVisionProfileID, Name: registryDefinitions[0].name, Address: address, Port: profiles.VLESSRealityVision.Port, ServerName: profiles.VLESSRealityVision.ServerName, Transport: "RAW", Security: "REALITY", UUID: profiles.VLESSRealityVision.UUID, ShortID: profiles.VLESSRealityVision.ShortID, PublicKey: profiles.VLESSRealityVision.PublicKey, Fingerprint: profiles.VLESSRealityVision.Fingerprint, Flow: "xtls-rprx-vision"}},
		{profiles.VLESSXHTTP.Enabled, PublicationProfile{ID: VLESSXHTTPProfileID, Name: registryDefinitions[1].name, Address: profiles.VLESSXHTTP.Hostname, Port: 443, Hostname: profiles.VLESSXHTTP.Hostname, Transport: "XHTTP", Security: "TLS", UUID: profiles.VLESSXHTTP.UUID, Path: profiles.VLESSXHTTP.Path, XHTTPServerMode: profiles.VLESSXHTTP.Mode}},
		{profiles.VLESSWebSocket.Enabled, PublicationProfile{ID: VLESSWebSocketProfileID, Name: registryDefinitions[2].name, Address: profiles.VLESSWebSocket.Hostname, Port: 443, Hostname: profiles.VLESSWebSocket.Hostname, Transport: "WebSocket", Security: "TLS", UUID: profiles.VLESSWebSocket.UUID, Path: profiles.VLESSWebSocket.Path, HTTPHost: profiles.VLESSWebSocket.Hostname, TLSName: profiles.VLESSWebSocket.Hostname}},
		{profiles.Hysteria2.Enabled, PublicationProfile{ID: Hysteria2ProfileID, Name: registryDefinitions[3].name, Address: address, Port: profiles.Hysteria2.Port, ServerName: profiles.Hysteria2.ServerName, Transport: "QUIC", Security: "TLS", Password: profiles.Hysteria2.Password, Obfuscation: profiles.Hysteria2.Obfuscation, ObfuscationSecret: profiles.Hysteria2.ObfuscationSecret}},
		{profiles.TUIC.Enabled, PublicationProfile{ID: TUICProfileID, Name: registryDefinitions[4].name, Address: address, Port: profiles.TUIC.Port, ServerName: profiles.TUIC.ServerName, Transport: "QUIC", Security: "TLS", UUID: profiles.TUIC.UUID, Password: profiles.TUIC.Password, CongestionControl: profiles.TUIC.CongestionControl}},
		{profiles.AnyTLS.Enabled, PublicationProfile{ID: AnyTLSProfileID, Name: registryDefinitions[5].name, Address: address, Port: profiles.AnyTLS.Port, ServerName: profiles.AnyTLS.ServerName, Transport: "TCP", Security: "TLS", Password: profiles.AnyTLS.Password}},
	}
	var source PublicationSource
	for _, item := range all {
		if item.enabled {
			source.profiles = append(source.profiles, item.profile)
		} else {
			source.omissions = append(source.omissions, publicationOmission(item.profile.ID, publicationLifecycle(profiles, item.profile.ID)))
		}
	}
	if !PublicationInputsMatch(source, profiles) {
		return PublicationSource{}, errors.New("Connection Profile publication source does not match Desired State")
	}
	return source, nil
}

// PrepareRegistryMutation admits exactly one reviewed profile lifecycle action
// and returns one redacted, one-use render authority for generated credentials.
func PrepareRegistryMutation(action RegistryMutationAction, profile ProfileID, address string, profiles state.ConnectionProfiles, source PublicationSource) (*RegistryRotation, error) {
	if !PublicationInputsMatch(source, profiles) {
		return nil, errors.New("Connection Profile publication source does not match current settings")
	}
	if action == RotateEveryProfileCredential {
		if profile != "" {
			return nil, errors.New("all-profile rotation cannot select one profile")
		}
		return RotateRegistryCredentials(profiles, source)
	}
	if !knownProfile(profile) {
		return nil, errors.New("Connection Profile selection is invalid")
	}
	if profileLifecycle(profiles, profile) == state.ProfileNotSetUp {
		return nil, errors.New("Not set up profiles do not have individual actions")
	}
	secrets := registryCredentialReader{}
	protect := func(value string) state.ClientAccessValue {
		protected := state.NewClientAccessValue(value)
		secrets[protected] = value
		return protected
	}
	switch action {
	case EnableProfile, DisableProfile:
		enabled := profileEnabled(profiles, profile)
		if enabled != (action == DisableProfile) {
			return nil, errors.New("Connection Profile enablement is unchanged")
		}
		setProfileEnabled(&profiles, profile, action == EnableProfile)
	case RotateProfileCredential:
		if err := rotateOneProfile(&profiles, profile, protect); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("Connection Profile mutation is invalid")
	}
	candidateSource, err := PublicationSourceFor(address, profiles)
	if err != nil {
		return nil, err
	}
	return &RegistryRotation{profiles: profiles, source: candidateSource, secrets: secrets, used: &atomic.Bool{}}, nil
}

func knownProfile(profile ProfileID) bool {
	for _, definition := range registryDefinitions {
		if definition.id == profile {
			return true
		}
	}
	return false
}

func profileLifecycle(profiles state.ConnectionProfiles, profile ProfileID) state.ProfileLifecycle {
	switch profile {
	case VLESSRealityVisionProfileID:
		return profiles.VLESSRealityVision.Lifecycle
	case VLESSXHTTPProfileID:
		return profiles.VLESSXHTTP.Lifecycle
	case VLESSWebSocketProfileID:
		return profiles.VLESSWebSocket.Lifecycle
	case Hysteria2ProfileID:
		return profiles.Hysteria2.Lifecycle
	case TUICProfileID:
		return profiles.TUIC.Lifecycle
	case AnyTLSProfileID:
		return profiles.AnyTLS.Lifecycle
	default:
		return ""
	}
}

func hasNotSetUpProfile(profiles state.ConnectionProfiles) bool {
	for _, profile := range registryDefinitions {
		if profileLifecycle(profiles, profile.id) == state.ProfileNotSetUp {
			return true
		}
	}
	return false
}

func profileEnabled(profiles state.ConnectionProfiles, profile ProfileID) bool {
	switch profile {
	case VLESSRealityVisionProfileID:
		return profiles.VLESSRealityVision.Enabled
	case VLESSXHTTPProfileID:
		return profiles.VLESSXHTTP.Enabled
	case VLESSWebSocketProfileID:
		return profiles.VLESSWebSocket.Enabled
	case Hysteria2ProfileID:
		return profiles.Hysteria2.Enabled
	case TUICProfileID:
		return profiles.TUIC.Enabled
	case AnyTLSProfileID:
		return profiles.AnyTLS.Enabled
	default:
		return false
	}
}

func setProfileEnabled(profiles *state.ConnectionProfiles, profile ProfileID, enabled bool) {
	lifecycle := state.ProfileDisabled
	if enabled {
		lifecycle = state.ProfileEnabled
	}
	switch profile {
	case VLESSRealityVisionProfileID:
		profiles.VLESSRealityVision.Enabled = enabled
		profiles.VLESSRealityVision.Lifecycle = lifecycle
	case VLESSXHTTPProfileID:
		profiles.VLESSXHTTP.Enabled = enabled
		profiles.VLESSXHTTP.Lifecycle = lifecycle
	case VLESSWebSocketProfileID:
		profiles.VLESSWebSocket.Enabled = enabled
		profiles.VLESSWebSocket.Lifecycle = lifecycle
	case Hysteria2ProfileID:
		profiles.Hysteria2.Enabled = enabled
		profiles.Hysteria2.Lifecycle = lifecycle
	case TUICProfileID:
		profiles.TUIC.Enabled = enabled
		profiles.TUIC.Lifecycle = lifecycle
	case AnyTLSProfileID:
		profiles.AnyTLS.Enabled = enabled
		profiles.AnyTLS.Lifecycle = lifecycle
	}
}

func rotateOneProfile(profiles *state.ConnectionProfiles, profile ProfileID, protect func(string) state.ClientAccessValue) error {
	switch profile {
	case VLESSRealityVisionProfileID:
		credentials, err := GenerateRealityCredentials()
		if err != nil {
			return err
		}
		profiles.VLESSRealityVision.UUID = protect(credentials.uuid.value)
		profiles.VLESSRealityVision.PrivateKey = state.NewInfrastructureSecret(credentials.privateKey.value)
		profiles.VLESSRealityVision.PublicKey = credentials.publicKey.value
		profiles.VLESSRealityVision.ShortID = protect(credentials.shortID.value)
	case VLESSXHTTPProfileID:
		credentials, err := GenerateXHTTPCredentials()
		if err != nil {
			return err
		}
		profiles.VLESSXHTTP.UUID, profiles.VLESSXHTTP.Path = protect(credentials.uuid.value), protect(credentials.path.value)
	case VLESSWebSocketProfileID:
		credentials, err := GenerateWebSocketCredentials()
		if err != nil {
			return err
		}
		profiles.VLESSWebSocket.UUID, profiles.VLESSWebSocket.Path = protect(credentials.uuid.value), protect(credentials.path.value)
	case Hysteria2ProfileID:
		credentials, err := GenerateHysteria2Credentials()
		if err != nil {
			return err
		}
		profiles.Hysteria2.Password = protect(credentials.password.value)
		if profiles.Hysteria2.Obfuscation {
			secret, err := generateHexSecret()
			if err != nil {
				return err
			}
			profiles.Hysteria2.ObfuscationSecret = protect(secret)
		}
	case TUICProfileID:
		credentials, err := GenerateTUICCredentials()
		if err != nil {
			return err
		}
		profiles.TUIC.UUID, profiles.TUIC.Password = protect(credentials.uuid.value), protect(credentials.password.value)
	case AnyTLSProfileID:
		credentials, err := GenerateAnyTLSCredentials()
		if err != nil {
			return err
		}
		profiles.AnyTLS.Password = protect(credentials.password.value)
	default:
		return errors.New("Connection Profile selection is invalid")
	}
	return nil
}

type registryCredentialReader map[state.ClientAccessValue]string

type registryCredentialLease struct {
	values registryCredentialReader
	active atomic.Bool
}

func (reader *registryCredentialLease) ReadClientAccessValue(value state.ClientAccessValue) string {
	if reader == nil || !reader.active.Load() {
		return ""
	}
	return reader.values[value]
}

func (credentials RegistryCredentials) Ready() bool {
	return credentials.Reality.valid() && credentials.XHTTP.valid() && credentials.WebSocket.valid() && credentials.Hysteria2.valid() && credentials.TUIC.valid() && credentials.AnyTLS.valid()
}

func (credentials RegistryCredentials) Independent() bool {
	if !credentials.Ready() {
		return false
	}
	values := []string{credentials.Reality.uuid.value, credentials.XHTTP.uuid.value, credentials.WebSocket.uuid.value, credentials.Hysteria2.password.value, credentials.TUIC.uuid.value, credentials.TUIC.password.value, credentials.AnyTLS.password.value, credentials.XHTTP.path.value, credentials.WebSocket.path.value}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func NewFreshRegistry(request RegistryViewRequest, credentials RegistryCredentials) (RegistryViewRequest, error) {
	if !credentials.Independent() {
		return RegistryViewRequest{}, errors.New("fresh registry credentials are not independent")
	}
	request.Reality.Credentials, request.XHTTP.Credentials, request.WebSocket.Credentials = credentials.Reality, credentials.XHTTP, credentials.WebSocket
	request.Hysteria2.Credentials, request.TUIC.Credentials, request.AnyTLS.Credentials = credentials.Hysteria2, credentials.TUIC, credentials.AnyTLS
	request.Reality.Enabled, request.XHTTP.Enabled, request.WebSocket.Enabled = true, true, true
	request.Hysteria2.Enabled, request.TUIC.Enabled, request.AnyTLS.Enabled = true, true, true
	request.Lifecycles = enabledRegistryLifecycles()
	return request, nil
}

// NewRevisionOneRegistry prepares the only supported first-Installation
// registry: VLESS REALITY Vision Enabled and every Cloudflare profile absent.
func NewRevisionOneRegistry(request RegistryViewRequest, credentials RealityCredentials) (RegistryViewRequest, error) {
	if !credentials.valid() || request.Reality.Revision == 0 {
		return RegistryViewRequest{}, errors.New("revision 1 registry inputs are invalid")
	}
	revision := request.Reality.Revision
	request.Reality.Credentials, request.Reality.Enabled = credentials, true
	request.XHTTP = XHTTPViewRequest{Revision: revision}
	request.WebSocket = WebSocketViewRequest{Revision: revision}
	request.Hysteria2 = Hysteria2ViewRequest{Revision: revision}
	request.TUIC = TUICViewRequest{Revision: revision}
	request.AnyTLS = AnyTLSViewRequest{Revision: revision}
	request.Lifecycles = revisionOneRegistryLifecycles()
	request.Exposure = nil
	return request, nil
}

// NewDeferredRegistry fills every deferred credential slot in one candidate.
// It cannot create a supported partial setup.
func NewDeferredRegistry(request RegistryViewRequest, credentials DeferredRegistryCredentials) (RegistryViewRequest, error) {
	if !credentials.independent(request.Reality.Credentials) {
		return RegistryViewRequest{}, errors.New("deferred registry credentials are not independent")
	}
	request.XHTTP.Credentials = credentials.XHTTP
	request.WebSocket.Credentials = credentials.WebSocket
	request.Hysteria2.Credentials = credentials.Hysteria2
	request.TUIC.Credentials = credentials.TUIC
	request.AnyTLS.Credentials = credentials.AnyTLS
	request.XHTTP.Enabled, request.WebSocket.Enabled, request.Hysteria2.Enabled, request.TUIC.Enabled, request.AnyTLS.Enabled = true, true, true, true, true
	request.Reality.Enabled = true
	request.Lifecycles = enabledRegistryLifecycles()
	request.Exposure = nil
	return request, nil
}

// DesiredProfiles protects the exact reviewed registry credentials for State.
func DesiredProfiles(request RegistryViewRequest) (state.ConnectionProfiles, bool) {
	if revisionOneRegistry(request) {
		if validateRevisionOneRegistry(request) != nil {
			return state.ConnectionProfiles{}, false
		}
		protect := state.NewClientAccessValue
		return state.ConnectionProfiles{
			VLESSRealityVision: state.VLESSRealityVision{Lifecycle: state.ProfileEnabled, Enabled: true, Port: request.Reality.Port, UUID: protect(request.Reality.Credentials.uuid.value), PrivateKey: state.NewInfrastructureSecret(request.Reality.Credentials.privateKey.value), PublicKey: request.Reality.Credentials.publicKey.value, ShortID: protect(request.Reality.Credentials.shortID.value), Target: request.Reality.Target.Address, ServerName: request.Reality.Target.ServerName, Fingerprint: request.Reality.Fingerprint},
			VLESSXHTTP:         state.VLESSXHTTP{Lifecycle: state.ProfileNotSetUp},
			VLESSWebSocket:     state.VLESSWebSocket{Lifecycle: state.ProfileNotSetUp},
			Hysteria2:          state.Hysteria2{Lifecycle: state.ProfileNotSetUp},
			TUIC:               state.TUIC{Lifecycle: state.ProfileNotSetUp},
			AnyTLS:             state.AnyTLS{Lifecycle: state.ProfileNotSetUp},
		}, true
	}
	if validateRegistryCandidate(request) != nil {
		return state.ConnectionProfiles{}, false
	}
	lifecycles := registryLifecycles(request)
	protect := state.NewClientAccessValue
	return state.ConnectionProfiles{
		VLESSRealityVision: state.VLESSRealityVision{Lifecycle: lifecycles.Reality, Enabled: request.Reality.Enabled, Port: request.Reality.Port, UUID: protect(request.Reality.Credentials.uuid.value), PrivateKey: state.NewInfrastructureSecret(request.Reality.Credentials.privateKey.value), PublicKey: request.Reality.Credentials.publicKey.value, ShortID: protect(request.Reality.Credentials.shortID.value), Target: request.Reality.Target.Address, ServerName: request.Reality.Target.ServerName, Fingerprint: request.Reality.Fingerprint},
		VLESSXHTTP:         state.VLESSXHTTP{Lifecycle: lifecycles.XHTTP, Enabled: request.XHTTP.Enabled, UUID: protect(request.XHTTP.Credentials.uuid.value), Path: protect(request.XHTTP.Credentials.path.value), Hostname: request.XHTTP.Hostname, OriginAddress: request.XHTTP.OriginAddress, OriginPort: request.XHTTP.OriginPort, Mode: request.XHTTP.Mode},
		VLESSWebSocket:     state.VLESSWebSocket{Lifecycle: lifecycles.WebSocket, Enabled: request.WebSocket.Enabled, UUID: protect(request.WebSocket.Credentials.uuid.value), Hostname: request.WebSocket.Hostname, OriginAddress: request.WebSocket.OriginAddress, OriginPort: request.WebSocket.OriginPort, Path: protect(request.WebSocket.Credentials.path.value)},
		Hysteria2:          state.Hysteria2{Lifecycle: lifecycles.Hysteria2, Enabled: request.Hysteria2.Enabled, Port: request.Hysteria2.Port, Password: protect(request.Hysteria2.Credentials.password.value), ServerName: request.Hysteria2.ServerName, CertificateID: request.Hysteria2.CertificateID, MasqueradeURL: "https://example.com/", Obfuscation: request.Hysteria2.Credentials.obfuscation, ObfuscationSecret: protect(request.Hysteria2.Credentials.obfuscationSecret.value)},
		TUIC:               state.TUIC{Lifecycle: lifecycles.TUIC, Enabled: request.TUIC.Enabled, Port: request.TUIC.Port, UUID: protect(request.TUIC.Credentials.uuid.value), Password: protect(request.TUIC.Credentials.password.value), ServerName: request.TUIC.ServerName, CertificateID: request.TUIC.CertificateID, CongestionControl: request.TUIC.CongestionControl, ZeroRTT: request.TUIC.ZeroRTT},
		AnyTLS:             state.AnyTLS{Lifecycle: lifecycles.AnyTLS, Enabled: request.AnyTLS.Enabled, Port: request.AnyTLS.Port, Password: protect(request.AnyTLS.Credentials.password.value), ServerName: request.AnyTLS.ServerName, CertificateID: request.AnyTLS.CertificateID, PaddingScheme: "upstream-default"},
	}, true
}

type RegistryExposureAuthority interface {
	ConnectionProfilesRegistryBinding() (revision uint64, digest string, valid bool)
	ConnectionProfilesListeners() (realityPort uint16, realityProtocol string, hysteria2Port uint16, hysteria2Protocol string, valid bool)
	ConnectionProfilesTUICListener() (port uint16, protocol string, valid bool)
	ConnectionProfilesAnyTLSListener() (port uint16, protocol string, valid bool)
	ConnectionProfilesRealityExposure() (address string, port uint16, protocol string, present, valid bool)
	ConnectionProfilesXHTTPExposure() (address string, port uint16, protocol string, present, valid bool)
	ConnectionProfilesWebSocketExposure() (address string, port uint16, protocol string, present, valid bool)
	ConnectionProfilesHysteria2Exposure() (address string, port uint16, protocol string, present, valid bool)
	ConnectionProfilesTUICExposure() (address string, port uint16, protocol string, present, valid bool)
	ConnectionProfilesAnyTLSExposure() (address string, port uint16, protocol string, present, valid bool)
	ConnectionProfilesFreshPortSelection() bool
	ConnectionProfilesManagedPortSelection() bool
}

type RegistryPortCorrectionAuthority interface {
	ConnectionProfilesPortCorrection() (purpose string, port, candidate uint16, protocol string, valid bool)
}

type CoreCapabilityObservation struct {
	CheckedAt             time.Time
	XrayNone, SingBoxNone bool
}

type RegistryCapabilityHost interface {
	ObserveCoreCapabilities(context.Context) CoreCapabilityObservation
}

type DeferredRegistryObservation struct {
	CheckedAt                  time.Time
	XrayRealityOnly            bool
	SingBoxConfigurationAbsent bool
	SingBoxServiceDisabled     bool
	SingBoxServiceInactive     bool
}

type DeferredRegistryHost interface {
	ObserveDeferredRegistry(context.Context) DeferredRegistryObservation
}

type registryCorrectionHost struct {
	host    RealityHost
	purpose string
	port    uint16
}

func (host registryCorrectionHost) listener(purpose string, observed Listener) Listener {
	if host.purpose != purpose {
		return observed
	}
	address := "0.0.0.0"
	if purpose == "VLESS XHTTP origin" || purpose == "VLESS WebSocket origin" {
		address = "127.0.0.1"
	}
	protocol := "tcp"
	if purpose == "Hysteria2" || purpose == "TUIC" {
		protocol = "udp"
	}
	return Listener{Address: address, Port: host.port, Protocol: protocol}
}

func (host registryCorrectionHost) ObserveReality(ctx context.Context, target RealityTarget) RealityObservation {
	observed := host.host.ObserveReality(ctx, target)
	observed.Listener = host.listener("VLESS REALITY Vision", observed.Listener)
	return observed
}
func (host registryCorrectionHost) ValidateReality(ctx context.Context, version string, candidate io.Reader) error {
	return host.host.ValidateReality(ctx, version, candidate)
}
func (host registryCorrectionHost) ObserveXHTTP(ctx context.Context, port uint16) XHTTPObservation {
	observer, ok := host.host.(XHTTPHost)
	if !ok {
		return XHTTPObservation{}
	}
	observed := observer.ObserveXHTTP(ctx, port)
	observed.Listener = host.listener("VLESS XHTTP origin", observed.Listener)
	return observed
}
func (host registryCorrectionHost) ObserveWebSocket(ctx context.Context, port uint16, httpHost, path string) WebSocketObservation {
	observer, ok := host.host.(WebSocketHost)
	if !ok {
		return WebSocketObservation{}
	}
	observed := observer.ObserveWebSocket(ctx, port, httpHost, path)
	observed.Listener = host.listener("VLESS WebSocket origin", observed.Listener)
	return observed
}
func (host registryCorrectionHost) ObserveHysteria2(ctx context.Context, request Hysteria2ViewRequest) Hysteria2Observation {
	observer, ok := host.host.(Hysteria2Host)
	if !ok {
		return Hysteria2Observation{}
	}
	observed := observer.ObserveHysteria2(ctx, request)
	observed.Listener = host.listener("Hysteria2", observed.Listener)
	return observed
}
func (host registryCorrectionHost) ValidateSingBox(ctx context.Context, version string, candidate io.Reader) error {
	validator, ok := host.host.(SingBoxValidator)
	if !ok {
		return errors.New("sing-box validator unavailable")
	}
	return validator.ValidateSingBox(ctx, version, candidate)
}
func (host registryCorrectionHost) ObserveTUIC(ctx context.Context, hysteria2 Hysteria2ViewRequest, request TUICViewRequest) TUICObservation {
	observer, ok := host.host.(TUICHost)
	if !ok {
		return TUICObservation{}
	}
	observed := observer.ObserveTUIC(ctx, hysteria2, request)
	observed.Listener = host.listener("TUIC", observed.Listener)
	return observed
}
func (host registryCorrectionHost) ObserveAnyTLS(ctx context.Context, hysteria2 Hysteria2ViewRequest, tuic TUICViewRequest, request AnyTLSViewRequest) AnyTLSObservation {
	observer, ok := host.host.(AnyTLSHost)
	if !ok {
		return AnyTLSObservation{}
	}
	observed := observer.ObserveAnyTLS(ctx, hysteria2, tuic, request)
	observed.Listener = host.listener("AnyTLS", observed.Listener)
	return observed
}

type RegistryViewRequest struct {
	ClientAddress string
	Reality       ViewRequest
	XHTTP         XHTTPViewRequest
	WebSocket     WebSocketViewRequest
	Hysteria2     Hysteria2ViewRequest
	TUIC          TUICViewRequest
	AnyTLS        AnyTLSViewRequest
	Exposure      RegistryExposureAuthority
	Lifecycles    RegistryLifecycles
}

type RegistryLifecycles struct {
	Reality, XHTTP, WebSocket, Hysteria2, TUIC, AnyTLS state.ProfileLifecycle
}

func enabledRegistryLifecycles() RegistryLifecycles {
	return RegistryLifecycles{state.ProfileEnabled, state.ProfileEnabled, state.ProfileEnabled, state.ProfileEnabled, state.ProfileEnabled, state.ProfileEnabled}
}

func revisionOneRegistryLifecycles() RegistryLifecycles {
	return RegistryLifecycles{state.ProfileEnabled, state.ProfileNotSetUp, state.ProfileNotSetUp, state.ProfileNotSetUp, state.ProfileNotSetUp, state.ProfileNotSetUp}
}

func registryLifecycles(request RegistryViewRequest) RegistryLifecycles {
	if request.Lifecycles != (RegistryLifecycles{}) {
		return request.Lifecycles
	}
	stateFor := func(enabled bool) state.ProfileLifecycle {
		if enabled {
			return state.ProfileEnabled
		}
		return state.ProfileDisabled
	}
	return RegistryLifecycles{stateFor(request.Reality.Enabled), stateFor(request.XHTTP.Enabled), stateFor(request.WebSocket.Enabled), stateFor(request.Hysteria2.Enabled), stateFor(request.TUIC.Enabled), stateFor(request.AnyTLS.Enabled)}
}

func revisionOneRegistry(request RegistryViewRequest) bool {
	return registryLifecycles(request) == revisionOneRegistryLifecycles()
}

type RegistryProfile struct {
	ID                                        ProfileID
	Name, Hostname, QualifiedVersion          string
	Enabled, DefaultEnabled, CredentialsReady bool
	SelectedListener, Listener                Listener
	Health                                    Health
	Lifecycle                                 state.ProfileLifecycle
}

type PublicationProfile struct {
	ID                                                       ProfileID
	Name, Address, Hostname, ServerName, Transport, Security string
	Port                                                     uint16
	UUID, Password, Path, ShortID                            state.ClientAccessValue
	ObfuscationSecret                                        state.ClientAccessValue
	PublicKey, Fingerprint, Flow, HTTPHost, TLSName          string
	Obfuscation                                              bool
	CongestionControl                                        state.CongestionControl
	XHTTPServerMode                                          state.XHTTPMode
}

type PublicationOmission struct {
	ID        ProfileID
	Name      string
	Lifecycle state.ProfileLifecycle
}

func (omission PublicationOmission) Reason() string {
	switch omission.Lifecycle {
	case state.ProfileNotSetUp:
		return "The Connection Profile is not set up"
	case state.ProfileDisabled:
		return "The Connection Profile is deliberately disabled"
	default:
		return ""
	}
}

type PublicationSource struct {
	profiles  []PublicationProfile
	omissions []PublicationOmission
}

// NewPublicationSource preserves the six fixed profile identities while
// allowing each identity to be either rendered or deliberately omitted.
func NewPublicationSource(profiles []PublicationProfile, omissions []PublicationOmission) (PublicationSource, error) {
	profileIndex, omissionIndex := 0, 0
	for _, definition := range registryDefinitions {
		if profileIndex < len(profiles) && profiles[profileIndex].ID == definition.id {
			profileIndex++
			continue
		}
		if omissionIndex < len(omissions) && omissions[omissionIndex] == publicationOmission(definition.id, omissions[omissionIndex].Lifecycle) && (omissions[omissionIndex].Lifecycle == state.ProfileNotSetUp || omissions[omissionIndex].Lifecycle == state.ProfileDisabled) {
			omissionIndex++
			continue
		}
		return PublicationSource{}, errors.New("Connection Profile publication source is incomplete or out of order")
	}
	if profileIndex != len(profiles) || omissionIndex != len(omissions) {
		return PublicationSource{}, errors.New("Connection Profile publication source is incomplete or out of order")
	}
	return PublicationSource{profiles: append([]PublicationProfile(nil), profiles...), omissions: append([]PublicationOmission(nil), omissions...)}, nil
}

func (PublicationSource) String() string   { return "Connection Profile publication source: redacted" }
func (PublicationSource) GoString() string { return "Connection Profile publication source: redacted" }
func (PublicationSource) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Connection Profile publication source cannot be rendered")
}
func (source PublicationSource) Profiles() []PublicationProfile {
	return append([]PublicationProfile(nil), source.profiles...)
}
func (source PublicationSource) Omissions() []PublicationOmission {
	return append([]PublicationOmission(nil), source.omissions...)
}

// PublicationInputsMatch proves that one publication source carries every
// rendered fact owned by candidate Connection Profiles.
func PublicationInputsMatch(source PublicationSource, candidate state.ConnectionProfiles) bool {
	profiles, omissions := source.Profiles(), source.Omissions()
	profileByID := make(map[ProfileID]PublicationProfile, len(profiles))
	omitted := make(map[ProfileID]PublicationOmission, len(omissions))
	for _, profile := range profiles {
		profileByID[profile.ID] = profile
	}
	for _, omission := range omissions {
		omitted[omission.ID] = omission
	}
	checks := []struct {
		id      ProfileID
		enabled bool
		match   func(PublicationProfile) bool
	}{
		{VLESSRealityVisionProfileID, candidate.VLESSRealityVision.Enabled, func(profile PublicationProfile) bool {
			return profile.Port == candidate.VLESSRealityVision.Port && profile.UUID == candidate.VLESSRealityVision.UUID && profile.ShortID == candidate.VLESSRealityVision.ShortID && profile.PublicKey == candidate.VLESSRealityVision.PublicKey && profile.ServerName == candidate.VLESSRealityVision.ServerName && profile.Fingerprint == candidate.VLESSRealityVision.Fingerprint && profile.Transport == "RAW" && profile.Security == "REALITY" && profile.Flow == "xtls-rprx-vision"
		}},
		{VLESSXHTTPProfileID, candidate.VLESSXHTTP.Enabled, func(profile PublicationProfile) bool {
			return profile.Port == 443 && profile.UUID == candidate.VLESSXHTTP.UUID && profile.Path == candidate.VLESSXHTTP.Path && profile.Address == candidate.VLESSXHTTP.Hostname && profile.Hostname == candidate.VLESSXHTTP.Hostname && profile.Transport == "XHTTP" && profile.Security == "TLS" && profile.XHTTPServerMode == candidate.VLESSXHTTP.Mode
		}},
		{VLESSWebSocketProfileID, candidate.VLESSWebSocket.Enabled, func(profile PublicationProfile) bool {
			return profile.Port == 443 && profile.UUID == candidate.VLESSWebSocket.UUID && profile.Path == candidate.VLESSWebSocket.Path && profile.Address == candidate.VLESSWebSocket.Hostname && profile.Hostname == candidate.VLESSWebSocket.Hostname && profile.TLSName == candidate.VLESSWebSocket.Hostname && profile.HTTPHost != "" && profile.Transport == "WebSocket" && profile.Security == "TLS"
		}},
		{Hysteria2ProfileID, candidate.Hysteria2.Enabled, func(profile PublicationProfile) bool {
			return profile.Port == candidate.Hysteria2.Port && profile.Password == candidate.Hysteria2.Password && profile.ServerName == candidate.Hysteria2.ServerName && profile.Transport == "QUIC" && profile.Security == "TLS" && profile.Obfuscation == candidate.Hysteria2.Obfuscation && profile.ObfuscationSecret == candidate.Hysteria2.ObfuscationSecret
		}},
		{TUICProfileID, candidate.TUIC.Enabled, func(profile PublicationProfile) bool {
			return profile.Port == candidate.TUIC.Port && profile.UUID == candidate.TUIC.UUID && profile.Password == candidate.TUIC.Password && profile.ServerName == candidate.TUIC.ServerName && profile.Transport == "QUIC" && profile.Security == "TLS" && profile.CongestionControl == candidate.TUIC.CongestionControl
		}},
		{AnyTLSProfileID, candidate.AnyTLS.Enabled, func(profile PublicationProfile) bool {
			return profile.Port == candidate.AnyTLS.Port && profile.Password == candidate.AnyTLS.Password && profile.ServerName == candidate.AnyTLS.ServerName && profile.Transport == "TCP" && profile.Security == "TLS"
		}},
	}
	for _, check := range checks {
		profile, present := profileByID[check.id]
		omission, absent := omitted[check.id]
		lifecycle := publicationLifecycle(candidate, check.id)
		if check.enabled != present || check.enabled && (lifecycle != state.ProfileEnabled || !check.match(profile) || absent) || !check.enabled && (!absent || omission != publicationOmission(check.id, lifecycle)) {
			return false
		}
	}
	return true
}

func PublicationSourceMatches(left, right PublicationSource) bool {
	return reflect.DeepEqual(left, right)
}

func publicationSourceWithCandidateCredentials(source PublicationSource, candidate state.ConnectionProfiles) (PublicationSource, error) {
	profiles := source.Profiles()
	for index := range profiles {
		switch profiles[index].ID {
		case VLESSRealityVisionProfileID:
			profiles[index].UUID, profiles[index].ShortID, profiles[index].PublicKey = candidate.VLESSRealityVision.UUID, candidate.VLESSRealityVision.ShortID, candidate.VLESSRealityVision.PublicKey
		case VLESSXHTTPProfileID:
			profiles[index].UUID, profiles[index].Path = candidate.VLESSXHTTP.UUID, candidate.VLESSXHTTP.Path
		case VLESSWebSocketProfileID:
			profiles[index].UUID, profiles[index].Path = candidate.VLESSWebSocket.UUID, candidate.VLESSWebSocket.Path
		case Hysteria2ProfileID:
			profiles[index].Password, profiles[index].ObfuscationSecret = candidate.Hysteria2.Password, candidate.Hysteria2.ObfuscationSecret
		case TUICProfileID:
			profiles[index].UUID, profiles[index].Password = candidate.TUIC.UUID, candidate.TUIC.Password
		case AnyTLSProfileID:
			profiles[index].Password = candidate.AnyTLS.Password
		}
	}
	return NewPublicationSource(profiles, source.Omissions())
}

type RegistryViewResult struct {
	Profiles       []RegistryProfile
	Publication    PublicationSource
	Health         Health
	VolatileSHA256 string
	Repairable     bool
}

type RegistryPlanRequest struct {
	Current, Candidate                                 RegistryViewRequest
	ChangeSet, StartingStateSHA256, DesiredStateSHA256 string
	ReleaseUpdate                                      bool
	Repair                                             systemchanges.ForwardRepairAuthority
	FreshInstallation                                  systemchanges.FreshInstallationAuthority
	PortCorrection                                     RegistryPortCorrectionAuthority
}

func (result RegistryViewResult) Profile(id ProfileID) (RegistryProfile, bool) {
	for _, profile := range result.Profiles {
		if profile.ID == id {
			return profile, true
		}
	}
	return RegistryProfile{}, false
}

func (module Interface) ViewRegistry(ctx context.Context, request RegistryViewRequest) RegistryViewResult {
	return module.viewRegistry(ctx, request, false)
}

func (module Interface) viewRegistry(ctx context.Context, request RegistryViewRequest, coreOnly bool) RegistryViewResult {
	address, addressErr := netip.ParseAddr(request.ClientAddress)
	if addressErr != nil || !address.IsGlobalUnicast() || request.Reality.Revision != request.XHTTP.Revision || request.Reality.Revision != request.WebSocket.Revision || request.Reality.Revision != request.Hysteria2.Revision || request.Reality.Revision != request.TUIC.Revision || request.Reality.Revision != request.AnyTLS.Revision {
		return registryInvalidResult(request, registryHealth("CONNECTION-PROFILES-REGISTRY-INPUT", "the selected client address or profile revision is invalid"))
	}
	if !validRegistryExposureAuthority(request.Exposure) || !validRegistryExposureBinding(request.Exposure, request.Reality.Revision) {
		return registryInvalidResult(request, registryHealth("CONNECTION-PROFILES-REGISTRY-EXPOSURE", "the fresh typed Network Policy exposure is unavailable"))
	}
	if failure := registryExposureFailure(request); failure != nil {
		return registryInvalidResult(request, *failure)
	}
	if revisionOneRegistry(request) {
		return module.viewRevisionOneRegistry(ctx, request)
	}
	if failure := validateRegistryLifecycles(request); failure != nil {
		return registryInvalidResult(request, *failure)
	}
	request = reviewedRegistryRequest(request)
	lifecycles := registryLifecycles(request)

	profiles := SingBoxProfileSet{}
	if request.TUIC.Enabled {
		profiles.TUIC = &request.TUIC
	}
	if request.AnyTLS.Enabled {
		profiles.AnyTLS = &request.AnyTLS
	}
	request.Hysteria2.Profiles = &profiles

	results := make([]RegistryProfile, 0, len(registryDefinitions))
	_, networkDigest, _ := request.Exposure.ConnectionProfilesRegistryBinding()
	volatile := networkDigest
	var firstFailure *Health
	appendProfile := func(profile RegistryProfile, digest string) {
		switch profile.ID {
		case VLESSRealityVisionProfileID:
			profile.Lifecycle = lifecycles.Reality
		case VLESSXHTTPProfileID:
			profile.Lifecycle = lifecycles.XHTTP
		case VLESSWebSocketProfileID:
			profile.Lifecycle = lifecycles.WebSocket
		case Hysteria2ProfileID:
			profile.Lifecycle = lifecycles.Hysteria2
		case TUICProfileID:
			profile.Lifecycle = lifecycles.TUIC
		case AnyTLSProfileID:
			profile.Lifecycle = lifecycles.AnyTLS
		}
		results = append(results, profile)
		volatile += digest
		if profile.Health.Outcome != Healthy && profile.Health.Outcome != Disabled && firstFailure == nil {
			health := profile.Health
			firstFailure = &health
		}
	}

	if !request.Reality.Enabled {
		profile, digest, health := disabledRealityProfile(request.Reality)
		if health != nil {
			profile.Health = *health
		}
		appendProfile(profile, digest)
	} else {
		reality := module.View(ctx, request.Reality)
		appendProfile(RegistryProfile{ID: VLESSRealityVisionProfileID, Name: reality.Profile.Name, QualifiedVersion: reality.Profile.XrayVersion, Enabled: true, DefaultEnabled: true, CredentialsReady: reality.Profile.CredentialsReady, SelectedListener: selectedRegistryListener(request, VLESSRealityVisionProfileID), Listener: reality.Profile.Listener, Health: reality.Health, Lifecycle: lifecycles.Reality}, reality.VolatileSHA256)
	}
	if !request.XHTTP.Enabled {
		profile, digest, health := disabledXHTTPProfile(request.XHTTP)
		if health != nil {
			profile.Health = *health
		}
		appendProfile(profile, digest)
	} else {
		xhttp := module.ViewXHTTP(ctx, request.XHTTP)
		if coreOnly {
			xhttp = module.viewXHTTPCore(ctx, request.XHTTP)
		}
		if xhttp.Health.Outcome == Healthy && !request.Reality.Enabled && !xhttp.observation.NoCapabilities {
			xhttp.Health = registryCapabilityFailure("Xray", "REALITY is disabled but xray.service still has capabilities")
		}
		appendProfile(RegistryProfile{ID: VLESSXHTTPProfileID, Name: xhttp.Profile.Name, Hostname: xhttp.Profile.Hostname, QualifiedVersion: xhttp.Profile.XrayVersion, Enabled: true, DefaultEnabled: true, CredentialsReady: xhttp.Profile.CredentialsReady, SelectedListener: selectedRegistryListener(request, VLESSXHTTPProfileID), Listener: xhttp.Profile.Listener, Health: xhttp.Health, Lifecycle: lifecycles.XHTTP}, xhttp.VolatileSHA256)
	}
	if !request.WebSocket.Enabled {
		profile, digest, health := disabledWebSocketProfile(request.WebSocket)
		if health != nil {
			profile.Health = *health
		}
		appendProfile(profile, digest)
	} else {
		websocket := module.ViewWebSocket(ctx, request.WebSocket)
		if coreOnly {
			websocket = module.viewWebSocketCore(ctx, request.WebSocket)
		}
		if websocket.Health.Outcome == Healthy && !request.Reality.Enabled && !websocket.observation.NoCapabilities {
			websocket.Health = registryCapabilityFailure("Xray", "REALITY is disabled but xray.service still has capabilities")
		}
		appendProfile(RegistryProfile{ID: VLESSWebSocketProfileID, Name: websocket.Profile.Name, Hostname: websocket.Profile.Hostname, QualifiedVersion: websocket.Profile.XrayVersion, Enabled: true, DefaultEnabled: true, CredentialsReady: websocket.Profile.CredentialsReady, SelectedListener: selectedRegistryListener(request, VLESSWebSocketProfileID), Listener: websocket.Profile.Listener, Health: websocket.Health, Lifecycle: lifecycles.WebSocket}, websocket.VolatileSHA256)
	}
	if !request.Hysteria2.Enabled {
		profile, digest, health := disabledHysteria2Profile(request.Hysteria2)
		if health != nil {
			profile.Health = *health
		}
		appendProfile(profile, digest)
	} else {
		hysteria2 := module.ViewHysteria2(ctx, request.Hysteria2)
		appendProfile(RegistryProfile{ID: Hysteria2ProfileID, Name: hysteria2.Profile.Name, Hostname: hysteria2.Profile.ServerName, QualifiedVersion: hysteria2.Profile.SingBoxVersion, Enabled: true, DefaultEnabled: true, CredentialsReady: hysteria2.Profile.CredentialsReady, SelectedListener: selectedRegistryListener(request, Hysteria2ProfileID), Listener: hysteria2.Profile.Listener, Health: hysteria2.Health, Lifecycle: lifecycles.Hysteria2}, hysteria2.VolatileSHA256)
	}
	if !request.TUIC.Enabled {
		profile, digest, health := disabledTUICProfile(request.TUIC)
		if health != nil {
			profile.Health = *health
		}
		appendProfile(profile, digest)
	} else {
		tuic := module.ViewTUIC(ctx, request.Hysteria2, request.TUIC)
		appendProfile(RegistryProfile{ID: TUICProfileID, Name: tuic.Profile.Name, Hostname: tuic.Profile.ServerName, QualifiedVersion: tuic.Profile.SingBoxVersion, Enabled: true, DefaultEnabled: true, CredentialsReady: tuic.Profile.CredentialsReady, SelectedListener: selectedRegistryListener(request, TUICProfileID), Listener: tuic.Profile.Listener, Health: tuic.Health, Lifecycle: lifecycles.TUIC}, tuic.VolatileSHA256)
	}
	if !request.AnyTLS.Enabled {
		profile, digest, health := disabledAnyTLSProfile(request.AnyTLS)
		if health != nil {
			profile.Health = *health
		}
		appendProfile(profile, digest)
	} else {
		anyTLS := module.ViewAnyTLS(ctx, request.Hysteria2, request.TUIC, request.AnyTLS)
		appendProfile(RegistryProfile{ID: AnyTLSProfileID, Name: anyTLS.Profile.Name, Hostname: anyTLS.Profile.ServerName, QualifiedVersion: anyTLS.Profile.SingBoxVersion, Enabled: true, DefaultEnabled: true, CredentialsReady: anyTLS.Profile.CredentialsReady, SelectedListener: selectedRegistryListener(request, AnyTLSProfileID), Listener: anyTLS.Profile.Listener, Health: anyTLS.Health, Lifecycle: lifecycles.AnyTLS}, anyTLS.VolatileSHA256)
	}
	allXrayDisabled := !request.Reality.Enabled && !request.XHTTP.Enabled && !request.WebSocket.Enabled
	allSingBoxDisabled := !request.Hysteria2.Enabled && !request.TUIC.Enabled && !request.AnyTLS.Enabled
	if request.Reality.Revision > 0 && (allXrayDisabled || allSingBoxDisabled) {
		host, ok := module.host.(RegistryCapabilityHost)
		observation := CoreCapabilityObservation{}
		if ok {
			observation = host.ObserveCoreCapabilities(ctx)
			encoded, _ := json.Marshal(observation)
			volatile += string(encoded)
		}
		if !ok || allXrayDisabled && !observation.XrayNone {
			health := registryCapabilityFailure("Xray", "all Xray profiles are disabled but empty service capabilities were not proved")
			markRegistryCoreFailure(results[:3], health)
			if firstFailure == nil {
				firstFailure = &health
			}
		}
		if !ok || allSingBoxDisabled && !observation.SingBoxNone {
			health := registryCapabilityFailure("sing-box", "all sing-box profiles are disabled but empty service capabilities were not proved")
			markRegistryCoreFailure(results[3:], health)
			if firstFailure == nil {
				firstFailure = &health
			}
		}
	}
	digest := sha256.Sum256([]byte(volatile))
	if firstFailure != nil {
		return RegistryViewResult{Profiles: results, Health: *firstFailure, VolatileSHA256: hex.EncodeToString(digest[:]), Repairable: repairableRegistryCode(firstFailure.Code)}
	}
	return RegistryViewResult{Profiles: results, Publication: registryPublication(request), Health: Health{Module: "Connection Profiles", Profile: "Registry", Outcome: Healthy, Code: "CONNECTION-PROFILES-REGISTRY-HEALTHY", NextActions: []string{"Build Plan", "Back"}}, VolatileSHA256: hex.EncodeToString(digest[:])}
}

func (module Interface) viewRevisionOneRegistry(ctx context.Context, request RegistryViewRequest) RegistryViewResult {
	if failure := validateRevisionOneRegistry(request); failure != nil {
		return registryInvalidResult(request, *failure)
	}
	reality := module.View(ctx, request.Reality)
	if reality.Health.Outcome != Healthy {
		return registryInvalidResult(request, reality.Health)
	}
	host, ok := module.host.(DeferredRegistryHost)
	observation := DeferredRegistryObservation{}
	if ok {
		observation = host.ObserveDeferredRegistry(ctx)
	}
	if !ok || !observation.XrayRealityOnly || !observation.SingBoxConfigurationAbsent || !observation.SingBoxServiceDisabled || !observation.SingBoxServiceInactive {
		health := registryHealth("CONNECTION-PROFILES-REGISTRY-EXPECTED-ABSENCE", "a deferred service configuration, capability, or active process exists or cannot be proved absent")
		return registryInvalidResult(request, health)
	}
	profiles := make([]RegistryProfile, len(registryDefinitions))
	profiles[0] = RegistryProfile{ID: VLESSRealityVisionProfileID, Name: reality.Profile.Name, QualifiedVersion: reality.Profile.XrayVersion, Enabled: true, DefaultEnabled: true, CredentialsReady: true, SelectedListener: selectedRegistryListener(request, VLESSRealityVisionProfileID), Listener: reality.Profile.Listener, Health: reality.Health, Lifecycle: state.ProfileEnabled}
	for index, definition := range registryDefinitions[1:] {
		profiles[index+1] = RegistryProfile{ID: definition.id, Name: definition.name, DefaultEnabled: true, Lifecycle: state.ProfileNotSetUp}
	}
	encoded, _ := json.Marshal(observation)
	digest := sha256.Sum256(append([]byte(reality.VolatileSHA256), encoded...))
	return RegistryViewResult{Profiles: profiles, Publication: registryPublication(request), Health: Health{Module: "Connection Profiles", Profile: "Registry", Outcome: Healthy, Code: "CONNECTION-PROFILES-REGISTRY-EXPECTED-ABSENCE", NextActions: []string{"Set up Cloudflare profiles", "Back"}}, VolatileSHA256: hex.EncodeToString(digest[:])}
}

func repairableRegistryCode(code string) bool {
	for _, suffix := range []string{"-CONFIGURATION", "-SERVICE", "-LISTENER", "-CAPABILITY", "-FUNCTION", "-EXPOSURE"} {
		if strings.HasSuffix(code, suffix) {
			return true
		}
	}
	return false
}

func (module Interface) PlanRegistry(ctx context.Context, request RegistryPlanRequest) PlanResult {
	freshInstallation := request.FreshInstallation.ConnectionProfilesFreshInstallation()
	freshPorts := freshInstallation && revisionOneRegistry(request.Candidate) && validRegistryExposureAuthority(request.Candidate.Exposure) && request.Candidate.Exposure.ConnectionProfilesFreshPortSelection()
	correctionPurpose, correctionPort, correctionCandidate, correctionProtocol, correction := registryPortCorrection(request.PortCorrection)
	correctedPorts := correction && validRegistryExposureAuthority(request.Candidate.Exposure) && request.Candidate.Exposure.ConnectionProfilesManagedPortSelection()
	current := RegistryViewResult{Health: Health{Outcome: Healthy}, VolatileSHA256: "not-installed"}
	if !freshPorts {
		current = module.ViewRegistry(ctx, request.Current)
		if current.Health.Outcome != Healthy && correctedPorts && registryCorrectionExplains(current, correctionPurpose) {
			validated := Interface{host: registryCorrectionHost{host: module.host, purpose: correctionPurpose, port: correctionPort}}.ViewRegistry(ctx, request.Current)
			validated.VolatileSHA256 = current.VolatileSHA256 + validated.VolatileSHA256
			current = validated
		}
	}
	repairRevision, repairSHA, repair := request.Repair.ConnectionProfilesForwardRepair()
	if !repair && current.Health.Outcome != Healthy {
		return PlanResult{Health: current.Health}
	}
	profileSetup := registryProfileSetup(request.Current, request.Candidate)
	action, mutation, validChange := registryChange(request.Current, request.Candidate, repair, freshPorts, correctedPorts, request.ReleaseUpdate, profileSetup, correctionPurpose, correctionPort, correctionCandidate, correctionProtocol)
	desiredStateValid := sha256Text.MatchString(request.DesiredStateSHA256)
	stateBindingValid := freshPorts && request.StartingStateSHA256 == "" && desiredStateValid || sha256Text.MatchString(request.StartingStateSHA256) && desiredStateValid && (repair && request.StartingStateSHA256 == request.DesiredStateSHA256 && repairRevision == request.Current.Reality.Revision && repairSHA == request.StartingStateSHA256 || request.ReleaseUpdate && !repair && request.StartingStateSHA256 == request.DesiredStateSHA256 || !repair && request.StartingStateSHA256 != request.DesiredStateSHA256)
	if !validChange || !registryLifecycleRevisions(request.Current, request.Candidate, freshPorts) || !planName.MatchString(request.ChangeSet) || !stateBindingValid {
		return PlanResult{Health: registryPlanFailure("STATE", "the request does not contain one exact profile lifecycle change and State binding")}
	}
	if revisionOneRegistry(request.Candidate) {
		if failure := validateRevisionOneRegistry(request.Candidate); failure != nil {
			return PlanResult{Health: *failure}
		}
	} else if failure := validateRegistryCandidate(request.Candidate); failure != nil {
		return PlanResult{Health: *failure}
	}
	request.Candidate = reviewedRegistryRequest(request.Candidate)
	if revisionOneRegistry(request.Candidate) {
		xray, err := realityConfiguration(request.Candidate.Reality)
		if err != nil {
			return PlanResult{Health: registryPlanFailure("CONFIGURATION", "the revision 1 Xray configuration is incomplete")}
		}
		volatileDigest := sha256.Sum256([]byte(current.VolatileSHA256))
		plan, failure := module.buildXrayPlan(ctx, xrayPlanSpec{
			identityPrefix: "profiles-registry-", description: action + "; keep every deferred profile setting, credential, service, listener, route, certificate binding, exposure, and publication entry absent",
			profile: "Registry", codePrefix: "CONNECTION-PROFILES-REGISTRY", version: request.Candidate.Reality.XrayVersion,
			revision: request.Candidate.Reality.Revision, changeSet: request.ChangeSet, startingStateSHA256: request.StartingStateSHA256, desiredStateSHA256: request.DesiredStateSHA256,
			volatileSHA256: hex.EncodeToString(volatileDigest[:]), configuration: xray, request: request, reality: request.Candidate.Reality,
			mutation: mutation,
		})
		if failure != nil {
			return PlanResult{Health: *failure}
		}
		return PlanResult{Plan: plan, Health: Health{Module: "Connection Profiles", Profile: "Registry", Outcome: Healthy, Code: "CONNECTION-PROFILES-REGISTRY-PLAN-READY", NextActions: []string{"Review Plan", "Back"}}}
	}
	xray, singBox, hysteria2 := registryConfigurations(request.Candidate)
	if len(xray) == 0 || len(singBox) == 0 {
		return PlanResult{Health: registryPlanFailure("CONFIGURATION", "the enablement change would remove a complete proxy-core configuration")}
	}
	publication := registryPublication(request.Candidate)
	plan, failure := module.buildSingBoxPlan(ctx, singBoxPlanSpec{
		profile: "REGISTRY", description: action + " through the canonical six-profile registry; update every reviewed artifact and restore both prior configurations on rollback",
		xrayVersion: request.Candidate.Reality.XrayVersion, singBoxVersion: request.Candidate.AnyTLS.SingBoxVersion, revision: request.Candidate.Reality.Revision,
		changeSet: request.ChangeSet, startingState: request.StartingStateSHA256, desiredState: request.DesiredStateSHA256,
		xray: xray, singBox: singBox, volatileInputs: current.VolatileSHA256 + repairSHA,
		binding: struct {
			Current, Candidate                     RegistryViewRequest
			ChangeSet, StartingState, DesiredState string
			RepairRevision                         uint64
			RepairSHA                              string
			FreshInstallation                      bool
			CorrectionPurpose, CorrectionProtocol  string
			CorrectionPort, CorrectionCandidate    uint16
			Network                                registryNetworkBinding
			Exposure                               []registryExposureFact
			Published                              []ProfileID
			Omissions                              []PublicationOmission
			Action                                 string
		}{registryComparable(request.Current), registryComparable(request.Candidate), request.ChangeSet, request.StartingStateSHA256, request.DesiredStateSHA256, repairRevision, repairSHA, freshPorts, correctionPurpose, correctionProtocol, correctionPort, correctionCandidate, registryNetworkAuthority(request.Candidate.Exposure), registryExposureFacts(request.Candidate.Exposure), publicationIDs(publication), publication.Omissions(), action},
		reality: request.Candidate.Reality, xhttp: &request.Candidate.XHTTP, websocket: &request.Candidate.WebSocket,
		hysteria2: &hysteria2, tuic: &request.Candidate.TUIC, anyTLS: &request.Candidate.AnyTLS,
		mutation: mutation,
	})
	if failure != "" {
		return PlanResult{Health: registryPlanFailure(failure, "native validation, protected binding, or the reversible transaction failed")}
	}
	return PlanResult{Plan: plan, Health: Health{Module: "Connection Profiles", Profile: "Registry", Outcome: Healthy, Code: "CONNECTION-PROFILES-REGISTRY-PLAN-READY", NextActions: []string{"Review Plan", "Back"}}}
}

// PlanUnchangedRegistry revalidates and reproduces the current complete native
// core configuration for a Subscription-only Change Set. It contributes no
// Connection Profiles mutation step.
func (module Interface) PlanUnchangedRegistry(ctx context.Context, current RegistryViewRequest, changeSet, stateSHA256 string) PlanResult {
	return module.planUnchangedRegistry(ctx, current, changeSet, stateSHA256, false)
}

func (module Interface) planUnchangedRegistry(ctx context.Context, current RegistryViewRequest, changeSet, stateSHA256 string, coreOnly bool) PlanResult {
	view := module.ViewRegistry(ctx, current)
	if coreOnly {
		view = module.viewRegistry(ctx, current, true)
	}
	if view.Health.Outcome != Healthy || !planName.MatchString(changeSet) || !sha256Text.MatchString(stateSHA256) {
		return PlanResult{Health: registryPlanFailure("UNCHANGED", "the current Managed registry is not freshly proved")}
	}
	xray, singBox, hysteria2 := registryConfigurations(current)
	if len(xray) == 0 || len(singBox) == 0 {
		return PlanResult{Health: registryPlanFailure("UNCHANGED", "the current complete core configuration is unavailable")}
	}
	plan, failure := module.buildSingBoxPlan(ctx, singBoxPlanSpec{
		profile: "REGISTRY", description: "reproduce the unchanged complete six-profile registry for Subscription-only publication",
		xrayVersion: current.Reality.XrayVersion, singBoxVersion: current.AnyTLS.SingBoxVersion, revision: current.Reality.Revision,
		changeSet: changeSet, startingState: stateSHA256, desiredState: stateSHA256, xray: xray, singBox: singBox, volatileInputs: view.VolatileSHA256,
		binding: registryComparable(current), reality: current.Reality, xhttp: &current.XHTTP, websocket: &current.WebSocket,
		hysteria2: &hysteria2, tuic: &current.TUIC, anyTLS: &current.AnyTLS,
	})
	if failure != "" {
		return PlanResult{Health: registryPlanFailure("UNCHANGED", "native validation or protected binding failed")}
	}
	plan.steps, plan.checks = nil, nil
	return PlanResult{Plan: plan, Health: Health{Module: "Connection Profiles", Profile: "Registry", Outcome: Healthy, Code: "CONNECTION-PROFILES-REGISTRY-UNCHANGED-READY", NextActions: []string{"Review Plan", "Back"}}}
}

// PlanUnchangedCoreRegistry proves and reproduces the exact current core while
// a separately owned Cloudflare repair corrects only route agreement.
func (module Interface) PlanUnchangedCoreRegistry(ctx context.Context, current RegistryViewRequest, changeSet, stateSHA256 string) PlanResult {
	return module.planUnchangedRegistry(ctx, current, changeSet, stateSHA256, true)
}

func registryCorrectionExplains(result RegistryViewResult, purpose string) bool {
	want := map[string]struct {
		id   ProfileID
		code string
	}{
		"VLESS REALITY Vision":   {VLESSRealityVisionProfileID, "CONNECTION-PROFILES-REALITY-LISTENER"},
		"VLESS XHTTP origin":     {VLESSXHTTPProfileID, "CONNECTION-PROFILES-XHTTP-LISTENER"},
		"VLESS WebSocket origin": {VLESSWebSocketProfileID, "CONNECTION-PROFILES-WEBSOCKET-LISTENER"},
		"Hysteria2":              {Hysteria2ProfileID, "CONNECTION-PROFILES-HYSTERIA2-LISTENER"},
		"TUIC":                   {TUICProfileID, "CONNECTION-PROFILES-TUIC-LISTENER"},
		"AnyTLS":                 {AnyTLSProfileID, "CONNECTION-PROFILES-ANYTLS-LISTENER"},
	}[purpose]
	if want.id == "" || len(result.Profiles) != len(registryDefinitions) {
		return false
	}
	for _, profile := range result.Profiles {
		if profile.ID == want.id {
			if profile.Health.Code != want.code || profile.Health.Outcome == Healthy || profile.Health.Outcome == Disabled {
				return false
			}
		} else if profile.Health.Outcome != Healthy && profile.Health.Outcome != Disabled {
			return false
		}
	}
	return true
}

func registryPortCorrection(authority RegistryPortCorrectionAuthority) (string, uint16, uint16, string, bool) {
	if authority == nil {
		return "", 0, 0, "", false
	}
	typeOf := reflect.TypeOf(authority)
	if typeOf.Kind() == reflect.Pointer {
		if reflect.ValueOf(authority).IsNil() {
			return "", 0, 0, "", false
		}
		typeOf = typeOf.Elem()
	}
	if typeOf.PkgPath() != "github.com/albertloky/SBXR/internal/networkpolicy" || typeOf.Name() != "PortCorrectionAuthority" {
		return "", 0, 0, "", false
	}
	return authority.ConnectionProfilesPortCorrection()
}

func registryLifecycleRevisions(current, candidate RegistryViewRequest, fresh bool) bool {
	all := func(request RegistryViewRequest, revision uint64) bool {
		return request.Reality.Revision == revision && request.XHTTP.Revision == revision && request.WebSocket.Revision == revision && request.Hysteria2.Revision == revision && request.TUIC.Revision == revision && request.AnyTLS.Revision == revision
	}
	if fresh {
		return all(current, 0) && all(candidate, 1)
	}
	if registryProfileSetup(current, candidate) {
		return all(current, current.Reality.Revision) && all(candidate, current.Reality.Revision+1)
	}
	return all(current, current.Reality.Revision) && all(candidate, current.Reality.Revision)
}

func publicationIDs(source PublicationSource) []ProfileID {
	profiles := source.Profiles()
	ids := make([]ProfileID, len(profiles))
	for index, profile := range profiles {
		ids[index] = profile.ID
	}
	return ids
}

func registryEnablementChange(current, candidate RegistryViewRequest) (ProfileID, bool, bool) {
	currentFacts, candidateFacts := current, candidate
	currentFacts.Exposure, candidateFacts.Exposure = nil, nil
	currentFacts.XHTTP.RouteHealth, candidateFacts.XHTTP.RouteHealth = cloudflaretunnel.XHTTPRouteHealth{}, cloudflaretunnel.XHTTPRouteHealth{}
	currentFacts.WebSocket.RouteHealth, candidateFacts.WebSocket.RouteHealth = cloudflaretunnel.WebSocketRouteHealth{}, cloudflaretunnel.WebSocketRouteHealth{}
	currentFacts.Hysteria2.Network, candidateFacts.Hysteria2.Network = nil, nil
	currentFacts.TUIC.Network, candidateFacts.TUIC.Network = nil, nil
	currentFacts.AnyTLS.Network, candidateFacts.AnyTLS.Network = nil, nil
	currentFacts.Reality.Enabled, candidateFacts.Reality.Enabled = false, false
	currentFacts.XHTTP.Enabled, candidateFacts.XHTTP.Enabled = false, false
	currentFacts.WebSocket.Enabled, candidateFacts.WebSocket.Enabled = false, false
	currentFacts.Hysteria2.Enabled, candidateFacts.Hysteria2.Enabled = false, false
	currentFacts.TUIC.Enabled, candidateFacts.TUIC.Enabled = false, false
	currentFacts.AnyTLS.Enabled, candidateFacts.AnyTLS.Enabled = false, false
	if !reflect.DeepEqual(currentFacts, candidateFacts) {
		return "", false, false
	}
	changes := []struct {
		id                 ProfileID
		current, candidate bool
	}{
		{VLESSRealityVisionProfileID, current.Reality.Enabled, candidate.Reality.Enabled},
		{VLESSXHTTPProfileID, current.XHTTP.Enabled, candidate.XHTTP.Enabled},
		{VLESSWebSocketProfileID, current.WebSocket.Enabled, candidate.WebSocket.Enabled},
		{Hysteria2ProfileID, current.Hysteria2.Enabled, candidate.Hysteria2.Enabled},
		{TUICProfileID, current.TUIC.Enabled, candidate.TUIC.Enabled},
		{AnyTLSProfileID, current.AnyTLS.Enabled, candidate.AnyTLS.Enabled},
	}
	var changed *struct {
		id                 ProfileID
		current, candidate bool
	}
	for index := range changes {
		if changes[index].current != changes[index].candidate {
			if changed != nil {
				return "", false, false
			}
			changed = &changes[index]
		}
	}
	if changed == nil {
		return "", false, false
	}
	return changed.id, changed.candidate, true
}

func registryChange(current, candidate RegistryViewRequest, repair, freshInstallation, corrected, releaseUpdate, profileSetup bool, correctionPurpose string, correctionPort, correctionCandidate uint16, correctionProtocol string) (string, systemchanges.MutationClass, bool) {
	if profileSetup && !repair && !freshInstallation && !corrected && !releaseUpdate {
		return "set up all five deferred profiles together", systemchanges.CloudflareProfileSetupMutation, true
	}
	if releaseUpdate && !repair && !freshInstallation && !corrected && reflect.DeepEqual(registryComparable(current), registryComparable(candidate)) {
		return "regenerate the complete registry for the freshly verified release", systemchanges.UpdateMutation, true
	}
	if repair && reflect.DeepEqual(registryComparable(current), registryComparable(candidate)) {
		return "repair the current proven Desired State", systemchanges.RepairMutation, true
	}
	if id, enabling, ok := registryEnablementChange(current, candidate); ok {
		action := "disable"
		if enabling {
			action = "re-enable"
		}
		return fmt.Sprintf("%s %s", action, id), systemchanges.SettingChangeMutation, true
	}
	currentFacts, candidateFacts := registryComparable(current), registryComparable(candidate)
	if freshInstallation {
		candidateFacts.Reality.Revision, candidateFacts.XHTTP.Revision, candidateFacts.WebSocket.Revision = 0, 0, 0
		candidateFacts.Hysteria2.Revision, candidateFacts.TUIC.Revision, candidateFacts.AnyTLS.Revision = 0, 0, 0
	}
	currentPorts, candidatePorts := registryPorts(currentFacts), registryPorts(candidateFacts)
	clearRegistryPorts(&currentFacts)
	clearRegistryPorts(&candidateFacts)
	if freshInstallation && !reflect.DeepEqual(currentPorts, candidatePorts) && reflect.DeepEqual(currentFacts, candidateFacts) {
		return "replace the reviewed profile ports", systemchanges.SettingChangeMutation, true
	}
	if corrected && reviewedPortCorrection(currentPorts, candidatePorts, correctionPurpose, correctionPort, correctionCandidate, correctionProtocol) && reflect.DeepEqual(currentFacts, candidateFacts) {
		return "change the one reviewed conflicted profile port", systemchanges.SettingChangeMutation, true
	}
	currentFacts, candidateFacts = registryComparable(current), registryComparable(candidate)
	changedCredentials := registryCredentialChanges(currentFacts, candidateFacts)
	clearRegistryCredentials(&currentFacts)
	clearRegistryCredentials(&candidateFacts)
	if (changedCredentials == 1 || changedCredentials == len(registryDefinitions)) && reflect.DeepEqual(currentFacts, candidateFacts) {
		action := "rotate one profile credential"
		if changedCredentials == len(registryDefinitions) {
			action = "replace all profile credentials together"
		}
		return action, systemchanges.RotationMutation, true
	}
	return "", "", false
}

func registryProfileSetup(current, candidate RegistryViewRequest) bool {
	if !revisionOneRegistry(current) || registryLifecycles(candidate) != enabledRegistryLifecycles() || candidate.Reality.Revision != current.Reality.Revision+1 || candidate.ClientAddress != current.ClientAddress {
		return false
	}
	currentReality, candidateReality := current.Reality, candidate.Reality
	currentReality.Revision, candidateReality.Revision = 0, 0
	return reflect.DeepEqual(currentReality, candidateReality)
}

func reviewedPortCorrection(current, candidate [6]uint16, purpose string, port, replacement uint16, protocol string) bool {
	purposes := [6]string{"VLESS REALITY Vision", "VLESS XHTTP origin", "VLESS WebSocket origin", "Hysteria2", "TUIC", "AnyTLS"}
	protocols := [6]string{"TCP", "TCP", "TCP", "UDP", "UDP", "TCP"}
	changed := -1
	for index := range current {
		if current[index] != candidate[index] {
			if changed >= 0 {
				return false
			}
			changed = index
		}
	}
	return changed >= 0 && purposes[changed] == purpose && protocols[changed] == protocol && current[changed] == port && candidate[changed] == replacement
}

func registryComparable(request RegistryViewRequest) RegistryViewRequest {
	request.Exposure = nil
	request.XHTTP.RouteHealth = cloudflaretunnel.XHTTPRouteHealth{}
	request.WebSocket.RouteHealth = cloudflaretunnel.WebSocketRouteHealth{}
	request.Hysteria2.Network, request.TUIC.Network, request.AnyTLS.Network = nil, nil, nil
	request.Hysteria2.Profiles = nil
	request.Reality.reviewedAlternative, request.XHTTP.reviewedAlternative, request.WebSocket.reviewedAlternative = false, false, false
	request.Hysteria2.reviewedAlternative, request.TUIC.reviewedAlternative, request.AnyTLS.reviewedAlternative = false, false, false
	return request
}

func registryPorts(request RegistryViewRequest) [6]uint16 {
	return [6]uint16{request.Reality.Port, request.XHTTP.OriginPort, request.WebSocket.OriginPort, request.Hysteria2.Port, request.TUIC.Port, request.AnyTLS.Port}
}

func clearRegistryPorts(request *RegistryViewRequest) {
	request.Reality.Port, request.XHTTP.OriginPort, request.WebSocket.OriginPort = 0, 0, 0
	request.Hysteria2.Port, request.TUIC.Port, request.AnyTLS.Port = 0, 0, 0
	request.Hysteria2.DirectTLS, request.TUIC.DirectTLS, request.AnyTLS.DirectTLS = DirectTLSContribution{}, DirectTLSContribution{}, DirectTLSContribution{}
}

func registryCredentialChanges(current, candidate RegistryViewRequest) int {
	changes := 0
	for _, changed := range []bool{
		current.Reality.Credentials != candidate.Reality.Credentials,
		current.XHTTP.Credentials != candidate.XHTTP.Credentials,
		current.WebSocket.Credentials != candidate.WebSocket.Credentials,
		current.Hysteria2.Credentials != candidate.Hysteria2.Credentials,
		current.TUIC.Credentials != candidate.TUIC.Credentials,
		current.AnyTLS.Credentials != candidate.AnyTLS.Credentials,
	} {
		if changed {
			changes++
		}
	}
	return changes
}

func clearRegistryCredentials(request *RegistryViewRequest) {
	request.Reality.Credentials, request.XHTTP.Credentials, request.WebSocket.Credentials = RealityCredentials{}, XHTTPCredentials{}, WebSocketCredentials{}
	request.Hysteria2.Credentials, request.TUIC.Credentials, request.AnyTLS.Credentials = Hysteria2Credentials{}, TUICCredentials{}, AnyTLSCredentials{}
}

func validateRegistryCandidate(request RegistryViewRequest) *Health {
	if failure := validateRegistryLifecycles(request); failure != nil {
		return failure
	}
	address, err := netip.ParseAddr(request.ClientAddress)
	if err != nil || !address.IsGlobalUnicast() || request.Reality.Revision != request.XHTTP.Revision || request.Reality.Revision != request.WebSocket.Revision || request.Reality.Revision != request.Hysteria2.Revision || request.Reality.Revision != request.TUIC.Revision || request.Reality.Revision != request.AnyTLS.Revision || request.Hysteria2.DestinationIP != request.ClientAddress || request.TUIC.DestinationIP != request.ClientAddress || request.AnyTLS.DestinationIP != request.ClientAddress || !validRegistryExposureAuthority(request.Exposure) || !validRegistryExposureBinding(request.Exposure, request.Reality.Revision) {
		health := registryPlanFailure("INPUT", "the client address, direct destinations, or typed exposure is invalid")
		return &health
	}
	if failure := registryExposureFailure(request); failure != nil {
		return failure
	}
	request = reviewedRegistryRequest(request)
	checks := []func() *Health{
		func() *Health {
			copy := request.Reality
			copy.Enabled = false
			_, _, failure := disabledRealityProfile(copy)
			return failure
		},
		func() *Health {
			copy := request.XHTTP
			copy.Enabled = false
			_, _, failure := disabledXHTTPProfile(copy)
			return failure
		},
		func() *Health {
			copy := request.WebSocket
			copy.Enabled = false
			_, _, failure := disabledWebSocketProfile(copy)
			return failure
		},
		func() *Health {
			copy := request.Hysteria2
			copy.Enabled = false
			_, _, failure := disabledHysteria2Profile(copy)
			return failure
		},
		func() *Health {
			copy := request.TUIC
			copy.Enabled = false
			_, _, failure := disabledTUICProfile(copy)
			return failure
		},
		func() *Health {
			copy := request.AnyTLS
			copy.Enabled = false
			_, _, failure := disabledAnyTLSProfile(copy)
			return failure
		},
	}
	for _, check := range checks {
		if failure := check(); failure != nil {
			return failure
		}
	}
	credentials := RegistryCredentials{request.Reality.Credentials, request.XHTTP.Credentials, request.WebSocket.Credentials, request.Hysteria2.Credentials, request.TUIC.Credentials, request.AnyTLS.Credentials}
	if !credentials.Independent() {
		health := registryPlanFailure("CREDENTIALS", "the six profile credentials or the two paths are not independent")
		return &health
	}
	return nil
}

func validateRegistryLifecycles(request RegistryViewRequest) *Health {
	lifecycles := registryLifecycles(request)
	checks := []struct {
		lifecycle state.ProfileLifecycle
		enabled   bool
	}{
		{lifecycles.Reality, request.Reality.Enabled},
		{lifecycles.XHTTP, request.XHTTP.Enabled},
		{lifecycles.WebSocket, request.WebSocket.Enabled},
		{lifecycles.Hysteria2, request.Hysteria2.Enabled},
		{lifecycles.TUIC, request.TUIC.Enabled},
		{lifecycles.AnyTLS, request.AnyTLS.Enabled},
	}
	for _, check := range checks {
		if check.lifecycle == state.ProfileNotSetUp || check.lifecycle == state.ProfileEnabled != check.enabled || check.lifecycle != state.ProfileEnabled && check.lifecycle != state.ProfileDisabled {
			health := registryHealth("CONNECTION-PROFILES-REGISTRY-LIFECYCLE", "a lifecycle state disagrees with profile capability")
			return &health
		}
	}
	return nil
}

func validateRevisionOneRegistry(request RegistryViewRequest) *Health {
	revision := request.Reality.Revision
	deferredAbsent := reflect.DeepEqual(request.XHTTP, XHTTPViewRequest{Revision: revision}) && reflect.DeepEqual(request.WebSocket, WebSocketViewRequest{Revision: revision}) && reflect.DeepEqual(request.Hysteria2, Hysteria2ViewRequest{Revision: revision}) && reflect.DeepEqual(request.TUIC, TUICViewRequest{Revision: revision}) && reflect.DeepEqual(request.AnyTLS, AnyTLSViewRequest{Revision: revision})
	host, port, targetErr := net.SplitHostPort(request.Reality.Target.Address)
	realityValid := request.Reality.Enabled && request.Reality.Port > 0 && targetErr == nil && port == "443" && host == request.Reality.Target.ServerName && validHostname(host) && request.Reality.Fingerprint == "chrome" && request.Reality.XrayVersion == qualifiedXrayVersion && request.Reality.Credentials.valid()
	if !deferredAbsent || !realityValid || request.Lifecycles != revisionOneRegistryLifecycles() {
		health := registryHealth("CONNECTION-PROFILES-REGISTRY-EXPECTED-ABSENCE", "revision 1 contains a deferred setting, credential, listener, route, certificate binding, exposure, or publication placeholder")
		return &health
	}
	return nil
}

func reviewedRegistryRequest(request RegistryViewRequest) RegistryViewRequest {
	request.Reality.reviewedAlternative = request.Reality.Port != 443
	request.XHTTP.reviewedAlternative = request.XHTTP.OriginPort != 11080
	request.WebSocket.reviewedAlternative = request.WebSocket.OriginPort != 11081
	request.Hysteria2.reviewedAlternative = request.Hysteria2.Port != 443
	request.TUIC.reviewedAlternative = request.TUIC.Port != 8443
	request.AnyTLS.reviewedAlternative = request.AnyTLS.Port != 9443
	if request.Hysteria2.reviewedAlternative || request.Reality.reviewedAlternative {
		request.Hysteria2.Network = request.Exposure
	}
	if request.TUIC.reviewedAlternative {
		request.TUIC.Network = request.Exposure
	}
	if request.AnyTLS.reviewedAlternative {
		request.AnyTLS.Network = request.Exposure
	}
	return request
}

func registryConfigurations(request RegistryViewRequest) ([]byte, []byte, Hysteria2ViewRequest) {
	request = reviewedRegistryRequest(request)
	hysteria2 := request.Hysteria2
	hysteria2.Profiles = &SingBoxProfileSet{TUIC: &request.TUIC, AnyTLS: &request.AnyTLS}
	xray, xrayErr := xrayConfiguration(&request.Reality, &request.XHTTP, &request.WebSocket)
	singBox, singBoxErr := singBoxConfiguration(&hysteria2, hysteria2.Profiles)
	if xrayErr != nil || singBoxErr != nil {
		return nil, nil, hysteria2
	}
	return xray, singBox, hysteria2
}

type registryExposureFact struct {
	Address, Protocol string
	Port              uint16
	Present, Valid    bool
}

type registryNetworkBinding struct {
	Revision uint64
	Digest   string
}

func registryNetworkAuthority(authority RegistryExposureAuthority) registryNetworkBinding {
	revision, digest, _ := authority.ConnectionProfilesRegistryBinding()
	return registryNetworkBinding{revision, digest}
}

func registryExposureFacts(authority RegistryExposureAuthority) []registryExposureFact {
	readers := []func() (string, uint16, string, bool, bool){authority.ConnectionProfilesRealityExposure, authority.ConnectionProfilesXHTTPExposure, authority.ConnectionProfilesWebSocketExposure, authority.ConnectionProfilesHysteria2Exposure, authority.ConnectionProfilesTUICExposure, authority.ConnectionProfilesAnyTLSExposure}
	facts := make([]registryExposureFact, 0, len(readers))
	for _, read := range readers {
		address, port, protocol, present, valid := read()
		facts = append(facts, registryExposureFact{address, protocol, port, present, valid})
	}
	return facts
}

func registryPlanFailure(suffix, found string) Health {
	return blockedHealth(Health{Module: "Connection Profiles", Profile: "Registry", Outcome: Failed, Code: "CONNECTION-PROFILES-REGISTRY-PLAN-" + suffix, Problem: "The reviewed profile lifecycle Plan is invalid", Found: found, Required: "one exact reviewed enablement, fresh port selection, credential rotation, proven-lineage repair, or core-update requalification", WhyStopped: "Connection Profiles requires fresh typed authority for every lifecycle change", NextActions: []string{"Build a fresh reviewed Plan", "Check again", "Back"}})
}

func disabledRealityProfile(request ViewRequest) (RegistryProfile, string, *Health) {
	host, port, err := net.SplitHostPort(request.Target.Address)
	valid := err == nil && port == "443" && host == request.Target.ServerName && validHostname(host) && selectedPort(request.Port, 443, request.reviewedAlternative) && request.XrayVersion == qualifiedXrayVersion && request.Fingerprint == "chrome" && request.Credentials.valid()
	return disabledRegistryProfile(VLESSRealityVisionProfileID, "VLESS REALITY Vision", "", request.XrayVersion, request.Credentials.valid(), request, valid)
}

func disabledXHTTPProfile(request XHTTPViewRequest) (RegistryProfile, string, *Health) {
	valid := request.OriginAddress == "127.0.0.1" && selectedPort(request.OriginPort, 11080, request.reviewedAlternative) && request.Mode == state.XHTTPPacketUp && request.XrayVersion == qualifiedXrayVersion && validHostname(request.Hostname) && request.Credentials.valid()
	return disabledRegistryProfile(VLESSXHTTPProfileID, "VLESS XHTTP", request.Hostname, request.XrayVersion, request.Credentials.valid(), request, valid)
}

func disabledWebSocketProfile(request WebSocketViewRequest) (RegistryProfile, string, *Health) {
	valid := request.OriginAddress == "127.0.0.1" && selectedPort(request.OriginPort, 11081, request.reviewedAlternative) && request.XrayVersion == qualifiedXrayVersion && validHostname(request.Hostname) && request.TLSName == request.Hostname && request.HTTPHost == request.Hostname && request.Credentials.valid()
	return disabledRegistryProfile(VLESSWebSocketProfileID, "VLESS WebSocket", request.Hostname, request.XrayVersion, request.Credentials.valid(), request, valid)
}

func disabledHysteria2Profile(request Hysteria2ViewRequest) (RegistryProfile, string, *Health) {
	valid := validDirectProfile(request.DestinationIP, request.ServerName, request.CertificateID, request.CertificatePointer, request.Revision, request.DirectTLS) && selectedPort(request.Port, 443, request.reviewedAlternative) && request.SingBoxVersion == qualifiedSingBoxVersion && request.MasqueradeResponse == "Not Found\n" && request.Credentials.valid()
	return disabledRegistryProfile(Hysteria2ProfileID, "Hysteria2", request.ServerName, request.SingBoxVersion, request.Credentials.valid(), request, valid)
}

func disabledTUICProfile(request TUICViewRequest) (RegistryProfile, string, *Health) {
	valid := validDirectProfile(request.DestinationIP, request.ServerName, request.CertificateID, request.CertificatePointer, request.Revision, request.DirectTLS) && selectedPort(request.Port, 8443, request.reviewedAlternative) && request.SingBoxVersion == qualifiedSingBoxVersion && request.CongestionControl == state.CongestionCubic && !request.ZeroRTT && request.Credentials.valid()
	return disabledRegistryProfile(TUICProfileID, "TUIC", request.ServerName, request.SingBoxVersion, request.Credentials.valid(), request, valid)
}

func disabledAnyTLSProfile(request AnyTLSViewRequest) (RegistryProfile, string, *Health) {
	valid := validDirectProfile(request.DestinationIP, request.ServerName, request.CertificateID, request.CertificatePointer, request.Revision, request.DirectTLS) && selectedPort(request.Port, 9443, request.reviewedAlternative) && request.MinimumSingBoxVersion == anyTLSMinimumSingBoxVersion && request.SingBoxVersion == qualifiedSingBoxVersion && request.UseCorePadding && request.Credentials.valid()
	return disabledRegistryProfile(AnyTLSProfileID, "AnyTLS", request.ServerName, request.SingBoxVersion, request.Credentials.valid(), request, valid)
}

func validDirectProfile(destination, hostname, certificateID, pointer string, revision uint64, directTLS DirectTLSContribution) bool {
	address, err := netip.ParseAddr(destination)
	directRevision, directDestination, directHostname, _, valid := directTLS.SystemChangesDirectTLS()
	return err == nil && address.IsGlobalUnicast() && validHostname(hostname) && certificateID != "" && pointer == directCertificatePointer && valid && directRevision == revision && directDestination == destination && directHostname == hostname
}

func disabledRegistryProfile(id ProfileID, name, hostname, version string, credentialsReady bool, request any, valid bool) (RegistryProfile, string, *Health) {
	encoded, _ := json.Marshal(request)
	digest := sha256.Sum256(encoded)
	if !valid {
		health := blockedHealth(Health{Module: "Connection Profiles", Profile: name, Outcome: Failed, Code: "CONNECTION-PROFILES-REGISTRY-DISABLED-SETTINGS", Problem: "The disabled profile settings are invalid", Found: "a preserved setting or credential is missing or changed", Required: "complete preserved settings and credential for deliberate re-enable", WhyStopped: "Disabled profiles retain valid settings without exposure", NextActions: []string{"Check again", "Back"}})
		return RegistryProfile{ID: id, Name: name, Hostname: hostname, QualifiedVersion: version, DefaultEnabled: true, CredentialsReady: credentialsReady, SelectedListener: disabledSelectedListener(id, request)}, hex.EncodeToString(digest[:]), &health
	}
	health := Health{Module: "Connection Profiles", Profile: name, Outcome: Disabled, Code: "CONNECTION-PROFILES-REGISTRY-DISABLED", Found: "deliberately disabled with exposure and publication omitted", Required: "no active listener or Tunnel route", NextActions: []string{"Build re-enable Plan", "Back"}}
	return RegistryProfile{ID: id, Name: name, Hostname: hostname, QualifiedVersion: version, DefaultEnabled: true, CredentialsReady: credentialsReady, SelectedListener: disabledSelectedListener(id, request), Health: health}, hex.EncodeToString(digest[:]), nil
}

func selectedRegistryListener(request RegistryViewRequest, id ProfileID) Listener {
	switch id {
	case VLESSRealityVisionProfileID:
		return Listener{"public", request.Reality.Port, "TCP"}
	case VLESSXHTTPProfileID:
		return Listener{"loopback", request.XHTTP.OriginPort, "TCP"}
	case VLESSWebSocketProfileID:
		return Listener{"loopback", request.WebSocket.OriginPort, "TCP"}
	case Hysteria2ProfileID:
		return Listener{"public", request.Hysteria2.Port, "UDP"}
	case TUICProfileID:
		return Listener{"public", request.TUIC.Port, "UDP"}
	case AnyTLSProfileID:
		return Listener{"public", request.AnyTLS.Port, "TCP"}
	}
	return Listener{}
}

func disabledSelectedListener(id ProfileID, request any) Listener {
	switch value := request.(type) {
	case ViewRequest:
		return Listener{"public", value.Port, "TCP"}
	case XHTTPViewRequest:
		return Listener{"loopback", value.OriginPort, "TCP"}
	case WebSocketViewRequest:
		return Listener{"loopback", value.OriginPort, "TCP"}
	case Hysteria2ViewRequest:
		return Listener{"public", value.Port, "UDP"}
	case TUICViewRequest:
		return Listener{"public", value.Port, "UDP"}
	case AnyTLSViewRequest:
		return Listener{"public", value.Port, "TCP"}
	}
	return Listener{}
}

func validRegistryExposureAuthority(authority RegistryExposureAuthority) bool {
	if authority == nil {
		return false
	}
	typeOf := reflect.TypeOf(authority)
	if typeOf.Kind() == reflect.Pointer {
		if reflect.ValueOf(authority).IsNil() {
			return false
		}
		typeOf = typeOf.Elem()
	}
	return typeOf.PkgPath() == "github.com/albertloky/SBXR/internal/networkpolicy" && typeOf.Name() == "ListenerContribution"
}

func validRegistryExposureBinding(authority RegistryExposureAuthority, revision uint64) bool {
	boundRevision, digest, valid := authority.ConnectionProfilesRegistryBinding()
	return valid && boundRevision == revision && sha256Text.MatchString(digest)
}

func registryExposureFailure(request RegistryViewRequest) *Health {
	tests := []struct {
		id      ProfileID
		enabled bool
		want    Listener
		read    func() (string, uint16, string, bool, bool)
	}{
		{registryDefinitions[0].id, request.Reality.Enabled, Listener{"public", request.Reality.Port, "TCP"}, request.Exposure.ConnectionProfilesRealityExposure},
		{registryDefinitions[1].id, request.XHTTP.Enabled, Listener{request.XHTTP.OriginAddress, request.XHTTP.OriginPort, "TCP"}, request.Exposure.ConnectionProfilesXHTTPExposure},
		{registryDefinitions[2].id, request.WebSocket.Enabled, Listener{request.WebSocket.OriginAddress, request.WebSocket.OriginPort, "TCP"}, request.Exposure.ConnectionProfilesWebSocketExposure},
		{registryDefinitions[3].id, request.Hysteria2.Enabled, Listener{"public", request.Hysteria2.Port, "UDP"}, request.Exposure.ConnectionProfilesHysteria2Exposure},
		{registryDefinitions[4].id, request.TUIC.Enabled, Listener{"public", request.TUIC.Port, "UDP"}, request.Exposure.ConnectionProfilesTUICExposure},
		{registryDefinitions[5].id, request.AnyTLS.Enabled, Listener{"public", request.AnyTLS.Port, "TCP"}, request.Exposure.ConnectionProfilesAnyTLSExposure},
	}
	for _, test := range tests {
		address, port, protocol, present, valid := test.read()
		if !valid || test.enabled != present || present && (Listener{address, port, protocol}) != test.want {
			health := blockedHealth(Health{Module: "Connection Profiles", Profile: string(test.id), Outcome: Failed, Code: "CONNECTION-PROFILES-REGISTRY-EXPOSURE", Problem: "The reviewed profile exposure does not agree", Found: fmt.Sprintf("%s/%d/%s present=%t", address, port, protocol, present), Required: fmt.Sprintf("enabled=%t with exact approved exposure", test.enabled), WhyStopped: "Connection Profiles never reports stale exposure as disabled or publishable", NextActions: []string{"Check again", "Back"}})
			return &health
		}
	}
	return nil
}

func registryPublication(request RegistryViewRequest) PublicationSource {
	lifecycles := registryLifecycles(request)
	all := []struct {
		enabled   bool
		lifecycle state.ProfileLifecycle
		profile   PublicationProfile
	}{
		{request.Reality.Enabled, lifecycles.Reality, PublicationProfile{ID: VLESSRealityVisionProfileID, Name: registryDefinitions[0].name, Address: request.ClientAddress, Port: request.Reality.Port, ServerName: request.Reality.Target.ServerName, Transport: "RAW", Security: "REALITY", UUID: state.NewClientAccessValue(request.Reality.Credentials.uuid.value), ShortID: state.NewClientAccessValue(request.Reality.Credentials.shortID.value), PublicKey: request.Reality.Credentials.publicKey.value, Fingerprint: request.Reality.Fingerprint, Flow: "xtls-rprx-vision"}},
		{request.XHTTP.Enabled, lifecycles.XHTTP, PublicationProfile{ID: VLESSXHTTPProfileID, Name: registryDefinitions[1].name, Address: request.XHTTP.Hostname, Port: 443, Hostname: request.XHTTP.Hostname, Transport: "XHTTP", Security: "TLS", UUID: state.NewClientAccessValue(request.XHTTP.Credentials.uuid.value), Path: state.NewClientAccessValue(request.XHTTP.Credentials.path.value), XHTTPServerMode: request.XHTTP.Mode}},
		{request.WebSocket.Enabled, lifecycles.WebSocket, PublicationProfile{ID: VLESSWebSocketProfileID, Name: registryDefinitions[2].name, Address: request.WebSocket.Hostname, Port: 443, Hostname: request.WebSocket.Hostname, Transport: "WebSocket", Security: "TLS", UUID: state.NewClientAccessValue(request.WebSocket.Credentials.uuid.value), Path: state.NewClientAccessValue(request.WebSocket.Credentials.path.value), HTTPHost: request.WebSocket.HTTPHost, TLSName: request.WebSocket.TLSName}},
		{request.Hysteria2.Enabled, lifecycles.Hysteria2, PublicationProfile{ID: Hysteria2ProfileID, Name: registryDefinitions[3].name, Address: request.ClientAddress, Port: request.Hysteria2.Port, ServerName: request.Hysteria2.ServerName, Transport: "QUIC", Security: "TLS", Password: state.NewClientAccessValue(request.Hysteria2.Credentials.password.value), Obfuscation: request.Hysteria2.Credentials.obfuscation, ObfuscationSecret: state.NewClientAccessValue(request.Hysteria2.Credentials.obfuscationSecret.value)}},
		{request.TUIC.Enabled, lifecycles.TUIC, PublicationProfile{ID: TUICProfileID, Name: registryDefinitions[4].name, Address: request.ClientAddress, Port: request.TUIC.Port, ServerName: request.TUIC.ServerName, Transport: "QUIC", Security: "TLS", UUID: state.NewClientAccessValue(request.TUIC.Credentials.uuid.value), Password: state.NewClientAccessValue(request.TUIC.Credentials.password.value), CongestionControl: request.TUIC.CongestionControl}},
		{request.AnyTLS.Enabled, lifecycles.AnyTLS, PublicationProfile{ID: AnyTLSProfileID, Name: registryDefinitions[5].name, Address: request.ClientAddress, Port: request.AnyTLS.Port, ServerName: request.AnyTLS.ServerName, Transport: "TCP", Security: "TLS", Password: state.NewClientAccessValue(request.AnyTLS.Credentials.password.value)}},
	}
	var source PublicationSource
	for _, item := range all {
		if item.enabled {
			source.profiles = append(source.profiles, item.profile)
		} else {
			source.omissions = append(source.omissions, publicationOmission(item.profile.ID, item.lifecycle))
		}
	}
	return source
}

func publicationLifecycle(profiles state.ConnectionProfiles, id ProfileID) state.ProfileLifecycle {
	lifecycle := profileLifecycle(profiles, id)
	if lifecycle != "" {
		return lifecycle
	}
	if profileEnabled(profiles, id) {
		return state.ProfileEnabled
	}
	return state.ProfileDisabled
}

func publicationOmission(id ProfileID, lifecycle state.ProfileLifecycle) PublicationOmission {
	for _, definition := range registryDefinitions {
		if definition.id == id {
			return PublicationOmission{ID: id, Name: definition.name, Lifecycle: lifecycle}
		}
	}
	return PublicationOmission{ID: id, Lifecycle: lifecycle}
}

func registryHealth(code, found string) Health {
	return blockedHealth(Health{Time: time.Time{}, Module: "Connection Profiles", Profile: "Registry", Outcome: Failed, Code: code, Problem: "The canonical six-profile registry is invalid", Found: found, Required: "exactly the six fixed Connection Profiles", WhyStopped: "Connection Profiles rejects a partial or extended registry", NextActions: []string{"Check again", "Back"}})
}

func registryInvalidResult(request RegistryViewRequest, health Health) RegistryViewResult {
	definitions := []struct {
		enabled, credentials bool
		hostname, version    string
	}{
		{request.Reality.Enabled, request.Reality.Credentials.valid(), "", request.Reality.XrayVersion},
		{request.XHTTP.Enabled, request.XHTTP.Credentials.valid(), request.XHTTP.Hostname, request.XHTTP.XrayVersion},
		{request.WebSocket.Enabled, request.WebSocket.Credentials.valid(), request.WebSocket.Hostname, request.WebSocket.XrayVersion},
		{request.Hysteria2.Enabled, request.Hysteria2.Credentials.valid(), request.Hysteria2.ServerName, request.Hysteria2.SingBoxVersion},
		{request.TUIC.Enabled, request.TUIC.Credentials.valid(), request.TUIC.ServerName, request.TUIC.SingBoxVersion},
		{request.AnyTLS.Enabled, request.AnyTLS.Credentials.valid(), request.AnyTLS.ServerName, request.AnyTLS.SingBoxVersion},
	}
	profiles := make([]RegistryProfile, len(registryDefinitions))
	lifecycles := registryLifecycles(request)
	states := [...]state.ProfileLifecycle{lifecycles.Reality, lifecycles.XHTTP, lifecycles.WebSocket, lifecycles.Hysteria2, lifecycles.TUIC, lifecycles.AnyTLS}
	for index, definition := range registryDefinitions {
		facts := definitions[index]
		profiles[index] = RegistryProfile{ID: definition.id, Name: definition.name, Hostname: facts.hostname, QualifiedVersion: facts.version, Enabled: facts.enabled, DefaultEnabled: true, CredentialsReady: facts.credentials, SelectedListener: selectedRegistryListener(request, definition.id), Health: health, Lifecycle: states[index]}
	}
	return RegistryViewResult{Profiles: profiles, Health: health, Repairable: repairableRegistryCode(health.Code)}
}

func registryCapabilityFailure(core, found string) Health {
	return blockedHealth(Health{Module: "Connection Profiles", Profile: "Registry", Outcome: Failed, Code: "CONNECTION-PROFILES-REGISTRY-CAPABILITY", Problem: "The shared " + core + " service capability is broader than required", Found: found, Required: "CAP_NET_BIND_SERVICE only while an enabled listener uses a port below 1024", WhyStopped: "Disabled profiles cannot leave unnecessary service privilege", NextActions: []string{"Check again", "Back"}})
}

func markRegistryCoreFailure(profiles []RegistryProfile, health Health) {
	for index := range profiles {
		profiles[index].Health = health
	}
}
