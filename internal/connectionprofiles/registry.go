package connectionprofiles

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"time"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/state"
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
	id       ProfileID
	name     string
	listener Listener
	exposure Listener
}

var registryDefinitions = [...]registryDefinition{
	{VLESSRealityVisionProfileID, "VLESS REALITY Vision", Listener{"public", 443, "TCP"}, Listener{"public", 443, "TCP"}},
	{VLESSXHTTPProfileID, "VLESS XHTTP", Listener{"loopback", 11080, "TCP"}, Listener{"127.0.0.1", 11080, "TCP"}},
	{VLESSWebSocketProfileID, "VLESS WebSocket", Listener{"loopback", 11081, "TCP"}, Listener{"127.0.0.1", 11081, "TCP"}},
	{Hysteria2ProfileID, "Hysteria2", Listener{"public", 443, "UDP"}, Listener{"public", 443, "UDP"}},
	{TUICProfileID, "TUIC", Listener{"public", 8443, "UDP"}, Listener{"public", 8443, "UDP"}},
	{AnyTLSProfileID, "AnyTLS", Listener{"public", 9443, "TCP"}, Listener{"public", 9443, "TCP"}},
}

type RegistryCredentials struct {
	Reality   RealityCredentials
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
	reality, realityErr := GenerateRealityCredentials()
	xhttp, xhttpErr := GenerateXHTTPCredentials()
	websocket, websocketErr := GenerateWebSocketCredentials()
	hysteria2, hysteria2Err := GenerateHysteria2Credentials()
	tuic, tuicErr := GenerateTUICCredentials()
	anyTLS, anyTLSErr := GenerateAnyTLSCredentials()
	credentials := RegistryCredentials{reality, xhttp, websocket, hysteria2, tuic, anyTLS}
	if errors.Join(realityErr, xhttpErr, websocketErr, hysteria2Err, tuicErr, anyTLSErr) != nil || !credentials.Independent() {
		return RegistryCredentials{}, errors.New("six independent Connection Profile credentials could not be generated")
	}
	return credentials, nil
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
	return request, nil
}

type RegistryExposureAuthority interface {
	ConnectionProfilesRegistryBinding() (revision uint64, digest string, valid bool)
	ConnectionProfilesRealityExposure() (address string, port uint16, protocol string, present, valid bool)
	ConnectionProfilesXHTTPExposure() (address string, port uint16, protocol string, present, valid bool)
	ConnectionProfilesWebSocketExposure() (address string, port uint16, protocol string, present, valid bool)
	ConnectionProfilesHysteria2Exposure() (address string, port uint16, protocol string, present, valid bool)
	ConnectionProfilesTUICExposure() (address string, port uint16, protocol string, present, valid bool)
	ConnectionProfilesAnyTLSExposure() (address string, port uint16, protocol string, present, valid bool)
}

type CoreCapabilityObservation struct {
	CheckedAt             time.Time
	XrayNone, SingBoxNone bool
}

type RegistryCapabilityHost interface {
	ObserveCoreCapabilities(context.Context) CoreCapabilityObservation
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
}

type RegistryProfile struct {
	ID                                        ProfileID
	Name, Hostname, QualifiedVersion          string
	Enabled, DefaultEnabled, CredentialsReady bool
	SelectedListener, Listener                Listener
	Health                                    Health
}

type PublicationProfile struct {
	ID                                                 ProfileID
	Address, Hostname, ServerName, Transport, Security string
	Port                                               uint16
	UUID, Password, Path, ShortID                      state.ClientAccessValue
	PublicKey, Fingerprint, Flow, HTTPHost, TLSName    string
	XHTTPServerMode                                    state.XHTTPMode
}

type PublicationOmission struct{ ID ProfileID }

type PublicationSource struct {
	profiles  []PublicationProfile
	omissions []PublicationOmission
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

type RegistryViewResult struct {
	Profiles       []RegistryProfile
	Publication    PublicationSource
	Health         Health
	VolatileSHA256 string
}

type RegistryPlanRequest struct {
	Current, Candidate                                 RegistryViewRequest
	ChangeSet, StartingStateSHA256, DesiredStateSHA256 string
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
		appendProfile(RegistryProfile{ID: VLESSRealityVisionProfileID, Name: reality.Profile.Name, QualifiedVersion: reality.Profile.XrayVersion, Enabled: true, DefaultEnabled: true, CredentialsReady: reality.Profile.CredentialsReady, SelectedListener: selectedRegistryListener(VLESSRealityVisionProfileID), Listener: reality.Profile.Listener, Health: reality.Health}, reality.VolatileSHA256)
	}
	if !request.XHTTP.Enabled {
		profile, digest, health := disabledXHTTPProfile(request.XHTTP)
		if health != nil {
			profile.Health = *health
		}
		appendProfile(profile, digest)
	} else {
		xhttp := module.ViewXHTTP(ctx, request.XHTTP)
		if xhttp.Health.Outcome == Healthy && !request.Reality.Enabled && !xhttp.observation.NoCapabilities {
			xhttp.Health = registryCapabilityFailure("Xray", "REALITY is disabled but xray.service still has capabilities")
		}
		appendProfile(RegistryProfile{ID: VLESSXHTTPProfileID, Name: xhttp.Profile.Name, Hostname: xhttp.Profile.Hostname, QualifiedVersion: xhttp.Profile.XrayVersion, Enabled: true, DefaultEnabled: true, CredentialsReady: xhttp.Profile.CredentialsReady, SelectedListener: selectedRegistryListener(VLESSXHTTPProfileID), Listener: xhttp.Profile.Listener, Health: xhttp.Health}, xhttp.VolatileSHA256)
	}
	if !request.WebSocket.Enabled {
		profile, digest, health := disabledWebSocketProfile(request.WebSocket)
		if health != nil {
			profile.Health = *health
		}
		appendProfile(profile, digest)
	} else {
		websocket := module.ViewWebSocket(ctx, request.WebSocket)
		if websocket.Health.Outcome == Healthy && !request.Reality.Enabled && !websocket.observation.NoCapabilities {
			websocket.Health = registryCapabilityFailure("Xray", "REALITY is disabled but xray.service still has capabilities")
		}
		appendProfile(RegistryProfile{ID: VLESSWebSocketProfileID, Name: websocket.Profile.Name, Hostname: websocket.Profile.Hostname, QualifiedVersion: websocket.Profile.XrayVersion, Enabled: true, DefaultEnabled: true, CredentialsReady: websocket.Profile.CredentialsReady, SelectedListener: selectedRegistryListener(VLESSWebSocketProfileID), Listener: websocket.Profile.Listener, Health: websocket.Health}, websocket.VolatileSHA256)
	}
	if !request.Hysteria2.Enabled {
		profile, digest, health := disabledHysteria2Profile(request.Hysteria2)
		if health != nil {
			profile.Health = *health
		}
		appendProfile(profile, digest)
	} else {
		hysteria2 := module.ViewHysteria2(ctx, request.Hysteria2)
		appendProfile(RegistryProfile{ID: Hysteria2ProfileID, Name: hysteria2.Profile.Name, Hostname: hysteria2.Profile.ServerName, QualifiedVersion: hysteria2.Profile.SingBoxVersion, Enabled: true, DefaultEnabled: true, CredentialsReady: hysteria2.Profile.CredentialsReady, SelectedListener: selectedRegistryListener(Hysteria2ProfileID), Listener: hysteria2.Profile.Listener, Health: hysteria2.Health}, hysteria2.VolatileSHA256)
	}
	if !request.TUIC.Enabled {
		profile, digest, health := disabledTUICProfile(request.TUIC)
		if health != nil {
			profile.Health = *health
		}
		appendProfile(profile, digest)
	} else {
		tuic := module.ViewTUIC(ctx, request.Hysteria2, request.TUIC)
		appendProfile(RegistryProfile{ID: TUICProfileID, Name: tuic.Profile.Name, Hostname: tuic.Profile.ServerName, QualifiedVersion: tuic.Profile.SingBoxVersion, Enabled: true, DefaultEnabled: true, CredentialsReady: tuic.Profile.CredentialsReady, SelectedListener: selectedRegistryListener(TUICProfileID), Listener: tuic.Profile.Listener, Health: tuic.Health}, tuic.VolatileSHA256)
	}
	if !request.AnyTLS.Enabled {
		profile, digest, health := disabledAnyTLSProfile(request.AnyTLS)
		if health != nil {
			profile.Health = *health
		}
		appendProfile(profile, digest)
	} else {
		anyTLS := module.ViewAnyTLS(ctx, request.Hysteria2, request.TUIC, request.AnyTLS)
		appendProfile(RegistryProfile{ID: AnyTLSProfileID, Name: anyTLS.Profile.Name, Hostname: anyTLS.Profile.ServerName, QualifiedVersion: anyTLS.Profile.SingBoxVersion, Enabled: true, DefaultEnabled: true, CredentialsReady: anyTLS.Profile.CredentialsReady, SelectedListener: selectedRegistryListener(AnyTLSProfileID), Listener: anyTLS.Profile.Listener, Health: anyTLS.Health}, anyTLS.VolatileSHA256)
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
		return RegistryViewResult{Profiles: results, Health: *firstFailure, VolatileSHA256: hex.EncodeToString(digest[:])}
	}
	return RegistryViewResult{Profiles: results, Publication: registryPublication(request), Health: Health{Module: "Connection Profiles", Profile: "Registry", Outcome: Healthy, Code: "CONNECTION-PROFILES-REGISTRY-HEALTHY", NextActions: []string{"Build Plan", "Back"}}, VolatileSHA256: hex.EncodeToString(digest[:])}
}

func (module Interface) PlanRegistry(ctx context.Context, request RegistryPlanRequest) PlanResult {
	current := module.ViewRegistry(ctx, request.Current)
	if current.Health.Outcome != Healthy {
		return PlanResult{Health: current.Health}
	}
	id, enabling, validChange := registryEnablementChange(request.Current, request.Candidate)
	if !validChange || request.Current.Reality.Revision != request.Candidate.Reality.Revision || !planName.MatchString(request.ChangeSet) || !sha256Text.MatchString(request.StartingStateSHA256) || !sha256Text.MatchString(request.DesiredStateSHA256) || request.StartingStateSHA256 == request.DesiredStateSHA256 {
		return PlanResult{Health: registryPlanFailure("STATE", "the request does not contain one exact enablement change and State binding")}
	}
	if failure := validateRegistryCandidate(request.Candidate); failure != nil {
		return PlanResult{Health: *failure}
	}
	xray, singBox, hysteria2 := registryConfigurations(request.Candidate)
	if len(xray) == 0 || len(singBox) == 0 {
		return PlanResult{Health: registryPlanFailure("CONFIGURATION", "the enablement change would remove a complete proxy-core configuration")}
	}
	action := "disable"
	if enabling {
		action = "re-enable"
	}
	publication := registryPublication(request.Candidate)
	plan, failure := module.buildSingBoxPlan(ctx, singBoxPlanSpec{
		profile: "REGISTRY", description: fmt.Sprintf("%s %s through the canonical six-profile registry; preserve settings and credentials, update exact exposure and publication omission, then restore both prior configurations on rollback", action, id),
		xrayVersion: request.Candidate.Reality.XrayVersion, singBoxVersion: request.Candidate.AnyTLS.SingBoxVersion, revision: request.Candidate.Reality.Revision,
		changeSet: request.ChangeSet, startingState: request.StartingStateSHA256, desiredState: request.DesiredStateSHA256,
		xray: xray, singBox: singBox, volatileInputs: current.VolatileSHA256,
		binding: struct {
			Request   RegistryPlanRequest
			Network   registryNetworkBinding
			Exposure  []registryExposureFact
			Published []ProfileID
			Omissions []PublicationOmission
			Profile   ProfileID
			Enabled   bool
		}{request, registryNetworkAuthority(request.Candidate.Exposure), registryExposureFacts(request.Candidate.Exposure), publicationIDs(publication), publication.Omissions(), id, enabling},
		reality: request.Candidate.Reality, xhttp: &request.Candidate.XHTTP, websocket: &request.Candidate.WebSocket,
		hysteria2: &hysteria2, tuic: &request.Candidate.TUIC, anyTLS: &request.Candidate.AnyTLS,
	})
	if failure != "" {
		return PlanResult{Health: registryPlanFailure(failure, "native validation, protected binding, or the reversible transaction failed")}
	}
	return PlanResult{Plan: plan, Health: Health{Module: "Connection Profiles", Profile: "Registry", Outcome: Healthy, Code: "CONNECTION-PROFILES-REGISTRY-PLAN-READY", NextActions: []string{"Review Plan", "Back"}}}
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

func validateRegistryCandidate(request RegistryViewRequest) *Health {
	address, err := netip.ParseAddr(request.ClientAddress)
	if err != nil || !address.IsGlobalUnicast() || request.Reality.Revision != request.XHTTP.Revision || request.Reality.Revision != request.WebSocket.Revision || request.Reality.Revision != request.Hysteria2.Revision || request.Reality.Revision != request.TUIC.Revision || request.Reality.Revision != request.AnyTLS.Revision || request.Hysteria2.DestinationIP != request.ClientAddress || request.TUIC.DestinationIP != request.ClientAddress || request.AnyTLS.DestinationIP != request.ClientAddress || !validRegistryExposureAuthority(request.Exposure) || !validRegistryExposureBinding(request.Exposure, request.Reality.Revision) {
		health := registryPlanFailure("INPUT", "the client address, direct destinations, or typed exposure is invalid")
		return &health
	}
	if failure := registryExposureFailure(request); failure != nil {
		return failure
	}
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

func registryConfigurations(request RegistryViewRequest) ([]byte, []byte, Hysteria2ViewRequest) {
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
	return Health{Module: "Connection Profiles", Profile: "Registry", Outcome: Failed, Code: "CONNECTION-PROFILES-REGISTRY-PLAN-" + suffix, Problem: "The reviewed registry enablement Plan is invalid", Found: found, Required: "one exact disable or re-enable preserving every profile setting and credential", WhyStopped: "Connection Profiles requires a new reviewed Plan for every enablement change", NextActions: []string{"Check again", "Back"}}
}

func disabledRealityProfile(request ViewRequest) (RegistryProfile, string, *Health) {
	host, port, err := net.SplitHostPort(request.Target.Address)
	valid := err == nil && port == "443" && host == request.Target.ServerName && validHostname(host) && request.Port == 443 && request.XrayVersion == qualifiedXrayVersion && request.Fingerprint == "chrome" && request.Credentials.valid()
	return disabledRegistryProfile(VLESSRealityVisionProfileID, "VLESS REALITY Vision", "", request.XrayVersion, request.Credentials.valid(), request, valid)
}

func disabledXHTTPProfile(request XHTTPViewRequest) (RegistryProfile, string, *Health) {
	valid := request.OriginAddress == "127.0.0.1" && request.OriginPort == 11080 && request.Mode == state.XHTTPPacketUp && request.XrayVersion == qualifiedXrayVersion && validHostname(request.Hostname) && request.Credentials.valid()
	return disabledRegistryProfile(VLESSXHTTPProfileID, "VLESS XHTTP", request.Hostname, request.XrayVersion, request.Credentials.valid(), request, valid)
}

func disabledWebSocketProfile(request WebSocketViewRequest) (RegistryProfile, string, *Health) {
	valid := request.OriginAddress == "127.0.0.1" && request.OriginPort == 11081 && request.XrayVersion == qualifiedXrayVersion && validHostname(request.Hostname) && request.TLSName == request.Hostname && request.HTTPHost == request.Hostname && request.Credentials.valid()
	return disabledRegistryProfile(VLESSWebSocketProfileID, "VLESS WebSocket", request.Hostname, request.XrayVersion, request.Credentials.valid(), request, valid)
}

func disabledHysteria2Profile(request Hysteria2ViewRequest) (RegistryProfile, string, *Health) {
	valid := validDirectProfile(request.DestinationIP, request.ServerName, request.CertificateID, request.CertificatePointer, request.Revision, request.DirectTLS) && request.Port == 443 && request.SingBoxVersion == qualifiedSingBoxVersion && request.MasqueradeResponse == "Not Found\n" && request.Credentials.valid()
	return disabledRegistryProfile(Hysteria2ProfileID, "Hysteria2", request.ServerName, request.SingBoxVersion, request.Credentials.valid(), request, valid)
}

func disabledTUICProfile(request TUICViewRequest) (RegistryProfile, string, *Health) {
	valid := validDirectProfile(request.DestinationIP, request.ServerName, request.CertificateID, request.CertificatePointer, request.Revision, request.DirectTLS) && request.Port == 8443 && request.SingBoxVersion == qualifiedSingBoxVersion && request.CongestionControl == state.CongestionCubic && !request.ZeroRTT && request.Credentials.valid()
	return disabledRegistryProfile(TUICProfileID, "TUIC", request.ServerName, request.SingBoxVersion, request.Credentials.valid(), request, valid)
}

func disabledAnyTLSProfile(request AnyTLSViewRequest) (RegistryProfile, string, *Health) {
	valid := validDirectProfile(request.DestinationIP, request.ServerName, request.CertificateID, request.CertificatePointer, request.Revision, request.DirectTLS) && request.Port == 9443 && request.MinimumSingBoxVersion == anyTLSMinimumSingBoxVersion && request.SingBoxVersion == qualifiedSingBoxVersion && request.UseCorePadding && request.Credentials.valid()
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
		health := Health{Module: "Connection Profiles", Profile: name, Outcome: Failed, Code: "CONNECTION-PROFILES-REGISTRY-DISABLED-SETTINGS", Problem: "The disabled profile settings are invalid", Found: "a preserved setting or credential is missing or changed", Required: "complete preserved settings and credential for deliberate re-enable", WhyStopped: "Disabled profiles retain valid settings without exposure", NextActions: []string{"Check again", "Back"}}
		return RegistryProfile{ID: id, Name: name, Hostname: hostname, QualifiedVersion: version, DefaultEnabled: true, CredentialsReady: credentialsReady, SelectedListener: selectedRegistryListener(id)}, hex.EncodeToString(digest[:]), &health
	}
	health := Health{Module: "Connection Profiles", Profile: name, Outcome: Disabled, Code: "CONNECTION-PROFILES-REGISTRY-DISABLED", Found: "deliberately disabled with exposure and publication omitted", Required: "no active listener or Tunnel route", NextActions: []string{"Build re-enable Plan", "Back"}}
	return RegistryProfile{ID: id, Name: name, Hostname: hostname, QualifiedVersion: version, DefaultEnabled: true, CredentialsReady: credentialsReady, SelectedListener: selectedRegistryListener(id), Health: health}, hex.EncodeToString(digest[:]), nil
}

func selectedRegistryListener(id ProfileID) Listener {
	for _, definition := range registryDefinitions {
		if definition.id == id {
			return definition.listener
		}
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
		{registryDefinitions[0].id, request.Reality.Enabled, registryDefinitions[0].exposure, request.Exposure.ConnectionProfilesRealityExposure},
		{registryDefinitions[1].id, request.XHTTP.Enabled, registryDefinitions[1].exposure, request.Exposure.ConnectionProfilesXHTTPExposure},
		{registryDefinitions[2].id, request.WebSocket.Enabled, registryDefinitions[2].exposure, request.Exposure.ConnectionProfilesWebSocketExposure},
		{registryDefinitions[3].id, request.Hysteria2.Enabled, registryDefinitions[3].exposure, request.Exposure.ConnectionProfilesHysteria2Exposure},
		{registryDefinitions[4].id, request.TUIC.Enabled, registryDefinitions[4].exposure, request.Exposure.ConnectionProfilesTUICExposure},
		{registryDefinitions[5].id, request.AnyTLS.Enabled, registryDefinitions[5].exposure, request.Exposure.ConnectionProfilesAnyTLSExposure},
	}
	for _, test := range tests {
		address, port, protocol, present, valid := test.read()
		if !valid || test.enabled != present || present && (Listener{address, port, protocol}) != test.want {
			health := Health{Module: "Connection Profiles", Profile: string(test.id), Outcome: Failed, Code: "CONNECTION-PROFILES-REGISTRY-EXPOSURE", Problem: "The reviewed profile exposure does not agree", Found: fmt.Sprintf("%s/%d/%s present=%t", address, port, protocol, present), Required: fmt.Sprintf("enabled=%t with exact approved exposure", test.enabled), WhyStopped: "Connection Profiles never reports stale exposure as disabled or publishable", NextActions: []string{"Check again", "Back"}}
			return &health
		}
	}
	return nil
}

func registryPublication(request RegistryViewRequest) PublicationSource {
	all := []struct {
		enabled bool
		profile PublicationProfile
	}{
		{request.Reality.Enabled, PublicationProfile{ID: VLESSRealityVisionProfileID, Address: request.ClientAddress, Port: request.Reality.Port, ServerName: request.Reality.Target.ServerName, Transport: "RAW", Security: "REALITY", UUID: state.NewClientAccessValue(request.Reality.Credentials.uuid.value), ShortID: state.NewClientAccessValue(request.Reality.Credentials.shortID.value), PublicKey: request.Reality.Credentials.publicKey.value, Fingerprint: request.Reality.Fingerprint, Flow: "xtls-rprx-vision"}},
		{request.XHTTP.Enabled, PublicationProfile{ID: VLESSXHTTPProfileID, Address: request.XHTTP.Hostname, Port: 443, Hostname: request.XHTTP.Hostname, Transport: "XHTTP", Security: "TLS", UUID: state.NewClientAccessValue(request.XHTTP.Credentials.uuid.value), Path: state.NewClientAccessValue(request.XHTTP.Credentials.path.value), XHTTPServerMode: request.XHTTP.Mode}},
		{request.WebSocket.Enabled, PublicationProfile{ID: VLESSWebSocketProfileID, Address: request.WebSocket.Hostname, Port: 443, Hostname: request.WebSocket.Hostname, Transport: "WebSocket", Security: "TLS", UUID: state.NewClientAccessValue(request.WebSocket.Credentials.uuid.value), Path: state.NewClientAccessValue(request.WebSocket.Credentials.path.value), HTTPHost: request.WebSocket.HTTPHost, TLSName: request.WebSocket.TLSName}},
		{request.Hysteria2.Enabled, PublicationProfile{ID: Hysteria2ProfileID, Address: request.ClientAddress, Port: request.Hysteria2.Port, ServerName: request.Hysteria2.ServerName, Transport: "QUIC", Security: "TLS", Password: state.NewClientAccessValue(request.Hysteria2.Credentials.password.value)}},
		{request.TUIC.Enabled, PublicationProfile{ID: TUICProfileID, Address: request.ClientAddress, Port: request.TUIC.Port, ServerName: request.TUIC.ServerName, Transport: "QUIC", Security: "TLS", UUID: state.NewClientAccessValue(request.TUIC.Credentials.uuid.value), Password: state.NewClientAccessValue(request.TUIC.Credentials.password.value)}},
		{request.AnyTLS.Enabled, PublicationProfile{ID: AnyTLSProfileID, Address: request.ClientAddress, Port: request.AnyTLS.Port, ServerName: request.AnyTLS.ServerName, Transport: "TCP", Security: "TLS", Password: state.NewClientAccessValue(request.AnyTLS.Credentials.password.value)}},
	}
	var source PublicationSource
	for _, item := range all {
		if item.enabled {
			source.profiles = append(source.profiles, item.profile)
		} else {
			source.omissions = append(source.omissions, PublicationOmission{ID: item.profile.ID})
		}
	}
	return source
}

func registryHealth(code, found string) Health {
	return Health{Time: time.Time{}, Module: "Connection Profiles", Profile: "Registry", Outcome: Failed, Code: code, Problem: "The canonical six-profile registry is invalid", Found: found, Required: "exactly the six fixed Connection Profiles", WhyStopped: "Connection Profiles rejects a partial or extended registry", NextActions: []string{"Check again", "Back"}}
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
	for index, definition := range registryDefinitions {
		facts := definitions[index]
		profiles[index] = RegistryProfile{ID: definition.id, Name: definition.name, Hostname: facts.hostname, QualifiedVersion: facts.version, Enabled: facts.enabled, DefaultEnabled: true, CredentialsReady: facts.credentials, SelectedListener: definition.listener, Health: health}
	}
	return RegistryViewResult{Profiles: profiles, Health: health}
}

func registryCapabilityFailure(core, found string) Health {
	return Health{Module: "Connection Profiles", Profile: "Registry", Outcome: Failed, Code: "CONNECTION-PROFILES-REGISTRY-CAPABILITY", Problem: "The shared " + core + " service capability is broader than required", Found: found, Required: "CAP_NET_BIND_SERVICE only while an enabled listener uses a port below 1024", WhyStopped: "Disabled profiles cannot leave unnecessary service privilege", NextActions: []string{"Check again", "Back"}}
}

func markRegistryCoreFailure(profiles []RegistryProfile, health Health) {
	for index := range profiles {
		profiles[index].Health = health
	}
}
