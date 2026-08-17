package main

import (
	"errors"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/state"
)

func clientAccessRegistryRequest(desired state.DesiredState, revision uint64, secrets state.ConnectionProfileSecretReader, exposure connectionprofiles.RegistryExposureAuthority, xhttp cloudflaretunnel.XHTTPRouteHealth, websocket cloudflaretunnel.WebSocketRouteHealth) (connectionprofiles.RegistryViewRequest, error) {
	if revision == 0 || secrets == nil {
		return connectionprofiles.RegistryViewRequest{}, errors.New("Managed Connection Profile inputs are unavailable")
	}
	profiles := desired.ConnectionProfiles
	reality, realityErr := connectionprofiles.NewRealityCredentials(secrets.ReadClientAccessValue(profiles.VLESSRealityVision.UUID), secrets.ReadInfrastructureSecret(profiles.VLESSRealityVision.PrivateKey), profiles.VLESSRealityVision.PublicKey, secrets.ReadClientAccessValue(profiles.VLESSRealityVision.ShortID))
	request := connectionprofiles.RegistryViewRequest{ClientAddress: desired.NetworkPolicy.PrimarySubscriptionAddress, Reality: connectionprofiles.ViewRequest{Revision: revision, Enabled: profiles.VLESSRealityVision.Enabled, Port: profiles.VLESSRealityVision.Port, Target: connectionprofiles.RealityTarget{Address: profiles.VLESSRealityVision.Target, ServerName: profiles.VLESSRealityVision.ServerName}, Fingerprint: profiles.VLESSRealityVision.Fingerprint, XrayVersion: desired.Software.XrayVersion}}
	if revisionOneConnectionProfiles(profiles) {
		request.Reality.Credentials = reality
		request, err := connectionprofiles.NewRevisionOneRegistry(request, reality)
		request.Exposure = exposure
		return request, err
	}
	if exposure == nil {
		return connectionprofiles.RegistryViewRequest{}, errors.New("Managed Connection Profile inputs are unavailable")
	}
	xhttpCredentials, xhttpErr := connectionprofiles.NewXHTTPCredentials(secrets.ReadClientAccessValue(profiles.VLESSXHTTP.UUID), secrets.ReadClientAccessValue(profiles.VLESSXHTTP.Path))
	websocketCredentials, websocketErr := connectionprofiles.NewWebSocketCredentials(secrets.ReadClientAccessValue(profiles.VLESSWebSocket.UUID), secrets.ReadClientAccessValue(profiles.VLESSWebSocket.Path))
	var hysteria2 connectionprofiles.Hysteria2Credentials
	var hysteria2Err error
	if profiles.Hysteria2.Obfuscation {
		hysteria2, hysteria2Err = connectionprofiles.NewObfuscatedHysteria2Credentials(secrets.ReadClientAccessValue(profiles.Hysteria2.Password), secrets.ReadClientAccessValue(profiles.Hysteria2.ObfuscationSecret))
	} else {
		hysteria2, hysteria2Err = connectionprofiles.NewHysteria2Credentials(secrets.ReadClientAccessValue(profiles.Hysteria2.Password))
	}
	tuic, tuicErr := connectionprofiles.NewTUICCredentials(secrets.ReadClientAccessValue(profiles.TUIC.UUID), secrets.ReadClientAccessValue(profiles.TUIC.Password))
	anyTLS, anyTLSErr := connectionprofiles.NewAnyTLSCredentials(secrets.ReadClientAccessValue(profiles.AnyTLS.Password))
	if errors.Join(realityErr, xhttpErr, websocketErr, hysteria2Err, tuicErr, anyTLSErr) != nil {
		return connectionprofiles.RegistryViewRequest{}, errors.New("Managed Connection Profile credentials are invalid")
	}
	directTLS := connectionprofiles.NewDirectTLSContribution(connectionprofiles.DirectTLSRequest{
		Revision: revision, DestinationIP: desired.NetworkPolicy.PrimarySubscriptionAddress, Hostname: desired.Cloudflare.DirectHostname,
		Hysteria2: connectionprofiles.DirectTLSConsumer{Port: profiles.Hysteria2.Port, CertificatePointer: desired.Certificates.DomainServingPointer},
		TUIC:      connectionprofiles.DirectTLSConsumer{Port: profiles.TUIC.Port, CertificatePointer: desired.Certificates.DomainServingPointer},
		AnyTLS:    connectionprofiles.DirectTLSConsumer{Port: profiles.AnyTLS.Port, CertificatePointer: desired.Certificates.DomainServingPointer},
	})
	return connectionprofiles.RegistryViewRequest{
		ClientAddress: desired.NetworkPolicy.PrimarySubscriptionAddress,
		Reality:       connectionprofiles.ViewRequest{Revision: revision, Enabled: profiles.VLESSRealityVision.Enabled, Port: profiles.VLESSRealityVision.Port, Target: connectionprofiles.RealityTarget{Address: profiles.VLESSRealityVision.Target, ServerName: profiles.VLESSRealityVision.ServerName}, Fingerprint: profiles.VLESSRealityVision.Fingerprint, XrayVersion: desired.Software.XrayVersion, Credentials: reality},
		XHTTP:         connectionprofiles.XHTTPViewRequest{Revision: revision, Enabled: profiles.VLESSXHTTP.Enabled, Hostname: profiles.VLESSXHTTP.Hostname, OriginAddress: profiles.VLESSXHTTP.OriginAddress, OriginPort: profiles.VLESSXHTTP.OriginPort, Mode: profiles.VLESSXHTTP.Mode, XrayVersion: desired.Software.XrayVersion, Credentials: xhttpCredentials, RouteHealth: xhttp},
		WebSocket:     connectionprofiles.WebSocketViewRequest{Revision: revision, Enabled: profiles.VLESSWebSocket.Enabled, Hostname: profiles.VLESSWebSocket.Hostname, TLSName: profiles.VLESSWebSocket.Hostname, HTTPHost: profiles.VLESSWebSocket.Hostname, OriginAddress: profiles.VLESSWebSocket.OriginAddress, OriginPort: profiles.VLESSWebSocket.OriginPort, XrayVersion: desired.Software.XrayVersion, Credentials: websocketCredentials, RouteHealth: websocket},
		Hysteria2:     connectionprofiles.Hysteria2ViewRequest{Revision: revision, Enabled: profiles.Hysteria2.Enabled, DestinationIP: desired.NetworkPolicy.PrimarySubscriptionAddress, Port: profiles.Hysteria2.Port, ServerName: profiles.Hysteria2.ServerName, CertificateID: profiles.Hysteria2.CertificateID, MasqueradeResponse: "Not Found\n", CertificatePointer: desired.Certificates.DomainServingPointer, SingBoxVersion: trimVersion(desired.Software.SingBoxVersion), Credentials: hysteria2, DirectTLS: directTLS},
		TUIC:          connectionprofiles.TUICViewRequest{Revision: revision, Enabled: profiles.TUIC.Enabled, DestinationIP: desired.NetworkPolicy.PrimarySubscriptionAddress, Port: profiles.TUIC.Port, ServerName: profiles.TUIC.ServerName, CertificateID: profiles.TUIC.CertificateID, CertificatePointer: desired.Certificates.DomainServingPointer, SingBoxVersion: trimVersion(desired.Software.SingBoxVersion), CongestionControl: profiles.TUIC.CongestionControl, ZeroRTT: profiles.TUIC.ZeroRTT, Credentials: tuic, DirectTLS: directTLS},
		AnyTLS:        connectionprofiles.AnyTLSViewRequest{Revision: revision, Enabled: profiles.AnyTLS.Enabled, DestinationIP: desired.NetworkPolicy.PrimarySubscriptionAddress, Port: profiles.AnyTLS.Port, ServerName: profiles.AnyTLS.ServerName, CertificateID: profiles.AnyTLS.CertificateID, CertificatePointer: desired.Certificates.DomainServingPointer, MinimumSingBoxVersion: "1.12.0", SingBoxVersion: trimVersion(desired.Software.SingBoxVersion), UseCorePadding: profiles.AnyTLS.PaddingScheme == "upstream-default", Credentials: anyTLS, DirectTLS: directTLS},
		Exposure:      exposure,
	}, nil
}

func revisionOneConnectionProfiles(profiles state.ConnectionProfiles) bool {
	return profiles.VLESSRealityVision.Lifecycle == state.ProfileEnabled && profiles.VLESSRealityVision.Enabled &&
		profiles.VLESSXHTTP.Lifecycle == state.ProfileNotSetUp && profiles.VLESSWebSocket.Lifecycle == state.ProfileNotSetUp &&
		profiles.Hysteria2.Lifecycle == state.ProfileNotSetUp && profiles.TUIC.Lifecycle == state.ProfileNotSetUp && profiles.AnyTLS.Lifecycle == state.ProfileNotSetUp
}
