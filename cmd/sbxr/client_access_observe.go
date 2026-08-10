package main

import (
	"context"
	"errors"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	networkubuntu "github.com/albertloky/SBXR/internal/networkpolicy/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func observeManagedClientAccess(ctx context.Context, snapshot state.Snapshot, cloudflareSecrets state.InfrastructureSecretReader, disk systemchanges.DiskRequirement) (networkpolicy.Result, cloudflaretunnel.XHTTPRouteHealth, cloudflaretunnel.WebSocketRouteHealth, error) {
	if ctx == nil || cloudflareSecrets == nil {
		return networkpolicy.Result{}, cloudflaretunnel.XHTTPRouteHealth{}, cloudflaretunnel.WebSocketRouteHealth{}, errors.New("Managed Client Access observation unavailable")
	}
	desired := snapshot.DesiredState
	token, err := cloudflaretunnel.NewManagementToken(cloudflareSecrets.ReadInfrastructureSecret(desired.Cloudflare.ManagementToken))
	if err != nil {
		return networkpolicy.Result{}, cloudflaretunnel.XHTTPRouteHealth{}, cloudflaretunnel.WebSocketRouteHealth{}, errors.New("Cloudflare observation authority unavailable")
	}
	return observeManagedClientAccessWithToken(ctx, snapshot, token, disk)
}

func observeManagedClientAccessWithToken(ctx context.Context, snapshot state.Snapshot, token cloudflaretunnel.ManagementToken, disk systemchanges.DiskRequirement) (networkpolicy.Result, cloudflaretunnel.XHTTPRouteHealth, cloudflaretunnel.WebSocketRouteHealth, error) {
	desired := snapshot.DesiredState
	api := cloudflaretunnel.NewProductionAPI()
	dnsReferences := []cloudflaretunnel.DNSRecordReference{{ID: desired.Cloudflare.XHTTPDNSRecordID}, {ID: desired.Cloudflare.WebSocketDNSRecordID}}
	if desired.Cloudflare.DirectIPv4RecordID != "" {
		dnsReferences = append(dnsReferences, cloudflaretunnel.DNSRecordReference{ID: desired.Cloudflare.DirectIPv4RecordID})
	}
	if desired.Cloudflare.DirectIPv6RecordID != "" {
		dnsReferences = append(dnsReferences, cloudflaretunnel.DNSRecordReference{ID: desired.Cloudflare.DirectIPv6RecordID})
	}
	observed, err := api.ObserveWholeTunnel(ctx, cloudflaretunnel.WholeTunnelRequest{AccountID: desired.Cloudflare.AccountID, ZoneID: desired.Cloudflare.ZoneID, TunnelID: desired.Cloudflare.TunnelID, DNSRecords: dnsReferences, Token: token})
	if err != nil {
		return networkpolicy.Result{}, cloudflaretunnel.XHTTPRouteHealth{}, cloudflaretunnel.WebSocketRouteHealth{}, errors.New("Cloudflare Tunnel observation failed")
	}
	expected := managedTunnelExpected(desired)
	xhttp := cloudflaretunnel.EvaluateXHTTPRouteHealth(observed, expected)
	websocket := cloudflaretunnel.EvaluateWebSocketRouteHealth(observed, expected)

	certificate, err := api.ObserveCertificateDNS(ctx, cloudflaretunnel.CertificateDNSRequest{ZoneID: desired.Cloudflare.ZoneID, ZoneName: desired.Cloudflare.ZoneName, Hostname: desired.Cloudflare.DirectHostname, PublicIPv4: desired.NetworkPolicy.PublicIPv4, PublicIPv6: desired.NetworkPolicy.PublicIPv6, IPv4RecordID: desired.Cloudflare.DirectIPv4RecordID, IPv6RecordID: desired.Cloudflare.DirectIPv6RecordID, Token: token})
	if err != nil {
		return networkpolicy.Result{}, cloudflaretunnel.XHTTPRouteHealth{}, cloudflaretunnel.WebSocketRouteHealth{}, errors.New("Direct TLS DNS observation failed")
	}
	certificateFacts := networkpolicy.CertificateFacts{DNS: networkpolicy.DNSFacts{Hostname: certificate.Hostname}}
	for _, address := range certificate.Addresses {
		if address.Is4() {
			certificateFacts.DNS.IPv4 = append(certificateFacts.DNS.IPv4, address.String())
		} else {
			certificateFacts.DNS.IPv6 = append(certificateFacts.DNS.IPv6, address.String())
		}
	}
	for _, record := range certificate.EffectiveCAA.Records {
		if record.Tag == "issue" && record.Value == "letsencrypt.org" {
			certificateFacts.CAA = networkpolicy.CAAFacts{Issuer: "letsencrypt.org", HTTP01Allowed: true}
		}
	}

	intent := clientAccessNetworkIntent(desired, snapshot.Revision, disk)
	adapter := networkubuntu.New()
	local, err := adapter.Observe(networkpolicy.ObservationRequest{Intent: intent, Stage: networkpolicy.PostApproval, Scope: networkpolicy.LocalObservations})
	if err != nil {
		return networkpolicy.Result{}, cloudflaretunnel.XHTTPRouteHealth{}, cloudflaretunnel.WebSocketRouteHealth{}, errors.New("Managed network observation failed")
	}
	proof := networkpolicy.ManagedProof{Lineage: networkpolicy.ProvenLineage, NftablesSHA256: local.Checksums["sbxr_nftables"], Listeners: expectedManagedListeners(intent)}
	ownerFacts := networkpolicy.OwnerFacts{DNS: "matches Desired State", Tunnel: "matches Desired State"}
	if observed.TunnelID != desired.Cloudflare.TunnelID || !observed.Connected {
		ownerFacts.Tunnel = "different from Desired State"
	}
	if !managedDNSMatches(observed.DNSRecords, expected.DNSRecords) {
		ownerFacts.DNS = "different from Desired State"
	}
	if desired.ConnectionProfiles.VLESSXHTTP.Enabled {
		ownerFacts.Routes = append(ownerFacts.Routes, networkpolicy.CloudflareRoute{Profile: "VLESS XHTTP", OriginAddress: "127.0.0.1", OriginPort: desired.ConnectionProfiles.VLESSXHTTP.OriginPort, Protocol: networkpolicy.TCP, Connected: observed.XHTTPOriginReachable})
	}
	if desired.ConnectionProfiles.VLESSWebSocket.Enabled {
		ownerFacts.Routes = append(ownerFacts.Routes, networkpolicy.CloudflareRoute{Profile: "VLESS WebSocket", OriginAddress: "127.0.0.1", OriginPort: desired.ConnectionProfiles.VLESSWebSocket.OriginPort, Protocol: networkpolicy.TCP, Connected: observed.WebSocketOriginReachable})
	}
	result := networkpolicy.New(adapter).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval, Managed: proof, OwnerFacts: ownerFacts, Certificate: certificateFacts})
	return result, xhttp, websocket, nil
}

func managedTunnelExpected(desired state.DesiredState) cloudflaretunnel.WholeTunnelExpected {
	routes := make([]cloudflaretunnel.Route, 0, 3)
	if desired.ConnectionProfiles.VLESSXHTTP.Enabled {
		routes = append(routes, cloudflaretunnel.Route{Hostname: desired.Cloudflare.XHTTPHostname, Service: "http://127.0.0.1:11080"})
	}
	if desired.ConnectionProfiles.VLESSWebSocket.Enabled {
		routes = append(routes, cloudflaretunnel.Route{Hostname: desired.Cloudflare.WebSocketHostname, Service: "http://127.0.0.1:11081"})
	}
	routes = append(routes, cloudflaretunnel.Route{Service: "http_status:404"})
	dns := []cloudflaretunnel.DNSExpected{
		{ID: desired.Cloudflare.XHTTPDNSRecordID, Name: desired.Cloudflare.XHTTPHostname, Type: "CNAME", Content: desired.Cloudflare.TunnelID + ".cfargotunnel.com", Proxied: true},
		{ID: desired.Cloudflare.WebSocketDNSRecordID, Name: desired.Cloudflare.WebSocketHostname, Type: "CNAME", Content: desired.Cloudflare.TunnelID + ".cfargotunnel.com", Proxied: true},
	}
	if desired.NetworkPolicy.PublicIPv4 != "" {
		dns = append(dns, cloudflaretunnel.DNSExpected{ID: desired.Cloudflare.DirectIPv4RecordID, Name: desired.Cloudflare.DirectHostname, Type: "A", Content: desired.NetworkPolicy.PublicIPv4})
	}
	if desired.NetworkPolicy.PublicIPv6 != "" {
		dns = append(dns, cloudflaretunnel.DNSExpected{ID: desired.Cloudflare.DirectIPv6RecordID, Name: desired.Cloudflare.DirectHostname, Type: "AAAA", Content: desired.NetworkPolicy.PublicIPv6})
	}
	return cloudflaretunnel.WholeTunnelExpected{TunnelID: desired.Cloudflare.TunnelID, Routes: routes, DNSRecords: dns}
}

func managedDNSMatches(observed []cloudflaretunnel.DNSObservation, expected []cloudflaretunnel.DNSExpected) bool {
	if len(observed) != len(expected) {
		return false
	}
	for _, want := range expected {
		found := false
		for _, got := range observed {
			if got.ID == want.ID && got.Name == want.Name && got.Type == want.Type && got.Content == want.Content && got.Proxied == want.Proxied {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func expectedManagedListeners(intent networkpolicy.Intent) []networkpolicy.ListenerProof {
	listeners := []networkpolicy.ListenerProof{{Address: "0.0.0.0", Port: intent.SSHPort, Protocol: networkpolicy.TCP}, {Address: "0.0.0.0", Port: intent.SubscriptionPort, Protocol: networkpolicy.TCP, Service: "sbxr-subscription.service"}}
	for _, item := range []struct {
		enabled  bool
		address  string
		port     uint16
		protocol networkpolicy.Protocol
		service  string
	}{
		{intent.Profiles.VLESSRealityVision.Enabled, "0.0.0.0", intent.Profiles.VLESSRealityVision.Port, networkpolicy.TCP, "xray.service"},
		{intent.Profiles.VLESSXHTTP.Enabled, "127.0.0.1", intent.Profiles.VLESSXHTTP.Port, networkpolicy.TCP, "xray.service"},
		{intent.Profiles.VLESSWebSocket.Enabled, "127.0.0.1", intent.Profiles.VLESSWebSocket.Port, networkpolicy.TCP, "xray.service"},
		{intent.Profiles.Hysteria2.Enabled, "0.0.0.0", intent.Profiles.Hysteria2.Port, networkpolicy.UDP, "sing-box.service"},
		{intent.Profiles.TUIC.Enabled, "0.0.0.0", intent.Profiles.TUIC.Port, networkpolicy.UDP, "sing-box.service"},
		{intent.Profiles.AnyTLS.Enabled, "0.0.0.0", intent.Profiles.AnyTLS.Port, networkpolicy.TCP, "sing-box.service"},
	} {
		if item.enabled {
			listeners = append(listeners, networkpolicy.ListenerProof{Address: item.address, Port: item.port, Protocol: item.protocol, Service: item.service})
		}
	}
	return listeners
}
