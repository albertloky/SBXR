package cloudflaretunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
)

type certificateDNSRecord struct {
	ID, Name, Type, Content string
	Proxied                 bool
	Data                    struct {
		Flags int
		Tag   string
		Value string
	}
}

func (api *httpAPI) ObserveCertificateDNS(ctx context.Context, request CertificateDNSRequest) (CertificateDNSFacts, error) {
	validBinding := func(address, id string) bool {
		return address == "" && id == "" || address != "" && immutableID.MatchString(id)
	}
	if api == nil || api.client == nil || !immutableID.MatchString(request.ZoneID) || !validZoneName(request.ZoneName) || !validOwnedHostname(request.Hostname, request.ZoneName, "direct") || request.Token.value == "" || !validPublicAddresses(request.PublicIPv4, request.PublicIPv6) || !validBinding(request.PublicIPv4, request.IPv4RecordID) || !validBinding(request.PublicIPv6, request.IPv6RecordID) {
		return CertificateDNSFacts{}, APIError{Kind: APIMalformed}
	}
	facts := CertificateDNSFacts{Hostname: request.Hostname}
	for _, expected := range []struct{ kind, content, id string }{{"A", request.PublicIPv4, request.IPv4RecordID}, {"AAAA", request.PublicIPv6, request.IPv6RecordID}} {
		records, err := api.certificateDNSRecords(ctx, request, request.Hostname, expected.kind)
		if err != nil {
			return CertificateDNSFacts{}, err
		}
		if expected.content == "" {
			if len(records) != 0 {
				return CertificateDNSFacts{}, APIError{Kind: APIAmbiguous}
			}
			continue
		}
		if len(records) == 0 {
			return CertificateDNSFacts{}, APIError{Kind: APITemporary}
		}
		if len(records) != 1 || records[0].ID != expected.id || records[0].Content != expected.content || records[0].Proxied {
			return CertificateDNSFacts{}, APIError{Kind: APIAmbiguous}
		}
		address, err := netip.ParseAddr(records[0].Content)
		if err != nil || expected.kind == "A" && !address.Is4() || expected.kind == "AAAA" && !address.Is6() {
			return CertificateDNSFacts{}, APIError{Kind: APIMalformed}
		}
		facts.Addresses = append(facts.Addresses, address)
	}
	for _, name := range []string{request.Hostname, request.ZoneName} {
		records, err := api.certificateDNSRecords(ctx, request, name, "CAA")
		if err != nil {
			return CertificateDNSFacts{}, err
		}
		if len(records) == 0 {
			continue
		}
		facts.EffectiveCAA.Name = name
		for _, record := range records {
			if record.Data.Flags < 0 || record.Data.Flags > 255 || record.Data.Tag == "" || !safeProviderValue(record.Data.Tag) || !safeProviderValue(record.Data.Value) {
				return CertificateDNSFacts{}, APIError{Kind: APIMalformed}
			}
			facts.EffectiveCAA.Records = append(facts.EffectiveCAA.Records, CAARecord{Flags: uint8(record.Data.Flags), Tag: strings.ToLower(record.Data.Tag), Value: record.Data.Value})
		}
		sort.Slice(facts.EffectiveCAA.Records, func(i, j int) bool {
			left, right := facts.EffectiveCAA.Records[i], facts.EffectiveCAA.Records[j]
			return left.Tag+"\x00"+left.Value+"\x00"+string(rune(left.Flags)) < right.Tag+"\x00"+right.Value+"\x00"+string(rune(right.Flags))
		})
		break
	}
	return facts, nil
}

func (api *httpAPI) certificateDNSRecords(ctx context.Context, request CertificateDNSRequest, name, kind string) ([]certificateDNSRecord, error) {
	records := []certificateDNSRecord{}
	seen := map[string]bool{}
	for page := 1; page <= maxZonePages; page++ {
		var envelope struct {
			Result []certificateDNSRecord `json:"result"`
		}
		query := url.Values{"name": {name}, "type": {kind}, "page": {fmt.Sprint(page)}, "per_page": {"100"}}
		if err := api.get(ctx, "/zones/"+request.ZoneID+"/dns_records", query, request.Token, &envelope); err != nil {
			return nil, err
		}
		if len(envelope.Result) > 100 {
			return nil, APIError{Kind: APIMalformed}
		}
		for _, record := range envelope.Result {
			if !immutableID.MatchString(record.ID) || seen[record.ID] || record.Name != name || record.Type != kind {
				return nil, APIError{Kind: APIMalformed}
			}
			seen[record.ID] = true
			records = append(records, record)
		}
		if len(envelope.Result) < 100 {
			return records, nil
		}
	}
	return nil, APIError{Kind: APIMalformed}
}

func (api *httpAPI) ObserveMutation(ctx context.Context, request MutationRequest) (MutationObservation, error) {
	if !immutableID.MatchString(request.AccountID) || !immutableID.MatchString(request.ZoneID) || !safePlanName.MatchString(request.Tunnel) || !validZoneName(request.Hostname) || request.Token.value == "" {
		return MutationObservation{}, APIError{Kind: APIMalformed}
	}
	tunnels, err := api.listResources(ctx, "/accounts/"+request.AccountID+"/cfd_tunnel", url.Values{"name": {request.Tunnel}}, request.Token, true)
	if err != nil {
		return MutationObservation{}, err
	}
	dns, err := api.listResources(ctx, "/zones/"+request.ZoneID+"/dns_records", url.Values{"name": {request.Hostname}}, request.Token, false)
	if err != nil {
		return MutationObservation{}, err
	}
	digest := sha256.Sum256([]byte(request.AccountID + "\n" + request.ZoneID + "\n" + request.Tunnel + "\n" + request.Hostname + "\n" + resourcesText(tunnels) + resourcesText(dns)))
	return MutationObservation{Digest: hex.EncodeToString(digest[:]), Tunnels: tunnels, DNSRecords: dns}, nil
}

func (api *httpAPI) listResources(ctx context.Context, path string, query url.Values, token ManagementToken, uuid bool) ([]OwnedResource, error) {
	var envelope struct {
		Result []struct{ ID, Name string } `json:"result"`
	}
	if err := api.get(ctx, path, query, token, &envelope); err != nil {
		return nil, err
	}
	result := make([]OwnedResource, len(envelope.Result))
	for index, item := range envelope.Result {
		if item.Name == "" || uuid && !tunnelUUID.MatchString(item.ID) || !uuid && !immutableID.MatchString(item.ID) {
			return nil, APIError{Kind: APIMalformed}
		}
		result[index] = OwnedResource{ID: item.ID, Name: item.Name}
	}
	return result, nil
}

func resourcesText(resources []OwnedResource) string {
	value := ""
	for _, resource := range resources {
		value += resource.ID + ":" + resource.Name + "\n"
	}
	return value
}

func (api *httpAPI) CreateTunnel(ctx context.Context, request CreateTunnelRequest) (CreatedTunnel, error) {
	var envelope struct {
		Result struct {
			ID, Name, Token string
			RemoteConfig    bool   `json:"remote_config"`
			Type            string `json:"tun_type"`
		} `json:"result"`
	}
	err := api.request(ctx, http.MethodPost, "/accounts/"+request.AccountID+"/cfd_tunnel", nil, request.Token, map[string]any{"name": request.Name, "config_src": "cloudflare"}, &envelope)
	result := envelope.Result
	if err != nil || !tunnelUUID.MatchString(result.ID) || result.Name != request.Name || result.Token == "" || !result.RemoteConfig || result.Type != "cfd_tunnel" {
		if err != nil {
			return CreatedTunnel{}, err
		}
		return CreatedTunnel{}, APIError{Kind: APIMalformed}
	}
	return CreatedTunnel{ID: result.ID, Name: result.Name, runToken: result.Token}, nil
}

func (api *httpAPI) GetTunnelToken(ctx context.Context, request GetTunnelTokenRequest) (TunnelTokenResult, error) {
	if api == nil || api.client == nil || !immutableID.MatchString(request.AccountID) || !tunnelUUID.MatchString(request.TunnelID) || request.Token.value == "" {
		return TunnelTokenResult{}, APIError{Kind: APIMalformed}
	}
	var envelope struct {
		Result string `json:"result"`
	}
	if err := api.get(ctx, "/accounts/"+request.AccountID+"/cfd_tunnel/"+request.TunnelID+"/token", nil, request.Token, &envelope); err != nil {
		return TunnelTokenResult{}, err
	}
	if envelope.Result == "" || len(envelope.Result) > 16<<10 || strings.ContainsAny(envelope.Result, "\r\n\x00") {
		return TunnelTokenResult{}, APIError{Kind: APIMalformed}
	}
	cell := &runTokenCell{}
	if !cell.issue(envelope.Result) {
		return TunnelTokenResult{}, APIError{Kind: APIMalformed}
	}
	digest := sha256.Sum256([]byte(envelope.Result))
	return TunnelTokenResult{token: TunnelRunToken{cell: cell}, sha256: hex.EncodeToString(digest[:])}, nil
}

func (api *httpAPI) PutConfiguration(ctx context.Context, request PutConfigurationRequest) (Configuration, error) {
	if api == nil || api.client == nil || !immutableID.MatchString(request.AccountID) || !tunnelUUID.MatchString(request.TunnelID) || request.Token.value == "" || !validPublishedRoutes(request.Routes) {
		return Configuration{}, APIError{Kind: APIMalformed}
	}
	var envelope struct {
		Result struct {
			TunnelID string `json:"tunnel_id"`
			Version  int    `json:"version"`
			Config   struct {
				Ingress []Route `json:"ingress"`
			} `json:"config"`
		} `json:"result"`
	}
	err := api.request(ctx, http.MethodPut, "/accounts/"+request.AccountID+"/cfd_tunnel/"+request.TunnelID+"/configurations", nil, request.Token, map[string]any{"config": map[string]any{"ingress": request.Routes}}, &envelope)
	if err != nil {
		return Configuration{}, err
	}
	if !tunnelUUID.MatchString(envelope.Result.TunnelID) || envelope.Result.Version < 1 {
		return Configuration{}, APIError{Kind: APIMalformed}
	}
	if envelope.Result.TunnelID != request.TunnelID || !sameRoutes(envelope.Result.Config.Ingress, request.Routes) {
		return Configuration{}, APIError{Kind: APIAmbiguous}
	}
	return Configuration{TunnelID: envelope.Result.TunnelID, Version: envelope.Result.Version, Routes: envelope.Result.Config.Ingress}, nil
}

func (api *httpAPI) CreateDNSRecord(ctx context.Context, request CreateDNSRecordRequest) (OwnedResource, error) {
	var envelope struct {
		Result struct {
			ID, Name, Type, Content string
			Proxied                 bool
		} `json:"result"`
	}
	err := api.request(ctx, http.MethodPost, "/zones/"+request.ZoneID+"/dns_records", nil, request.Token, map[string]any{"type": request.Type, "name": request.Name, "content": request.Content, "proxied": request.Proxied}, &envelope)
	result := envelope.Result
	if err != nil || !immutableID.MatchString(result.ID) || result.Name != request.Name || result.Type != request.Type || result.Content != request.Content || result.Proxied != request.Proxied {
		if err != nil {
			return OwnedResource{}, err
		}
		return OwnedResource{}, APIError{Kind: APIMalformed}
	}
	return OwnedResource{ID: result.ID, Name: result.Name}, nil
}

func (api *httpAPI) ObserveWholeTunnel(ctx context.Context, request WholeTunnelRequest) (WholeTunnelObservation, error) {
	if !api.validWholeTunnelRequest(request) {
		return WholeTunnelObservation{}, APIError{Kind: APIMalformed}
	}
	var tunnel struct {
		Result struct {
			ID, Status  string
			Connections []struct{ ID string } `json:"connections"`
		} `json:"result"`
	}
	if err := api.get(ctx, "/accounts/"+request.AccountID+"/cfd_tunnel/"+request.TunnelID, nil, request.Token, &tunnel); err != nil {
		return WholeTunnelObservation{}, err
	}
	if !tunnelUUID.MatchString(tunnel.Result.ID) || !validTunnelStatus(tunnel.Result.Status) {
		return WholeTunnelObservation{}, APIError{Kind: APIMalformed}
	}
	if tunnel.Result.ID != request.TunnelID {
		return WholeTunnelObservation{}, APIError{Kind: APIAmbiguous}
	}
	connectionIDs := make(map[string]bool, len(tunnel.Result.Connections))
	for _, connection := range tunnel.Result.Connections {
		if !safeProviderValue(connection.ID) {
			return WholeTunnelObservation{}, APIError{Kind: APIMalformed}
		}
		if connectionIDs[connection.ID] {
			return WholeTunnelObservation{}, APIError{Kind: APIAmbiguous}
		}
		connectionIDs[connection.ID] = true
	}
	var config struct {
		Result struct {
			TunnelID string `json:"tunnel_id"`
			Config   struct {
				Ingress []Route `json:"ingress"`
			} `json:"config"`
		} `json:"result"`
	}
	if err := api.get(ctx, "/accounts/"+request.AccountID+"/cfd_tunnel/"+request.TunnelID+"/configurations", nil, request.Token, &config); err != nil {
		return WholeTunnelObservation{}, err
	}
	if !tunnelUUID.MatchString(config.Result.TunnelID) {
		return WholeTunnelObservation{}, APIError{Kind: APIMalformed}
	}
	if config.Result.TunnelID != request.TunnelID {
		return WholeTunnelObservation{}, APIError{Kind: APIAmbiguous}
	}
	if len(config.Result.Config.Ingress) > 3 {
		return WholeTunnelObservation{}, APIError{Kind: APIMalformed}
	}
	for _, route := range config.Result.Config.Ingress {
		if !safeObservedRoute(route) {
			return WholeTunnelObservation{}, APIError{Kind: APIMalformed}
		}
	}
	dns := make([]DNSObservation, 0, len(request.DNSRecords))
	for _, record := range request.DNSRecords {
		var envelope struct {
			Result struct {
				ID, Name, Type, Content string
				Proxied                 bool
			} `json:"result"`
		}
		if err := api.get(ctx, "/zones/"+request.ZoneID+"/dns_records/"+record.ID, nil, request.Token, &envelope); err != nil {
			return WholeTunnelObservation{}, err
		}
		result := envelope.Result
		if !immutableID.MatchString(result.ID) || !validZoneName(result.Name) || result.Type != "CNAME" && result.Type != "A" && result.Type != "AAAA" || !safeProviderValue(result.Content) {
			return WholeTunnelObservation{}, APIError{Kind: APIMalformed}
		}
		if result.ID != record.ID {
			return WholeTunnelObservation{}, APIError{Kind: APIAmbiguous}
		}
		dns = append(dns, DNSObservation{ID: envelope.Result.ID, Name: envelope.Result.Name, Type: envelope.Result.Type, Content: envelope.Result.Content, Proxied: envelope.Result.Proxied})
	}
	if api.origins == nil {
		return WholeTunnelObservation{}, APIError{Kind: APIMalformed}
	}
	xhttp, xhttpErr := api.origins.Reachable(ctx, "127.0.0.1:11080")
	websocket, websocketErr := api.origins.Reachable(ctx, "127.0.0.1:11081")
	if xhttpErr != nil || websocketErr != nil {
		return WholeTunnelObservation{}, APIError{Kind: APITemporary}
	}
	return WholeTunnelObservation{TunnelID: tunnel.Result.ID, Connected: tunnel.Result.Status == "healthy" && len(tunnel.Result.Connections) > 0, Routes: config.Result.Config.Ingress, DNSRecords: dns, XHTTPOriginReachable: xhttp, WebSocketOriginReachable: websocket}, nil
}

func (api *httpAPI) validWholeTunnelRequest(request WholeTunnelRequest) bool {
	if api == nil || api.client == nil || api.origins == nil || !immutableID.MatchString(request.AccountID) || !immutableID.MatchString(request.ZoneID) || !tunnelUUID.MatchString(request.TunnelID) || request.Token.value == "" || len(request.DNSRecords) < 2 || len(request.DNSRecords) > 4 {
		return false
	}
	seen := make(map[string]bool, len(request.DNSRecords))
	for _, record := range request.DNSRecords {
		if !immutableID.MatchString(record.ID) || seen[record.ID] {
			return false
		}
		seen[record.ID] = true
	}
	return true
}

func validPublishedRoutes(routes []Route) bool {
	return len(routes) == 3 && validZoneName(routes[0].Hostname) && routes[0].Service == xhttpOrigin && validZoneName(routes[1].Hostname) && routes[1].Service == webSocketOrigin && routes[0].Hostname != routes[1].Hostname && routes[2] == (Route{Service: "http_status:404"})
}

func safeObservedRoute(route Route) bool {
	if !safeProviderValue(route.Service) {
		return false
	}
	return route.Hostname == "" || validZoneName(route.Hostname)
}

func safeProviderValue(value string) bool {
	return value != "" && len(value) <= 2048 && !strings.ContainsAny(value, "\x00\r\n")
}

func validTunnelStatus(status string) bool {
	return status == "healthy" || status == "degraded" || status == "down" || status == "inactive"
}

func (api *httpAPI) DeleteDNSRecord(ctx context.Context, request DeleteDNSRecordRequest) error {
	return api.request(ctx, http.MethodDelete, "/zones/"+request.ZoneID+"/dns_records/"+request.ID, nil, request.Token, nil, nil)
}
func (api *httpAPI) DeleteTunnel(ctx context.Context, request DeleteTunnelRequest) error {
	return api.request(ctx, http.MethodDelete, "/accounts/"+request.AccountID+"/cfd_tunnel/"+request.ID, nil, request.Token, nil, nil)
}
