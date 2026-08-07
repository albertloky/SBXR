package cloudflaretunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
)

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
