package cloudflaretunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
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
	var tunnel struct {
		Result struct {
			ID, Status  string
			Connections []struct{ ID string } `json:"connections"`
		} `json:"result"`
	}
	if err := api.get(ctx, "/accounts/"+request.AccountID+"/cfd_tunnel/"+request.TunnelID, nil, request.Token, &tunnel); err != nil {
		return WholeTunnelObservation{}, err
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

func (api *httpAPI) DeleteDNSRecord(ctx context.Context, request DeleteDNSRecordRequest) error {
	return api.request(ctx, http.MethodDelete, "/zones/"+request.ZoneID+"/dns_records/"+request.ID, nil, request.Token, nil, nil)
}
func (api *httpAPI) DeleteTunnel(ctx context.Context, request DeleteTunnelRequest) error {
	return api.request(ctx, http.MethodDelete, "/accounts/"+request.AccountID+"/cfd_tunnel/"+request.ID, nil, request.Token, nil, nil)
}
