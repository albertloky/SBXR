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
	return CreatedTunnel{ID: result.ID, Name: result.Name, RunToken: newTunnelRunToken(result.Token)}, nil
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
	err := api.request(ctx, http.MethodPost, "/zones/"+request.ZoneID+"/dns_records", nil, request.Token, map[string]any{"type": "CNAME", "name": request.Name, "content": request.Content, "proxied": request.Proxied}, &envelope)
	result := envelope.Result
	if err != nil || !immutableID.MatchString(result.ID) || result.Name != request.Name || result.Type != "CNAME" || result.Content != request.Content || !result.Proxied {
		if err != nil {
			return OwnedResource{}, err
		}
		return OwnedResource{}, APIError{Kind: APIMalformed}
	}
	return OwnedResource{ID: result.ID, Name: result.Name}, nil
}

func (api *httpAPI) CheckXHTTP(ctx context.Context, request XHTTPHealthRequest) (bool, error) {
	var tunnel struct {
		Result struct {
			ID, Status  string
			Connections []struct{ ID string } `json:"connections"`
		} `json:"result"`
	}
	if err := api.get(ctx, "/accounts/"+request.AccountID+"/cfd_tunnel/"+request.TunnelID, nil, request.Token, &tunnel); err != nil {
		return false, err
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
		return false, err
	}
	var dns struct {
		Result struct {
			ID, Name, Type, Content string
			Proxied                 bool
		} `json:"result"`
	}
	if err := api.get(ctx, "/zones/"+request.ZoneID+"/dns_records/"+request.DNSRecordID, nil, request.Token, &dns); err != nil {
		return false, err
	}
	wantRoutes := []Route{{Hostname: request.Hostname, Service: request.Origin}, {Service: "http_status:404"}}
	return tunnel.Result.ID == request.TunnelID && tunnel.Result.Status == "healthy" && len(tunnel.Result.Connections) > 0 && config.Result.TunnelID == request.TunnelID && sameRoutes(config.Result.Config.Ingress, wantRoutes) && dns.Result.ID == request.DNSRecordID && dns.Result.Name == request.Hostname && dns.Result.Type == "CNAME" && dns.Result.Content == request.TunnelID+".cfargotunnel.com" && dns.Result.Proxied, nil
}

func (api *httpAPI) DeleteDNSRecord(ctx context.Context, request DeleteDNSRecordRequest) error {
	return api.request(ctx, http.MethodDelete, "/zones/"+request.ZoneID+"/dns_records/"+request.ID, nil, request.Token, nil, nil)
}
func (api *httpAPI) DeleteTunnel(ctx context.Context, request DeleteTunnelRequest) error {
	return api.request(ctx, http.MethodDelete, "/accounts/"+request.AccountID+"/cfd_tunnel/"+request.ID, nil, request.Token, nil, nil)
}
