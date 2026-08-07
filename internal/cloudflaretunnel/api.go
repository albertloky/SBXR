package cloudflaretunnel

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	cloudflareAPIURL          = "https://api.cloudflare.com/client/v4"
	maxCloudflareResponseSize = 1 << 20 // ponytail: raise only if an official response shape exceeds 1 MiB.
	maxZonePages              = 100     // ponytail: replace with a cursor if Cloudflare removes bounded pages.
)

type NameServerResolver interface {
	LookupNS(context.Context, string) ([]*net.NS, error)
}

type httpAPI struct {
	client   *http.Client
	baseURL  string
	resolver NameServerResolver
}

func newHTTPAPI(client *http.Client, baseURL string, resolver NameServerResolver) *httpAPI {
	return &httpAPI{client: client, baseURL: strings.TrimRight(baseURL, "/"), resolver: resolver}
}

func NewProductionAPI() API {
	return newHTTPAPI(&http.Client{Timeout: 15 * time.Second}, cloudflareAPIURL, net.DefaultResolver)
}

func (api *httpAPI) Observe(ctx context.Context, request ObservationRequest) (Observation, error) {
	if api == nil || api.client == nil || api.resolver == nil || !immutableID.MatchString(request.AccountID) || !immutableID.MatchString(request.ZoneID) || !validZoneName(request.ZoneName) || request.Token.value == "" {
		return Observation{}, APIError{Kind: APIMalformed}
	}
	token, err := api.verifyToken(ctx, request)
	if err != nil {
		return Observation{}, err
	}
	policies, err := api.tokenPolicies(ctx, request, token.ID, token.Status)
	if err != nil {
		return Observation{}, err
	}
	account, zone, err := api.selectedZone(ctx, request)
	if err != nil {
		return Observation{}, err
	}
	nameservers, err := api.resolver.LookupNS(ctx, request.ZoneName)
	if err != nil {
		return Observation{}, APIError{Kind: APITemporary}
	}
	zone.ObservedNameServers = make([]string, len(nameservers))
	for index, nameserver := range nameservers {
		if nameserver == nil || nameserver.Host == "" {
			return Observation{}, APIError{Kind: APIMalformed}
		}
		zone.ObservedNameServers[index] = nameserver.Host
	}
	return Observation{Account: account, Zone: zone, Token: token, Policies: policies}, nil
}

func (api *httpAPI) verifyToken(ctx context.Context, request ObservationRequest) (TokenObservation, error) {
	var envelope struct {
		Result struct {
			ID        string `json:"id"`
			Status    string `json:"status"`
			ExpiresOn string `json:"expires_on"`
		} `json:"result"`
	}
	if err := api.get(ctx, "/accounts/"+request.AccountID+"/tokens/verify", nil, request.Token, &envelope); err != nil {
		return TokenObservation{}, err
	}
	if !immutableID.MatchString(envelope.Result.ID) || !validTokenStatus(envelope.Result.Status) {
		return TokenObservation{}, APIError{Kind: APIMalformed}
	}
	token := TokenObservation{ID: envelope.Result.ID, Status: envelope.Result.Status}
	if envelope.Result.ExpiresOn != "" {
		expires, err := time.Parse(time.RFC3339, envelope.Result.ExpiresOn)
		if err != nil {
			return TokenObservation{}, APIError{Kind: APIMalformed}
		}
		token.ExpiresOn = &expires
	}
	return token, nil
}

func (api *httpAPI) tokenPolicies(ctx context.Context, request ObservationRequest, tokenID, tokenStatus string) ([]TokenPolicy, error) {
	var envelope struct {
		Result struct {
			ID       string `json:"id"`
			Status   string `json:"status"`
			Policies []struct {
				Effect           string `json:"effect"`
				PermissionGroups []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"permission_groups"`
				Resources map[string]string `json:"resources"`
			} `json:"policies"`
		} `json:"result"`
	}
	if err := api.get(ctx, "/accounts/"+request.AccountID+"/tokens/"+tokenID, nil, request.Token, &envelope); err != nil {
		return nil, err
	}
	if envelope.Result.ID != tokenID || envelope.Result.Status != tokenStatus {
		return nil, APIError{Kind: APIAmbiguous}
	}
	if !validTokenStatus(envelope.Result.Status) || len(envelope.Result.Policies) == 0 {
		return nil, APIError{Kind: APIMalformed}
	}
	policies := make([]TokenPolicy, len(envelope.Result.Policies))
	for policyIndex, source := range envelope.Result.Policies {
		if source.Effect == "" || len(source.PermissionGroups) == 0 || len(source.Resources) == 0 {
			return nil, APIError{Kind: APIMalformed}
		}
		policy := TokenPolicy{Effect: source.Effect, PermissionGroups: make([]string, len(source.PermissionGroups)), Resources: make(map[string]string, len(source.Resources))}
		for permissionIndex, group := range source.PermissionGroups {
			if group.ID == "" || group.Name == "" {
				return nil, APIError{Kind: APIMalformed}
			}
			policy.PermissionGroups[permissionIndex] = group.Name
		}
		for resource, value := range source.Resources {
			if resource == "" || value == "" {
				return nil, APIError{Kind: APIMalformed}
			}
			policy.Resources[resource] = value
		}
		policies[policyIndex] = policy
	}
	return policies, nil
}

func (api *httpAPI) selectedZone(ctx context.Context, request ObservationRequest) (AccountObservation, ZoneObservation, error) {
	var matches []ZoneObservation
	account := AccountObservation{}
	for page := 1; page <= maxZonePages; page++ {
		query := url.Values{"account.id": {request.AccountID}, "name": {request.ZoneName}, "page": {strconv.Itoa(page)}, "per_page": {"50"}}
		var envelope struct {
			Result []struct {
				ID          string   `json:"id"`
				Name        string   `json:"name"`
				Status      string   `json:"status"`
				NameServers []string `json:"name_servers"`
				Account     struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"account"`
			} `json:"result"`
			ResultInfo struct {
				Page       int `json:"page"`
				PerPage    int `json:"per_page"`
				TotalPages int `json:"total_pages"`
				Count      int `json:"count"`
			} `json:"result_info"`
		}
		if err := api.get(ctx, "/zones", query, request.Token, &envelope); err != nil {
			return AccountObservation{}, ZoneObservation{}, err
		}
		info := envelope.ResultInfo
		if info.Page != page || info.PerPage != 50 || info.TotalPages < page || info.TotalPages > maxZonePages || info.Count != len(envelope.Result) {
			return AccountObservation{}, ZoneObservation{}, APIError{Kind: APIMalformed}
		}
		for _, source := range envelope.Result {
			if source.ID != request.ZoneID || source.Name != request.ZoneName || source.Account.ID != request.AccountID || source.Account.Name == "" || !validZoneStatus(source.Status) || len(source.NameServers) == 0 {
				return AccountObservation{}, ZoneObservation{}, APIError{Kind: APIAmbiguous}
			}
			account = AccountObservation{ID: source.Account.ID, Name: source.Account.Name}
			matches = append(matches, ZoneObservation{ID: source.ID, AccountID: source.Account.ID, Name: source.Name, Status: source.Status, AssignedNameServers: append([]string(nil), source.NameServers...)})
		}
		if page == info.TotalPages {
			break
		}
	}
	if len(matches) != 1 {
		return AccountObservation{}, ZoneObservation{}, APIError{Kind: APIAmbiguous}
	}
	return account, matches[0], nil
}

func (api *httpAPI) get(ctx context.Context, path string, query url.Values, token ManagementToken, target any) error {
	return api.request(ctx, http.MethodGet, path, query, token, nil, target)
}

func (api *httpAPI) request(ctx context.Context, method, path string, query url.Values, token ManagementToken, source, target any) error {
	var requestBody io.Reader
	if source != nil {
		encoded, err := json.Marshal(source)
		if err != nil {
			return APIError{Kind: APIMalformed}
		}
		requestBody = strings.NewReader(string(encoded))
	}
	request, err := http.NewRequestWithContext(ctx, method, api.baseURL+path, requestBody)
	if err != nil {
		return APIError{Kind: APIMalformed}
	}
	request.URL.RawQuery = query.Encode()
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+token.value)
	if source != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := api.client.Do(request)
	if err != nil {
		return APIError{Kind: APITemporary}
	}
	defer response.Body.Close()
	if kind := statusErrorKind(response.StatusCode); kind != "" {
		return APIError{Kind: kind}
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxCloudflareResponseSize+1))
	if err != nil {
		return APIError{Kind: APITemporary}
	}
	if len(responseBody) > maxCloudflareResponseSize {
		return APIError{Kind: APIMalformed}
	}
	var status struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
	}
	if json.Unmarshal(responseBody, &status) != nil {
		return APIError{Kind: APIMalformed}
	}
	if !status.Success {
		return APIError{Kind: APIPermanent}
	}
	if len(status.Result) == 0 || string(status.Result) == "null" || target != nil && json.Unmarshal(responseBody, target) != nil {
		return APIError{Kind: APIMalformed}
	}
	return nil
}

func statusErrorKind(status int) APIErrorKind {
	switch {
	case status == http.StatusUnauthorized:
		return APIUnauthorized
	case status == http.StatusForbidden:
		return APIForbidden
	case status == http.StatusTooManyRequests || status >= 500:
		return APITemporary
	case status < 200 || status >= 300:
		return APIPermanent
	default:
		return ""
	}
}

func validTokenStatus(status string) bool {
	return status == "active" || status == "disabled" || status == "expired"
}

func validZoneStatus(status string) bool {
	return status == "active" || status == "pending" || status == "initializing" || status == "moved"
}
