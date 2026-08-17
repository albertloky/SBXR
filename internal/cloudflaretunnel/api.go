package cloudflaretunnel

import (
	"context"
	"encoding/json"
	"errors"
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
	maxActiveZonePages        = 10      // ponytail: 500 active zones; add filtered discovery only if the API gains a safe exact filter.
	maxZonePages              = 100     // ponytail: replace with a cursor if Cloudflare removes bounded pages.
)

type NameServerResolver interface {
	LookupNS(context.Context, string) ([]*net.NS, error)
}

type httpAPI struct {
	client   *http.Client
	baseURL  string
	resolver NameServerResolver
	origins  OriginObserver
}

type OriginObserver interface {
	Reachable(context.Context, string) (bool, error)
}

type localOriginObserver struct{}

func (localOriginObserver) Reachable(ctx context.Context, address string) (bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/", nil)
	if err != nil {
		return false, err
	}
	client := http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	_ = response.Body.Close()
	return response.StatusCode >= 100 && response.StatusCode <= 599, nil
}

func newHTTPAPI(client *http.Client, baseURL string, resolver NameServerResolver) *httpAPI {
	return &httpAPI{client: client, baseURL: strings.TrimRight(baseURL, "/"), resolver: resolver, origins: localOriginObserver{}}
}

func NewProductionAPI() MutationAPI {
	return newHTTPAPI(&http.Client{Timeout: 15 * time.Second}, cloudflareAPIURL, net.DefaultResolver)
}

func (api *httpAPI) Observe(ctx context.Context, request ObservationRequest) (Observation, error) {
	if api == nil || api.client == nil || api.resolver == nil || !immutableID.MatchString(request.AccountID) || !immutableID.MatchString(request.ZoneID) || !validZoneName(request.ZoneName) || request.Token.value == "" {
		return Observation{}, APIError{Kind: APIMalformed}
	}
	token, err := api.verifyToken(ctx, request)
	if err != nil {
		return Observation{}, requiringPermission(err, UserAPITokensEditPermission)
	}
	account, zone, err := api.selectedZone(ctx, request)
	if err != nil {
		return Observation{}, requiringPermission(err, ZoneReadPermission)
	}
	if err := api.probeList(ctx, "/zones/"+request.ZoneID+"/dns_records", url.Values{"page": {"1"}, "per_page": {"1"}}, request.Token); err != nil {
		return Observation{}, requiringPermission(err, DNSEditPermission)
	}
	if err := api.probeList(ctx, "/accounts/"+request.AccountID+"/cfd_tunnel", url.Values{"is_deleted": {"false"}, "page": {"1"}, "per_page": {"1"}}, request.Token); err != nil {
		return Observation{}, requiringPermission(err, CloudflareTunnelEditPermission)
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
	return Observation{Account: account, Zone: zone, Token: token, DNSListProven: true, TunnelListProven: true}, nil
}

func requiringPermission(err error, permission PermissionKind) error {
	var apiError APIError
	if errors.As(err, &apiError) && (apiError.Kind == APIUnauthorized || apiError.Kind == APIForbidden) {
		apiError.RequiredPermission = permission
		return apiError
	}
	return err
}

func (api *httpAPI) verifyToken(ctx context.Context, request ObservationRequest) (TokenObservation, error) {
	var envelope struct {
		Result struct {
			ID        string `json:"id"`
			Status    string `json:"status"`
			ExpiresOn string `json:"expires_on"`
		} `json:"result"`
	}
	if err := api.get(ctx, "/user/tokens/verify", nil, request.Token, &envelope); err != nil {
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

func (api *httpAPI) selectedZone(ctx context.Context, request ObservationRequest) (AccountObservation, ZoneObservation, error) {
	var matches []ZoneObservation
	account := AccountObservation{}
	for page := 1; page <= maxActiveZonePages; page++ {
		query := url.Values{"status": {"active"}, "page": {strconv.Itoa(page)}, "per_page": {"50"}}
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
		if info.TotalPages > maxActiveZonePages {
			return AccountObservation{}, ZoneObservation{}, APIError{Kind: APILimit}
		}
		if info.Page != page || info.PerPage != 50 || info.TotalPages < page || info.Count != len(envelope.Result) {
			return AccountObservation{}, ZoneObservation{}, APIError{Kind: APIMalformed}
		}
		for _, source := range envelope.Result {
			if !immutableID.MatchString(source.ID) || !validZoneName(source.Name) || !immutableID.MatchString(source.Account.ID) || source.Account.Name == "" || source.Status != "active" || len(source.NameServers) == 0 {
				return AccountObservation{}, ZoneObservation{}, APIError{Kind: APIMalformed}
			}
			if source.ID == request.ZoneID && source.Name == request.ZoneName && source.Account.ID == request.AccountID {
				account = AccountObservation{ID: source.Account.ID, Name: source.Account.Name}
				matches = append(matches, ZoneObservation{ID: source.ID, AccountID: source.Account.ID, Name: source.Name, Status: source.Status, AssignedNameServers: append([]string(nil), source.NameServers...)})
			}
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

func (api *httpAPI) probeList(ctx context.Context, path string, query url.Values, token ManagementToken) error {
	var envelope struct {
		Result     []json.RawMessage `json:"result"`
		ResultInfo struct {
			Page    int `json:"page"`
			PerPage int `json:"per_page"`
			Count   int `json:"count"`
		} `json:"result_info"`
	}
	if err := api.get(ctx, path, query, token, &envelope); err != nil {
		return err
	}
	if envelope.ResultInfo.Page != 1 || envelope.ResultInfo.PerPage != 1 || envelope.ResultInfo.Count != len(envelope.Result) || len(envelope.Result) > 1 {
		return APIError{Kind: APIMalformed}
	}
	return nil
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
	case status == http.StatusNotFound:
		return APINotFound
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
