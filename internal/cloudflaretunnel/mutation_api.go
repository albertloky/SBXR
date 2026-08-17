package cloudflaretunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

var managementTokenCandidateName = regexp.MustCompile(`^sbxr-rotation-[0-9a-f]{32}$`)

type CreateManagementTokenCandidateRequest struct {
	Current       ManagementToken
	Name          string
	RequestSHA256 string
	CanonicalBody json.RawMessage
	NotBefore     time.Time
	NotAfter      time.Time
}

func (api *httpAPI) PrepareManagementTokenCandidate(ctx context.Context, current ManagementToken, name string, notBefore, notAfter time.Time) (CreateManagementTokenCandidateRequest, error) {
	request := CreateManagementTokenCandidateRequest{Current: current, Name: name, NotBefore: notBefore, NotAfter: notAfter}
	groups, err := api.managementTokenPermissionGroups(ctx, request)
	if err != nil {
		return CreateManagementTokenCandidateRequest{}, err
	}
	body, err := json.Marshal(managementTokenCandidateBody{Name: name, Policies: broadManagementTokenPolicies(groups)})
	if err != nil {
		return CreateManagementTokenCandidateRequest{}, APIError{Kind: APIMalformed}
	}
	digest := sha256.Sum256(body)
	request.RequestSHA256 = hex.EncodeToString(digest[:])
	request.CanonicalBody = body
	return request, nil
}

type ReconcileManagementTokenCandidateRequest = CreateManagementTokenCandidateRequest

type ManagementTokenCandidate struct {
	id, name, requestSHA256 string
	issuedOn                time.Time
	token                   ManagementToken
	used                    *atomic.Bool
}

func (candidate ManagementTokenCandidate) ID() string            { return candidate.id }
func (candidate ManagementTokenCandidate) RequestSHA256() string { return candidate.requestSHA256 }
func (candidate ManagementTokenCandidate) String() string {
	return "Cloudflare management-token candidate: redacted"
}
func (candidate ManagementTokenCandidate) GoString() string { return candidate.String() }
func (candidate ManagementTokenCandidate) ConsumeInfrastructureSecret() (string, bool) {
	if candidate.token.value == "" || candidate.used == nil || !candidate.used.CompareAndSwap(false, true) {
		return "", false
	}
	return candidate.token.value, true
}

func (api *httpAPI) CreateManagementTokenCandidate(ctx context.Context, request CreateManagementTokenCandidateRequest) (ManagementTokenCandidate, error) {
	prior, err := api.managementTokenCandidateMatches(ctx, request)
	if err != nil {
		if len(request.CanonicalBody) != 0 {
			return ManagementTokenCandidate{}, ManagementTokenCandidateCleanupError{}
		}
		return ManagementTokenCandidate{}, err
	}
	if len(prior) > 1 {
		if len(request.CanonicalBody) != 0 {
			return ManagementTokenCandidate{}, ManagementTokenCandidateCleanupError{}
		}
		return ManagementTokenCandidate{}, APIError{Kind: APIAmbiguous}
	}
	if len(prior) == 1 {
		candidateID := prior[0].id
		if err := api.DeleteManagementToken(ctx, DeleteManagementTokenRequest{ID: candidateID, Token: request.Current}); err != nil {
			return ManagementTokenCandidate{}, ManagementTokenCandidateCleanupError{candidateID: candidateID}
		}
		remaining, cleanupErr := api.managementTokenCandidateMatches(ctx, request)
		if cleanupErr != nil || len(remaining) != 0 {
			return ManagementTokenCandidate{}, ManagementTokenCandidateCleanupError{candidateID: candidateID}
		}
	}
	if len(request.CanonicalBody) != 0 && time.Now().UTC().After(request.NotAfter) {
		return ManagementTokenCandidate{}, APIError{Kind: APIAmbiguous}
	}
	var body managementTokenCandidateBody
	if len(request.CanonicalBody) == 0 {
		groups, groupErr := api.managementTokenPermissionGroups(ctx, request)
		if groupErr != nil {
			return ManagementTokenCandidate{}, groupErr
		}
		body = managementTokenCandidateBody{Name: request.Name, Policies: broadManagementTokenPolicies(groups)}
	} else {
		body, err = managementTokenBody(request)
		if err != nil {
			return ManagementTokenCandidate{}, err
		}
	}
	var envelope struct {
		Result struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Status   string `json:"status"`
			IssuedOn string `json:"issued_on"`
			Value    string `json:"value"`
		} `json:"result"`
	}
	if err := api.request(ctx, http.MethodPost, "/user/tokens", nil, request.Current, body, &envelope); err != nil {
		if !apiErrorIs(err, APITemporary) && !apiErrorIs(err, APIAmbiguous) {
			return ManagementTokenCandidate{}, err
		}
		matches, reconcileErr := api.managementTokenCandidateMatches(ctx, request)
		if reconcileErr != nil || len(matches) != 1 {
			if len(request.CanonicalBody) != 0 {
				return ManagementTokenCandidate{}, ManagementTokenCandidateCleanupError{}
			}
			return ManagementTokenCandidate{}, APIError{Kind: APIAmbiguous}
		}
		candidateID := matches[0].id
		if deleteErr := api.DeleteManagementToken(ctx, DeleteManagementTokenRequest{ID: candidateID, Token: request.Current}); deleteErr != nil {
			return ManagementTokenCandidate{}, ManagementTokenCandidateCleanupError{candidateID: candidateID}
		}
		remaining, cleanupErr := api.managementTokenCandidateMatches(ctx, request)
		if cleanupErr != nil || len(remaining) != 0 {
			return ManagementTokenCandidate{}, ManagementTokenCandidateCleanupError{candidateID: candidateID}
		}
		return ManagementTokenCandidate{}, APIError{Kind: APIAmbiguous}
	}
	candidate, candidateErr := newManagementTokenCandidate(envelope.Result.ID, envelope.Result.Name, envelope.Result.Status, envelope.Result.IssuedOn, envelope.Result.Value, request)
	if candidateErr == nil {
		return candidate, nil
	}
	if immutableID.MatchString(envelope.Result.ID) {
		if deleteErr := api.DeleteManagementToken(ctx, DeleteManagementTokenRequest{ID: envelope.Result.ID, Token: request.Current}); deleteErr != nil && !apiErrorIs(deleteErr, APINotFound) {
			return ManagementTokenCandidate{}, ManagementTokenCandidateCleanupError{candidateID: envelope.Result.ID}
		}
		if absentErr := api.VerifyManagementTokenCandidateAbsent(ctx, request); absentErr != nil {
			return ManagementTokenCandidate{}, ManagementTokenCandidateCleanupError{candidateID: envelope.Result.ID}
		}
	} else {
		matches, reconcileErr := api.managementTokenCandidateMatches(ctx, request)
		if reconcileErr != nil || len(matches) != 1 {
			return ManagementTokenCandidate{}, ManagementTokenCandidateCleanupError{}
		}
		candidateID := matches[0].id
		if deleteErr := api.DeleteManagementToken(ctx, DeleteManagementTokenRequest{ID: candidateID, Token: request.Current}); deleteErr != nil && !apiErrorIs(deleteErr, APINotFound) {
			return ManagementTokenCandidate{}, ManagementTokenCandidateCleanupError{candidateID: candidateID}
		}
		if absentErr := api.VerifyManagementTokenCandidateAbsent(ctx, request); absentErr != nil {
			return ManagementTokenCandidate{}, ManagementTokenCandidateCleanupError{candidateID: candidateID}
		}
	}
	return ManagementTokenCandidate{}, candidateErr
}

func (api *httpAPI) ReconcileManagementTokenCandidate(ctx context.Context, request ReconcileManagementTokenCandidateRequest) (ManagementTokenCandidate, error) {
	matches, err := api.managementTokenCandidateMatches(ctx, request)
	if err != nil || len(matches) != 1 {
		if err != nil {
			return ManagementTokenCandidate{}, err
		}
		return ManagementTokenCandidate{}, APIError{Kind: APIAmbiguous}
	}
	return matches[0], nil
}

func (api *httpAPI) VerifyManagementTokenCandidateAbsent(ctx context.Context, request ReconcileManagementTokenCandidateRequest) error {
	matches, err := api.managementTokenCandidateMatches(ctx, request)
	if err != nil || len(matches) != 0 {
		return APIError{Kind: APIAmbiguous}
	}
	return nil
}

func (api *httpAPI) managementTokenCandidateMatches(ctx context.Context, request ReconcileManagementTokenCandidateRequest) ([]ManagementTokenCandidate, error) {
	if !validManagementTokenCandidateRequest(request) {
		return nil, APIError{Kind: APIMalformed}
	}
	var body managementTokenCandidateBody
	if len(request.CanonicalBody) == 0 {
		groups, groupErr := api.managementTokenPermissionGroups(ctx, request)
		if groupErr != nil {
			return nil, groupErr
		}
		body = managementTokenCandidateBody{Name: request.Name, Policies: broadManagementTokenPolicies(groups)}
	} else {
		var err error
		body, err = managementTokenBody(request)
		if err != nil {
			return nil, err
		}
	}
	wantPolicies := body.Policies
	var matches []ManagementTokenCandidate
	for page := 1; page <= maxActiveZonePages; page++ {
		var envelope struct {
			Result     []managementTokenCandidateRecord `json:"result"`
			ResultInfo struct {
				Page       int `json:"page"`
				PerPage    int `json:"per_page"`
				TotalPages int `json:"total_pages"`
				Count      int `json:"count"`
			} `json:"result_info"`
		}
		query := url.Values{"name": {request.Name}, "page": {fmt.Sprint(page)}, "per_page": {"50"}}
		if err := api.get(ctx, "/user/tokens", query, request.Current, &envelope); err != nil {
			return nil, err
		}
		info := envelope.ResultInfo
		if info.TotalPages > maxActiveZonePages {
			return nil, APIError{Kind: APIAmbiguous}
		}
		if info.Page != page || info.PerPage != 50 || info.TotalPages < page || info.Count != len(envelope.Result) {
			return nil, APIError{Kind: APIMalformed}
		}
		for _, result := range envelope.Result {
			issued, parseErr := time.Parse(time.RFC3339, result.IssuedOn)
			if parseErr != nil || result.Name != request.Name || result.Status != "active" || issued.Before(request.NotBefore) || issued.After(request.NotAfter) || string(result.ExpiresOn) != "null" || string(result.Condition) != "null" || !reflect.DeepEqual(result.Policies, wantPolicies) {
				return nil, APIError{Kind: APIAmbiguous}
			}
			candidate, candidateErr := newManagementTokenCandidate(result.ID, result.Name, result.Status, result.IssuedOn, "", request)
			if candidateErr != nil {
				return nil, candidateErr
			}
			matches = append(matches, candidate)
		}
		if page == info.TotalPages {
			break
		}
	}
	return matches, nil
}

type managementTokenPolicy struct {
	Effect           string              `json:"effect"`
	PermissionGroups []map[string]string `json:"permission_groups"`
	Resources        map[string]string   `json:"resources"`
}

type managementTokenCandidateBody struct {
	Name      string                  `json:"name"`
	Policies  []managementTokenPolicy `json:"policies"`
	ExpiresOn any                     `json:"expires_on"`
	Condition any                     `json:"condition"`
}

type managementTokenCandidateRecord struct {
	ID        string                  `json:"id"`
	Name      string                  `json:"name"`
	Status    string                  `json:"status"`
	IssuedOn  string                  `json:"issued_on"`
	Policies  []managementTokenPolicy `json:"policies"`
	ExpiresOn json.RawMessage         `json:"expires_on"`
	Condition json.RawMessage         `json:"condition"`
}

func broadManagementTokenPolicies(groups map[string]string) []managementTokenPolicy {
	return []managementTokenPolicy{
		{Effect: "allow", PermissionGroups: []map[string]string{{"id": groups["User API Tokens Edit"]}}, Resources: map[string]string{"com.cloudflare.api.user.*": "*"}},
		{Effect: "allow", PermissionGroups: []map[string]string{{"id": groups["Cloudflare Tunnel Edit"]}}, Resources: map[string]string{"com.cloudflare.api.account.*": "*"}},
		{Effect: "allow", PermissionGroups: []map[string]string{{"id": groups["DNS Edit"]}, {"id": groups["Zone Read"]}}, Resources: map[string]string{"com.cloudflare.api.account.zone.*": "*"}},
	}
}

func (api *httpAPI) managementTokenPermissionGroups(ctx context.Context, request CreateManagementTokenCandidateRequest) (map[string]string, error) {
	if request.Current.value == "" || !managementTokenCandidateName.MatchString(request.Name) || request.NotBefore.IsZero() || request.NotAfter.Before(request.NotBefore) || request.NotAfter.Sub(request.NotBefore) > 5*time.Minute {
		return nil, APIError{Kind: APIMalformed}
	}
	var envelope struct {
		Result []struct{ ID, Name string } `json:"result"`
	}
	if err := api.get(ctx, "/user/tokens/permission_groups", nil, request.Current, &envelope); err != nil {
		return nil, err
	}
	want := map[string]string{"User API Tokens Edit": "", "Cloudflare Tunnel Edit": "", "DNS Edit": "", "Zone Read": ""}
	for _, group := range envelope.Result {
		if _, ok := want[group.Name]; ok && group.ID != "" {
			if want[group.Name] != "" {
				return nil, APIError{Kind: APIAmbiguous}
			}
			want[group.Name] = group.ID
		}
	}
	for _, id := range want {
		if id == "" {
			return nil, APIError{Kind: APIMalformed}
		}
	}
	return want, nil
}

func validManagementTokenCandidateRequest(request CreateManagementTokenCandidateRequest) bool {
	return request.Current.value != "" && managementTokenCandidateName.MatchString(request.Name) && sha256Text.MatchString(request.RequestSHA256) && !request.NotBefore.IsZero() && !request.NotAfter.Before(request.NotBefore) && request.NotAfter.Sub(request.NotBefore) <= 5*time.Minute
}

func managementTokenBody(request CreateManagementTokenCandidateRequest) (managementTokenCandidateBody, error) {
	if !validManagementTokenCandidateRequest(request) {
		return managementTokenCandidateBody{}, APIError{Kind: APIMalformed}
	}
	var body managementTokenCandidateBody
	if len(request.CanonicalBody) == 0 || json.Unmarshal(request.CanonicalBody, &body) != nil || body.Name != request.Name || body.ExpiresOn != nil || body.Condition != nil {
		return managementTokenCandidateBody{}, APIError{Kind: APIMalformed}
	}
	canonical, err := json.Marshal(body)
	digest := sha256.Sum256(canonical)
	if err != nil || hex.EncodeToString(digest[:]) != request.RequestSHA256 {
		return managementTokenCandidateBody{}, APIError{Kind: APIMalformed}
	}
	return body, nil
}

func newManagementTokenCandidate(id, name, status, issuedOn, value string, request CreateManagementTokenCandidateRequest) (ManagementTokenCandidate, error) {
	issued, err := time.Parse(time.RFC3339, issuedOn)
	if err != nil || !immutableID.MatchString(id) || name != request.Name || status != "active" || issued.Before(request.NotBefore) || issued.After(request.NotAfter) {
		return ManagementTokenCandidate{}, APIError{Kind: APIAmbiguous}
	}
	var token ManagementToken
	if value != "" {
		token, err = NewManagementToken(value)
		if err != nil {
			return ManagementTokenCandidate{}, APIError{Kind: APIMalformed}
		}
	}
	return ManagementTokenCandidate{id: id, name: name, requestSHA256: request.RequestSHA256, issuedOn: issued, token: token, used: &atomic.Bool{}}, nil
}

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
	var routes []Route
	if len(tunnels) == 1 {
		configuration, configErr := api.GetConfiguration(ctx, GetConfigurationRequest{AccountID: request.AccountID, TunnelID: tunnels[0].ID, Token: request.Token})
		if configErr != nil {
			return MutationObservation{}, configErr
		}
		routes = append([]Route(nil), configuration.Routes...)
	}
	routeJSON, _ := json.Marshal(routes)
	digest := sha256.Sum256([]byte(request.AccountID + "\n" + request.ZoneID + "\n" + request.Tunnel + "\n" + request.Hostname + "\n" + resourcesText(tunnels) + resourcesText(dns) + string(routeJSON)))
	return MutationObservation{Digest: hex.EncodeToString(digest[:]), Tunnels: tunnels, DNSRecords: dns, Routes: routes}, nil
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

func (api *httpAPI) GetConfiguration(ctx context.Context, request GetConfigurationRequest) (Configuration, error) {
	if api == nil || api.client == nil || !immutableID.MatchString(request.AccountID) || !tunnelUUID.MatchString(request.TunnelID) || request.Token.value == "" {
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
	if err := api.get(ctx, "/accounts/"+request.AccountID+"/cfd_tunnel/"+request.TunnelID+"/configurations", nil, request.Token, &envelope); err != nil {
		return Configuration{}, err
	}
	if envelope.Result.TunnelID != request.TunnelID || !tunnelUUID.MatchString(envelope.Result.TunnelID) || envelope.Result.Version < 1 || len(envelope.Result.Config.Ingress) > 3 {
		return Configuration{}, APIError{Kind: APIAmbiguous}
	}
	for _, route := range envelope.Result.Config.Ingress {
		if !safeObservedRoute(route) {
			return Configuration{}, APIError{Kind: APIMalformed}
		}
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

func (api *httpAPI) GetDNSRecord(ctx context.Context, request GetDNSRecordRequest) (DNSObservation, error) {
	if api == nil || api.client == nil || !immutableID.MatchString(request.ZoneID) || !immutableID.MatchString(request.ID) || request.Token.value == "" {
		return DNSObservation{}, APIError{Kind: APIMalformed}
	}
	var envelope struct {
		Result struct {
			ID, Name, Type, Content string
			Proxied                 bool
		} `json:"result"`
	}
	if err := api.get(ctx, "/zones/"+request.ZoneID+"/dns_records/"+request.ID, nil, request.Token, &envelope); err != nil {
		return DNSObservation{}, err
	}
	result := envelope.Result
	if result.ID != request.ID || !immutableID.MatchString(result.ID) || !validZoneName(result.Name) || result.Type != "CNAME" && result.Type != "A" && result.Type != "AAAA" || !safeProviderValue(result.Content) {
		return DNSObservation{}, APIError{Kind: APIAmbiguous}
	}
	return DNSObservation{ID: result.ID, Name: result.Name, Type: result.Type, Content: result.Content, Proxied: result.Proxied}, nil
}

func (api *httpAPI) PutDNSRecord(ctx context.Context, request PutDNSRecordRequest) (OwnedResource, error) {
	if api == nil || api.client == nil || !immutableID.MatchString(request.ZoneID) || !immutableID.MatchString(request.ID) || !validZoneName(request.Name) || request.Type != "CNAME" && request.Type != "A" && request.Type != "AAAA" || !safeProviderValue(request.Content) || request.Token.value == "" {
		return OwnedResource{}, APIError{Kind: APIMalformed}
	}
	var envelope struct {
		Result struct {
			ID, Name, Type, Content string
			Proxied                 bool
		} `json:"result"`
	}
	err := api.request(ctx, http.MethodPut, "/zones/"+request.ZoneID+"/dns_records/"+request.ID, nil, request.Token, map[string]any{"type": request.Type, "name": request.Name, "content": request.Content, "proxied": request.Proxied}, &envelope)
	result := envelope.Result
	if err != nil {
		return OwnedResource{}, err
	}
	if result.ID != request.ID || result.Name != request.Name || result.Type != request.Type || result.Content != request.Content || result.Proxied != request.Proxied {
		return OwnedResource{}, APIError{Kind: APIAmbiguous}
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
	if len(routes) < 1 || len(routes) > 3 || routes[len(routes)-1] != (Route{Service: "http_status:404"}) {
		return false
	}
	seen := map[string]bool{}
	for _, route := range routes[:len(routes)-1] {
		if !validZoneName(route.Hostname) || route.Service != xhttpOrigin && route.Service != webSocketOrigin || seen[route.Service] {
			return false
		}
		seen[route.Service] = true
	}
	return true
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
	err := api.request(ctx, http.MethodDelete, "/zones/"+request.ZoneID+"/dns_records/"+request.ID, nil, request.Token, nil, nil)
	if apiErrorIs(err, APINotFound) {
		return nil
	}
	return err
}
func (api *httpAPI) DeleteTunnel(ctx context.Context, request DeleteTunnelRequest) error {
	err := api.request(ctx, http.MethodDelete, "/accounts/"+request.AccountID+"/cfd_tunnel/"+request.ID, nil, request.Token, nil, nil)
	if apiErrorIs(err, APINotFound) {
		return nil
	}
	return err
}

type DeleteManagementTokenRequest struct {
	ID    string
	Token ManagementToken
}

func (api *httpAPI) DeleteManagementToken(ctx context.Context, request DeleteManagementTokenRequest) error {
	if !immutableID.MatchString(request.ID) || request.Token.value == "" {
		return APIError{Kind: APIMalformed}
	}
	return api.request(ctx, http.MethodDelete, "/user/tokens/"+request.ID, nil, request.Token, nil, nil)
}

func (api *httpAPI) GetTunnel(ctx context.Context, request GetTunnelRequest) (OwnedResource, error) {
	if !immutableID.MatchString(request.AccountID) || !tunnelUUID.MatchString(request.ID) || request.Token.value == "" {
		return OwnedResource{}, APIError{Kind: APIMalformed}
	}
	var envelope struct {
		Result struct{ ID, Name string } `json:"result"`
	}
	if err := api.get(ctx, "/accounts/"+request.AccountID+"/cfd_tunnel/"+request.ID, nil, request.Token, &envelope); err != nil {
		return OwnedResource{}, err
	}
	if envelope.Result.ID != request.ID || envelope.Result.Name == "" {
		return OwnedResource{}, APIError{Kind: APIAmbiguous}
	}
	return OwnedResource{ID: envelope.Result.ID, Name: envelope.Result.Name}, nil
}
