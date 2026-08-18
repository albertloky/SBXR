package cloudflaretunnel_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
)

const mutationTunnelID = "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415"

type reachableOrigins struct{ addresses []string }

func (origins *reachableOrigins) Reachable(_ context.Context, address string) (bool, error) {
	origins.addresses = append(origins.addresses, address)
	return true, nil
}

func TestRemovalDeletesAreRestartIdempotentOnlyForNotFound(t *testing.T) {
	managementToken, err := cloudflaretunnel.NewManagementToken(token)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(status) }))
			defer server.Close()
			api := cloudflaretunnel.NewFixtureMutationAPI(server.Client(), server.URL, staticResolver{}, &reachableOrigins{})
			dnsErr := api.DeleteDNSRecord(context.Background(), cloudflaretunnel.DeleteDNSRecordRequest{ZoneID: zoneID, ID: strings.Repeat("3", 32), Token: managementToken})
			tunnelErr := api.DeleteTunnel(context.Background(), cloudflaretunnel.DeleteTunnelRequest{AccountID: accountID, ID: mutationTunnelID, Token: managementToken})
			if (dnsErr != nil) != (status != http.StatusNotFound) || (tunnelErr != nil) != (status != http.StatusNotFound) {
				t.Fatalf("delete errors = (%v, %v)", dnsErr, tunnelErr)
			}
		})
	}
}

func TestManagementTokenDeletionUsesTheExactUserTokenID(t *testing.T) {
	managementToken, err := cloudflaretunnel.NewManagementToken(token)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		called = request.Method == http.MethodDelete && request.URL.Path == "/user/tokens/"+tokenID
		fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":{}}`)
	}))
	defer server.Close()
	api := cloudflaretunnel.NewFixtureMutationAPI(server.Client(), server.URL, staticResolver{}, &reachableOrigins{})
	if err := api.DeleteManagementToken(t.Context(), cloudflaretunnel.DeleteManagementTokenRequest{ID: tokenID, Token: managementToken}); err != nil || !called {
		t.Fatalf("DeleteManagementToken() = %v, called=%t", err, called)
	}
}

func TestHTTPMutationAPICreatesOnlyTheBoundBroadUserTokenCandidate(t *testing.T) {
	managementToken, err := cloudflaretunnel.NewManagementToken(token)
	if err != nil {
		t.Fatal(err)
	}
	const candidateSecret = "CANDIDATE_USER_TOKEN_MARKER_0000000000000000"
	const candidateName = "sbxr-rotation-7f3a91c27f3a91c27f3a91c27f3a91c2"
	requestSHA := "7f3a91c27f3a91c27f3a91c27f3a91c2" + strings.Repeat("a", 32)
	notBefore := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	var created map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.Method + " " + request.URL.Path {
		case "GET /user/tokens/permission_groups":
			fmt.Fprint(response, `{"success":true,"result":[{"id":"p1","name":"User API Tokens Edit"},{"id":"p2","name":"Cloudflare Tunnel Edit"},{"id":"p3","name":"DNS Edit"},{"id":"p4","name":"Zone Read"}]}`)
		case "GET /user/tokens":
			fmt.Fprint(response, `{"success":true,"result":[],"result_info":{"page":1,"per_page":50,"total_pages":1,"count":0}}`)
		case "POST /user/tokens":
			if request.Header.Get("Authorization") != "Bearer "+token || json.NewDecoder(request.Body).Decode(&created) != nil {
				t.Fatal("candidate request was not authenticated or valid JSON")
			}
			fmt.Fprint(response, `{"success":true,"result":{"id":"44444444444444444444444444444444","name":"`+candidateName+`","status":"active","issued_on":"2026-08-17T00:00:00Z","value":"`+candidateSecret+`"}}`)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	api := cloudflaretunnel.NewFixtureMutationAPI(server.Client(), server.URL, staticResolver{}, &reachableOrigins{})
	candidate, err := api.CreateManagementTokenCandidate(t.Context(), cloudflaretunnel.CreateManagementTokenCandidateRequest{Current: managementToken, Name: candidateName, RequestSHA256: requestSHA, NotBefore: notBefore, NotAfter: notBefore.Add(time.Minute)})
	if err != nil || candidate.ID() != "44444444444444444444444444444444" || candidate.RequestSHA256() != requestSHA {
		t.Fatalf("candidate = (%+v, %v)", candidate, err)
	}
	rendered := fmt.Sprintf("%v %#v", candidate, candidate)
	if strings.Contains(rendered, candidateSecret) || strings.Contains(rendered, token) {
		t.Fatalf("candidate leaked a token: %s", rendered)
	}
	policies, _ := created["policies"].([]any)
	if created["name"] != candidateName || len(policies) != 3 || created["expires_on"] != nil || created["condition"] != nil || strings.Contains(fmt.Sprint(created), candidateSecret) {
		t.Fatalf("candidate request = %#v", created)
	}
}

func TestHTTPMutationAPIReconcilesExactlyOneBoundCandidate(t *testing.T) {
	managementToken, _ := cloudflaretunnel.NewManagementToken(token)
	requestSHA := strings.Repeat("b", 64)
	candidateName := "sbxr-rotation-" + strings.Repeat("b", 32)
	notBefore := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	policies := `"policies":[{"effect":"allow","permission_groups":[{"id":"p1"}],"resources":{"com.cloudflare.api.user.*":"*"}},{"effect":"allow","permission_groups":[{"id":"p2"}],"resources":{"com.cloudflare.api.account.*":"*"}},{"effect":"allow","permission_groups":[{"id":"p3"},{"id":"p4"}],"resources":{"com.cloudflare.api.account.zone.*":"*"}}],"expires_on":null,"condition":null`
	for _, test := range []struct {
		name, result string
		want         bool
	}{
		{"one exact", `[{"id":"44444444444444444444444444444444","name":"` + candidateName + `","status":"active","issued_on":"2026-08-17T00:00:00Z",` + policies + `}]`, true},
		{"zero", `[]`, false},
		{"multiple", `[{"id":"44444444444444444444444444444444","name":"` + candidateName + `","status":"active","issued_on":"2026-08-17T00:00:00Z",` + policies + `},{"id":"55555555555555555555555555555555","name":"` + candidateName + `","status":"active","issued_on":"2026-08-17T00:00:00Z",` + policies + `}]`, false},
		{"contradictory", `[{"id":"44444444444444444444444444444444","name":"` + candidateName + `","status":"disabled","issued_on":"2026-08-17T00:00:00Z",` + policies + `}]`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/user/tokens/permission_groups":
					fmt.Fprint(response, `{"success":true,"result":[{"id":"p1","name":"User API Tokens Edit"},{"id":"p2","name":"Cloudflare Tunnel Edit"},{"id":"p3","name":"DNS Edit"},{"id":"p4","name":"Zone Read"}]}`)
				case "/user/tokens":
					if request.URL.Query().Get("name") != candidateName || request.URL.Query().Get("page") != "1" || request.URL.Query().Get("per_page") != "50" {
						t.Fatalf("candidate reconciliation request = %s", request.URL)
					}
					fmt.Fprint(response, `{"success":true,"result":`+test.result+`,"result_info":{"page":1,"per_page":50,"total_pages":1,"count":`+fmt.Sprint(strings.Count(test.result, `"id"`)/5)+`}}`)
				default:
					http.NotFound(response, request)
				}
			}))
			defer server.Close()
			api := cloudflaretunnel.NewFixtureMutationAPI(server.Client(), server.URL, staticResolver{}, &reachableOrigins{})
			candidate, err := api.ReconcileManagementTokenCandidate(t.Context(), cloudflaretunnel.ReconcileManagementTokenCandidateRequest{Current: managementToken, Name: candidateName, RequestSHA256: requestSHA, NotBefore: notBefore, NotAfter: notBefore.Add(time.Minute)})
			if (err == nil) != test.want || test.want && candidate.ID() != "44444444444444444444444444444444" {
				t.Fatalf("reconcile = (%+v, %v), want success=%t", candidate, err, test.want)
			}
		})
	}
}

func TestHTTPMutationAPICleansAnExactCandidateAfterALostCreateResponse(t *testing.T) {
	managementToken, _ := cloudflaretunnel.NewManagementToken(token)
	requestSHA := strings.Repeat("d", 64)
	candidateName := "sbxr-rotation-" + strings.Repeat("d", 32)
	notBefore := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.Method + " " + request.URL.Path {
		case "GET /user/tokens/permission_groups":
			fmt.Fprint(response, `{"success":true,"result":[{"id":"p1","name":"User API Tokens Edit"},{"id":"p2","name":"Cloudflare Tunnel Edit"},{"id":"p3","name":"DNS Edit"},{"id":"p4","name":"Zone Read"}]}`)
		case "POST /user/tokens":
			response.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(response, `{"success":false,"errors":[{"code":10000,"message":"temporary"}]}`)
		case "GET /user/tokens":
			result := `[]`
			count := 0
			if !deleted {
				result = `[{"id":"44444444444444444444444444444444","name":"` + candidateName + `","status":"active","issued_on":"2026-08-17T00:00:00Z","policies":[{"effect":"allow","permission_groups":[{"id":"p1"}],"resources":{"com.cloudflare.api.user.*":"*"}},{"effect":"allow","permission_groups":[{"id":"p2"}],"resources":{"com.cloudflare.api.account.*":"*"}},{"effect":"allow","permission_groups":[{"id":"p3"},{"id":"p4"}],"resources":{"com.cloudflare.api.account.zone.*":"*"}}],"expires_on":null,"condition":null}]`
				count = 1
			}
			fmt.Fprintf(response, `{"success":true,"result":%s,"result_info":{"page":1,"per_page":50,"total_pages":1,"count":%d}}`, result, count)
		case "DELETE /user/tokens/44444444444444444444444444444444":
			deleted = true
			fmt.Fprint(response, `{"success":true,"result":{}}`)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	api := cloudflaretunnel.NewFixtureMutationAPI(server.Client(), server.URL, staticResolver{}, &reachableOrigins{})
	_, err := api.CreateManagementTokenCandidate(t.Context(), cloudflaretunnel.CreateManagementTokenCandidateRequest{Current: managementToken, Name: candidateName, RequestSHA256: requestSHA, NotBefore: notBefore, NotAfter: notBefore.Add(time.Minute)})
	if err == nil || !deleted {
		t.Fatalf("lost create = %v, deleted=%t", err, deleted)
	}
}

func TestHTTPMutationAPIExposesSecretFreeAuthoritativeDNSAndEffectiveCAA(t *testing.T) {
	managementToken, err := cloudflaretunnel.NewManagementToken(token)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		name, kind := request.URL.Query().Get("name"), request.URL.Query().Get("type")
		switch name + "/" + kind {
		case "direct.example.com/A":
			fmt.Fprint(response, `{"success":true,"result":[{"id":"33333333333333333333333333333333","name":"direct.example.com","type":"A","content":"192.0.2.10","proxied":false}]}`)
		case "direct.example.com/AAAA":
			fmt.Fprint(response, `{"success":true,"result":[{"id":"44444444444444444444444444444444","name":"direct.example.com","type":"AAAA","content":"2001:db8::10","proxied":false}]}`)
		case "direct.example.com/CAA":
			fmt.Fprint(response, `{"success":true,"result":[]}`)
		case "example.com/CAA":
			fmt.Fprint(response, `{"success":true,"result":[{"id":"55555555555555555555555555555555","name":"example.com","type":"CAA","data":{"flags":0,"tag":"issue","value":"letsencrypt.org; validationmethods=http-01"}}]}`)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	api := cloudflaretunnel.NewFixtureMutationAPI(server.Client(), server.URL, staticResolver{}, &reachableOrigins{})
	request := cloudflaretunnel.CertificateDNSRequest{ZoneID: zoneID, ZoneName: "example.com", Hostname: "direct.example.com", PublicIPv4: "192.0.2.10", PublicIPv6: "2001:db8::10", IPv4RecordID: "33333333333333333333333333333333", IPv6RecordID: "44444444444444444444444444444444", Token: managementToken}
	facts, err := api.ObserveCertificateDNS(context.Background(), request)
	if err != nil || facts.Hostname != request.Hostname || facts.Addresses[0] != netip.MustParseAddr(request.PublicIPv4) || facts.Addresses[1] != netip.MustParseAddr(request.PublicIPv6) || facts.EffectiveCAA.Name != request.ZoneName || len(facts.EffectiveCAA.Records) != 1 || facts.EffectiveCAA.Records[0].Tag != "issue" {
		t.Fatalf("ObserveCertificateDNS() = %+v, %v", facts, err)
	}
	rendered := fmt.Sprintf("%+v %#v %s", request, facts, request)
	for _, forbidden := range []string{token, "33333333333333333333333333333333", "44444444444444444444444444444444", "55555555555555555555555555555555"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("certificate DNS handoff leaked %q: %s", forbidden, rendered)
		}
	}
}

func TestHTTPMutationAPIClassifiesDNSPropagationAndDrift(t *testing.T) {
	managementToken, err := cloudflaretunnel.NewManagementToken(token)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, result string
		kind         cloudflaretunnel.APIErrorKind
	}{
		{name: "provider delay", result: `[]`, kind: cloudflaretunnel.APITemporary},
		{name: "DNS drift", result: `[{"id":"33333333333333333333333333333333","name":"direct.example.com","type":"A","content":"192.0.2.99","proxied":false}]`, kind: cloudflaretunnel.APIAmbiguous},
		{name: "changed ID", result: `[{"id":"77777777777777777777777777777777","name":"direct.example.com","type":"A","content":"192.0.2.10","proxied":false}]`, kind: cloudflaretunnel.APIAmbiguous},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				if request.URL.Query().Get("type") == "A" {
					fmt.Fprint(response, `{"success":true,"result":`+test.result+`}`)
					return
				}
				fmt.Fprint(response, `{"success":true,"result":[]}`)
			}))
			defer server.Close()
			api := cloudflaretunnel.NewFixtureMutationAPI(server.Client(), server.URL, staticResolver{}, &reachableOrigins{})
			_, gotErr := api.ObserveCertificateDNS(context.Background(), cloudflaretunnel.CertificateDNSRequest{ZoneID: zoneID, ZoneName: "example.com", Hostname: "direct.example.com", PublicIPv4: "192.0.2.10", IPv4RecordID: "33333333333333333333333333333333", Token: managementToken})
			assertAPIError(t, gotErr, test.kind)
		})
	}
}

func TestHTTPMutationAPIConsumesEveryEffectiveCAAPage(t *testing.T) {
	managementToken, err := cloudflaretunnel.NewManagementToken(token)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		name, kind := request.URL.Query().Get("name"), request.URL.Query().Get("type")
		if kind == "A" {
			fmt.Fprint(response, `{"success":true,"result":[{"id":"33333333333333333333333333333333","name":"direct.example.com","type":"A","content":"192.0.2.10","proxied":false}]}`)
			return
		}
		if kind != "CAA" || name != "direct.example.com" {
			fmt.Fprint(response, `{"success":true,"result":[]}`)
			return
		}
		count := 100
		if request.URL.Query().Get("page") == "2" {
			count = 1
		}
		records := make([]map[string]any, count)
		for index := range records {
			number := index + 1
			if request.URL.Query().Get("page") == "2" {
				number = 101
			}
			records[index] = map[string]any{"id": fmt.Sprintf("%032x", number), "name": name, "type": kind, "data": map[string]any{"flags": 0, "tag": "issue", "value": fmt.Sprintf("issuer-%d.example", number)}}
		}
		_ = json.NewEncoder(response).Encode(map[string]any{"success": true, "result": records})
	}))
	defer server.Close()
	api := cloudflaretunnel.NewFixtureMutationAPI(server.Client(), server.URL, staticResolver{}, &reachableOrigins{})
	facts, err := api.ObserveCertificateDNS(context.Background(), cloudflaretunnel.CertificateDNSRequest{ZoneID: zoneID, ZoneName: "example.com", Hostname: "direct.example.com", PublicIPv4: "192.0.2.10", IPv4RecordID: "33333333333333333333333333333333", Token: managementToken})
	if err != nil || len(facts.EffectiveCAA.Records) != 101 {
		t.Fatalf("effective CAA count = %d, %v", len(facts.EffectiveCAA.Records), err)
	}
}

func TestHTTPMutationAPIConfiguresAndObservesBothIndependentRoutes(t *testing.T) {
	managementToken, err := cloudflaretunnel.NewManagementToken(token)
	if err != nil {
		t.Fatal(err)
	}
	routes := []cloudflaretunnel.Route{{Hostname: "xhttp.example.com", Service: "http://127.0.0.1:11080"}, {Hostname: "ws.example.com", Service: "http://127.0.0.1:11081"}, {Service: "http_status:404"}}
	dnsIDs := []string{"33333333333333333333333333333333", "44444444444444444444444444444444"}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		switch {
		case request.Method == http.MethodPut && strings.HasSuffix(request.URL.Path, "/configurations"):
			var body struct {
				Config struct {
					Ingress []cloudflaretunnel.Route `json:"ingress"`
				} `json:"config"`
			}
			if json.NewDecoder(request.Body).Decode(&body) != nil || fmt.Sprint(body.Config.Ingress) != fmt.Sprint(routes) {
				t.Errorf("configuration body = %#v", body)
			}
			fmt.Fprintf(response, `{"success":true,"result":{"tunnel_id":%q,"version":7,"config":{"ingress":[{"hostname":"xhttp.example.com","service":"http://127.0.0.1:11080"},{"hostname":"ws.example.com","service":"http://127.0.0.1:11081"},{"service":"http_status:404"}]}}}`, mutationTunnelID)
		case request.URL.Path == "/accounts/"+accountID+"/cfd_tunnel/"+mutationTunnelID:
			fmt.Fprintf(response, `{"success":true,"result":{"id":%q,"status":"healthy","connections":[{"id":"connection-1"}]}}`, mutationTunnelID)
		case strings.HasSuffix(request.URL.Path, "/configurations"):
			fmt.Fprintf(response, `{"success":true,"result":{"tunnel_id":%q,"config":{"ingress":[{"hostname":"xhttp.example.com","service":"http://127.0.0.1:11080"},{"hostname":"ws.example.com","service":"http://127.0.0.1:11081"},{"service":"http_status:404"}]}}}`, mutationTunnelID)
		case strings.HasSuffix(request.URL.Path, "/"+dnsIDs[0]):
			fmt.Fprintf(response, `{"success":true,"result":{"id":%q,"name":"xhttp.example.com","type":"CNAME","content":%q,"proxied":true}}`, dnsIDs[0], mutationTunnelID+".cfargotunnel.com")
		case strings.HasSuffix(request.URL.Path, "/"+dnsIDs[1]):
			fmt.Fprintf(response, `{"success":true,"result":{"id":%q,"name":"ws.example.com","type":"CNAME","content":%q,"proxied":true}}`, dnsIDs[1], mutationTunnelID+".cfargotunnel.com")
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	origins := &reachableOrigins{}
	api := cloudflaretunnel.NewFixtureMutationAPI(server.Client(), server.URL, staticResolver{}, origins)
	configured, err := api.PutConfiguration(context.Background(), cloudflaretunnel.PutConfigurationRequest{AccountID: accountID, TunnelID: mutationTunnelID, Token: managementToken, Routes: routes})
	if err != nil || configured.Version != 7 || fmt.Sprint(configured.Routes) != fmt.Sprint(routes) {
		t.Fatalf("PutConfiguration() = %+v, %v", configured, err)
	}
	observed, err := api.ObserveWholeTunnel(context.Background(), cloudflaretunnel.WholeTunnelRequest{AccountID: accountID, ZoneID: zoneID, TunnelID: mutationTunnelID, DNSRecords: []cloudflaretunnel.DNSRecordReference{{ID: dnsIDs[0]}, {ID: dnsIDs[1]}}, Token: managementToken})
	if err != nil || observed.TunnelID != mutationTunnelID || !observed.Connected || fmt.Sprint(observed.Routes) != fmt.Sprint(routes) || len(observed.DNSRecords) != 2 || !observed.XHTTPOriginReachable || !observed.WebSocketOriginReachable || fmt.Sprint(origins.addresses) != "[127.0.0.1:11080 127.0.0.1:11081]" {
		t.Fatalf("ObserveWholeTunnel() = %+v, %v; origins=%v", observed, err, origins.addresses)
	}
}

func TestHTTPMutationAPIRepairsOnlyExactCommittedProviderIDs(t *testing.T) {
	managementToken, err := cloudflaretunnel.NewManagementToken(token)
	if err != nil {
		t.Fatal(err)
	}
	dnsID := "33333333333333333333333333333333"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.Method + " " + request.URL.Path {
		case http.MethodGet + " /accounts/" + accountID + "/cfd_tunnel/" + mutationTunnelID + "/configurations":
			fmt.Fprintf(response, `{"success":true,"result":{"tunnel_id":%q,"version":4,"config":{"ingress":[{"service":"http_status:404"}]}}}`, mutationTunnelID)
		case http.MethodGet + " /zones/" + zoneID + "/dns_records/" + dnsID:
			fmt.Fprintf(response, `{"success":true,"result":{"id":%q,"name":"xhttp.example.com","type":"CNAME","content":"old.example.com","proxied":true}}`, dnsID)
		case http.MethodPut + " /zones/" + zoneID + "/dns_records/" + dnsID:
			fmt.Fprintf(response, `{"success":true,"result":{"id":%q,"name":"xhttp.example.com","type":"CNAME","content":%q,"proxied":true}}`, dnsID, mutationTunnelID+".cfargotunnel.com")
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	api := cloudflaretunnel.NewFixtureMutationAPI(server.Client(), server.URL, staticResolver{}, &reachableOrigins{})
	configuration, err := api.GetConfiguration(t.Context(), cloudflaretunnel.GetConfigurationRequest{AccountID: accountID, TunnelID: mutationTunnelID, Token: managementToken})
	if err != nil || configuration.TunnelID != mutationTunnelID || len(configuration.Routes) != 1 {
		t.Fatalf("GetConfiguration() = %+v, %v", configuration, err)
	}
	prior, err := api.GetDNSRecord(t.Context(), cloudflaretunnel.GetDNSRecordRequest{ZoneID: zoneID, ID: dnsID, Token: managementToken})
	if err != nil || prior.ID != dnsID || prior.Content != "old.example.com" {
		t.Fatalf("GetDNSRecord() = %+v, %v", prior, err)
	}
	repaired, err := api.PutDNSRecord(t.Context(), cloudflaretunnel.PutDNSRecordRequest{ZoneID: zoneID, ID: dnsID, Type: "CNAME", Name: "xhttp.example.com", Content: mutationTunnelID + ".cfargotunnel.com", Proxied: true, Token: managementToken})
	if err != nil || repaired.ID != dnsID || repaired.Name != "xhttp.example.com" {
		t.Fatalf("PutDNSRecord() = %+v, %v", repaired, err)
	}
}

func TestHTTPMutationAPIRefusesContradictoryWholeTunnelIdentifiers(t *testing.T) {
	managementToken, err := cloudflaretunnel.NewManagementToken(token)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, result string }{
		{"Tunnel ID", `{"id":"11111111-1111-4111-8111-111111111111","status":"healthy","connections":[{"id":"connection-1"}]}`},
		{"connection ID", `{"id":"` + mutationTunnelID + `","status":"healthy","connections":[{"id":"connection-1"},{"id":"connection-1"}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(response, `{"success":true,"result":`+test.result+`}`)
			}))
			defer server.Close()
			api := cloudflaretunnel.NewFixtureMutationAPI(server.Client(), server.URL, staticResolver{}, &reachableOrigins{})
			_, gotErr := api.ObserveWholeTunnel(context.Background(), cloudflaretunnel.WholeTunnelRequest{AccountID: accountID, ZoneID: zoneID, TunnelID: mutationTunnelID, DNSRecords: []cloudflaretunnel.DNSRecordReference{{ID: "33333333333333333333333333333333"}, {ID: "44444444444444444444444444444444"}}, Token: managementToken})
			assertAPIError(t, gotErr, cloudflaretunnel.APIAmbiguous)
		})
	}
}

func TestHTTPMutationAPIRetrievesTheCurrentTunnelTokenOnlyThroughTheDocumentedEndpoint(t *testing.T) {
	managementToken, err := cloudflaretunnel.NewManagementToken(token)
	if err != nil {
		t.Fatal(err)
	}
	runToken := "CLOUDFLARE-ROTATED-RUN-TOKEN-MARKER"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/accounts/"+accountID+"/cfd_tunnel/"+mutationTunnelID+"/token" || request.Header.Get("Authorization") != "Bearer "+token {
			t.Fatalf("unexpected token request: %s %s", request.Method, request.URL.Path)
		}
		fmt.Fprintf(response, `{"success":true,"result":%q}`, runToken)
	}))
	defer server.Close()
	api := cloudflaretunnel.NewFixtureMutationAPI(server.Client(), server.URL, staticResolver{}, &reachableOrigins{})
	result, err := api.GetTunnelToken(context.Background(), cloudflaretunnel.GetTunnelTokenRequest{AccountID: accountID, TunnelID: mutationTunnelID, Token: managementToken})
	if err != nil || !result.ChangedFrom(strings.Repeat("0", 64)) {
		t.Fatalf("GetTunnelToken() = (%+v, %v)", result, err)
	}
	if rendered := fmt.Sprintf("%+v %#v %s", result, result, result); strings.Contains(rendered, runToken) {
		t.Fatalf("run token escaped opaque result: %s", rendered)
	}
	t.Log("RELEASE-STAGED-ONBOARDING-MARKER-TUNNEL-RUN-TOKEN")
}
