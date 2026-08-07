package cloudflaretunnel_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
)

const mutationTunnelID = "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415"

type reachableOrigins struct{ addresses []string }

func (origins *reachableOrigins) Reachable(_ context.Context, address string) (bool, error) {
	origins.addresses = append(origins.addresses, address)
	return true, nil
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
