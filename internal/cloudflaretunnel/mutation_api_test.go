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

func TestMutationAPIUsesOfficialScopedTunnelConfigurationAndDNSShapes(t *testing.T) {
	managementToken, _ := cloudflaretunnel.NewManagementToken(token)
	tunnelID := "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415"
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.Method+" "+request.URL.RequestURI())
		if request.Header.Get("Authorization") != "Bearer "+token {
			t.Error("missing scoped bearer authentication")
		}
		var body map[string]any
		if request.Body != nil {
			_ = json.NewDecoder(request.Body).Decode(&body)
		}
		response.Header().Set("Content-Type", "application/json")
		switch request.Method + " " + request.URL.Path {
		case "GET /accounts/" + accountID + "/cfd_tunnel", "GET /zones/" + zoneID + "/dns_records":
			fmt.Fprint(response, `{"success":true,"result":[]}`)
		case "POST /accounts/" + accountID + "/cfd_tunnel":
			if body["name"] != "sbxr-main" || body["config_src"] != "cloudflare" {
				t.Fatalf("create body = %v", body)
			}
			fmt.Fprint(response, `{"success":true,"result":{"id":"`+tunnelID+`","name":"sbxr-main","token":"RUN-SECRET-MARKER","remote_config":true,"tun_type":"cfd_tunnel"}}`)
		case "PUT /accounts/" + accountID + "/cfd_tunnel/" + tunnelID + "/configurations":
			fmt.Fprint(response, `{"success":true,"result":{"tunnel_id":"`+tunnelID+`","version":1,"config":{"ingress":[{"hostname":"xhttp.example.com","service":"http://127.0.0.1:11080"},{"hostname":"","service":"http_status:404"}]}}}`)
		case "POST /zones/" + zoneID + "/dns_records":
			if body["type"] != "CNAME" || body["proxied"] != true || body["content"] != tunnelID+".cfargotunnel.com" {
				t.Fatalf("DNS body = %v", body)
			}
			fmt.Fprint(response, `{"success":true,"result":{"id":"33333333333333333333333333333333","name":"xhttp.example.com","type":"CNAME","content":"`+tunnelID+`.cfargotunnel.com","proxied":true}}`)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	api := cloudflaretunnel.NewFixtureHTTPAPI(server.Client(), server.URL, staticResolver{})
	observation, err := api.ObserveMutation(context.Background(), cloudflaretunnel.MutationRequest{AccountID: accountID, ZoneID: zoneID, Tunnel: "sbxr-main", Hostname: "xhttp.example.com", Token: managementToken})
	if err != nil || len(observation.Tunnels) != 0 || len(observation.DNSRecords) != 0 || len(observation.Digest) != 64 {
		t.Fatalf("observation = %+v %v", observation, err)
	}
	created, err := api.CreateTunnel(context.Background(), cloudflaretunnel.CreateTunnelRequest{AccountID: accountID, Name: "sbxr-main", Token: managementToken})
	if err != nil {
		t.Fatal(err)
	}
	routes := []cloudflaretunnel.Route{{Hostname: "xhttp.example.com", Service: "http://127.0.0.1:11080"}, {Service: "http_status:404"}}
	configured, err := api.PutConfiguration(context.Background(), cloudflaretunnel.PutConfigurationRequest{AccountID: accountID, TunnelID: created.ID, Token: managementToken, Routes: routes})
	if err != nil || configured.Version != 1 {
		t.Fatalf("configuration = %+v %v", configured, err)
	}
	if _, err := api.CreateDNSRecord(context.Background(), cloudflaretunnel.CreateDNSRecordRequest{ZoneID: zoneID, Name: "xhttp.example.com", Content: tunnelID + ".cfargotunnel.com", Proxied: true, Token: managementToken}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(requests, ",")
	for _, expected := range []string{"GET /accounts/" + accountID + "/cfd_tunnel?name=sbxr-main", "GET /zones/" + zoneID + "/dns_records?name=xhttp.example.com", "POST /accounts/" + accountID + "/cfd_tunnel", "PUT /accounts/" + accountID + "/cfd_tunnel/" + tunnelID + "/configurations", "POST /zones/" + zoneID + "/dns_records"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing %q in %s", expected, joined)
		}
	}
}
