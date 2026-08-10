package cloudflaretunnel

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestPrepareClientAccessRoutesUsesExactEnabledProfiles(t *testing.T) {
	request := ClientAccessRoutesRequest{
		ChangeSet: "client-access-0001", AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), TunnelID: "11111111-1111-4111-8111-111111111111", XHTTPDNSRecordID: strings.Repeat("c", 32), WebSocketDNSRecordID: strings.Repeat("d", 32),
		XHTTPHostname: "xhttp.example.com", WebSocketHostname: "ws.example.com",
		CurrentXHTTP: true, CurrentWebSocket: true, CandidateWebSocket: true,
	}
	plan, err := PrepareClientAccessRoutes(request)
	if err != nil {
		t.Fatal(err)
	}
	steps := plan.Steps()
	if len(steps) != 1 {
		t.Fatalf("steps = %d, want 1", len(steps))
	}
	change, ok := steps[0].CloudflareChange()
	if !ok || change.Action != systemchanges.CloudflareRoutesPut || len(change.Routes) != 2 || change.Routes[0].Hostname != request.WebSocketHostname || change.Routes[1].Origin != "http_status:404" {
		t.Fatalf("unexpected exact route replacement: %+v", change)
	}
	if _, err := PrepareClientAccessRoutes(ClientAccessRoutesRequest{
		ChangeSet: request.ChangeSet, AccountID: request.AccountID, ZoneID: request.ZoneID, TunnelID: request.TunnelID, XHTTPDNSRecordID: request.XHTTPDNSRecordID, WebSocketDNSRecordID: request.WebSocketDNSRecordID,
		XHTTPHostname: request.XHTTPHostname, WebSocketHostname: request.WebSocketHostname,
		CurrentXHTTP: true, CurrentWebSocket: true,
	}); err == nil {
		t.Fatal("accepted two profile enablement changes in one profile operation")
	}
	if !validPublishedRoutes([]Route{{Service: "http_status:404"}}) {
		t.Fatal("fallback-only deliberate disablement was refused by the production API boundary")
	}
}

func TestClientAccessRoutesBindsRollbackAndHealthToTheReviewedRoutes(t *testing.T) {
	request := ClientAccessRoutesRequest{
		ChangeSet: "client-access-0001", AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), TunnelID: "11111111-1111-4111-8111-111111111111", XHTTPDNSRecordID: strings.Repeat("c", 32), WebSocketDNSRecordID: strings.Repeat("d", 32),
		XHTTPHostname: "xhttp.example.com", WebSocketHostname: "ws.example.com", CurrentXHTTP: true, CurrentWebSocket: true, CandidateWebSocket: true,
	}
	plan, err := PrepareClientAccessRoutes(request)
	if err != nil {
		t.Fatal(err)
	}
	prior := clientAccessRoutes(ClientAccessRoutesRequest{CandidateXHTTP: true, CandidateWebSocket: true, XHTTPHostname: request.XHTTPHostname, WebSocketHostname: request.WebSocketHostname})
	api := &executorFixture{priorConfiguration: Configuration{TunnelID: request.TunnelID, Version: 1, Routes: prior}}
	token, _ := NewManagementToken("cfat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	executor, err := plan.Executor(api, token)
	if err != nil {
		t.Fatal(err)
	}
	var rollback bytes.Buffer
	if err := executor.CaptureRollback(plan.Steps()[0], func(source io.Reader) error { _, err := io.Copy(&rollback, source); return err }); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(plan.Steps()[0], "", time.Second); err != nil {
		t.Fatal(err)
	}
	api.whole = WholeTunnelObservation{TunnelID: request.TunnelID, Connected: true, Routes: clientAccessRoutes(request), DNSRecords: []DNSObservation{
		{ID: request.XHTTPDNSRecordID, Name: request.XHTTPHostname, Type: "CNAME", Content: request.TunnelID + ".cfargotunnel.com", Proxied: true},
		{ID: request.WebSocketDNSRecordID, Name: request.WebSocketHostname, Type: "CNAME", Content: request.TunnelID + ".cfargotunnel.com", Proxied: true},
	}, WebSocketOriginReachable: true}
	if status, err := executor.CheckWholeTunnel(nil, time.Second); err != nil || status != systemchanges.Healthy {
		t.Fatalf("health = %s, %v", status, err)
	}
	api.priorConfiguration.Routes = []Route{{Service: "http_status:404"}}
	if _, err := plan.Executor(api, token); err == nil {
		t.Fatal("stale provider routes were accepted")
	}
}
