package cloudflaretunnel

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestWholeTunnelHealthRequiresBothIndependentRoutesAndOrigins(t *testing.T) {
	want := WholeTunnelExpected{TunnelID: testTunnelID, Routes: []Route{{Hostname: "xhttp.example.com", Service: xhttpOrigin}, {Hostname: "ws.example.com", Service: webSocketOrigin}, {Service: "http_status:404"}}, DNSRecords: []DNSExpected{{ID: "dns-x", Name: "xhttp.example.com", Type: "CNAME", Content: testTunnelID + ".cfargotunnel.com", Proxied: true}, {ID: "dns-w", Name: "ws.example.com", Type: "CNAME", Content: testTunnelID + ".cfargotunnel.com", Proxied: true}}}
	observed := WholeTunnelObservation{TunnelID: testTunnelID, Connected: true, Routes: append([]Route(nil), want.Routes...), DNSRecords: []DNSObservation{{ID: "dns-x", Name: "xhttp.example.com", Type: "CNAME", Content: testTunnelID + ".cfargotunnel.com", Proxied: true}, {ID: "dns-w", Name: "ws.example.com", Type: "CNAME", Content: testTunnelID + ".cfargotunnel.com", Proxied: true}}, XHTTPOriginReachable: true, WebSocketOriginReachable: true}
	if health := EvaluateWholeTunnel(observed, want); health.Outcome != Healthy {
		t.Fatalf("healthy observation = %+v", health)
	}

	tests := []struct {
		name, code string
		change     func(*WholeTunnelObservation)
	}{
		{"one route missing", "CLOUDFLARE-ROUTE-PARTIAL", func(got *WholeTunnelObservation) { got.Routes = got.Routes[:2] }},
		{"public origin", "CLOUDFLARE-ROUTE-ORIGIN", func(got *WholeTunnelObservation) {
			got.Routes[0].Service = "http://203.0.113.1:11080/PROVIDER-OUTPUT-MARKER"
		}},
		{"disconnected", "CLOUDFLARE-TUNNEL-DISCONNECTED", func(got *WholeTunnelObservation) { got.Connected = false }},
		{"xhttp origin down", "CLOUDFLARE-XHTTP-ORIGIN-UNREACHABLE", func(got *WholeTunnelObservation) { got.XHTTPOriginReachable = false }},
		{"websocket origin down", "CLOUDFLARE-WEBSOCKET-ORIGIN-UNREACHABLE", func(got *WholeTunnelObservation) { got.WebSocketOriginReachable = false }},
		{"missing websocket DNS", "CLOUDFLARE-DNS-MISSING", func(got *WholeTunnelObservation) { got.DNSRecords = got.DNSRecords[:1] }},
		{"contradictory DNS", "CLOUDFLARE-DNS-DRIFT", func(got *WholeTunnelObservation) {
			got.DNSRecords[1].ID = "other"
			got.DNSRecords = append(got.DNSRecords, DNSObservation{ID: "dns-w", Name: "wrong.example.com"})
		}},
		{"duplicate DNS identifier", "CLOUDFLARE-DNS-ID-CONTRADICTION", func(got *WholeTunnelObservation) {
			got.DNSRecords = append(got.DNSRecords, got.DNSRecords[1])
		}},
		{"contradictory Tunnel identifier", "CLOUDFLARE-TUNNEL-ID", func(got *WholeTunnelObservation) { got.TunnelID = "PROVIDER-OUTPUT-MARKER" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := observed
			got.Routes = append([]Route(nil), observed.Routes...)
			got.DNSRecords = append([]DNSObservation(nil), observed.DNSRecords...)
			tt.change(&got)
			health := EvaluateWholeTunnel(got, want)
			if health.Outcome == Healthy || health.Code != tt.code || health.Problem == "" || health.WhyStopped == "" || strings.Contains(health.Found+health.Required+health.Explanation+health.Evidence, "PROVIDER-OUTPUT-MARKER") {
				t.Fatalf("health = %+v", health)
			}
		})
	}
}

func TestTunnelHealthKeepsIndependentRouteRows(t *testing.T) {
	want := WholeTunnelExpected{TunnelID: testTunnelID, Routes: []Route{{Hostname: "xhttp.example.com", Service: xhttpOrigin}, {Hostname: "ws.example.com", Service: webSocketOrigin}, {Service: "http_status:404"}}, DNSRecords: []DNSExpected{{ID: "dns-x", Name: "xhttp.example.com", Type: "CNAME", Content: testTunnelID + ".cfargotunnel.com", Proxied: true}, {ID: "dns-w", Name: "ws.example.com", Type: "CNAME", Content: testTunnelID + ".cfargotunnel.com", Proxied: true}}}
	observed := WholeTunnelObservation{TunnelID: testTunnelID, Connected: true, Routes: append([]Route(nil), want.Routes...), DNSRecords: []DNSObservation{{ID: "dns-x", Name: "xhttp.example.com", Type: "CNAME", Content: testTunnelID + ".cfargotunnel.com", Proxied: true}, {ID: "dns-w", Name: "ws.example.com", Type: "CNAME", Content: testTunnelID + ".cfargotunnel.com", Proxied: true}}, XHTTPOriginReachable: true, WebSocketOriginReachable: true}
	rows := EvaluateTunnelHealth(observed, want)
	if rows.XHTTP.Code != "CLOUDFLARE-XHTTP-ROUTE-HEALTHY" || rows.WebSocket.Code != "CLOUDFLARE-WEBSOCKET-ROUTE-HEALTHY" || rows.Whole.Code != "CLOUDFLARE-WHOLE-TUNNEL-HEALTHY" {
		t.Fatalf("healthy rows = %+v", rows)
	}
	binding := EvaluateXHTTPRouteHealth(observed, want)
	if binding.Hostname != "xhttp.example.com" || binding.Origin != xhttpOrigin || binding.Health.Code != "CLOUDFLARE-XHTTP-ROUTE-HEALTHY" {
		t.Fatalf("typed XHTTP route binding = %+v", binding)
	}
	websocketBinding := EvaluateWebSocketRouteHealth(observed, want)
	if websocketBinding.Hostname != "ws.example.com" || websocketBinding.Origin != webSocketOrigin || websocketBinding.Health.Code != "CLOUDFLARE-WEBSOCKET-ROUTE-HEALTHY" {
		t.Fatalf("typed WebSocket route binding = %+v", websocketBinding)
	}
	observed.XHTTPOriginReachable = false
	rows = EvaluateTunnelHealth(observed, want)
	if rows.XHTTP.Code != "CLOUDFLARE-XHTTP-ORIGIN-UNREACHABLE" || rows.WebSocket.Outcome != Healthy || rows.Whole.Outcome == Healthy {
		t.Fatalf("independent rows = %+v", rows)
	}
}

func TestWholeTunnelConvergenceReturnsCompleteTypedFinding(t *testing.T) {
	want := WholeTunnelExpected{TunnelID: testTunnelID, Routes: []Route{{Hostname: "xhttp.example.com", Service: xhttpOrigin}, {Hostname: "ws.example.com", Service: webSocketOrigin}, {Service: "http_status:404"}}}
	api := &executorFixture{whole: WholeTunnelObservation{TunnelID: testTunnelID, Routes: want.Routes}}
	clock := &planClock{}
	health := (Executor{api: api}).WaitForWholeTunnel(context.Background(), WholeTunnelRequest{}, want, clock)
	if health.Outcome != Unknown || health.Code != "CLOUDFLARE-CONVERGENCE-TIMEOUT" || health.Time != clock.Now().UTC() || health.Problem == "" || health.Found == "" || health.Required == "" || health.WhyStopped == "" || health.Evidence == "" || clock.elapsed != 5*time.Minute {
		t.Fatalf("convergence health = %+v after %s", health, clock.elapsed)
	}
}
