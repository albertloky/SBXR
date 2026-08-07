package cloudflaretunnel

import "testing"

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
		{"public origin", "CLOUDFLARE-ROUTE-ORIGIN", func(got *WholeTunnelObservation) { got.Routes[0].Service = "http://203.0.113.1:11080" }},
		{"disconnected", "CLOUDFLARE-TUNNEL-DISCONNECTED", func(got *WholeTunnelObservation) { got.Connected = false }},
		{"websocket origin down", "CLOUDFLARE-ORIGIN-UNREACHABLE", func(got *WholeTunnelObservation) { got.WebSocketOriginReachable = false }},
		{"contradictory DNS", "CLOUDFLARE-DNS-DRIFT", func(got *WholeTunnelObservation) {
			got.DNSRecords[1].ID = "other"
			got.DNSRecords = append(got.DNSRecords, DNSObservation{ID: "dns-w", Name: "wrong.example.com"})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := observed
			got.Routes = append([]Route(nil), observed.Routes...)
			got.DNSRecords = append([]DNSObservation(nil), observed.DNSRecords...)
			tt.change(&got)
			health := EvaluateWholeTunnel(got, want)
			if health.Outcome == Healthy || health.Code != tt.code || health.Problem == "" || health.WhyStopped == "" {
				t.Fatalf("health = %+v", health)
			}
		})
	}
}
