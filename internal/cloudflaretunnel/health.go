package cloudflaretunnel

import "fmt"

type DNSExpected struct {
	ID, Name, Type, Content string
	Proxied                 bool
}
type WholeTunnelExpected struct {
	TunnelID   string
	Routes     []Route
	DNSRecords []DNSExpected
}

func EvaluateWholeTunnel(observed WholeTunnelObservation, expected WholeTunnelExpected) Health {
	base := Health{Module: "Cloudflare Tunnel", NextActions: []string{"Check again", "Back"}}
	if observed.TunnelID == "" {
		base.Outcome, base.Code, base.Explanation = Unknown, "CLOUDFLARE-OBSERVATION-UNKNOWN", "The Tunnel observation is unavailable."
		return finishHealth(base)
	}
	if observed.TunnelID != expected.TunnelID {
		base.Outcome, base.Code, base.Found, base.Required, base.Explanation = Failed, "CLOUDFLARE-TUNNEL-ID", observed.TunnelID, expected.TunnelID, "The observed Tunnel identifier contradicts committed ownership."
		return finishHealth(base)
	}
	if !sameRoutes(observed.Routes, expected.Routes) {
		base.Outcome, base.Code, base.Found, base.Required, base.Explanation = classifyRouteDifference(observed.Routes, expected.Routes)
		return finishHealth(base)
	}
	if health, ok := compareDNS(observed.DNSRecords, expected.DNSRecords); !ok {
		return finishHealth(health)
	}
	if !observed.Connected {
		base.Outcome, base.Code, base.Explanation = NeedsAttention, "CLOUDFLARE-TUNNEL-DISCONNECTED", "The owned Tunnel has no connected cloudflared session."
		return finishHealth(base)
	}
	if !observed.XHTTPOriginReachable || !observed.WebSocketOriginReachable {
		base.Outcome, base.Code, base.Found, base.Required, base.Explanation = Failed, "CLOUDFLARE-ORIGIN-UNREACHABLE", fmt.Sprintf("xhttp=%t websocket=%t", observed.XHTTPOriginReachable, observed.WebSocketOriginReachable), "both exact loopback HTTP origins reachable", "One or both independent Connection Profile origins failed."
		return finishHealth(base)
	}
	base.Outcome, base.Code, base.Explanation = Healthy, "CLOUDFLARE-WHOLE-TUNNEL-HEALTHY", "The connected Tunnel, both independent routes, owned DNS, and exact loopback origins agree."
	return finishHealth(base)
}

func classifyRouteDifference(got, want []Route) (Outcome, string, string, string, string) {
	for _, route := range got {
		if route.Service != "http_status:404" && route.Service != xhttpOrigin && route.Service != webSocketOrigin {
			return Failed, "CLOUDFLARE-ROUTE-ORIGIN", route.Service, "only http://127.0.0.1:11080, http://127.0.0.1:11081, and final http_status:404", "A route points at a wrong or public origin."
		}
	}
	return NeedsAttention, "CLOUDFLARE-ROUTE-PARTIAL", fmt.Sprintf("%d routes", len(got)), fmt.Sprintf("%d exact routes", len(want)), "A required public hostname route or the 404 terminator is missing or mismatched."
}

func compareDNS(got []DNSObservation, want []DNSExpected) (Health, bool) {
	byID := make(map[string]DNSObservation, len(got))
	for _, record := range got {
		byID[record.ID] = record
	}
	for _, expected := range want {
		observed, exists := byID[expected.ID]
		if !exists {
			return Health{Module: "Cloudflare Tunnel", Outcome: NeedsAttention, Code: "CLOUDFLARE-DNS-MISSING", Found: "owned DNS record absent", Required: expected.ID, Explanation: "A committed DNS record has not converged.", NextActions: []string{"Check again", "Back"}}, false
		}
		if observed.Name != expected.Name || observed.Type != expected.Type || observed.Content != expected.Content || observed.Proxied != expected.Proxied {
			return Health{Module: "Cloudflare Tunnel", Outcome: Failed, Code: "CLOUDFLARE-DNS-DRIFT", Found: "owned DNS record content differs", Required: expected.Name + " " + expected.Type, Explanation: "A committed DNS identifier points at contradictory content.", NextActions: []string{"Create forward-repair Plan", "Check again", "Back"}}, false
		}
	}
	return Health{}, true
}

func finishHealth(health Health) Health {
	if health.Outcome != Healthy {
		health.Problem = health.Explanation
		if health.Found == "" {
			health.Found = "the typed whole-Tunnel check did not pass"
		}
		if health.Required == "" {
			health.Required = "both exact routes, owned DNS, one connected Tunnel, and both loopback origins"
		}
		health.WhyStopped = "SBXR does not report partial Cloudflare state as Healthy"
		health.Evidence = "copyable redacted " + health.Code + " result"
	}
	if len(health.NextActions) > 0 {
		health.NextAction = health.NextActions[0]
	}
	return health
}
