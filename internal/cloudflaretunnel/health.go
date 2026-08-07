package cloudflaretunnel

import (
	"fmt"
	"strings"
)

type DNSExpected struct {
	ID, Name, Type, Content string
	Proxied                 bool
}
type WholeTunnelExpected struct {
	TunnelID   string
	Routes     []Route
	DNSRecords []DNSExpected
}

type TunnelHealth struct {
	XHTTP, WebSocket, Whole Health
}

func EvaluateTunnelHealth(observed WholeTunnelObservation, expected WholeTunnelExpected) TunnelHealth {
	xhttp := evaluateRouteHealth("XHTTP", "CLOUDFLARE-XHTTP", xhttpOrigin, observed.XHTTPOriginReachable, observed, expected)
	websocket := evaluateRouteHealth("WebSocket", "CLOUDFLARE-WEBSOCKET", webSocketOrigin, observed.WebSocketOriginReachable, observed, expected)
	return TunnelHealth{XHTTP: xhttp, WebSocket: websocket, Whole: evaluateWholeTunnel(observed, expected, xhttp, websocket)}
}

func EvaluateWholeTunnel(observed WholeTunnelObservation, expected WholeTunnelExpected) Health {
	return EvaluateTunnelHealth(observed, expected).Whole
}

func evaluateWholeTunnel(observed WholeTunnelObservation, expected WholeTunnelExpected, xhttp, websocket Health) Health {
	base := Health{Module: "Cloudflare Tunnel", NextActions: []string{"Check again", "Back"}}
	if observed.TunnelID == "" {
		base.Outcome, base.Code, base.Explanation = Unknown, "CLOUDFLARE-OBSERVATION-UNKNOWN", "The Tunnel observation is unavailable."
		return finishHealth(base)
	}
	if observed.TunnelID != expected.TunnelID {
		base.Outcome, base.Code, base.Found, base.Required, base.Explanation = Failed, "CLOUDFLARE-TUNNEL-ID", "a different immutable Tunnel identifier", "the committed immutable Tunnel identifier", "The observed Tunnel identifier contradicts committed ownership."
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
	if xhttp.Outcome != Healthy {
		return xhttp
	}
	if websocket.Outcome != Healthy {
		return websocket
	}
	base.Outcome, base.Code, base.Explanation = Healthy, "CLOUDFLARE-WHOLE-TUNNEL-HEALTHY", "The connected Tunnel, both independent routes, owned DNS, and exact loopback origins agree."
	return finishHealth(base)
}

func evaluateRouteHealth(profile, code, origin string, reachable bool, observed WholeTunnelObservation, expected WholeTunnelExpected) Health {
	base := Health{Module: "Cloudflare Tunnel", NextActions: []string{"Check again", "Back"}}
	if observed.TunnelID == "" {
		base.Outcome, base.Code, base.Explanation = Unknown, code+"-OBSERVATION-UNKNOWN", "The "+profile+" route observation is unavailable."
		return finishHealth(base)
	}
	if observed.TunnelID != expected.TunnelID {
		base.Outcome, base.Code, base.Found, base.Required, base.Explanation = Failed, code+"-TUNNEL-ID", "a different immutable Tunnel identifier", "the committed immutable Tunnel identifier", "The "+profile+" route belongs to contradictory Tunnel evidence."
		return finishHealth(base)
	}
	var route Route
	for _, candidate := range expected.Routes {
		if candidate.Service == origin {
			route = candidate
		}
	}
	observedRoutes := make([]Route, 0, 1)
	for _, candidate := range observed.Routes {
		if candidate.Hostname == route.Hostname {
			observedRoutes = append(observedRoutes, candidate)
		}
	}
	if route.Hostname == "" || len(observedRoutes) != 1 {
		base.Outcome, base.Code, base.Explanation = NeedsAttention, code+"-ROUTE-MISSING", "The exact "+profile+" hostname route is absent or repeated."
		return finishHealth(base)
	}
	if observedRoutes[0] != route {
		base.Outcome, base.Code, base.Explanation = Failed, code+"-ROUTE-ORIGIN", "The "+profile+" route has a wrong or public origin."
		return finishHealth(base)
	}
	var dns DNSExpected
	for _, candidate := range expected.DNSRecords {
		if candidate.Name == route.Hostname {
			dns = candidate
		}
	}
	if health, ok := compareDNS(observed.DNSRecords, []DNSExpected{dns}); !ok {
		health.Code = code + strings.TrimPrefix(health.Code, "CLOUDFLARE")
		return finishHealth(health)
	}
	if !observed.Connected {
		base.Outcome, base.Code, base.Explanation = NeedsAttention, code+"-TUNNEL-DISCONNECTED", "The "+profile+" route has no connected cloudflared session."
		return finishHealth(base)
	}
	if !reachable {
		base.Outcome, base.Code, base.Explanation = Failed, code+"-ORIGIN-UNREACHABLE", "The independent "+profile+" loopback HTTP origin failed."
		return finishHealth(base)
	}
	base.Outcome, base.Code, base.Explanation = Healthy, code+"-ROUTE-HEALTHY", "The independent "+profile+" route, DNS, Tunnel connection, and loopback origin agree."
	return finishHealth(base)
}

func classifyRouteDifference(got, want []Route) (Outcome, string, string, string, string) {
	for _, route := range got {
		if route.Service != "http_status:404" && route.Service != xhttpOrigin && route.Service != webSocketOrigin {
			return Failed, "CLOUDFLARE-ROUTE-ORIGIN", "a route outside the approved loopback origins", "only http://127.0.0.1:11080, http://127.0.0.1:11081, and final http_status:404", "A route points at a wrong or public origin."
		}
	}
	return NeedsAttention, "CLOUDFLARE-ROUTE-PARTIAL", fmt.Sprintf("%d routes", len(got)), fmt.Sprintf("%d exact routes", len(want)), "A required public hostname route or the 404 terminator is missing or mismatched."
}

func compareDNS(got []DNSObservation, want []DNSExpected) (Health, bool) {
	byID := make(map[string]DNSObservation, len(got))
	for _, record := range got {
		if _, exists := byID[record.ID]; exists {
			return Health{Module: "Cloudflare Tunnel", Outcome: Failed, Code: "CLOUDFLARE-DNS-ID-CONTRADICTION", Found: "one immutable DNS identifier appeared more than once", Required: "each committed DNS identifier exactly once", Explanation: "The provider observation contains contradictory ownership evidence.", NextActions: []string{"Create forward-repair Plan", "Check again", "Back"}}, false
		}
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
