package cloudflaretunnel

import "github.com/albertloky/SBXR/internal/systemchanges"

func QualificationConfiguration() []byte {
	return []byte("ingress:\n  - hostname: xhttp.example.com\n    service: http://127.0.0.1:11080\n  - hostname: ws.example.com\n    service: http://127.0.0.1:11081\n  - service: http_status:404\n")
}

type controlledRemovalObserver struct{ inventory map[string][]string }

func (observer controlledRemovalObserver) ObserveRemovalResource(review, resource, immutableID string) (RemovalObservation, error) {
	return RemovalObservation{ReviewID: review, Resource: resource, ImmutableID: immutableID, OwnedBySBXR: true, TokenActive: true, TokenAvailableLocally: true, Inventory: observer.inventory}, nil
}

// ControlledRemovalAuthorities proves the fixed provider-resource inventory.
func ControlledRemovalAuthorities(review string) ([]systemchanges.CloudflareRemovalAuthority, error) {
	inventory := map[string][]string{"cloudflare-dns-record": {"dns-direct", "dns-websocket", "dns-xhttp"}, "cloudflare-route": {"tunnel-routes"}, "cloudflare-tunnel": {"tunnel-id"}}
	result := make([]systemchanges.CloudflareRemovalAuthority, 0, 5)
	for category, identities := range inventory {
		for _, identity := range identities {
			authority, err := NewRemoval(controlledRemovalObserver{inventory: inventory}).ProveRemovalResource(review, category, identity)
			if err != nil {
				return nil, err
			}
			result = append(result, authority)
		}
	}
	return result, nil
}
