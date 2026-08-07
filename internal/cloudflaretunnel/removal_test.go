package cloudflaretunnel

import "testing"

type fixedRemovalObserver struct{ observation RemovalObservation }

func (observer fixedRemovalObserver) ObserveRemovalResource(string, string, string) (RemovalObservation, error) {
	return observer.observation, nil
}

func TestRemovalAuthorityRefusesAChangedImmutableID(t *testing.T) {
	observer := fixedRemovalObserver{RemovalObservation{
		ReviewID:              "removal-review-0008",
		Resource:              "cloudflare-dns-record",
		ImmutableID:           "different-dns-record-id",
		OwnedBySBXR:           true,
		TokenActive:           true,
		TokenAvailableLocally: true,
		Inventory:             map[string][]string{"cloudflare-dns-record": {"different-dns-record-id"}},
	}}
	if _, err := NewRemoval(observer).ProveRemovalResource("removal-review-0008", "cloudflare-dns-record", "committed-dns-record-id"); err == nil {
		t.Fatal("changed Cloudflare identifier was accepted for Complete removal")
	}
}
