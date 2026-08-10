package cloudflaretunnel

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

type fixedRemovalObserver struct{ observation RemovalObservation }

func (observer fixedRemovalObserver) ObserveRemovalResource(string, string, string) (RemovalObservation, error) {
	return observer.observation, nil
}

func TestRemovalRecoveryAuthorityRoundTripsOnlyThroughProtectedSnapshot(t *testing.T) {
	secret := "cfat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	token, err := NewManagementToken(secret)
	if err != nil {
		t.Fatal(err)
	}
	authority := RemovalRecoveryAuthority{
		AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), ZoneName: "example.com",
		TunnelID: "11111111-1111-4111-8111-111111111111", DNSRecordIDs: []string{strings.Repeat("c", 32), strings.Repeat("d", 32)},
		Routes: []Route{{Hostname: "xhttp.example.com", Service: "http://127.0.0.1:11080"}, {Service: "http_status:404"}},
	}
	var snapshot bytes.Buffer
	if err := WriteRemovalRecovery(token, authority, func(source io.Reader) error { _, err := snapshot.ReadFrom(source); return err }); err != nil {
		t.Fatal(err)
	}
	got, restored, err := ReadRemovalRecovery(bytes.NewReader(snapshot.Bytes()))
	if err != nil || !reflect.DeepEqual(got, authority) {
		t.Fatalf("restored authority = %+v %v", got, err)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", restored, restored), secret) {
		t.Fatal("restored token rendered its protected value")
	}
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
