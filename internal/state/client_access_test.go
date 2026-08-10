package state

import "testing"

func TestManagedClientAccessLeaseIsExactOneUseAndRevokedAfterTheCallback(t *testing.T) {
	storage := &mutableStateStorage{document: documentFor(t, completeDesiredState())}
	module := New(storage)
	loaded, err := module.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	var retained ConnectionProfileSecretReader
	want := completeDesiredState().ConnectionProfiles.AnyTLS.Password
	if err := module.WithManagedConnectionProfileSecrets(loaded, func(snapshot Snapshot, reader ConnectionProfileSecretReader) error {
		retained = reader
		if snapshot.DesiredState.ConnectionProfiles.AnyTLS.Password != want || reader.ReadClientAccessValue(want) == "" {
			t.Fatal("fresh Managed lease did not expose the exact owning value")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if retained.ReadClientAccessValue(want) != "" {
		t.Fatal("Managed Client Access reader remained active after the callback")
	}
	if err := module.WithManagedConnectionProfileSecrets(loaded, func(Snapshot, ConnectionProfileSecretReader) error { return nil }); err == nil {
		t.Fatal("Managed Client Access lease was reusable")
	}
	var subscription ClientAccessReader
	if err := module.WithManagedSubscriptionSecrets(loaded, func(snapshot Snapshot, reader ClientAccessReader) error {
		subscription = reader
		if reader.ReadClientAccessValue(snapshot.DesiredState.Subscription.Token) == "" {
			t.Fatal("Subscription lease did not expose its owning value")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if subscription.ReadClientAccessValue(completeDesiredState().Subscription.Token) != "" {
		t.Fatal("Subscription reader remained active after the callback")
	}
	var infrastructure InfrastructureSecretReader
	if err := module.WithManagedCloudflareSecrets(loaded, func(snapshot Snapshot, reader InfrastructureSecretReader) error {
		infrastructure = reader
		if reader.ReadInfrastructureSecret(snapshot.DesiredState.Cloudflare.ManagementToken) == "" {
			t.Fatal("Cloudflare lease did not expose its owning value")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if infrastructure.ReadInfrastructureSecret(completeDesiredState().Cloudflare.ManagementToken) != "" {
		t.Fatal("Cloudflare reader remained active after the callback")
	}
}
