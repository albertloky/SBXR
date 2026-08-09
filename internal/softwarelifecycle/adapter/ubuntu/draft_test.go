package ubuntu

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestDraftStorePersistsOnlyTheFixedNonSecretChoicesAt0600(t *testing.T) {
	store := NewDraftStoreAt(t.TempDir())
	draft := softwarelifecycle.InstallationDraft{Domain: "example.com", OwnerEmail: "owner@example.com", PublicIPv4: "192.0.2.10", PrimaryAddress: "192.0.2.10", SSHPort: 2222, RealityPort: 443, Hysteria2Port: 443, TUICPort: 8443, AnyTLSPort: 9443, SubscriptionPort: 10443}
	if err := store.Save(draft); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(store.path())
	if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("draft file = (%+v, %v)", info, err)
	}
	loaded, err := store.Load()
	if err != nil || !reflect.DeepEqual(loaded, draft) {
		t.Fatalf("Load() = (%+v, %v)", loaded, err)
	}
	if err := store.Discard(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(store.path()); !os.IsNotExist(err) {
		t.Fatalf("draft remains: %v", err)
	}
}

func TestDraftStoreRefusesSecretLikeValuesLinksAndBroadModes(t *testing.T) {
	store := NewDraftStoreAt(t.TempDir())
	invalid := softwarelifecycle.InstallationDraft{Domain: "SECRET-MARKER", OwnerEmail: "owner@example.com", PublicIPv4: "192.0.2.10", PrimaryAddress: "192.0.2.10", SSHPort: 1, RealityPort: 1, Hysteria2Port: 1, TUICPort: 1, AnyTLSPort: 1, SubscriptionPort: 1}
	if err := store.Save(invalid); err == nil {
		t.Fatal("invalid draft accepted")
	}
	if err := os.MkdirAll(store.directory(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(store.home, "unrelated"), store.path()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("linked draft accepted")
	}
	target := filepath.Join(store.home, "outside")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(store.path()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, store.path()); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(softwarelifecycle.InstallationDraft{Domain: "example.com", OwnerEmail: "owner@example.com", PublicIPv4: "192.0.2.10", PrimaryAddress: "192.0.2.10", SSHPort: 1, RealityPort: 1, Hysteria2Port: 1, TUICPort: 1, AnyTLSPort: 1, SubscriptionPort: 1}); err == nil {
		t.Fatal("linked draft replaced")
	}
	if body, err := os.ReadFile(target); err != nil || string(body) != "keep" {
		t.Fatalf("outside file changed: %q, %v", body, err)
	}
}
