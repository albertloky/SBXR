package host

import (
	"bytes"
	"os"
	"testing"
)

func TestClientIdentitySubscriptionPreparationRecoversEachPublicationBoundary(t *testing.T) {
	for boundary := 1; boundary <= 8; boundary++ {
		t.Run(string(rune('0'+boundary)), func(t *testing.T) {
			a, source := servingFiles(t)
			artifact := []byte("vless://prepared-target\n")
			sub := ClientIdentitySubscription{Source: source, Target: source, SourceArtifactSHA256: digest([]byte("source artifact\n")), TargetArtifactSHA256: digest(artifact)}
			original, _ := os.ReadFile(a.path(ServingStatePath))
			calls := 0
			a.syncDirectoryFault = func(string) error {
				calls++
				if calls == boundary {
					return os.ErrInvalid
				}
				return nil
			}
			a.PrepareClientIdentitySubscription(sub, artifact)
			a.syncDirectoryFault = nil
			if !a.InspectClientIdentitySubscription(sub, "8.8.8.8", false, false).Accepted {
				t.Fatal("recorded publication cannot be inspected for cleanup")
			}
			if !a.PrepareClientIdentitySubscription(sub, artifact) {
				t.Fatal("exact prepared target could not finish publication")
			}
			current, _ := os.ReadFile(a.path(ServingStatePath))
			if !bytes.Equal(original, current) {
				t.Fatal("preparation changed canonical source state")
			}
			if !a.PublishClientIdentitySubscription(source, source) || !a.ClientIdentitySubscriptionArtifactMatches(sub, artifact) || !a.RemoveClientIdentitySubscription(sub) {
				t.Fatal("selected artifact/state failed finishing")
			}
			if !a.SubscriptionRotationStagingEmpty() {
				t.Fatal("secret-bearing staging survived")
			}
		})
	}
}

func TestClientIdentityServingStartupUpgradeRecoversPublicationBoundaries(t *testing.T) {
	for boundary := 1; boundary <= 6; boundary++ {
		t.Run(string(rune('0'+boundary)), func(t *testing.T) {
			a, _ := servingFiles(t)
			if err := os.WriteFile(a.path(ServingUnitPath), []byte(legacyServingUnit), 0644); err != nil {
				t.Fatal(err)
			}
			calls := 0
			a.syncDirectoryFault = func(string) error {
				calls++
				if calls == boundary {
					return os.ErrInvalid
				}
				return nil
			}
			a.UpgradeClientIdentityServingStartup()
			a.syncDirectoryFault = nil
			if !a.UpgradeClientIdentityServingStartup() {
				t.Fatal("exact startup publication could not recover")
			}
			for _, path := range []string{ServingUnitPath + ".sbxr-next", ServingUnitPath + ".sbxr-next.sbxr-next"} {
				if !a.safelyAbsent(path) {
					t.Fatal("startup staging survived")
				}
			}
		})
	}
}

func TestClientIdentityCleanupAcceptsRecordedCertificatePublicationWithoutChangingIdentity(t *testing.T) {
	a, source := servingFiles(t)
	target := source
	target.CertificateGeneration++
	artifact := []byte("vless://unused-target\n")
	sub := ClientIdentitySubscription{Source: source, Target: target, SourceArtifactSHA256: digest([]byte("source artifact\n")), TargetArtifactSHA256: digest(artifact)}
	if !a.PrepareClientIdentitySubscription(sub, artifact) || !a.PublishClientIdentitySubscription(source, target) {
		t.Fatal("certificate publication setup failed")
	}
	if !a.InspectClientIdentitySubscription(sub, "8.8.8.8", true, false).Accepted {
		t.Fatal("recorded same-link certificate publication blocked source cleanup")
	}
	if !a.RemoveClientIdentitySubscription(sub) || !a.InspectClientIdentitySubscription(sub, "8.8.8.8", true, false).Accepted {
		t.Fatal("cleanup could not resume after staged target removal")
	}
}
