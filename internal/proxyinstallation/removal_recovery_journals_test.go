package proxyinstallation

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
)

func TestRemovalRetainsInterruptedJournalsAndRecoversFresh(t *testing.T) {
	for _, variant := range []string{"enablement-early", "enablement-prepared", "rotation-cleanup", "rotation-forward", "client-cleanup", "client-forward", "client-subscription", "compromised"} {
		t.Run(variant, func(t *testing.T) {
			host := acceptedHost()
			lifecycle := &controlledRemovalLifecycle{ready: true}
			module := newInstalledInterface(lifecycle, host, acceptedSingBox{})
			if variant == "client-subscription" {
				module = newInstalledInterface(lifecycle, host, singboxadapter.New())
			}
			setup := module.Review(t.Context(), StartSetupAction)
			if result := module.Execute(t.Context(), *setup.Prepared, Approved, nil); result.Code != SetupComplete {
				t.Fatal(result)
			}
			if !strings.HasPrefix(variant, "client-") || variant == "client-subscription" {
				if variant == "enablement-early" {
					host.failSubscriptionCheckpoint = 1
				} else if variant == "enablement-prepared" {
					host.failSubscriptionPreparation = true
				}
				enable := module.Review(t.Context(), EnableSubscriptionAction)
				module.Execute(t.Context(), *enable.Prepared, Approved, nil)
			}
			if strings.HasPrefix(variant, "rotation-") {
				host.failRotationEffect = "prepare"
				if variant == "rotation-forward" {
					host.failRotationEffect = "publish"
				}
				rotate := module.Review(t.Context(), RotateSubscriptionLinkAction)
				if rotate.Prepared == nil {
					t.Fatalf("rotation review: %#v", rotate)
				}
				module.Execute(t.Context(), *rotate.Prepared, Approved, nil)
			}
			if strings.HasPrefix(variant, "client-") {
				host.clientIdentityFail = "stop"
				if variant != "client-cleanup" {
					host.clientIdentityFail = "start"
				}
				rotate := module.Review(t.Context(), RotateClientIdentityAction)
				if rotate.Prepared == nil {
					t.Fatalf("client review: %#v", rotate)
				}
				module.Execute(t.Context(), *rotate.Prepared, Approved, nil)
			}
			if variant == "compromised" {
				record, _ := decodeOwnership(host.ownership)
				record.SubscriptionCompromised = true
				host.ownership = ownershipBytes(record)
			}
			removal := module.Review(t.Context(), CompleteRemovalAction)
			if removal.Prepared == nil {
				t.Fatalf("removal review: %#v", removal)
			}
			lifecycle.failInstalledRecord = true
			if result := module.Execute(t.Context(), *removal.Prepared, Approved, nil); result.Code != RemovalNeedsCompletion || lifecycle.executable {
				t.Fatalf("executable deletion interruption: %#v", result)
			}
			captured := bytes.Clone(host.ownership)
			record, valid := decodeOwnership(captured)
			if !valid || record.Direction != removalRequired || record.RemovalCheckpoint != 10 {
				t.Fatalf("unreadable emitted removal journal: %s", captured)
			}
			if strings.HasPrefix(variant, "enablement-") && record.Enablement == nil || strings.HasPrefix(variant, "rotation-") && record.Rotation == nil || strings.HasPrefix(variant, "client-") && record.ClientRotation == nil || variant == "client-subscription" && record.ClientRotation.Subscription == nil || variant == "compromised" && !record.SubscriptionCompromised {
				t.Fatalf("interruption did not retain the requested journal: %s", captured)
			}
			t.Logf("emitted journal: %s", bytes.TrimSpace(captured))
			fresh := newInstalledInterface(lifecycle, host, acceptedSingBox{})
			finish := fresh.Review(t.Context(), FinishRemovalAction)
			if finish.Prepared == nil {
				t.Fatalf("fresh finish: %#v", finish)
			}
			if result := fresh.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted {
				t.Fatalf("fresh removal: %#v", result)
			}
		})
	}
}

func TestSharedInstallerRemovalJournalsAreSupportedProductAuthority(t *testing.T) {
	paths, err := filepath.Glob("testdata/removal-recovery/*.json")
	if err != nil || len(paths) < 8 {
		t.Fatalf("missing shared recovery fixtures: %v", err)
	}
	for _, path := range paths {
		body, err := os.ReadFile(path)
		record, valid := decodeOwnership(body)
		if err != nil || !valid || record.Direction != removalRequired {
			t.Fatalf("unsupported shared journal %s: %v", path, err)
		}
	}
}

func TestRemovalEmitsRetainedActivationAtExecutableDeletion(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		name := "activation-recorded"
		if accepted {
			name = "activation-accepted"
		}
		t.Run(name, func(t *testing.T) {
			_, renewal, lifecycle := renewalInstallation(t)
			record, _ := decodeOwnership(renewal.ownership)
			// Retained legacy resources may include an SBXR-created recorder directory.
			resources := hostadapter.SubscriptionResourcesForEnablement(record.PublicIPv4, hostadapter.SubscriptionPreflight{RecorderDirectoryCreated: true})
			record.SubscriptionResources = &resources
			record.Resources = recordResources(record, false)
			record.ResourceCreatingReleases = nil
			for range record.Resources {
				record.ResourceCreatingReleases = append(record.ResourceCreatingReleases, record.Release)
			}
			hostOwnership := ownershipBytes(record)
			renewal.ownership = hostOwnership
			target := *record.Serving
			target.CertificateGeneration++
			for i := range target.CertificateSHA256 {
				target.CertificateSHA256[i] = strings.Repeat(string(rune('5'+i)), 64)
			}
			host := &activationTestHost{renewalTestHost: renewal, published: target, loaded: *record.Serving, activationFails: !accepted}
			if accepted {
				host.failPublishAt = 3
			}
			module := newInstalledInterface(lifecycle, host, acceptedSingBox{})
			change := module.Review(t.Context(), FinishSubscriptionChangeAction)
			if change.Prepared == nil {
				t.Fatal("activation unavailable")
			}
			module.Execute(t.Context(), *change.Prepared, Approved, nil)
			pending, valid := decodeOwnership(host.ownership)
			if !valid || pending.Activation == nil {
				t.Fatal("activation interruption did not retain journal")
			}
			lifecycle.failInstalledRecord = true
			removal := module.Review(t.Context(), CompleteRemovalAction)
			if removal.Prepared == nil {
				t.Fatal("removal unavailable")
			}
			if result := module.Execute(t.Context(), *removal.Prepared, Approved, nil); result.Code != RemovalNeedsCompletion || lifecycle.executable {
				t.Fatalf("executable deletion interruption: %#v", result)
			}
			captured := bytes.Clone(host.ownership)
			committed, valid := decodeOwnership(captured)
			if !valid || committed.RemovalCheckpoint != 10 || committed.Activation == nil {
				t.Fatalf("activation removal journal invalid: %s", captured)
			}
			t.Logf("emitted journal: %s", bytes.TrimSpace(captured))
			fresh := newInstalledInterface(lifecycle, host, acceptedSingBox{})
			finish := fresh.Review(t.Context(), FinishRemovalAction)
			if finish.Prepared == nil {
				t.Fatal("fresh recovery unavailable")
			}
			if result := fresh.Execute(t.Context(), *finish.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted {
				t.Fatal(result)
			}
		})
	}
}
