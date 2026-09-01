package proxyinstallation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
	"github.com/albertloky/SBXR/internal/proxyinstallation/subscriptionserving"
)

type clientIdentitySubscriptionHost interface {
	UpgradeClientIdentityServingStartup() bool
	VerifyClientIdentityServingStartup(context.Context) bool
	ClientIdentitySubscriptionReady(context.Context, hostadapter.ServingAuthority, hostadapter.RenewalAuthority) (hostadapter.ServingAuthority, bool)
	PrepareClientIdentitySubscription(hostadapter.ClientIdentitySubscription, []byte) bool
	InspectClientIdentitySubscription(hostadapter.ClientIdentitySubscription, string, bool, bool) hostadapter.Observation
	StopClientIdentitySubscription(context.Context) bool
	PublishClientIdentitySubscription(hostadapter.ServingAuthority, hostadapter.ServingAuthority) bool
	RemoveClientIdentitySubscription(hostadapter.ClientIdentitySubscription) bool
	ClientIdentitySubscriptionArtifactMatches(hostadapter.ClientIdentitySubscription, []byte) bool
}

func (m *installedInterface) clientIdentitySubscriptionAdmitted(ctx context.Context, record ownershipRecord) bool {
	if record.Enablement != nil || record.Rotation != nil || record.Repair != nil || record.Activation != nil || record.ClientRotation != nil {
		return false
	}
	if record.Serving == nil {
		absent := m.host.InspectSubscriptionAbsence(ctx)
		return absent.Observed && absent.Accepted
	}
	host, ok := m.host.(clientIdentitySubscriptionHost)
	if !ok || record.Renewal == nil {
		return false
	}
	_, ready := host.ClientIdentitySubscriptionReady(ctx, *record.Serving, *record.Renewal)
	return ready
}

func clientArtifact(configuration []byte, ipv4 string) ([]byte, string, bool) {
	facts, err := singboxadapter.New().CurrentConnectionFacts(configuration, ipv4)
	if err != nil {
		return nil, "", false
	}
	artifact, code := subscriptionserving.Artifact(facts)
	sum := sha256.Sum256(artifact)
	return artifact, hex.EncodeToString(sum[:]), code == subscriptionserving.Ready
}

func (m *installedInterface) inspectClientIdentitySubscription(record ownershipRecord) bool {
	sub := record.ClientRotation.Subscription
	if sub == nil {
		return true
	}
	host, ok := m.host.(clientIdentitySubscriptionHost)
	required, _ := clientRotationRequirements(record.ClientRotation.Checkpoint)
	return ok && host.InspectClientIdentitySubscription(*sub, record.PublicIPv4, required, record.ClientRotation.Direction == "forward").Accepted
}

// finishIdentitySubscription never issues a certificate or clears renewal
// evidence. A stopped/expired independent capability may remain unavailable,
// but selected artifact and saved-state agreement are mandatory.
func (m *installedInterface) finishIdentitySubscription(ctx context.Context, record *ownershipRecord, current *[]byte) bool {
	sub := record.ClientRotation.Subscription
	if sub == nil {
		return true
	}
	host, ok := m.host.(clientIdentitySubscriptionHost)
	activation, activationOK := m.host.(certificateActivationHost)
	serving, servingOK := m.host.(subscriptionRotationHost)
	if !ok || !activationOK || !servingOK {
		return false
	}
	if !host.UpgradeClientIdentityServingStartup() || !m.host.(clientIdentityHost).ReloadProxyStartupIntegration(ctx) || !host.VerifyClientIdentityServingStartup(ctx) {
		return false
	}
	configuration, err := m.host.ReadConfiguration(ctx, hostSetupSpec, record.ConfigurationSHA256)
	artifact, hash, valid := clientArtifact(configuration, record.PublicIPv4)
	want := sub.TargetArtifactSHA256
	if record.ClientRotation.Direction == "cleanup" {
		want = sub.SourceArtifactSHA256
	}
	if err != nil || !valid || hash != want {
		return false
	}
	if record.ClientRotation.Direction == "forward" && !host.ClientIdentitySubscriptionArtifactMatches(*sub, artifact) {
		return false
	}
	if !host.PublishClientIdentitySubscription(*record.Serving, sub.Target) {
		return false
	}
	if *record.Serving != sub.Target {
		accepted := sub.Target
		record.Serving = &accepted
		updateSubscriptionResources(record, record.Release)
		var published bool
		*current, published = m.publishClientIdentityCheckpoint(*record, *current)
		if !published {
			return false
		}
	}
	if _, ok := serving.ReadSubscriptionLink(*record.Serving, record.PublicIPv4); !ok || !host.RemoveClientIdentitySubscription(*sub) {
		return false
	}
	// Ordinary certificate inspection deliberately requires empty staging.
	// The exact selected artifact was checked above; remove only its proved
	// publication before inspecting or activating the selected certificate.
	inspection := activation.InspectCertificateActivation(ctx, *record.Renewal, *record.Serving)
	if inspection.Accepted && inspection.Observed && inspection.Published != *record.Serving {
		if !compatibleCertificateTarget(*record.Serving, inspection.Published) {
			return false
		}
		sub.Target = inspection.Published
		updateSubscriptionResources(record, record.Release)
		var published bool
		*current, published = m.publishClientIdentityCheckpoint(*record, *current)
		if !published || !host.PublishClientIdentitySubscription(*record.Serving, sub.Target) {
			return false
		}
		accepted := sub.Target
		record.Serving = &accepted
		updateSubscriptionResources(record, record.Release)
		*current, published = m.publishClientIdentityCheckpoint(*record, *current)
		if !published {
			return false
		}
		inspection = activation.InspectCertificateActivation(ctx, *record.Renewal, *record.Serving)
	}
	if _, ok := serving.ReadSubscriptionLink(*record.Serving, record.PublicIPv4); !ok {
		return false
	}
	if !inspection.Observed || !inspection.Accepted || inspection.Published != *record.Serving {
		// Fresh certificate validation failed. Prove serving stopped; never
		// resume with stale TLS material or call uncertain artifact data healthy.
		return host.StopClientIdentitySubscription(ctx)
	}
	if inspection.Loaded != *record.Serving {
		if !serving.ActivatePreparedSubscription(ctx, *record.Serving, *record.Renewal) {
			return host.StopClientIdentitySubscription(ctx)
		}
	}
	fresh := activation.InspectCertificateActivation(ctx, *record.Renewal, *record.Serving)
	if !fresh.Observed || !fresh.Accepted || fresh.Published != *record.Serving || fresh.Loaded != *record.Serving {
		return host.StopClientIdentitySubscription(ctx)
	}
	return true
}
