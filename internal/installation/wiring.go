package installation

import (
	"errors"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
)

// installWiring is the thin composition seam that lets State call each owning
// Module while one Software Lifecycle Plan remains the reviewed umbrella Plan.
type installWiring struct {
	install      *softwarelifecycle.InstallPlan
	profiles     *connectionprofiles.Plan
	subscription *subscriptionpublication.Plan
	cloudflare   *cloudflaretunnel.Plan
	ip, domain   *certificatelifecycle.Plan
	network      networkpolicy.Result
	networkState state.NetworkPolicyInputs
}

func (w *installWiring) Identity() string { return w.install.Identity() }
func (w *installWiring) SHA256() string   { return w.install.SHA256() }
func (w *installWiring) StateRuntimeArtifactOwner() any {
	if w == nil {
		return nil
	}
	return w.profiles
}
func (w *installWiring) StateCloudflareRuntimeArtifactOwner() any {
	if w == nil {
		return nil
	}
	return w.cloudflare
}
func (w *installWiring) StateSubscriptionRuntimeArtifactOwner() any {
	if w == nil {
		return nil
	}
	return w.subscription
}

func (w *installWiring) ValidateConnectionProfiles(profiles state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) error {
	if w == nil || w.profiles == nil {
		return errors.New("Connection Profiles install Plan unavailable")
	}
	return w.profiles.ValidateConnectionProfiles(profiles, secrets)
}

func (w *installWiring) PrepareConnectionProfiles(profiles state.ConnectionProfiles, secrets state.ConnectionProfileSecretReader) ([]byte, []byte, error) {
	if err := w.ValidateConnectionProfiles(profiles, secrets); err != nil {
		return nil, nil, err
	}
	return w.profiles.PrepareConnectionProfiles(profiles, secrets)
}

func (w *installWiring) ValidateSubscription(settings state.SubscriptionSettings, secrets state.ClientAccessReader) error {
	if w == nil || w.subscription == nil {
		return errors.New("Subscription Publication install Plan unavailable")
	}
	return w.subscription.ValidateSubscription(settings, secrets)
}

func (w *installWiring) PrepareSubscriptionPublication() ([]byte, error) {
	if w == nil || w.subscription == nil {
		return nil, errors.New("Subscription Publication install Plan unavailable")
	}
	return w.subscription.PrepareSubscriptionPublication()
}

func (w *installWiring) ValidateCloudflare(settings state.CloudflareSettings, secrets state.InfrastructureSecretReader) error {
	if w == nil || w.cloudflare == nil || secrets == nil || !w.cloudflare.MatchesDesiredState(settings.AccountID, settings.ZoneID, settings.ZoneName, settings.TunnelName, settings.XHTTPHostname, settings.WebSocketHostname, settings.DirectHostname, w.networkState.PublicIPv4, w.networkState.PublicIPv6, secrets.ReadInfrastructureSecret(settings.ManagementToken)) {
		return errors.New("Cloudflare install Plan does not match Desired State")
	}
	return nil
}

func (w *installWiring) ValidateCertificates(settings state.CertificateSettings) error {
	if w == nil || w.ip == nil || w.domain == nil || !w.ip.MatchesDesiredState(settings.RenewalPolicy, settings.OwnerEmail, settings.ACMEAccountID, settings.IPCertificateID, settings.IPServingPointer, settings.DomainCertificateID, settings.DomainServingPointer, settings.DomainHostname) || !w.domain.MatchesDesiredState(settings.RenewalPolicy, settings.OwnerEmail, settings.ACMEAccountID, settings.IPCertificateID, settings.IPServingPointer, settings.DomainCertificateID, settings.DomainServingPointer, settings.DomainHostname) {
		return errors.New("Certificate Lifecycle install Plans do not match Desired State")
	}
	return nil
}

func (w *installWiring) ValidateNetworkPolicy(inputs state.NetworkPolicyInputs) error {
	if w == nil || inputs != w.networkState || !w.network.MatchesDesiredState(inputs.SSHPort, inputs.PublicIPv4, inputs.PublicIPv6, inputs.PrimarySubscriptionAddress) {
		return errors.New("Network Policy install result does not match Desired State")
	}
	return nil
}

func (w *installWiring) ValidateSoftwareLifecycle(intent state.SoftwareLifecycleIntent) error {
	if w == nil || w.install == nil || !w.install.MatchesDesiredState(intent.Software.XrayVersion, intent.Software.SingBoxVersion, intent.Software.CloudflaredVersion, intent.Software.CertbotVersion) {
		return errors.New("Software Lifecycle install Plan does not match Desired State")
	}
	return nil
}
