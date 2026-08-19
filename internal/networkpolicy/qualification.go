package networkpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// ControlledInstallationAdapter returns deterministic no-live Installation facts.
func ControlledInstallationAdapter() Adapter { return controlledInstallationAdapter{} }

// ControlledInstallationCollisionAdapter adds one unproved selected-seam holder.
func ControlledInstallationCollisionAdapter() Adapter {
	return controlledInstallationAdapter{selectedSeamCollision: true}
}

// ControlledCloudflareProfileSetupAdapter returns deterministic Managed-host facts.
func ControlledCloudflareProfileSetupAdapter() Adapter {
	return controlledCloudflareProfileSetupAdapter{}
}

// ControlledInstallationSSHPreservationProof proves the deterministic direct SSH session.
func ControlledInstallationSSHPreservationProof() (SSHPreservationProof, error) {
	proof, failure := New(controlledInstallationSSHAdapter{}).ProveSSHPreservation("1.1.1.1 50000 8.8.8.8 22")
	if failure != nil {
		return SSHPreservationProof{}, errors.New("controlled SSH Preservation Proof unavailable")
	}
	return proof, nil
}

type controlledInstallationAdapter struct{ selectedSeamCollision bool }

type controlledCloudflareProfileSetupAdapter struct{}

func (controlledCloudflareProfileSetupAdapter) Observe(request ObservationRequest) (Observations, error) {
	intent := request.Intent
	return Observations{
		Host:       HostFacts{UbuntuVersion: "24.04.3", UbuntuServer: true, Architecture: "amd64", Systemd: true, LogicalCPUs: 1, PhysicalRAM: 1024 << 20},
		PublicIPv4: []string{intent.PublicIPv4}, SSH: SSHFacts{DetectedPort: intent.SSHPort, ServerAddress: intent.PublicIPv4, CurrentSessions: []string{"controlled-session"}}, Firewall: FirewallFacts{SBXRTableState: "matches Desired State", RootVerified: true}, Routes: RouteFacts{IPv4: "default via 192.0.2.1"},
		Outbound: OutboundFacts{DNS: true, GitHubHTTPS: true, GitHubAttestationHTTPS: true, CloudflareHTTPS: true, ACMEHTTPS: true, CertificateEndpointsHTTPS: true, TimeService: true, TunnelTCP7844: true, TunnelUDP7844: true},
		Disk:     DiskFacts{FilesystemBytes: 20 << 30, AvailableBytes: 3 << 30}, Time: TimeFacts{Synchronized: true, Owner: "systemd-timesyncd"}, Lineage: ProvenLineage, OwnerFacts: OwnerFacts{DNS: "absent", Tunnel: "absent"},
		Listeners:   []Listener{{Address: "0.0.0.0", Port: intent.Profiles.VLESSRealityVision.Port, Protocol: TCP, Service: "xray.service", Ownership: SBXROwned}, {Address: "0.0.0.0", Port: intent.SubscriptionPort, Protocol: TCP, Service: "sbxr-subscription.service", Ownership: SBXROwned}},
		LocalProofs: []LocalProof{{Purpose: "VLESS REALITY Vision", Address: intent.PublicIPv4, Port: intent.Profiles.VLESSRealityVision.Port, Protocol: TCP, RouteMatches: true, ConfigurationMatches: true}},
		Certificate: CertificateFacts{DNS: DNSFacts{Hostname: "direct.example.com"}, CAA: CAAFacts{Issuer: "letsencrypt.org", HTTP01Allowed: true}}, Checksums: map[string]string{"sshd_config": "sha256:ssh", "nftables": "sha256:nft"},
	}, nil
}

func (adapter controlledInstallationAdapter) Observe(request ObservationRequest) (Observations, error) {
	observed := Observations{
		Host:       HostFacts{UbuntuVersion: "24.04.3", UbuntuServer: true, Architecture: "amd64", Systemd: true, LogicalCPUs: 1, PhysicalRAM: 1024 << 20},
		PublicIPv4: []string{"8.8.8.8"}, SSH: SSHFacts{DetectedPort: 22, ServerAddress: "8.8.8.8", CurrentSessions: []string{strings.Repeat("6", 64)}}, Firewall: FirewallFacts{ActiveManager: "ufw.service", SBXRTableState: "absent", UFWConfiguredState: UFWConfigDisabled, UFWReportedState: UFWStatusInactive, RootVerified: true}, Routes: RouteFacts{IPv4: "default via 192.0.2.1"},
		Outbound: OutboundFacts{DNS: true, GitHubHTTPS: true, GitHubAttestationHTTPS: true, CloudflareHTTPS: true, ACMEHTTPS: true, CertificateEndpointsHTTPS: true, TimeService: true, TunnelTCP7844: true, TunnelUDP7844: true},
		Disk:     DiskFacts{FilesystemBytes: 20 << 30, AvailableBytes: 3 << 30}, Time: TimeFacts{Synchronized: true, Owner: "systemd-timesyncd"}, OwnerFacts: OwnerFacts{DNS: "fresh", Tunnel: "fresh"},
		Listeners: []Listener{
			{Address: "0.0.0.0", Port: 22, Protocol: TCP, Process: "sshd", Service: "ssh.service"},
			{Address: "127.0.0.53", Port: 53, Protocol: TCP, Process: "systemd-resolve", Service: "systemd-resolved.service", Executable: "/usr/lib/systemd/systemd-resolved"},
			{Address: "127.0.0.53", Port: 53, Protocol: UDP, Process: "systemd-resolve", Service: "systemd-resolved.service", Executable: "/usr/lib/systemd/systemd-resolved"},
			{Address: "127.0.0.54", Port: 53, Protocol: TCP, Process: "systemd-resolve", Service: "systemd-resolved.service", Executable: "/usr/lib/systemd/systemd-resolved"},
			{Address: "127.0.0.54", Port: 53, Protocol: UDP, Process: "systemd-resolve", Service: "systemd-resolved.service", Executable: "/usr/lib/systemd/systemd-resolved"},
			{Address: "0.0.0.0", Port: 67, Protocol: UDP, Process: "dhclient"},
			{Address: "::", Port: 547, Protocol: UDP, Process: "dhcp6"},
			{Address: "127.0.0.1", Port: 123, Protocol: UDP, Process: "chronyd", Service: "chrony.service"},
			{Address: "0.0.0.0", Port: 5355, Protocol: UDP, Process: "systemd-resolve", Service: "systemd-resolved.service"},
			{Address: "0.0.0.0", Port: 5353, Protocol: UDP, Process: "avahi-daemon", Service: "avahi-daemon.service"},
		},
		Certificate: CertificateFacts{DNS: DNSFacts{Hostname: "direct.example.com"}, CAA: CAAFacts{Issuer: "letsencrypt.org", HTTP01Allowed: true}}, Checksums: map[string]string{"sshd_config": "sha256:ssh", "nftables": "sha256:nft"}, ReclamationComplete: true,
	}
	if adapter.selectedSeamCollision {
		if len(request.ListenerSeams) == 0 {
			return Observations{}, errors.New("controlled selected listener seam unavailable")
		}
		seam := request.ListenerSeams[0]
		observed.Listeners = append(observed.Listeners, Listener{Address: seam.Address, Port: seam.Port, Protocol: seam.Protocol, Process: "caddy", Service: "caddy.service"})
	}
	return observed, nil
}

type controlledInstallationSSHAdapter struct{ controlledInstallationAdapter }

type controlledRemovalObserver struct{ inventory map[string][]string }

func (observer controlledRemovalObserver) ObserveRemovalResource(review, resource, immutableID string) (RemovalObservation, error) {
	return RemovalObservation{ReviewID: review, Resource: resource, ImmutableID: immutableID, OwnedBySBXR: true, Inventory: observer.inventory}, nil
}

// ControlledRemovalAuthorities proves the fixed local/public controlled inventory.
func ControlledRemovalAuthorities(review string) ([]RemovalAuthority, error) {
	inventory := map[string][]string{"firewall-table": {"inet-sbxr"}, "public-listener": {"listener-xray"}, "public-service": {"service-xray"}}
	result := make([]RemovalAuthority, 0, 3)
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

func (controlledInstallationSSHAdapter) Observe(request ObservationRequest) (Observations, error) {
	observed, err := (controlledInstallationAdapter{}).Observe(request)
	digest := sha256.Sum256([]byte("1.1.1.1 50000 8.8.8.8 22"))
	observed.SSH = SSHFacts{DetectedPort: 22, ServerAddress: "8.8.8.8", CurrentSessions: []string{hex.EncodeToString(digest[:])}, SessionsComplete: true, Service: "ssh.service", Listener: "0.0.0.0:22/tcp"}
	observed.Listeners = []Listener{{Address: "0.0.0.0", Port: 22, Protocol: TCP, Process: "sshd", Service: "ssh.service"}}
	return observed, err
}
