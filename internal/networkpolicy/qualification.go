package networkpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// ControlledInstallationAdapter returns deterministic no-live Installation facts.
func ControlledInstallationAdapter() Adapter { return controlledInstallationAdapter{} }

// ControlledInstallationSSHPreservationProof proves the deterministic direct SSH session.
func ControlledInstallationSSHPreservationProof() (SSHPreservationProof, error) {
	proof, failure := New(controlledInstallationSSHAdapter{}).ProveSSHPreservation("1.1.1.1 50000 8.8.8.8 22")
	if failure != nil {
		return SSHPreservationProof{}, errors.New("controlled SSH Preservation Proof unavailable")
	}
	return proof, nil
}

type controlledInstallationAdapter struct{}

func (controlledInstallationAdapter) Observe(request ObservationRequest) (Observations, error) {
	return Observations{
		Host:       HostFacts{UbuntuVersion: "24.04.3", UbuntuServer: true, Architecture: "amd64", Systemd: true, LogicalCPUs: 1, PhysicalRAM: 1024 << 20},
		PublicIPv4: []string{"8.8.8.8"}, SSH: SSHFacts{DetectedPort: 22, ServerAddress: "8.8.8.8", CurrentSessions: []string{strings.Repeat("6", 64)}}, Firewall: FirewallFacts{SBXRTableState: "absent", RootVerified: request.Stage == PostApproval}, Routes: RouteFacts{IPv4: "default via 192.0.2.1"},
		Outbound: OutboundFacts{DNS: true, GitHubHTTPS: true, GitHubAttestationHTTPS: true, CloudflareHTTPS: true, ACMEHTTPS: true, CertificateEndpointsHTTPS: true, TimeService: true, TunnelTCP7844: true, TunnelUDP7844: true},
		Disk:     DiskFacts{FilesystemBytes: 20 << 30, AvailableBytes: 3 << 30}, Time: TimeFacts{Synchronized: true, Owner: "systemd-timesyncd"}, OwnerFacts: OwnerFacts{DNS: "fresh", Tunnel: "fresh"},
		Certificate: CertificateFacts{DNS: DNSFacts{Hostname: "direct.example.com"}, CAA: CAAFacts{Issuer: "letsencrypt.org", HTTP01Allowed: true}}, Checksums: map[string]string{"sshd_config": "sha256:ssh", "nftables": "sha256:nft"}, ReclamationComplete: true,
	}, nil
}

type controlledInstallationSSHAdapter struct{ controlledInstallationAdapter }

func (controlledInstallationSSHAdapter) Observe(request ObservationRequest) (Observations, error) {
	observed, err := (controlledInstallationAdapter{}).Observe(request)
	digest := sha256.Sum256([]byte("1.1.1.1 50000 8.8.8.8 22"))
	observed.SSH = SSHFacts{DetectedPort: 22, ServerAddress: "8.8.8.8", CurrentSessions: []string{hex.EncodeToString(digest[:])}, SessionsComplete: true, Service: "ssh.service", Listener: "0.0.0.0:22/tcp"}
	observed.Listeners = []Listener{{Address: "0.0.0.0", Port: 22, Protocol: TCP, Process: "sshd", Service: "ssh.service"}}
	return observed, err
}
