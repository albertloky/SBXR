// Package connectionprofiles owns SBXR's runtime connection profile facts.
package connectionprofiles

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"
)

const domainCertificatePointer = "/var/lib/sbxr/certificates/domain/current"

type DirectTLSConsumer struct {
	Port               uint16
	CertificatePointer string
	Insecure           bool
}

type DirectTLSRequest struct {
	Revision                uint64
	DestinationIP, Hostname string
	Hysteria2, TUIC, AnyTLS DirectTLSConsumer
}

// DirectTLSContribution is an opaque, secret-free fact contributed to System Changes.
type DirectTLSContribution struct {
	revision                uint64
	destinationIP, hostname string
	digest                  string
	valid                   bool
}

func NewDirectTLSContribution(request DirectTLSRequest) DirectTLSContribution {
	address, err := netip.ParseAddr(request.DestinationIP)
	valid := request.Revision > 0 && err == nil && address.IsGlobalUnicast() && validHostname(request.Hostname) &&
		request.Hysteria2 == (DirectTLSConsumer{Port: 443, CertificatePointer: domainCertificatePointer}) &&
		request.TUIC == (DirectTLSConsumer{Port: 8443, CertificatePointer: domainCertificatePointer}) &&
		request.AnyTLS == (DirectTLSConsumer{Port: 9443, CertificatePointer: domainCertificatePointer})
	encoded, _ := json.Marshal(request)
	digest := sha256.Sum256(encoded)
	return DirectTLSContribution{revision: request.Revision, destinationIP: request.DestinationIP, hostname: request.Hostname, digest: hex.EncodeToString(digest[:]), valid: valid}
}

func (contribution DirectTLSContribution) SystemChangesDirectTLS() (uint64, string, string, string, bool) {
	return contribution.revision, contribution.destinationIP, contribution.hostname, contribution.digest, contribution.valid
}

func validHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 || hostname != strings.ToLower(hostname) {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}
