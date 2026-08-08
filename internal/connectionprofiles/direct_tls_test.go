package connectionprofiles_test

import (
	"testing"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
)

func TestDirectTLSContributionRequiresThreeExactSharedConsumers(t *testing.T) {
	request := connectionprofiles.DirectTLSRequest{
		Revision: 7, DestinationIP: "192.0.2.10", Hostname: "direct.example.com",
		Hysteria2: connectionprofiles.DirectTLSConsumer{Port: 443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"},
		TUIC:      connectionprofiles.DirectTLSConsumer{Port: 8443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"},
		AnyTLS:    connectionprofiles.DirectTLSConsumer{Port: 9443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"},
	}
	valid := connectionprofiles.NewDirectTLSContribution(request)
	if _, _, _, digest, ok := valid.SystemChangesDirectTLS(); !ok || len(digest) != 64 {
		t.Fatal("exact Direct TLS consumers were refused")
	}
	for _, change := range []func(*connectionprofiles.DirectTLSRequest){
		func(request *connectionprofiles.DirectTLSRequest) { request.TUIC.Port = 0 },
		func(request *connectionprofiles.DirectTLSRequest) {
			request.AnyTLS.CertificatePointer = "/var/lib/sbxr/certificates/domain/other"
		},
		func(request *connectionprofiles.DirectTLSRequest) { request.Hysteria2.Insecure = true },
	} {
		invalid := request
		change(&invalid)
		if _, _, _, _, ok := connectionprofiles.NewDirectTLSContribution(invalid).SystemChangesDirectTLS(); ok {
			t.Fatalf("consumer disagreement accepted: %#v", invalid)
		}
	}
}
