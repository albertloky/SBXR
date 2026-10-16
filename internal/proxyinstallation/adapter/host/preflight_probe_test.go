package host

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDestinationProbeRetainsLastCompletedCheckOnTLSFailure(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err == nil {
			connection.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	fact := liveDestinationObservation(ctx, Destination{Address: listener.Addr().String(), ServerName: "localhost"})
	if !fact.DNS || !fact.TCP || fact.TLS13 || fact.HTTP2 || fact.CertificateName || fact.Compatible() {
		t.Fatalf("TLS refusal lost probe stage: %#v", fact)
	}
	listener.Close()
	<-done
}
