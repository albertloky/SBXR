package ubuntu

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
)

func TestServingCertificateObservationUsesTheAnchoredActivePointer(t *testing.T) {
	root := t.TempDir()
	set := filepath.Join(root, "var/lib/sbxr/certificates/domain/sets/domain-active")
	if err := os.MkdirAll(set, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "direct.example.com"}, DNSNames: []string{"direct.example.com"}, NotBefore: now.Add(-15 * 24 * time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), AuthorityKeyId: []byte{1, 2, 3}}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err := os.WriteFile(filepath.Join(set, "fullchain.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sets/domain-active", filepath.Join(root, "var/lib/sbxr/certificates/domain/current")); err != nil {
		t.Fatal(err)
	}
	observed, certificate, found, err := (Adapter{root: root, uid: os.Geteuid(), gid: os.Getegid()}).observeServingCertificate(certificatelifecycle.DomainLineage)
	if err != nil || !found || certificate == nil || observed.Identity != "direct.example.com" || observed.Profile != "tlsserver" || observed.ActiveServingID != "domain-active" || !observed.NotAfter.Equal(template.NotAfter) {
		t.Fatalf("active domain observation = (%+v, %+v, %t, %v)", observed, certificate, found, err)
	}
}

func TestACMERenewalInformationSeamIsBoundedAndFailClosed(t *testing.T) {
	mode := "available"
	requestedPath := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/directory" {
			if mode == "cross-origin redirect" {
				http.Redirect(response, request, "https://example.invalid/directory", http.StatusFound)
				return
			}
			if mode == "explicitly unavailable" {
				_, _ = io.WriteString(response, `{}`)
				return
			}
			if mode == "malformed directory" {
				_, _ = io.WriteString(response, `{"renewalInfo":`)
				return
			}
			_, _ = io.WriteString(response, `{"renewalInfo":"`+"https://"+request.Host+`/renewal"}`)
			return
		}
		requestedPath = request.URL.Path
		switch mode {
		case "downgrade redirect":
			http.Redirect(response, request, "http://"+request.Host+"/renewal", http.StatusFound)
		case "timeout":
			<-request.Context().Done()
		case "malformed response":
			_, _ = io.WriteString(response, `{"suggestedWindow":{"start":"RAW-ARI-SECRET-MARKER","end":"2026-08-09T00:00:00Z"}}`)
		case "contradictory response":
			_, _ = io.WriteString(response, `{"suggestedWindow":{"start":"2026-08-10T00:00:00Z","end":"2026-08-09T00:00:00Z"}}`)
		default:
			_, _ = io.WriteString(response, `{"suggestedWindow":{"start":"2026-08-08T00:00:00Z","end":"2026-08-09T00:00:00Z"}}`)
		}
	}))
	defer server.Close()
	adapter := Adapter{ariDirectory: server.URL + "/directory", httpClient: server.Client()}
	certificate := &x509.Certificate{AuthorityKeyId: []byte{0x69, 0x88, 0x5b, 0x6b, 0x87, 0x46, 0x40, 0x41, 0xe1, 0xb3, 0x7b, 0x84, 0x7b, 0xa0, 0xae, 0x2c, 0xde, 0x01, 0xc8, 0xd4}, SerialNumber: new(big.Int).SetBytes([]byte{0x87, 0x65, 0x43, 0x21})}

	information := adapter.observeDomainRenewalInformation(t.Context(), certificate)
	if information.Status != certificatelifecycle.RenewalInformationAvailable || information.WindowStart.Format(time.RFC3339) != "2026-08-08T00:00:00Z" || information.WindowEnd.Format(time.RFC3339) != "2026-08-09T00:00:00Z" || requestedPath != "/renewal/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE" {
		t.Fatalf("available ARI = %+v path %q", information, requestedPath)
	}
	for _, test := range []struct {
		mode string
		want certificatelifecycle.RenewalInformationStatus
	}{
		{mode: "explicitly unavailable", want: certificatelifecycle.RenewalInformationUnavailable},
		{mode: "malformed directory", want: certificatelifecycle.RenewalInformationInvalid},
		{mode: "malformed response", want: certificatelifecycle.RenewalInformationInvalid},
		{mode: "contradictory response", want: certificatelifecycle.RenewalInformationInvalid},
		{mode: "cross-origin redirect", want: certificatelifecycle.RenewalInformationInvalid},
		{mode: "downgrade redirect", want: certificatelifecycle.RenewalInformationInvalid},
	} {
		mode = test.mode
		information = adapter.observeDomainRenewalInformation(t.Context(), certificate)
		if information.Status != test.want || strings.Contains(string(information.Status), "MARKER") {
			t.Fatalf("%s ARI = %+v", test.mode, information)
		}
	}
	mode = "timeout"
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if information = adapter.observeDomainRenewalInformation(ctx, certificate); information.Status != certificatelifecycle.RenewalInformationUnavailable {
		t.Fatalf("timeout ARI = %+v", information)
	}
}
