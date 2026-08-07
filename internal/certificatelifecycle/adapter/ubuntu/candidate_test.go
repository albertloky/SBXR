package ubuntu

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestValidateIPCandidateRejectsWrongIdentityKeyAndFilesystem(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name                                                      string
		ip                                                        string
		wrongKey, unsafe, symlink, untrusted, expired, wrongUsage bool
	}{
		{name: "valid", ip: "192.0.2.10"},
		{name: "IPv6", ip: "2001:db8::10"},
		{name: "wrong SAN", ip: "198.51.100.10"},
		{name: "key mismatch", ip: "192.0.2.10", wrongKey: true},
		{name: "unsafe mode", ip: "192.0.2.10", unsafe: true},
		{name: "symlink", ip: "192.0.2.10", symlink: true},
		{name: "untrusted chain", ip: "192.0.2.10", untrusted: true},
		{name: "expired", ip: "192.0.2.10", expired: true},
		{name: "wrong usage", ip: "192.0.2.10", wrongUsage: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, roots := writeCandidate(t, now, "192.0.2.10", test.wrongKey, test.wrongUsage)
			if test.name == "IPv6" {
				root, roots = writeCandidate(t, now, "2001:db8::10", false)
			}
			if test.unsafe {
				mustChmod(t, filepath.Join(root, "var/lib/sbxr/certbot/production/live/sbxr-ip/privkey.pem"), 0o644)
			}
			if test.symlink {
				key := filepath.Join(root, "var/lib/sbxr/certbot/production/live/sbxr-ip/privkey.pem")
				if err := os.Rename(key, key+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("privkey.pem.real", key); err != nil {
					t.Fatal(err)
				}
			}
			if test.untrusted {
				roots = x509.NewCertPool()
			}
			checkedAt := now
			if test.expired {
				checkedAt = now.Add(200 * time.Hour)
			}
			err := ValidateIPCandidate(root, systemchanges.CertificateChange{Action: systemchanges.CertificateIPOrder, Identity: test.ip, RequiredProfile: "shortlived", CertName: "sbxr-ip", OwnerEmail: "owner@example.com", ConfigDirectory: "/var/lib/sbxr/certbot/production", Account: "production"}, checkedAt, roots, os.Geteuid())
			if (test.name == "valid" || test.name == "IPv6") != (err == nil) {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}

func TestValidateIPCandidateRedactsPrivateMaterial(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	root, roots := writeCandidate(t, now, "192.0.2.10", false)
	key := filepath.Join(root, "var/lib/sbxr/certbot/production/live/sbxr-ip/privkey.pem")
	if err := os.WriteFile(key, []byte("PRIVATE-KEY-MARKER"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := ValidateIPCandidate(root, systemchanges.CertificateChange{Action: systemchanges.CertificateIPOrder, Identity: "192.0.2.10", RequiredProfile: "shortlived", CertName: "sbxr-ip", ConfigDirectory: "/var/lib/sbxr/certbot/production", Account: "production"}, now, roots, os.Geteuid())
	if err == nil || strings.Contains(err.Error(), "MARKER") {
		t.Fatalf("private material crossed seam: %v", err)
	}
}

func TestValidateDomainCandidateRejectsWrongIdentityKeyAndFilesystem(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name, hostname                                         string
		wrongKey, unsafe, untrusted, expired, wrongUsage, long bool
	}{
		{name: "valid", hostname: "direct.example.com"},
		{name: "wrong SAN", hostname: "wrong.example.com"},
		{name: "key mismatch", hostname: "direct.example.com", wrongKey: true},
		{name: "unsafe mode", hostname: "direct.example.com", unsafe: true},
		{name: "untrusted chain", hostname: "direct.example.com", untrusted: true},
		{name: "expired", hostname: "direct.example.com", expired: true},
		{name: "wrong usage", hostname: "direct.example.com", wrongUsage: true},
		{name: "fallback lifetime", hostname: "direct.example.com", long: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, roots := writeDomainCandidate(t, now, "direct.example.com", test.wrongKey, test.wrongUsage, test.long)
			if test.unsafe {
				mustChmod(t, filepath.Join(root, "var/lib/sbxr/certbot/production/live/sbxr-domain/privkey.pem"), 0o644)
			}
			if test.untrusted {
				roots = x509.NewCertPool()
			}
			checkedAt := now
			if test.expired {
				checkedAt = now.Add(50 * 24 * time.Hour)
			}
			err := ValidateDomainCandidate(root, systemchanges.CertificateChange{Action: systemchanges.CertificateDomainOrder, Identity: test.hostname, DestinationIP: "192.0.2.10", RequiredProfile: "tlsserver", CertName: "sbxr-domain", ConfigDirectory: "/var/lib/sbxr/certbot/production", Account: "production"}, checkedAt, roots, os.Geteuid())
			if (test.name == "valid") != (err == nil) {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}

func TestValidateDomainCandidateRedactsPrivateMaterial(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	root, roots := writeDomainCandidate(t, now, "direct.example.com", false, false, false)
	key := filepath.Join(root, "var/lib/sbxr/certbot/production/live/sbxr-domain/privkey.pem")
	if err := os.WriteFile(key, []byte("DOMAIN-PRIVATE-KEY-MARKER"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := ValidateDomainCandidate(root, systemchanges.CertificateChange{Action: systemchanges.CertificateDomainOrder, Identity: "direct.example.com", DestinationIP: "192.0.2.10", RequiredProfile: "tlsserver", CertName: "sbxr-domain", ConfigDirectory: "/var/lib/sbxr/certbot/production", Account: "production"}, now, roots, os.Geteuid())
	if err == nil || strings.Contains(err.Error(), "MARKER") {
		t.Fatalf("domain private material crossed seam: %v", err)
	}
}

func writeCandidate(t *testing.T, now time.Time, identity string, wrongKey bool, wrongUsage ...bool) (string, *x509.CertPool) {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "var/lib/sbxr/certbot/production/live/sbxr-ip")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if len(wrongUsage) == 1 && wrongUsage[0] {
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: identity}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(159 * time.Hour), IPAddresses: []net.IP{net.ParseIP(identity)}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &key.PublicKey, caKey)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	if err := os.WriteFile(filepath.Join(directory, "fullchain.pem"), chain, 0o600); err != nil {
		t.Fatal(err)
	}
	if wrongKey {
		key, _ = rsa.GenerateKey(rand.Reader, 2048)
	}
	private := x509.MarshalPKCS1PrivateKey(key)
	if err := os.WriteFile(filepath.Join(directory, "privkey.pem"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: private}), 0o600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return root, roots
}

func writeDomainCandidate(t *testing.T, now time.Time, identity string, wrongKey, wrongUsage, longLifetime bool) (string, *x509.CertPool) {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "var/lib/sbxr/certbot/production/live/sbxr-domain")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if wrongUsage {
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	lifetime := 45 * 24 * time.Hour
	if longLifetime {
		lifetime = 90 * 24 * time.Hour
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(12), Subject: pkix.Name{CommonName: identity}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(lifetime - time.Hour), DNSNames: []string{identity}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &key.PublicKey, caKey)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	if err := os.WriteFile(filepath.Join(directory, "fullchain.pem"), chain, 0o600); err != nil {
		t.Fatal(err)
	}
	if wrongKey {
		key, _ = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err := os.WriteFile(filepath.Join(directory, "privkey.pem"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return root, roots
}

func mustChmod(t *testing.T, name string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}
