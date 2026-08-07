package ubuntu

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

// ValidateIPCandidate proves only certificate facts. It never returns key or
// certificate bytes across the Adapter boundary.
func ValidateIPCandidate(root string, change systemchanges.CertificateChange, now time.Time, roots *x509.CertPool, uid int) error {
	return validateIPCandidate(root, change, now, roots, uid, true)
}

func validateIPCandidate(root string, change systemchanges.CertificateChange, now time.Time, roots *x509.CertPool, uid int, trusted bool) error {
	address, err := netip.ParseAddr(change.Identity)
	validLocation := change.Action == systemchanges.CertificateIPOrder && change.ConfigDirectory == "/var/lib/sbxr/certbot/production" && change.Account == "production" || change.Action == systemchanges.CertificateIPStage && change.ConfigDirectory == "/var/lib/sbxr/certbot/staging/sbxr-ip" && change.Account == "disposable-staging-sbxr-ip"
	if err != nil || !address.IsGlobalUnicast() || change.RequiredProfile != "shortlived" || change.CertName != "sbxr-ip" || !validLocation {
		return errors.New("IP certificate identity is invalid")
	}
	config := filepath.Join(root, strings.TrimPrefix(change.ConfigDirectory, "/"))
	directory := filepath.Join(config, "live", change.CertName)
	for _, candidate := range []string{config, filepath.Join(config, "live"), directory} {
		if err := safeDirectory(candidate, uid, 0o700); err != nil {
			return errors.New("IP certificate directory is unsafe")
		}
	}
	chainPEM, err := safeFile(filepath.Join(directory, "fullchain.pem"), uid, 0o600)
	if err != nil {
		return errors.New("IP certificate chain is unsafe")
	}
	keyPEM, err := safeFile(filepath.Join(directory, "privkey.pem"), uid, 0o600)
	if err != nil {
		return errors.New("IP certificate key is unsafe")
	}
	return validateIPMaterial(chainPEM, keyPEM, address, now, roots, trusted)
}

func validateIPMaterial(chainPEM, keyPEM []byte, address netip.Addr, now time.Time, roots *x509.CertPool, trusted bool) error {
	certificates, err := parseCertificates(chainPEM)
	if err != nil || len(certificates) < 2 {
		return errors.New("IP certificate chain is incomplete")
	}
	leaf := certificates[0]
	if len(leaf.IPAddresses) != 1 || len(leaf.DNSNames) != 0 || !leaf.IPAddresses[0].Equal(address.AsSlice()) || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.NotAfter.Sub(leaf.NotBefore) < 150*time.Hour || leaf.NotAfter.Sub(leaf.NotBefore) > 170*time.Hour || !serverUsage(leaf.ExtKeyUsage) {
		return errors.New("IP certificate facts are invalid")
	}
	privateKey, err := parsePrivateKey(keyPEM)
	if err != nil || !publicKeysEqual(leaf.PublicKey, privateKey.Public()) {
		return errors.New("IP certificate key does not match")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	if !trusted {
		return nil
	}
	if roots == nil {
		roots, err = x509.SystemCertPool()
		if err != nil {
			return errors.New("trusted roots unavailable")
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: address.String(), Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return errors.New("IP certificate chain is untrusted")
	}
	return nil
}

func safeDirectory(name string, uid int, mode os.FileMode) error {
	info, err := os.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode().Perm() != mode || info.Mode()&os.ModeSymlink != 0 || fileUID(info) != uid {
		return errors.New("unsafe directory")
	}
	return nil
}

func safeFile(name string, uid int, mode os.FileMode) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 1<<20 || fileUID(info) != uid {
		return nil, errors.New("unsafe file")
	}
	return os.ReadFile(name)
}

func fileUID(info os.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}

func fileGID(info os.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Gid)
}

func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for len(bytes.TrimSpace(data)) > 0 {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("malformed certificate chain")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
		data = rest
	}
	return certificates, nil
}

func parsePrivateKey(data []byte) (crypto.Signer, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("malformed private key")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if private, ok := key.(crypto.Signer); ok {
			return private, nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported private key")
}

func publicKeysEqual(left, right any) bool {
	leftDER, leftErr := x509.MarshalPKIXPublicKey(left)
	rightDER, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && reflect.DeepEqual(leftDER, rightDER)
}

func serverUsage(usages []x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

var _ crypto.Signer = (*rsa.PrivateKey)(nil)
var _ crypto.Signer = (*ecdsa.PrivateKey)(nil)
