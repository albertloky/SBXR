package ubuntu

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
)

const productionDirectory = "https://acme-v02.api.letsencrypt.org/directory"

var errARIRedirect = errors.New("ACME Renewal Information redirect refused")

func (adapter Adapter) observeServingCertificate(lineage certificatelifecycle.Lineage) (certificatelifecycle.CertificateObservation, *x509.Certificate, bool, error) {
	root := adapter.root
	if root == "" {
		root = "/"
	}
	name, profile, prefix := "ip", "shortlived", "ip-"
	if lineage == certificatelifecycle.DomainLineage {
		name, profile, prefix = "domain", "tlsserver", "domain-"
	}
	base, err := os.OpenRoot(filepath.Join(root, "var/lib/sbxr/certificates", name))
	if errors.Is(err, os.ErrNotExist) {
		return certificatelifecycle.CertificateObservation{}, nil, false, nil
	}
	if err != nil {
		return certificatelifecycle.CertificateObservation{}, nil, false, err
	}
	defer base.Close()
	baseInfo, err := base.Stat(".")
	if err != nil || !baseInfo.IsDir() || baseInfo.Mode().Perm() != 0o750 || fileUID(baseInfo) != adapter.uid {
		return certificatelifecycle.CertificateObservation{}, nil, false, errors.New("certificate serving directory is unsafe")
	}
	pointer, err := base.Lstat("current")
	if errors.Is(err, os.ErrNotExist) {
		return certificatelifecycle.CertificateObservation{}, nil, false, nil
	}
	if err != nil || pointer.Mode()&os.ModeSymlink == 0 || fileUID(pointer) != adapter.uid {
		return certificatelifecycle.CertificateObservation{}, nil, false, errors.New("certificate serving pointer is unsafe")
	}
	target, err := base.Readlink("current")
	if err != nil || !safeServingTarget(target, prefix) {
		return certificatelifecycle.CertificateObservation{}, nil, false, errors.New("certificate serving target is unsafe")
	}
	set, err := base.Lstat(target)
	if err != nil || !set.IsDir() || set.Mode().Perm() != 0o750 || fileUID(set) != adapter.uid {
		return certificatelifecycle.CertificateObservation{}, nil, false, errors.New("certificate serving set is unsafe")
	}
	chainInfo, err := base.Lstat(filepath.Join(target, "fullchain.pem"))
	if err != nil || !chainInfo.Mode().IsRegular() || chainInfo.Mode().Perm() != 0o640 || chainInfo.Size() <= 0 || chainInfo.Size() > maximumOutput || fileUID(chainInfo) != adapter.uid {
		return certificatelifecycle.CertificateObservation{}, nil, false, errors.New("certificate serving chain is unsafe")
	}
	chain, err := base.ReadFile(filepath.Join(target, "fullchain.pem"))
	if err != nil || len(chain) > maximumOutput {
		return certificatelifecycle.CertificateObservation{}, nil, false, errors.New("certificate serving chain is unavailable")
	}
	block, _ := pem.Decode(chain)
	if block == nil || block.Type != "CERTIFICATE" {
		return certificatelifecycle.CertificateObservation{}, nil, false, errors.New("certificate serving chain is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certificatelifecycle.CertificateObservation{}, nil, false, errors.New("certificate serving chain is invalid")
	}
	identity := ""
	if lineage == certificatelifecycle.IPLineage && len(certificate.IPAddresses) == 1 {
		identity = certificate.IPAddresses[0].String()
	} else if lineage == certificatelifecycle.DomainLineage && len(certificate.DNSNames) == 1 {
		identity = certificate.DNSNames[0]
	}
	if identity == "" {
		return certificatelifecycle.CertificateObservation{}, nil, false, errors.New("certificate serving identity is invalid")
	}
	return certificatelifecycle.CertificateObservation{Identity: identity, Profile: profile, ActiveServingID: filepath.Base(target), NotBefore: certificate.NotBefore.UTC(), NotAfter: certificate.NotAfter.UTC()}, certificate, true, nil
}

func (adapter Adapter) observeDomainRenewalInformation(parent context.Context, certificate *x509.Certificate) certificatelifecycle.RenewalInformation {
	unavailable := certificatelifecycle.RenewalInformation{Status: certificatelifecycle.RenewalInformationUnavailable}
	invalid := certificatelifecycle.RenewalInformation{Status: certificatelifecycle.RenewalInformationInvalid}
	if certificate == nil || len(certificate.AuthorityKeyId) == 0 || certificate.SerialNumber == nil || certificate.SerialNumber.Sign() < 0 {
		return invalid
	}
	directory := adapter.ariDirectory
	if directory == "" {
		directory = productionDirectory
	}
	directoryURL, err := url.Parse(directory)
	if err != nil || directoryURL.Scheme != "https" || directoryURL.Host == "" {
		return invalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	client := adapter.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	body, status, err := getSmall(ctx, client, directory)
	if errors.Is(err, errARIRedirect) {
		return invalid
	}
	if err != nil || status == http.StatusNotFound || status == http.StatusTooManyRequests || status >= 500 {
		return unavailable
	}
	if status != http.StatusOK {
		return invalid
	}
	var discovered struct {
		RenewalInfo string `json:"renewalInfo"`
	}
	if json.Unmarshal(body, &discovered) != nil {
		return invalid
	}
	if discovered.RenewalInfo == "" {
		return unavailable
	}
	base, err := url.Parse(discovered.RenewalInfo)
	if err != nil || base.Scheme != directoryURL.Scheme || base.Host != directoryURL.Host {
		return invalid
	}
	serial := derIntegerContent(certificate.SerialNumber)
	if len(serial) == 0 {
		return invalid
	}
	identifier := base64.RawURLEncoding.EncodeToString(certificate.AuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(serial)
	endpoint := strings.TrimRight(base.String(), "/") + "/" + identifier
	body, status, err = getSmall(ctx, client, endpoint)
	if errors.Is(err, errARIRedirect) {
		return invalid
	}
	if err != nil || status == http.StatusNotFound || status == http.StatusTooManyRequests || status >= 500 {
		return unavailable
	}
	if status != http.StatusOK {
		return invalid
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var document struct {
		SuggestedWindow struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"suggestedWindow"`
		ExplanationURL string `json:"explanationURL,omitempty"`
	}
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF || document.SuggestedWindow.Start.IsZero() || document.SuggestedWindow.End.IsZero() || !document.SuggestedWindow.Start.Before(document.SuggestedWindow.End) {
		return invalid
	}
	return certificatelifecycle.RenewalInformation{Status: certificatelifecycle.RenewalInformationAvailable, WindowStart: document.SuggestedWindow.Start.UTC(), WindowEnd: document.SuggestedWindow.End.UTC()}
}

func getSmall(ctx context.Context, client *http.Client, endpoint string) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	boundedClient := *client
	boundedClient.CheckRedirect = func(*http.Request, []*http.Request) error { return errARIRedirect }
	response, err := boundedClient.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
	if err != nil || len(body) > 16<<10 {
		return nil, response.StatusCode, errors.New("ACME Renewal Information response exceeded limit")
	}
	return body, response.StatusCode, nil
}

func derIntegerContent(value *big.Int) []byte {
	if value == nil || value.Sign() < 0 {
		return nil
	}
	content := value.Bytes()
	if len(content) == 0 {
		return []byte{0}
	}
	if content[0]&0x80 != 0 {
		return append([]byte{0}, content...)
	}
	return content
}
