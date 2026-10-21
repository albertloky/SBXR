package host

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const HTTPSRetirementDirectory = "/var/lib/sbxr/subscription-https-retired"
const httpsRenewalConfiguration = "/etc/letsencrypt/renewal/sbxr-subscription.conf"
const httpsRetirementCapability = "SBXR-SUBSCRIPTION-HTTPS-RETIREMENT-V1"

func HTTPSRetirementCapability() string { return httpsRetirementCapability }

// HTTPSRetirementAuthority retains historical cleanup ownership, not active
// renewal authority. HTTP never loads these certificates or checks their age.
type HTTPSRetirementAuthority struct {
	Serving             ServingAuthority              `json:"serving"`
	Renewal             RenewalAuthority              `json:"renewal"`
	Resources           SubscriptionResourceAuthority `json:"resources"`
	ConfigurationMode   uint32                        `json:"configuration_mode"`
	ConfigurationSHA256 string                        `json:"configuration_sha256"`
	EvidenceSHA256      string                        `json:"evidence_sha256"`
}

func (r HTTPSRetirementAuthority) Valid() bool {
	validHash := func(value string) bool {
		body, err := hex.DecodeString(value)
		return err == nil && len(body) == 32 && hex.EncodeToString(body) == value && strings.Trim(value, "0") != ""
	}
	mode := os.FileMode(r.ConfigurationMode)
	return r.Serving.Valid() && !r.Serving.HTTP && r.Renewal.Valid() && r.Resources.Valid() && !r.Resources.HTTP && r.Resources.PublicIPv4 == r.Renewal.PublicIPv4 && mode&^0777 == 0 && mode&0133 == 0 && mode&0400 != 0 && validHash(r.ConfigurationSHA256) && validHash(r.EvidenceSHA256)
}

func (r HTTPSRetirementAuthority) ResourcesList() []string {
	resources := []string{
		HTTPSRetirementDirectory + " root:root 0700 retained-https-v1",
		HTTPSRetirementDirectory + "/renewal.conf root:root 0" + strconv.FormatUint(uint64(r.ConfigurationMode), 8) + " one-link sha256:" + r.ConfigurationSHA256,
		HTTPSRetirementDirectory + "/recorder.conf root:root 0644 one-link recorder-v1",
		HTTPSRetirementDirectory + "/deploy-hook root:root 0700 one-link deploy-writer-v1",
		HTTPSRetirementDirectory + "/post-hook root:root 0700 one-link post-writer-v1",
		RenewalEvidencePath + " root:root 0600 one-link retired-evidence-sha256:" + r.EvidenceSHA256,
		RenewalAdmissionPath + " root:root 0600 one-link admission-v1",
		RenewalWriterPath + " root:root 0600 one-link writer-v1",
	}
	resources = append(resources, r.Serving.Resources()[5:]...)
	resources = append(resources, r.Resources.Resources()[3:]...)
	return resources
}

type retirementPublication struct {
	source, backup string
	mode           os.FileMode
	hash           string
}

func (r HTTPSRetirementAuthority) publications() []retirementPublication {
	return []retirementPublication{
		{httpsRenewalConfiguration, HTTPSRetirementDirectory + "/renewal.conf", os.FileMode(r.ConfigurationMode), r.ConfigurationSHA256},
		{RenewalDropInPath, HTTPSRetirementDirectory + "/recorder.conf", 0644, digest([]byte(RenewalDropIn))},
		{RenewalDeployHookPath, HTTPSRetirementDirectory + "/deploy-hook", 0700, digest([]byte(RenewalDeployHook))},
		{RenewalPostHookPath, HTTPSRetirementDirectory + "/post-hook", 0700, digest([]byte(RenewalPostHook))},
	}
}

func (a Adapter) AcquireHTTPSRetirementExclusion(r HTTPSRetirementAuthority, removing bool) (*RenewalExclusion, bool) {
	if !r.Valid() {
		return nil, false
	}
	admission, ok := a.openRenewalLock(RenewalAdmissionPath, true)
	if !ok && !(removing && a.safelyAbsent(RenewalAdmissionPath)) {
		return nil, false
	}
	writer, ok := a.openRenewalLock(RenewalWriterPath, true)
	if !ok && !(removing && a.safelyAbsent(RenewalWriterPath)) {
		if admission != nil {
			admission.Close()
		}
		return nil, false
	}
	exclusion := &RenewalExclusion{authority: r.Renewal, admission: admission, writer: writer}
	if _, err := a.protectedServingFile(RenewalEvidencePath, 0600, r.EvidenceSHA256); err != nil && !(removing && errors.Is(err, os.ErrNotExist)) {
		exclusion.Release()
		return nil, false
	}
	return exclusion, true
}

func (a Adapter) inspectRetiredCertificates(r HTTPSRetirementAuthority, removing bool) bool {
	// Historical files must satisfy the same metadata/generation admission
	// that exact cleanup will later use, before removal can be committed.
	if _, safe := a.removableServingArchive(r.Serving); !safe {
		return false
	}
	archive, live := []string{}, []string{}
	for _, name := range certificateNames {
		archive = append(archive, name+strconv.Itoa(r.Serving.CertificateGeneration)+".pem")
		live = append(live, name+".pem")
	}
	if !a.servingDirectory(servingArchive, archive, removing) || !a.servingDirectory(servingLive, live, removing) {
		return false
	}
	for i, name := range certificateNames {
		mode := os.FileMode(0644)
		if name == "privkey" {
			mode = 0600
		}
		if _, err := a.protectedServingFile(servingArchive+"/"+archive[i], mode, r.Serving.CertificateSHA256[i]); err != nil && !(removing && errors.Is(err, os.ErrNotExist)) {
			return false
		}
		path := servingLive + "/" + name + ".pem"
		if err := a.safeParents(path); err != nil && !(removing && errors.Is(err, os.ErrNotExist)) {
			return false
		}
		info, err := os.Lstat(a.path(path))
		if removing && errors.Is(err, os.ErrNotExist) {
			continue
		}
		stat, owned := infoSys(info)
		target, targetErr := os.Readlink(a.path(path))
		if err != nil || !owned || stat.Uid != a.ownerUID() || info.Mode()&os.ModeSymlink == 0 || targetErr != nil || target != "../../archive/sbxr-subscription/"+archive[i] {
			return false
		}
	}
	return true
}

func (a Adapter) retirementDirectory(r HTTPSRetirementAuthority, removing bool) bool {
	var allowed []string
	for _, p := range r.publications() {
		allowed = append(allowed, filepath.Base(p.backup))
	}
	return a.servingDirectory(HTTPSRetirementDirectory, allowed, removing)
}

func (a Adapter) InspectHTTPSRetirement(r HTTPSRetirementAuthority, removing bool) bool {
	if !r.Valid() || !a.retirementDirectory(r, removing) || !a.inspectRetiredCertificates(r, removing) || !a.safelyAbsent(RenewalEvidenceNextPath) {
		return false
	}
	for _, p := range r.publications() {
		if !a.safelyAbsent(p.source) {
			return false
		}
		if _, err := a.protectedServingFile(p.backup, p.mode, p.hash); err != nil && !(removing && errors.Is(err, os.ErrNotExist)) {
			return false
		}
	}
	for _, p := range []struct {
		path, hash string
	}{{RenewalEvidencePath, r.EvidenceSHA256}, {RenewalAdmissionPath, digest([]byte("sbxr renewal admission v1\n"))}, {RenewalWriterPath, digest([]byte("sbxr renewal writer v1\n"))}} {
		if _, err := a.protectedServingFile(p.path, 0600, p.hash); err != nil && !(removing && errors.Is(err, os.ErrNotExist)) {
			return false
		}
	}
	return true
}

func (a Adapter) RemoveHTTPSRetirement(ctx context.Context, r HTTPSRetirementAuthority) bool {
	if !a.InspectHTTPSRetirement(r, true) || !a.safelyAbsent(SubscriptionFirewallUnitPath) {
		return false
	}
	// Shared Certbot exclusion belongs to the caller. Preserve other lineages,
	// accounts, snapd, Certbot and their ordinary timer throughout this cleanup.
	if !a.removeOwnedLineage(&r.Serving) {
		return false
	}
	for _, p := range r.publications() {
		if !a.removeClientPublication(p.backup, p.mode, p.hash) {
			return false
		}
	}
	for _, p := range []struct {
		path, hash string
	}{{RenewalEvidencePath, r.EvidenceSHA256}, {RenewalAdmissionPath, digest([]byte("sbxr renewal admission v1\n"))}, {RenewalWriterPath, digest([]byte("sbxr renewal writer v1\n"))}} {
		if !a.removeClientPublication(p.path, 0600, p.hash) {
			return false
		}
	}
	if r.Resources.RecorderDirectoryCreated && !a.safelyAbsent(filepath.Dir(RenewalDropInPath)) && !a.removeEmptyDirectory(filepath.Dir(RenewalDropInPath)) {
		return false
	}
	return (a.safelyAbsent(HTTPSRetirementDirectory) || a.removeEmptyDirectory(HTTPSRetirementDirectory)) && a.servingCommand(ctx, "daemon-reload")
}
