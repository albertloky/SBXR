package host

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const HTTPSRetirementDirectory = "/var/lib/sbxr/subscription-https-retired"
const httpsRenewalConfiguration = "/etc/letsencrypt/renewal/sbxr-subscription.conf"
const httpsRetirementCapability = "SBXR-SUBSCRIPTION-HTTPS-RETIREMENT-V1"

func HTTPSRetirementCapability() string { return httpsRetirementCapability }

// DiscardHTTPMigrationPublication preserves current authority while removing
// only its exact planned publication. The caller holds whole-host authority;
// the ordinary forward writer can then recheck facts and publish it again.
func (a Adapter) DiscardHTTPMigrationPublication(current, next []byte) bool {
	const currentPath = "/var/lib/sbxr/proxy-ownership.json"
	const nextPath = "/var/lib/sbxr/.proxy-ownership.json.next"
	body, err := a.ReadOwnership(currentPath)
	if err != nil || !bytes.Equal(body, current) || a.safeParents(nextPath) != nil {
		return false
	}
	if a.safelyAbsent(nextPath) {
		return true
	}
	info, err := os.Lstat(a.path(nextPath))
	stat, owned := infoSys(info)
	if err != nil || !owned || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != a.ownerUID() || stat.Nlink != 1 {
		return false
	}
	var staged []byte
	if info.Size() != 0 {
		staged, err = a.ReadOwnership(nextPath)
		if err != nil {
			return false
		}
	}
	if !bytes.HasPrefix(next, staged) {
		return false
	}
	return os.Remove(a.path(nextPath)) == nil && a.syncOwnershipDirectory(a.path(filepath.Dir(nextPath))) == nil
}

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

func ownedHTTPSRenewalConfiguration(body []byte) bool {
	want := map[string]string{
		"archive_dir": servingArchive,
		"cert":        servingLive + "/cert.pem",
		"chain":       servingLive + "/chain.pem",
		"fullchain":   servingLive + "/fullchain.pem",
		"privkey":     servingLive + "/privkey.pem",
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		key, value, found := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if expected, owned := want[key]; found && owned {
			if seen[key] || value != expected {
				return false
			}
			seen[key] = true
		}
	}
	return len(seen) == len(want)
}

// SnapshotHTTPSRetirement runs under renewal and shared Certbot exclusion.
// Everything that can subsequently be retired is bound before any effects.
func (a Adapter) SnapshotHTTPSRetirement(serving ServingAuthority, renewal RenewalAuthority, resources SubscriptionResourceAuthority, exclusion *RenewalExclusion) (HTTPSRetirementAuthority, bool) {
	r := HTTPSRetirementAuthority{Serving: serving, Renewal: renewal, Resources: resources}
	configuration, mode, safe := a.safeRenewalConfig(httpsRenewalConfiguration)
	evidence, evidenceErr := a.protectedServingFile(RenewalEvidencePath, 0600, "")
	r.ConfigurationMode, r.ConfigurationSHA256, r.EvidenceSHA256 = uint32(mode), digest(configuration), digest(evidence)
	if exclusion == nil || exclusion.authority != renewal || !safe || !ownedHTTPSRenewalConfiguration(configuration) || evidenceErr != nil || !r.Valid() || !a.inspectRetiredCertificates(r, false) || !a.safelyAbsent(HTTPSRetirementDirectory) || !a.InspectServingFiles(serving, false).Accepted || !a.renewalFiles(renewal) || !a.renewalRoute() || !a.renewalHooksSafe() || !a.exactSubscriptionFirewall(resources.PublicIPv4) {
		return HTTPSRetirementAuthority{}, false
	}
	unit, err := a.protectedServingFile(SubscriptionFirewallUnitPath, 0644, resources.FirewallSHA256)
	return r, err == nil && string(unit) == subscriptionFirewallUnit(resources.PublicIPv4)
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

func (a Adapter) retirementDirectory(r HTTPSRetirementAuthority, pending, removing bool) bool {
	var allowed []string
	for _, p := range r.publications() {
		allowed = append(allowed, filepath.Base(p.backup))
		if pending {
			allowed = append(allowed, filepath.Base(p.backup)+".sbxr-next")
		}
	}
	return a.servingDirectory(HTTPSRetirementDirectory, allowed, pending || removing)
}

func (a Adapter) InspectHTTPSRetirement(r HTTPSRetirementAuthority, removing bool) bool {
	if !r.Valid() || !a.retirementDirectory(r, false, removing) || !a.inspectRetiredCertificates(r, removing) || !a.safelyAbsent(RenewalEvidenceNextPath) {
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

// replaceHTTPSMigrationFile is a bounded expected-current publication. A crash
// before rename leaves the old file intact; after rename its target is accepted
// on retry. No foreign type, owner, link count or byte content is adopted.
func (a Adapter) replaceHTTPSMigrationFile(path string, source, target []byte, mode os.FileMode) bool {
	current, err := a.protectedServingFile(path, mode, "")
	if err != nil || !bytes.Equal(current, source) && !bytes.Equal(current, target) {
		return false
	}
	candidate := path + ".sbxr-next"
	if bytes.Equal(current, target) {
		return a.removeClientPublication(candidate, mode, digest(target)) && a.syncOwnershipDirectory(a.path(filepath.Dir(path))) == nil
	}
	staged, stagedErr := a.protectedServingFile(candidate, mode, "")
	if errors.Is(stagedErr, os.ErrNotExist) {
		f, err := os.OpenFile(a.path(candidate), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
		if err != nil {
			return false
		}
		modeErr := f.Chmod(mode)
		n, writeErr := f.Write(target)
		syncErr, closeErr := f.Sync(), f.Close()
		if modeErr != nil || writeErr != nil || n != len(target) || syncErr != nil || closeErr != nil {
			return false
		}
		staged, stagedErr = a.protectedServingFile(candidate, mode, "")
	}
	if stagedErr != nil || !bytes.Equal(staged, target) {
		return false
	}
	return a.replaceSubscriptionFile(path, candidate, target, mode, digest(source))
}

// An interrupted Write can leave only a prefix in journal-owned staging.
// Preserve completed publications; regenerate only an exact target prefix in
// a protected one-link file. Foreign bytes, links, modes and parents refuse.
func (a Adapter) resetIncompleteHTTPSMigrationPublication(path string, target []byte, mode os.FileMode) bool {
	if a.safelyAbsent(path) {
		return true
	}
	if a.safeParents(path) != nil {
		return false
	}
	info, err := os.Lstat(a.path(path))
	stat, owned := infoSys(info)
	if err != nil || !owned || !info.Mode().IsRegular() || info.Mode().Perm() != mode || stat.Uid != a.ownerUID() || stat.Nlink != 1 {
		// The existing publication primitive also permits its exact completed
		// destination/staging hard-link pair, and removes it durably on retry.
		_, err := a.clientPublicationFile(strings.TrimSuffix(path, ".sbxr-next"), mode, digest(target))
		return err == nil
	}
	var staged []byte
	if info.Size() > 0 {
		staged, err = a.protectedServingFile(path, mode, "")
		if err != nil {
			return false
		}
	}
	if !bytes.HasPrefix(target, staged) {
		return false
	}
	if bytes.Equal(target, staged) {
		return true
	}
	return os.Remove(a.path(path)) == nil && a.syncOwnershipDirectory(a.path(filepath.Dir(path))) == nil
}

func (a Adapter) MigrateHTTPSRetirement(ctx context.Context, r HTTPSRetirementAuthority, target ServingAuthority, exclusion *RenewalExclusion) bool {
	if ctx.Err() != nil || exclusion == nil || exclusion.authority != r.Renewal || !r.Valid() || !target.Valid() || !target.HTTP || target.LinkID != r.Serving.LinkID || target.CredentialSHA256 != r.Serving.CredentialSHA256 || !a.retirementDirectory(r, true, false) || !a.inspectRetiredCertificates(r, false) {
		return false
	}
	for _, p := range r.publications() {
		body, err := a.protectedServingFile(p.source, p.mode, p.hash)
		if errors.Is(err, os.ErrNotExist) {
			body, err = a.clientPublicationFile(p.backup, p.mode, p.hash)
		}
		if err != nil || !a.resetIncompleteHTTPSMigrationPublication(p.backup+".sbxr-next", body, p.mode) {
			return false
		}
	}
	if !a.resetIncompleteHTTPSMigrationPublication(ServingStatePath+".sbxr-next", servingStateBytes(target), 0600) || !a.resetIncompleteHTTPSMigrationPublication(SubscriptionFirewallUnitPath+".sbxr-next", []byte(httpSubscriptionFirewallUnit(r.Renewal.PublicIPv4)), 0644) || !a.httpsMigrationFilesSafe(r, target) {
		return false
	}
	// Inspect every input and publication before stopping anything.
	for _, p := range r.publications() {
		source, sourceErr := a.protectedServingFile(p.source, p.mode, p.hash)
		backup, backupErr := a.clientPublicationFile(p.backup, p.mode, p.hash)
		if sourceErr != nil && !errors.Is(sourceErr, os.ErrNotExist) || backupErr != nil && !errors.Is(backupErr, os.ErrNotExist) || sourceErr != nil && backupErr != nil || sourceErr == nil && backupErr == nil && !bytes.Equal(source, backup) {
			return false
		}
	}
	if !a.servingCommand(ctx, "stop", "sbxr-subscription.service") || !a.ServingQuiescent() {
		return false
	}
	if a.safelyAbsent(HTTPSRetirementDirectory) {
		if a.safeParents(HTTPSRetirementDirectory) != nil || os.Mkdir(a.path(HTTPSRetirementDirectory), 0700) != nil || a.syncOwnershipDirectory(a.path(filepath.Dir(HTTPSRetirementDirectory))) != nil {
			return false
		}
	}
	for _, p := range r.publications() {
		body, err := a.protectedServingFile(p.source, p.mode, p.hash)
		if errors.Is(err, os.ErrNotExist) {
			body, err = a.protectedServingFile(p.backup, p.mode, p.hash)
		}
		if err != nil || !a.publishSubscriptionFile(p.backup, body, p.mode) || !a.removeClientPublication(p.source, p.mode, p.hash) {
			return false
		}
	}
	if !a.servingCommand(ctx, "stop", "sbxr-subscription-firewall.service") || !a.replaceHTTPSMigrationFile(SubscriptionFirewallUnitPath, []byte(subscriptionFirewallUnit(r.Renewal.PublicIPv4)), []byte(httpSubscriptionFirewallUnit(r.Renewal.PublicIPv4)), 0644) || !a.replaceHTTPSMigrationFile(ServingStatePath, servingStateBytes(r.Serving), servingStateBytes(target), 0600) || !a.servingCommand(ctx, "daemon-reload") || !a.officialRenewalRoute() || !a.servingCommand(ctx, "enable", "--now", "sbxr-subscription-firewall.service") || !a.exactHTTPSubscriptionFirewall(r.Renewal.PublicIPv4) || !a.InspectHTTPSRetirement(r, false) {
		return false
	}
	return a.activateHTTPSubscription(ctx, target, r.Renewal.PublicIPv4)
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

func (a Adapter) HTTPMigrationExecutable() bool {
	body, err := a.readInstalledUpdateExecutable()
	return err == nil && bytes.Contains(body, []byte(httpsRetirementCapability)) && bytes.Contains(body, []byte("SBXR-SUBSCRIPTION-HTTP-V1"))
}

func (a Adapter) httpsMigrationFilesSafe(r HTTPSRetirementAuthority, target ServingAuthority) bool {
	state, err := a.protectedServingFile(ServingStatePath, 0600, "")
	selected := r.Serving
	if bytes.Equal(state, servingStateBytes(target)) {
		selected = target
	}
	if err != nil || !a.inspectServingFilesWithState(target, selected, false, false, false, true).Accepted {
		return false
	}
	for _, p := range []struct {
		path           string
		source, target []byte
		mode           os.FileMode
	}{{ServingStatePath, servingStateBytes(r.Serving), servingStateBytes(target), 0600}, {SubscriptionFirewallUnitPath, []byte(subscriptionFirewallUnit(r.Renewal.PublicIPv4)), []byte(httpSubscriptionFirewallUnit(r.Renewal.PublicIPv4)), 0644}} {
		body, err := a.protectedServingFile(p.path, p.mode, "")
		if err != nil || !bytes.Equal(body, p.source) && !bytes.Equal(body, p.target) {
			return false
		}
		if staged, err := a.protectedServingFile(p.path+".sbxr-next", p.mode, digest(p.target)); err != nil && !errors.Is(err, os.ErrNotExist) || err == nil && !bytes.Equal(staged, p.target) {
			return false
		}
	}
	run := a.subscriptionCommand
	if run == nil {
		run = commandOutput
	}
	for property, want := range map[string]string{"FragmentPath": SubscriptionFirewallUnitPath, "DropInPaths": ""} {
		value, code, observed := run(context.Background(), "systemctl", "show", "--property="+property, "--value", "sbxr-subscription-firewall.service")
		if !observed || code != 0 || strings.TrimSpace(value) != want {
			return false
		}
	}
	rules, code, observed := run(context.Background(), "iptables-save", "-t", "filter")
	if !observed || code != 0 {
		return false
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(rules, "\n") {
		if !strings.Contains(line, "--comment sbxr-subscription") {
			continue
		}
		valid := false
		for _, port := range []string{"80", "8443"} {
			want := "-A INPUT -d " + r.Renewal.PublicIPv4 + "/32 -p tcp -m tcp --dport " + port + " -m comment --comment sbxr-subscription -j ACCEPT"
			valid = valid || line == want && !seen[port]
			if line == want {
				seen[port] = true
			}
		}
		if !valid {
			return false
		}
	}
	return true
}
