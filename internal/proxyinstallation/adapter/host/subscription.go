package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

// SubscriptionPreflight contains read-only admission facts, not execution authority.
type SubscriptionPreflight struct {
	TCP80, TCP8443, Clock, PackageLocks, RenewalIdle, Dependencies, Firewall Observation
	SnapdInstalled, CertbotInstalled                                         bool
	DependencyIdentity, FirewallIdentity                                     string
	RenewalCorrection                                                        string
}

// SubscriptionEnableInput is the exact generation authorized by the Ownership
// Record before the Host Adapter creates any subscription resource.
type SubscriptionEnableInput struct {
	PublicIPv4 string
	Credential []byte
	Serving    ServingAuthority
	Renewal    RenewalAuthority
	Resources  SubscriptionResourceAuthority
	Report     func(string)
	Authorize  func(int, *ServingAuthority) bool
}

type SubscriptionEnableResult struct {
	Serving   ServingAuthority
	Renewal   RenewalAuthority
	Resources SubscriptionResourceAuthority
	Prepared  bool
}

type SubscriptionCleanupInput struct {
	Checkpoint       int
	LinkID           string
	CredentialSHA256 string
	RecorderID       string
	Serving          *ServingAuthority
	Renewal          *RenewalAuthority
	Resources        *SubscriptionResourceAuthority
}

type SubscriptionRotationInput struct {
	Source     ServingAuthority
	Target     ServingAuthority
	Renewal    RenewalAuthority
	Credential []byte
}

const SubscriptionFirewallUnitPath = "/etc/systemd/system/sbxr-subscription-firewall.service"
const SubscriptionServingCheckpoint = 8
const SubscriptionActivationCheckpoint = 23
const SubscriptionCandidateTokenPath = ServingStagingPath + "/credential"
const SubscriptionCandidateStatePath = ServingStagingPath + "/serving.json"

type SubscriptionResourceAuthority struct {
	PublicIPv4     string `json:"public_ipv4"`
	FirewallSHA256 string `json:"firewall_sha256"`
	SnapdCreated   bool   `json:"snapd_created"`
	CertbotCreated bool   `json:"certbot_created"`
}

func (a SubscriptionResourceAuthority) Valid() bool {
	ip := net.ParseIP(a.PublicIPv4)
	digest, err := hex.DecodeString(a.FirewallSHA256)
	return ip != nil && ip.To4() != nil && ip.String() == a.PublicIPv4 && err == nil && len(digest) == 32 && hex.EncodeToString(digest) == a.FirewallSHA256
}

func (a SubscriptionResourceAuthority) Resources() []string {
	snapd, certbot := "reused", "reused"
	if a.SnapdCreated {
		snapd = "created"
	}
	if a.CertbotCreated {
		certbot = "created"
	}
	return []string{
		SubscriptionFirewallUnitPath + " root:root 0644 one-link sha256:" + a.FirewallSHA256,
		"iptables filter INPUT " + a.PublicIPv4 + "/32 tcp/80 comment=sbxr-subscription exact-owned",
		"iptables filter INPUT " + a.PublicIPv4 + "/32 tcp/8443 comment=sbxr-subscription exact-owned",
		"snapd dependency " + snapd,
		"official Certbot snap dependency " + certbot,
	}
}

func SubscriptionResourcesForEnablement(publicIPv4 string, facts SubscriptionPreflight) SubscriptionResourceAuthority {
	return SubscriptionResourceAuthority{
		PublicIPv4: publicIPv4, FirewallSHA256: digest([]byte(subscriptionFirewallUnit(publicIPv4))),
		SnapdCreated: !facts.SnapdInstalled, CertbotCreated: !facts.CertbotInstalled,
	}
}

var certbotDirectoryLocks = []string{"/etc/letsencrypt/.certbot.lock", "/var/lib/letsencrypt/.certbot.lock", "/var/log/letsencrypt/.certbot.lock"}

func (adapter Adapter) AcquireSubscriptionReviewLock(name string) (*MutationLock, bool, error) {
	parentCheck := name
	if name == "/run/lock/sbxr.lock" {
		parentCheck = filepath.Dir(name)
	}
	if err := adapter.safeParents(parentCheck); err != nil {
		return nil, false, err
	}
	if name == "/run/lock/sbxr.lock" {
		// A root-owned sticky shared directory protects the existing root-owned lock.
		info, err := os.Lstat(adapter.path(parentCheck))
		if err != nil {
			return nil, false, err
		}
		stat, ok := infoSys(info)
		if !ok || !info.IsDir() || stat.Uid != adapter.ownerUID() || info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return nil, false, &parentSafetyError{path: parentCheck, mode: info.Mode()}
		}
	}
	return softwarelifecycle.AcquireExistingMutationLockAuthority(adapter.path(name), adapter.ownerUID())
}

func (adapter Adapter) PreflightSubscription(ctx context.Context, ipv4 string) SubscriptionPreflight {
	facts := SubscriptionPreflight{}
	if ctx.Err() != nil || net.ParseIP(ipv4).To4() == nil {
		return facts
	}
	command := adapter.subscriptionCommand
	if command == nil {
		command = commandOutput
	}
	bind := adapter.subscriptionBind
	if bind == nil {
		bind = subscriptionTCPAvailable
	}
	facts.TCP80 = observation(bind(ipv4, "80"), true)
	facts.TCP8443 = observation(bind(ipv4, "8443"), true)
	if adapter.clockSynchronized != nil {
		facts.Clock = observation(adapter.clockSynchronized(ctx), true)
	}
	if adapter.packageLocksAvailable != nil {
		facts.PackageLocks = observation(adapter.packageLocksAvailable(), true)
	}

	// Certbot uses these shared directory locks. Observation never creates them.
	facts.RenewalIdle = observation(true, true)
	for _, path := range certbotDirectoryLocks {
		if err := adapter.safeParents(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			facts.RenewalIdle = observation(false, false)
			facts.RenewalCorrection = "Restore safe, inspectable Certbot parent directories, then review again."
			var parent *parentSafetyError
			if errors.As(err, &parent) {
				if parent.err == nil {
					facts.RenewalIdle.Observed = true
					facts.RenewalCorrection = fmt.Sprintf("Unsafe Certbot parent %s (mode %04o). Require a root-owned directory with no group or other write permission; inspect and correct it before reviewing again.", parent.path, parent.mode.Perm())
				} else {
					facts.RenewalCorrection = "Cannot inspect Certbot parent " + parent.path + ". Restore safe read-only inspection, then review again."
				}
			}
			break
		}
		fact, correction := adapter.inspectCertbotLock(path)
		if !fact.Accepted {
			facts.RenewalIdle, facts.RenewalCorrection = fact, correction
			break
		}
	}
	_, code, observed := command(ctx, "pgrep", "--exact", "certbot")
	if facts.RenewalIdle.Accepted {
		facts.RenewalIdle = observation(code == 1, observed && (code == 0 || code == 1))
		if !facts.RenewalIdle.Observed {
			facts.RenewalCorrection = "Cannot inspect shared Certbot processes. Restore process inspection, then review again."
		} else if !facts.RenewalIdle.Accepted {
			facts.RenewalCorrection = "Wait for shared Certbot work to finish; do not terminate it."
		}
	}

	// Only a known iptables filter surface can support the reviewed exact rules.
	rules, code, observed := command(ctx, "iptables-save", "-t", "filter")
	var stableRules []string
	for _, line := range strings.Split(rules, "\n") {
		if !strings.HasPrefix(line, "#") {
			stableRules = append(stableRules, line)
		}
	}
	rules = strings.Join(stableRules, "\n")
	facts.Firewall = observation(code == 0 && strings.Contains(rules, "*filter\n") && strings.Contains(rules, ":INPUT ") && strings.Contains(rules, "\nCOMMIT") && !strings.Contains(rules, "sbxr-subscription"), observed && code == 0)
	facts.FirewallIdentity = fmt.Sprintf("%x", sha256.Sum256([]byte(rules)))

	return adapter.subscriptionDependencies(ctx, facts)
}

func (adapter Adapter) subscriptionDependencies(ctx context.Context, facts SubscriptionPreflight) SubscriptionPreflight {
	command := adapter.subscriptionCommand
	if command == nil {
		command = commandOutput
	}
	packages, code, observed := command(ctx, "dpkg-query", "--show", "--showformat=${Package} ${db:Status-Status} ${Version}\\n", "snapd", "certbot")
	if !observed || (code != 0 && code != 1) || code == 0 && strings.TrimSpace(packages) == "" {
		return facts
	}
	for _, line := range strings.Split(strings.TrimSpace(packages), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "snapd" && fields[0] != "certbot" {
			return facts
		}
		if fields[1] == "not-installed" || fields[1] == "config-files" {
			continue
		}
		if fields[1] != "installed" || fields[0] == "certbot" {
			return facts
		}
		facts.SnapdInstalled = true
	}
	identity := packages
	if facts.SnapdInstalled {
		// Listing all installed snaps distinguishes genuine absence from a failed lookup.
		snaps, code, observed := command(ctx, "snap", "list", "--unicode=always", "--color=never")
		if !observed || code != 0 {
			return facts
		}
		lines := strings.Split(strings.TrimSpace(snaps), "\n")
		if strings.TrimSpace(snaps) != "" && strings.Join(strings.Fields(lines[0]), " ") != "Name Version Rev Tracking Publisher Notes" {
			return facts
		}
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) != 6 {
				return facts
			}
			if fields[0] != "certbot" {
				continue
			}
			version := strings.Split(fields[1], ".")
			if len(version) != 3 {
				return facts
			}
			major, e1 := strconv.Atoi(version[0])
			minor, e2 := strconv.Atoi(version[1])
			_, e3 := strconv.Atoi(version[2])
			if e1 != nil || e2 != nil || e3 != nil || major < 5 || major == 5 && minor < 4 || fields[4] != "certbot-eff✓" || fields[5] != "classic" && fields[5] != "classic,held" {
				return facts
			}
			facts.CertbotInstalled = true
		}
		changes, code, observed := command(ctx, "snap", "changes")
		if !observed || code != 0 {
			return facts
		}
		changeLines := strings.Split(strings.TrimSpace(changes), "\n")
		if strings.TrimSpace(changes) != "" && strings.Join(strings.Fields(changeLines[0]), " ") != "ID Status Spawn Ready Summary" {
			return facts
		}
		for index, line := range changeLines {
			if index == 0 {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[1] != "Done" && fields[1] != "Error" && fields[1] != "Undone" {
				return facts
			}
		}
		identity += snaps
	} else {
		for _, path := range []string{"/snap/certbot", "/snap/bin/certbot", "/var/lib/snapd/snaps"} {
			if !adapter.safelyAbsent(path) {
				return facts
			}
		}
	}
	facts.DependencyIdentity = fmt.Sprintf("%x", sha256.Sum256([]byte(identity)))
	facts.Dependencies = observation(true, true)
	return facts
}

func (adapter Adapter) PrepareSubscription(ctx context.Context, input SubscriptionEnableInput) SubscriptionEnableResult {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(string(input.Credential))
	if err != nil || len(input.Credential) != 43 || len(decoded) != 32 || input.Serving.CertificateGeneration != 0 || input.Serving.LinkID == "" || input.Serving.CredentialSHA256 != digest(input.Credential) || !input.Renewal.Valid() || input.Renewal.PublicIPv4 != input.PublicIPv4 {
		return SubscriptionEnableResult{}
	}
	facts := adapter.PreflightSubscription(ctx, input.PublicIPv4)
	if !facts.TCP80.Accepted || !facts.TCP8443.Accepted || !facts.Clock.Accepted || !facts.PackageLocks.Accepted || !facts.RenewalIdle.Accepted || !facts.Dependencies.Accepted || !facts.Firewall.Accepted {
		return SubscriptionEnableResult{}
	}
	run := adapter.subscriptionCommand
	if run == nil {
		run = commandOutput
	}
	runOK := func(name string, arguments ...string) bool {
		_, code, observed := run(ctx, name, arguments...)
		return observed && code == 0
	}
	authorize := func(checkpoint int, serving *ServingAuthority) bool {
		return input.Authorize != nil && input.Authorize(checkpoint, serving)
	}
	resources := SubscriptionResourcesForEnablement(input.PublicIPv4, facts)
	if input.Resources != resources || !resources.Valid() {
		return SubscriptionEnableResult{}
	}
	unit := subscriptionFirewallUnit(input.PublicIPv4)
	if input.Report != nil {
		input.Report("Preparing subscription resources")
	}
	if !authorize(1, nil) {
		return SubscriptionEnableResult{Resources: resources}
	}
	if !facts.SnapdInstalled && !runOK("apt-get", "update") {
		return SubscriptionEnableResult{Resources: resources}
	}
	if !authorize(2, nil) || !facts.SnapdInstalled && !runOK("apt-get", "install", "-y", "snapd") {
		return SubscriptionEnableResult{Resources: resources}
	}
	if !authorize(3, nil) || !facts.CertbotInstalled && !runOK("snap", "install", "certbot", "--classic") {
		return SubscriptionEnableResult{Resources: resources}
	}
	if !adapter.officialRenewalRoute() {
		return SubscriptionEnableResult{Resources: resources}
	}
	if !authorize(4, nil) {
		return SubscriptionEnableResult{Resources: resources}
	}
	if !adapter.publishSubscriptionFile(SubscriptionFirewallUnitPath, []byte(unit), 0644) || !authorize(5, nil) || !runOK("systemctl", "daemon-reload") || !authorize(6, nil) || !runOK("systemctl", "enable", "--now", "sbxr-subscription-firewall.service") || !adapter.exactSubscriptionFirewall(input.PublicIPv4) {
		return SubscriptionEnableResult{Resources: resources}
	}
	if input.Report != nil {
		input.Report("Obtaining subscription certificate")
	}
	if !authorize(7, nil) {
		return SubscriptionEnableResult{Resources: resources}
	}
	if !runOK("/snap/bin/certbot", "certonly", "--non-interactive", "--agree-tos", "--register-unsafely-without-email", "--standalone", "--preferred-challenges", "http", "--no-directory-hooks", "--cert-name", "sbxr-subscription", "--profile", "shortlived", "--ip-address", input.PublicIPv4) {
		return SubscriptionEnableResult{Resources: resources}
	}
	generation, ok := adapter.renewalLineageTarget(input.Renewal)
	certificateGeneration, valid := renewalLineageGeneration(input.Renewal, generation)
	if !ok || !valid || !adapter.validRenewalCertificate(input.Renewal, certificateGeneration) {
		return SubscriptionEnableResult{Resources: resources}
	}
	serving := input.Serving
	serving.CertificateGeneration = certificateGeneration
	for index, name := range certificateNames {
		mode := os.FileMode(0644)
		if name == "privkey" {
			mode = 0600
		}
		body, err := adapter.protectedServingFile(servingArchive+"/"+name+strconv.Itoa(certificateGeneration)+".pem", mode, "")
		if err != nil {
			return SubscriptionEnableResult{Resources: resources}
		}
		serving.CertificateSHA256[index] = digest(body)
	}
	if !authorize(8, &serving) {
		return SubscriptionEnableResult{Serving: serving, Renewal: input.Renewal, Resources: resources}
	}
	if input.Report != nil {
		input.Report("Preparing subscription credential")
	}
	if !adapter.prepareServingStaging() || !authorize(9, &serving) {
		return SubscriptionEnableResult{Resources: resources}
	}
	credential := append(bytes.Clone(input.Credential), '\n')
	state := servingStateBytes(serving)
	if !adapter.publishSubscriptionFile(SubscriptionCandidateTokenPath, credential, 0600) || !authorize(10, &serving) || !adapter.publishSubscriptionFile(SubscriptionCandidateStatePath, state, 0600) {
		return SubscriptionEnableResult{Resources: resources}
	}
	if token, err := adapter.protectedServingFile(SubscriptionCandidateTokenPath, 0600, digest(credential)); err != nil || !bytes.Equal(token, credential) {
		return SubscriptionEnableResult{Resources: resources}
	}
	if candidate, err := adapter.protectedServingFile(SubscriptionCandidateStatePath, 0600, digest(state)); err != nil || !bytes.Equal(candidate, state) {
		return SubscriptionEnableResult{Resources: resources}
	}
	if !authorize(11, &serving) || !adapter.publishSubscriptionFile(ServingTokenPath, credential, 0600) || !authorize(12, &serving) || !adapter.publishSubscriptionFile(ServingStatePath, state, 0600) || !authorize(13, &serving) || !adapter.publishSubscriptionFile(ServingUnitPath, []byte(ServingUnit), 0644) || !authorize(14, &serving) || !adapter.removeFile(SubscriptionCandidateTokenPath).OK || !authorize(15, &serving) || !adapter.removeFile(SubscriptionCandidateStatePath).OK || !adapter.servingDirectory(ServingStagingPath, nil, false) {
		return SubscriptionEnableResult{Resources: resources}
	}
	if input.Report != nil {
		input.Report("Preparing subscription serving state")
	}
	evidence, err := json.Marshal(RenewalEvidence{Schema: 1, RecorderID: input.Renewal.RecorderID, EstablishedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return SubscriptionEnableResult{Resources: resources}
	}
	evidence = append(evidence, '\n')
	for index, file := range renewalManagedFiles {
		if !authorize(16+index, &serving) || !adapter.publishSubscriptionFile(file.path, []byte(file.body), file.mode) {
			return SubscriptionEnableResult{Resources: resources}
		}
	}
	if !authorize(21, &serving) || !adapter.publishSubscriptionFile(RenewalEvidencePath, evidence, 0600) || !authorize(22, &serving) || !runOK("systemctl", "daemon-reload") {
		return SubscriptionEnableResult{Resources: resources}
	}
	return SubscriptionEnableResult{Serving: serving, Renewal: input.Renewal, Resources: resources, Prepared: true}
}

func (adapter Adapter) publishSubscriptionFile(path string, body []byte, mode os.FileMode) bool {
	temporary := path + ".sbxr-next"
	if destination, destinationErr := os.Lstat(adapter.path(path)); destinationErr == nil {
		if staged, stagedErr := os.Lstat(adapter.path(temporary)); stagedErr == nil && os.SameFile(destination, staged) {
			if os.Remove(adapter.path(temporary)) != nil || adapter.syncOwnershipDirectory(adapter.path(filepath.Dir(path))) != nil {
				return false
			}
		}
	}
	current, err := adapter.protectedServingFile(path, mode, "")
	if err == nil {
		if !bytes.Equal(current, body) {
			return false
		}
		if staged, stagedErr := adapter.protectedServingFile(temporary, mode, ""); stagedErr == nil {
			return bytes.Equal(staged, body) && os.Remove(adapter.path(temporary)) == nil && adapter.syncOwnershipDirectory(adapter.path(filepath.Dir(path))) == nil
		} else if !errors.Is(stagedErr, os.ErrNotExist) {
			return false
		}
		return adapter.syncOwnershipDirectory(adapter.path(filepath.Dir(path))) == nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false
	}
	staged, stagedErr := adapter.protectedServingFile(temporary, mode, "")
	if errors.Is(stagedErr, os.ErrNotExist) {
		file, createErr := os.OpenFile(adapter.path(temporary), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
		if createErr != nil {
			return false
		}
		if err := file.Chmod(mode); err != nil {
			_ = file.Close()
			return false
		}
		written, writeErr := file.Write(body)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || written != len(body) || syncErr != nil || closeErr != nil || adapter.syncOwnershipDirectory(adapter.path(filepath.Dir(path))) != nil {
			return false
		}
		staged, stagedErr = adapter.protectedServingFile(temporary, mode, "")
	}
	if stagedErr != nil || !bytes.Equal(staged, body) || os.Link(adapter.path(temporary), adapter.path(path)) != nil || adapter.syncOwnershipDirectory(adapter.path(filepath.Dir(path))) != nil || os.Remove(adapter.path(temporary)) != nil || adapter.syncOwnershipDirectory(adapter.path(filepath.Dir(path))) != nil {
		return false
	}
	current, err = adapter.protectedServingFile(path, mode, "")
	return err == nil && bytes.Equal(current, body)
}

func (adapter Adapter) ActivatePreparedSubscription(ctx context.Context, serving ServingAuthority, renewal RenewalAuthority) bool {
	published, valid := adapter.publishedServingAuthority(renewal, serving)
	if !serving.Valid() || !renewal.Valid() || !valid || published != serving || !adapter.renewalFiles(renewal) || !adapter.exactSubscriptionFirewall(renewal.PublicIPv4) {
		return false
	}
	if loaded, observed := adapter.loadedServingAuthority(ctx, renewal, serving, serving); observed && loaded == serving {
		return true
	}
	run := adapter.subscriptionCommand
	if run == nil {
		run = commandOutput
	}
	return adapter.runtimeStart(ctx, ServingRole, func() bool {
		_, code, observed := run(ctx, "systemctl", "enable", "--now", "sbxr-subscription.service")
		return observed && code == 0
	})
}

func (adapter Adapter) PrepareSubscriptionRotation(input SubscriptionRotationInput) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(string(input.Credential))
	if err != nil || len(input.Credential) != 43 || len(decoded) != 32 || !input.Source.Valid() || !input.Target.Valid() || !input.Renewal.Valid() || input.Source.CertificateGeneration != input.Target.CertificateGeneration || input.Source.CertificateSHA256 != input.Target.CertificateSHA256 || input.Source.LinkID == input.Target.LinkID || input.Source.CredentialSHA256 == input.Target.CredentialSHA256 || input.Target.CredentialSHA256 != digest(input.Credential) {
		return false
	}
	if link, ok := adapter.ReadSubscriptionLink(input.Source, input.Renewal.PublicIPv4); !ok || len(link) == 0 || !adapter.prepareServingStaging() {
		return false
	}
	credential := append(bytes.Clone(input.Credential), '\n')
	return adapter.publishSubscriptionFile(SubscriptionCandidateTokenPath, credential, 0600) && adapter.publishSubscriptionFile(SubscriptionCandidateStatePath, servingStateBytes(input.Target), 0600)
}

func (adapter Adapter) StopSubscriptionRotation(ctx context.Context, input SubscriptionRotationInput) bool {
	credential, credentialErr := adapter.protectedServingFile(SubscriptionCandidateTokenPath, 0600, "")
	state, stateErr := adapter.protectedServingFile(SubscriptionCandidateStatePath, 0600, digest(servingStateBytes(input.Target)))
	if link, ok := adapter.ReadSubscriptionLink(input.Source, input.Renewal.PublicIPv4); !ok || len(link) == 0 || credentialErr != nil || len(credential) != 44 || credential[43] != '\n' || digest(credential[:43]) != input.Target.CredentialSHA256 || stateErr != nil || !bytes.Equal(state, servingStateBytes(input.Target)) || !adapter.servingCommand(ctx, "stop", "sbxr-subscription.service") {
		return false
	}
	return adapter.ServingQuiescent()
}

func (adapter Adapter) PublishSubscriptionRotation(input SubscriptionRotationInput) bool {
	if len(input.Credential) == 0 {
		candidate, err := adapter.protectedServingFile(SubscriptionCandidateTokenPath, 0600, "")
		if err != nil {
			candidate, err = adapter.protectedServingFile(ServingTokenPath, 0600, "")
		}
		if err != nil || len(candidate) != 44 || candidate[43] != '\n' || digest(candidate[:43]) != input.Target.CredentialSHA256 {
			return false
		}
		input.Credential = candidate[:43]
	}
	return adapter.replaceSubscriptionFile(ServingTokenPath, SubscriptionCandidateTokenPath, append(bytes.Clone(input.Credential), '\n'), 0600, input.Source.CredentialSHA256) &&
		adapter.replaceSubscriptionFile(ServingStatePath, SubscriptionCandidateStatePath, servingStateBytes(input.Target), 0600, digest(servingStateBytes(input.Source)))
}

func (adapter Adapter) RestoreSubscriptionRotation(ctx context.Context, input SubscriptionRotationInput) bool {
	if link, ok := adapter.ReadSubscriptionLink(input.Source, input.Renewal.PublicIPv4); !ok || len(link) == 0 {
		return false
	}
	if !adapter.removeSubscriptionCandidates(&input.Target, input.Target.CredentialSHA256) {
		return false
	}
	return adapter.ActivatePreparedSubscription(ctx, input.Source, input.Renewal) && adapter.InspectPreparedSubscription(ctx, input.Source, input.Renewal).Accepted
}

func (adapter Adapter) RemoveSubscriptionRotation(ctx context.Context, input SubscriptionRotationInput, exclusion *ServingExclusion) bool {
	if !input.Source.Valid() || !input.Target.Valid() || !adapter.validServingExclusion(exclusion) || !adapter.servingCommand(ctx, "disable", "--now", "sbxr-subscription.service") || !adapter.ServingQuiescent() || !adapter.removeSubscriptionCandidates(&input.Target, input.Target.CredentialSHA256) {
		return false
	}
	token, tokenErr := adapter.protectedServingFile(ServingTokenPath, 0600, "")
	if tokenErr == nil && (len(token) != 44 || token[43] != '\n' || digest(token[:43]) != input.Source.CredentialSHA256 && digest(token[:43]) != input.Target.CredentialSHA256) || tokenErr != nil && !errors.Is(tokenErr, os.ErrNotExist) {
		return false
	}
	state, stateErr := adapter.protectedServingFile(ServingStatePath, 0600, "")
	if stateErr == nil && !bytes.Equal(state, servingStateBytes(input.Source)) && !bytes.Equal(state, servingStateBytes(input.Target)) || stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return false
	}
	return adapter.removeFile(ServingTokenPath).OK && adapter.removeFile(ServingStatePath).OK && adapter.ServingQuiescent()
}

func (adapter Adapter) RemoveSubscriptionRepair(ctx context.Context, source, target ServingAuthority, exclusion *ServingExclusion) bool {
	stagingAccepted := adapter.servingDirectory(ServingStagingPath, nil, false) || adapter.safelyAbsent(ServingStagingPath)
	if !source.Valid() || !target.Valid() || source.LinkID != target.LinkID || source.CredentialSHA256 != target.CredentialSHA256 || !adapter.validServingExclusion(exclusion) || !stagingAccepted {
		return false
	}
	unit, unitErr := adapter.protectedServingFile(ServingUnitPath, 0644, "")
	wants, wantsErr := os.Readlink(adapter.path(ServingUnitWantsPath))
	archivePaths, archiveOK := adapter.removableServingArchive(target)
	unitPresent := unitErr == nil
	unitAccepted := unitPresent && knownServingUnit(unit) || errors.Is(unitErr, os.ErrNotExist) && adapter.safelyAbsent(ServingUnitPath)
	wantsAccepted := wantsErr == nil && wants == "../sbxr-subscription.service" || errors.Is(wantsErr, os.ErrNotExist) && adapter.safelyAbsent(ServingUnitWantsPath)
	if !unitAccepted || !wantsAccepted || !archiveOK {
		return false
	}
	token, tokenErr := adapter.protectedServingFile(ServingTokenPath, 0600, "")
	if tokenErr == nil && (len(token) != 44 || token[43] != '\n' || digest(token[:43]) != source.CredentialSHA256) || tokenErr != nil && !errors.Is(tokenErr, os.ErrNotExist) {
		return false
	}
	state, stateErr := adapter.protectedServingFile(ServingStatePath, 0600, "")
	if stateErr == nil && !bytes.Equal(state, servingStateBytes(source)) && !bytes.Equal(state, servingStateBytes(target)) || stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return false
	}
	for index, name := range certificateNames {
		path := servingLive + "/" + name + ".pem"
		link, err := os.Readlink(adapter.path(path))
		if errors.Is(err, os.ErrNotExist) && adapter.safelyAbsent(path) {
			continue
		}
		generation, valid := servingArchiveIdentity(filepath.Base(link))
		selected := source
		if generation == target.CertificateGeneration {
			selected = target
		}
		mode := os.FileMode(0644)
		if name == "privkey" {
			mode = 0600
		}
		if err != nil || !valid || generation != source.CertificateGeneration && generation != target.CertificateGeneration || link != "../../archive/sbxr-subscription/"+filepath.Base(link) {
			return false
		}
		if _, err := adapter.protectedServingFile(servingArchive+"/"+name+strconv.Itoa(generation)+".pem", mode, selected.CertificateSHA256[index]); err != nil {
			return false
		}
	}
	for index, file := range exclusion.files {
		info, err := file.Stat()
		current, currentErr := os.Lstat(adapter.path(certbotDirectoryLocks[index]))
		if err != nil || currentErr != nil || !os.SameFile(info, current) {
			return false
		}
	}
	if unitPresent && !adapter.servingCommand(ctx, "disable", "--now", "sbxr-subscription.service") || !adapter.ServingQuiescent() {
		return false
	}
	paths := make([]string, 0, len(certificateNames)+len(archivePaths)+7)
	for _, name := range certificateNames {
		paths = append(paths, servingLive+"/"+name+".pem")
	}
	paths = append(paths, archivePaths...)
	paths = append(paths, servingLive, servingArchive, ServingTokenPath, ServingStatePath, ServingStagingPath, ServingUnitWantsPath, ServingUnitPath)
	for _, path := range paths {
		if err := os.Remove(adapter.path(path)); errors.Is(err, os.ErrNotExist) {
			if !adapter.syncAbsentPath(path) {
				return false
			}
		} else if err != nil || adapter.syncOwnershipDirectory(adapter.path(filepath.Dir(path))) != nil {
			return false
		}
	}
	return adapter.servingCommand(ctx, "daemon-reload") && adapter.ServingQuiescent()
}

func (adapter Adapter) SubscriptionRotationStagingEmpty() bool {
	return adapter.servingDirectory(ServingStagingPath, nil, false) && adapter.syncOwnershipDirectory(adapter.path(ServingStagingPath)) == nil
}

func (adapter Adapter) replaceSubscriptionFile(path, candidate string, target []byte, mode os.FileMode, sourceDigest string) bool {
	current, err := adapter.protectedServingFile(path, mode, "")
	if err == nil && bytes.Equal(current, target) {
		return adapter.syncOwnershipDirectory(adapter.path(filepath.Dir(path))) == nil && adapter.removeFile(candidate).OK && adapter.syncOwnershipDirectory(adapter.path(filepath.Dir(candidate))) == nil
	}
	sourceMatches := digest(current) == sourceDigest
	if path == ServingTokenPath {
		sourceMatches = digest(bytes.TrimSuffix(current, []byte{'\n'})) == sourceDigest
	}
	if err != nil || !sourceMatches {
		return false
	}
	staged, err := adapter.protectedServingFile(candidate, mode, digest(target))
	if err != nil || !bytes.Equal(staged, target) || os.Rename(adapter.path(candidate), adapter.path(path)) != nil || adapter.syncOwnershipDirectory(adapter.path(filepath.Dir(path))) != nil {
		return false
	}
	published, err := adapter.protectedServingFile(path, mode, digest(target))
	return err == nil && bytes.Equal(published, target)
}

func subscriptionFirewallUnit(ipv4 string) string {
	rule80 := `-d ` + ipv4 + `/32 -p tcp --dport 80 -m comment --comment sbxr-subscription -j ACCEPT`
	rule8443 := `-d ` + ipv4 + `/32 -p tcp --dport 8443 -m comment --comment sbxr-subscription -j ACCEPT`
	command := `/usr/sbin/iptables -w`
	return `[Unit]
Description=SBXR Subscription Firewall
Before=sbxr-subscription.service snap.certbot.renew.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -ec '` + command + ` -C INPUT ` + rule80 + ` || ` + command + ` -I INPUT 1 ` + rule80 + `'
ExecStart=/bin/sh -ec '` + command + ` -C INPUT ` + rule8443 + ` || ` + command + ` -I INPUT 1 ` + rule8443 + `'
ExecStop=/bin/sh -ec 'while ` + command + ` -C INPUT ` + rule8443 + `; do ` + command + ` -D INPUT ` + rule8443 + `; done'
ExecStop=/bin/sh -ec 'while ` + command + ` -C INPUT ` + rule80 + `; do ` + command + ` -D INPUT ` + rule80 + `; done'

[Install]
WantedBy=multi-user.target
`
}

func servingStateBytes(serving ServingAuthority) []byte {
	body, _ := json.Marshal(struct {
		Schema  int              `json:"schema"`
		Serving ServingAuthority `json:"serving"`
	}{Schema: 1, Serving: serving})
	return append(body, '\n')
}

func (adapter Adapter) prepareServingStaging() bool {
	if err := os.Mkdir(adapter.path(ServingStagingPath), 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return false
	}
	return adapter.servingDirectory(ServingStagingPath, nil, false) && adapter.syncOwnershipDirectory(adapter.path(filepath.Dir(ServingStagingPath))) == nil
}

func (adapter Adapter) exactSubscriptionFirewall(ipv4 string) bool {
	run := adapter.subscriptionCommand
	if run == nil {
		run = commandOutput
	}
	body, code, observed := run(context.Background(), "iptables-save", "-t", "filter")
	if !observed || code != 0 {
		return false
	}
	wants := []string{
		"-A INPUT -d " + ipv4 + "/32 -p tcp -m tcp --dport 80 -m comment --comment sbxr-subscription -j ACCEPT",
		"-A INPUT -d " + ipv4 + "/32 -p tcp -m tcp --dport 8443 -m comment --comment sbxr-subscription -j ACCEPT",
	}
	for _, want := range wants {
		if strings.Count(body, want) != 1 {
			return false
		}
	}
	return strings.Count(body, "--comment sbxr-subscription") == 2
}

func (adapter Adapter) InspectPreparedSubscription(ctx context.Context, serving ServingAuthority, renewal RenewalAuthority) Observation {
	if !serving.Valid() || !renewal.Valid() || !adapter.InspectServingFiles(serving, false).Accepted || !adapter.renewalFiles(renewal) || !adapter.exactSubscriptionFirewall(renewal.PublicIPv4) {
		return observation(false, true)
	}
	inspection := adapter.InspectCertificateActivation(ctx, renewal, serving)
	return observation(inspection.Observed && inspection.Accepted && inspection.Published == serving && inspection.Loaded == serving, inspection.Observed)
}

func (adapter Adapter) ReadSubscriptionLink(serving ServingAuthority, publicIPv4 string) ([]byte, bool) {
	if !serving.Valid() || net.ParseIP(publicIPv4).To4() == nil {
		return nil, false
	}
	token, err := adapter.protectedServingFile(ServingTokenPath, 0600, "")
	if err != nil || len(token) != 44 || token[43] != '\n' || digest(token[:43]) != serving.CredentialSHA256 {
		return nil, false
	}
	state := servingStateBytes(serving)
	actual, err := adapter.protectedServingFile(ServingStatePath, 0600, digest(state))
	if err != nil || !bytes.Equal(actual, state) {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(string(token[:43]))
	if err != nil || len(decoded) != 32 {
		return nil, false
	}
	return []byte("https://" + publicIPv4 + ":8443/s/" + string(token[:43])), true
}

func (adapter Adapter) CleanupPreparedSubscription(ctx context.Context, input SubscriptionCleanupInput) bool {
	if input.Resources == nil || !input.Resources.Valid() {
		return false
	}
	lineagePresent := !adapter.safelyAbsent("/etc/letsencrypt/renewal/sbxr-subscription.conf") || !adapter.safelyAbsent(servingLive) || !adapter.safelyAbsent(servingArchive)
	if input.Serving == nil && lineagePresent && input.Checkpoint >= 7 {
		serving, ok := adapter.recoverEnablementServing(input)
		if !ok {
			return false
		}
		input.Serving = &serving
	}
	credential := []byte(nil)
	state := []byte(nil)
	if input.Serving != nil {
		state = servingStateBytes(*input.Serving)
	}
	if token, err := adapter.protectedServingFile(ServingTokenPath, 0600, ""); err == nil {
		credential = token
	} else if token, err = adapter.protectedServingFile(SubscriptionCandidateTokenPath, 0600, ""); err == nil {
		credential = token
	} else if token, err = adapter.protectedServingFile(SubscriptionCandidateTokenPath+".sbxr-next", 0600, ""); err == nil && len(token) == 44 && token[43] == '\n' && digest(token[:43]) == input.CredentialSHA256 {
		credential = token
	}
	for _, file := range []struct {
		path string
		body []byte
		mode os.FileMode
	}{{SubscriptionCandidateTokenPath, credential, 0600}, {SubscriptionCandidateStatePath, state, 0600}, {ServingTokenPath, credential, 0600}, {ServingStatePath, state, 0600}, {ServingUnitPath, []byte(ServingUnit), 0644}} {
		if len(file.body) > 0 && !adapter.removeSubscriptionPublication(file.path, file.body, file.mode) {
			return false
		}
	}
	for _, file := range renewalManagedFiles {
		if !adapter.removeSubscriptionPublication(file.path, []byte(file.body), file.mode) {
			return false
		}
	}
	evidenceTemporary := RenewalEvidencePath + ".sbxr-next"
	if evidence, err := adapter.protectedServingFile(evidenceTemporary, 0600, ""); err == nil {
		var value RenewalEvidence
		if json.Unmarshal(bytes.TrimSpace(evidence), &value) != nil || value.Schema != 1 || value.RecorderID != input.RecorderID || !adapter.removeSubscriptionPublication(RenewalEvidencePath, evidence, 0600) {
			return false
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false
	}
	var servingExclusion *ServingExclusion
	if input.Serving != nil || lineagePresent {
		var ok bool
		servingExclusion, ok = adapter.AcquireServingExclusion()
		if !ok {
			return false
		}
		defer servingExclusion.Release()
	}
	if !adapter.removeSubscriptionCandidates(input.Serving, input.CredentialSHA256) {
		return false
	}
	if input.Serving != nil {
		if !adapter.RemoveServingRuntime(ctx, *input.Serving, servingExclusion) {
			return false
		}
	} else {
		for _, file := range []struct {
			path, body string
			mode       os.FileMode
		}{{ServingUnitPath, ServingUnit, 0644}} {
			body, err := adapter.protectedServingFile(file.path, file.mode, "")
			if err == nil && string(body) != file.body || err != nil && !errors.Is(err, os.ErrNotExist) {
				return false
			}
			if !adapter.removeFile(file.path).OK {
				return false
			}
		}
		token, err := adapter.protectedServingFile(ServingTokenPath, 0600, "")
		if err == nil && (len(token) != 44 || token[43] != '\n' || digest(token[:43]) != input.CredentialSHA256) || err != nil && !errors.Is(err, os.ErrNotExist) {
			return false
		}
		if !adapter.removeFile(SubscriptionCandidateTokenPath).OK || !adapter.removeFile(SubscriptionCandidateStatePath).OK || !adapter.removeEmptyDirectory(ServingStagingPath) && !adapter.safelyAbsent(ServingStagingPath) || !adapter.removeFile(ServingTokenPath).OK || !adapter.removeFile(ServingStatePath).OK {
			return false
		}
	}
	if input.Renewal != nil {
		exclusion, ok := adapter.AcquireRenewalExclusion(*input.Renewal)
		if !ok {
			return false
		}
		defer exclusion.Release()
		removed := adapter.RemoveRenewalIntegration(ctx, *input.Renewal, exclusion)
		if !removed {
			return false
		}
	} else {
		for _, file := range renewalManagedFiles {
			body, err := adapter.protectedServingFile(file.path, file.mode, "")
			if err == nil && string(body) != file.body || err != nil && !errors.Is(err, os.ErrNotExist) {
				return false
			}
			if !adapter.removeFile(file.path).OK {
				return false
			}
		}
		for _, path := range []string{RenewalEvidencePath, RenewalEvidenceNextPath} {
			if !adapter.removeFile(path).OK {
				return false
			}
		}
	}
	if !adapter.RemoveSubscriptionResources(ctx, *input.Resources, input.Serving) {
		return false
	}
	return adapter.InspectSubscriptionAbsence(ctx).Observed && adapter.InspectSubscriptionAbsence(ctx).Accepted
}

func (adapter Adapter) removeSubscriptionPublication(path string, body []byte, mode os.FileMode) bool {
	temporary := path + ".sbxr-next"
	if destination, destinationErr := os.Lstat(adapter.path(path)); destinationErr == nil {
		if staged, stagedErr := os.Lstat(adapter.path(temporary)); stagedErr == nil && os.SameFile(destination, staged) {
			return os.Remove(adapter.path(temporary)) == nil && adapter.syncOwnershipDirectory(adapter.path(filepath.Dir(path))) == nil
		}
	}
	staged, err := adapter.protectedServingFile(temporary, mode, "")
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil || !bytes.Equal(staged, body) {
		return false
	}
	return os.Remove(adapter.path(temporary)) == nil && adapter.syncOwnershipDirectory(adapter.path(filepath.Dir(path))) == nil
}

func (adapter Adapter) recoverEnablementServing(input SubscriptionCleanupInput) (ServingAuthority, bool) {
	if input.Resources == nil {
		return ServingAuthority{}, false
	}
	renewal := RenewalAuthority{RecorderID: input.RecorderID, Lineage: "sbxr-subscription", PublicIPv4: input.Resources.PublicIPv4, Invocation: OfficialRenewalInvocation}
	generation, ok := adapter.renewalLineageTarget(renewal)
	certificateGeneration, valid := renewalLineageGeneration(renewal, generation)
	serving := ServingAuthority{LinkID: input.LinkID, CredentialSHA256: input.CredentialSHA256, CertificateGeneration: certificateGeneration}
	if !ok || !valid || !adapter.validRenewalCertificate(renewal, certificateGeneration) {
		return ServingAuthority{}, false
	}
	for index, name := range certificateNames {
		mode := os.FileMode(0644)
		if name == "privkey" {
			mode = 0600
		}
		body, err := adapter.protectedServingFile(servingArchive+"/"+name+strconv.Itoa(certificateGeneration)+".pem", mode, "")
		if err != nil {
			return ServingAuthority{}, false
		}
		serving.CertificateSHA256[index] = digest(body)
	}
	return serving, serving.Valid()
}

func (adapter Adapter) removeSubscriptionCandidates(serving *ServingAuthority, credentialSHA256 string) bool {
	token, tokenErr := adapter.protectedServingFile(SubscriptionCandidateTokenPath, 0600, "")
	if tokenErr == nil && (len(token) != 44 || token[43] != '\n' || digest(token[:43]) != credentialSHA256) || tokenErr != nil && !errors.Is(tokenErr, os.ErrNotExist) {
		return false
	}
	state, stateErr := adapter.protectedServingFile(SubscriptionCandidateStatePath, 0600, "")
	if stateErr == nil && (serving == nil || !bytes.Equal(state, servingStateBytes(*serving))) || stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return false
	}
	return adapter.removeFile(SubscriptionCandidateTokenPath).OK && adapter.removeFile(SubscriptionCandidateStatePath).OK
}

func (adapter Adapter) removeOwnedLineage(authority *ServingAuthority) bool {
	conf := "/etc/letsencrypt/renewal/sbxr-subscription.conf"
	if authority == nil {
		return adapter.removePartialOwnedLineage(conf)
	}
	if !adapter.safelyAbsent(conf) {
		body, _, ok := adapter.safeRenewalConfig(conf)
		if !ok || !strings.Contains(string(body), "archive_dir = /etc/letsencrypt/archive/sbxr-subscription") || !strings.Contains(string(body), "cert = /etc/letsencrypt/live/sbxr-subscription/cert.pem") {
			return false
		}
	}
	archivePaths, ok := adapter.removableServingArchive(*authority)
	if !ok {
		return false
	}
	for _, name := range certificateNames {
		path := servingLive + "/" + name + ".pem"
		if info, err := os.Lstat(adapter.path(path)); err == nil {
			target, linkErr := os.Readlink(adapter.path(path))
			generation, valid := servingArchiveIdentity(filepath.Base(target))
			if info.Mode()&os.ModeSymlink == 0 || linkErr != nil || !valid || generation < 1 || filepath.Base(target) != name+strconv.Itoa(generation)+".pem" || target != "../../archive/sbxr-subscription/"+filepath.Base(target) {
				return false
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return false
		}
		if !adapter.removeFile(path).OK {
			return false
		}
	}
	for index, name := range certificateNames {
		path := servingArchive + "/" + name + strconv.Itoa(authority.CertificateGeneration) + ".pem"
		mode := os.FileMode(0644)
		if name == "privkey" {
			mode = 0600
		}
		body, err := adapter.protectedServingFile(path, mode, authority.CertificateSHA256[index])
		if err != nil && !errors.Is(err, os.ErrNotExist) || err == nil && digest(body) != authority.CertificateSHA256[index] {
			return false
		}
	}
	for _, path := range archivePaths {
		if !adapter.removeFile(path).OK {
			return false
		}
	}
	for _, path := range []string{servingLive, servingArchive} {
		if !adapter.removeEmptyDirectory(path) && !adapter.safelyAbsent(path) {
			return false
		}
	}
	if !adapter.removeFile(conf).OK {
		return false
	}
	return true
}

func (adapter Adapter) removePartialOwnedLineage(conf string) bool {
	if _, err := os.Lstat(adapter.path(conf)); errors.Is(err, os.ErrNotExist) {
		if !adapter.syncAbsentPath(conf) {
			return false
		}
	} else if err != nil {
		return false
	} else {
		body, _, ok := adapter.safeRenewalConfig(conf)
		if !ok || !strings.Contains(string(body), "archive_dir = /etc/letsencrypt/archive/sbxr-subscription") || !strings.Contains(string(body), "cert = /etc/letsencrypt/live/sbxr-subscription/cert.pem") {
			return false
		}
	}
	for _, directory := range []string{servingLive, servingArchive} {
		entries, err := os.ReadDir(adapter.path(directory))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false
		}
		for _, entry := range entries {
			path := directory + "/" + entry.Name()
			if directory == servingArchive {
				_, valid := servingArchiveIdentity(entry.Name())
				mode := os.FileMode(0644)
				if strings.HasPrefix(entry.Name(), "privkey") {
					mode = 0600
				}
				if !valid {
					return false
				}
				if _, err := adapter.protectedServingFile(path, mode, ""); err != nil {
					return false
				}
			} else {
				if !slices.Contains(certificateNames, strings.TrimSuffix(entry.Name(), ".pem")) {
					return false
				}
				target, err := os.Readlink(adapter.path(path))
				if err != nil || !strings.HasPrefix(target, "../../archive/sbxr-subscription/") {
					return false
				}
				if _, valid := servingArchiveIdentity(filepath.Base(target)); !valid {
					return false
				}
			}
			if !adapter.removeFile(path).OK {
				return false
			}
		}
		if !adapter.removeEmptyDirectory(directory) && !adapter.safelyAbsent(directory) {
			return false
		}
	}
	if _, err := os.Lstat(adapter.path(conf)); errors.Is(err, os.ErrNotExist) {
		return adapter.syncAbsentPath(conf)
	}
	return adapter.removeFile(conf).OK
}

func (adapter Adapter) RemoveSubscriptionResources(ctx context.Context, authority SubscriptionResourceAuthority, serving *ServingAuthority) bool {
	if !authority.Valid() {
		return false
	}
	unit, err := adapter.protectedServingFile(SubscriptionFirewallUnitPath, 0644, authority.FirewallSHA256)
	if err != nil && !errors.Is(err, os.ErrNotExist) || err == nil && string(unit) != subscriptionFirewallUnit(authority.PublicIPv4) {
		return false
	}
	if !adapter.removeSubscriptionPublication(SubscriptionFirewallUnitPath, []byte(subscriptionFirewallUnit(authority.PublicIPv4)), 0644) {
		return false
	}
	run := adapter.subscriptionCommand
	if run == nil {
		run = commandOutput
	}
	if err == nil {
		_, code, observed := run(ctx, "systemctl", "disable", "--now", "sbxr-subscription-firewall.service")
		if !observed || code != 0 || !adapter.removeFile(SubscriptionFirewallUnitPath).OK {
			return false
		}
	}
	if !adapter.removeOwnedLineage(serving) {
		return false
	}
	_, code, observed := run(ctx, "systemctl", "daemon-reload")
	if !observed || code != 0 {
		return false
	}
	rules, code, observed := run(ctx, "iptables-save", "-t", "filter")
	return observed && code == 0 && !strings.Contains(rules, "--comment sbxr-subscription")
}

func subscriptionTCPAvailable(ipv4, port string) bool {
	listener, err := net.Listen("tcp4", net.JoinHostPort(ipv4, port))
	if err != nil {
		return false
	}
	return listener.Close() == nil
}

func (adapter Adapter) certbotLockAvailable(name string) bool {
	fact, _ := adapter.inspectCertbotLock(name)
	return fact.Observed && fact.Accepted
}

func (adapter Adapter) inspectCertbotLock(name string) (Observation, string) {
	path := adapter.path(name)
	unknown := "Cannot inspect shared Certbot lock " + name + ". Restore safe read-only lock inspection, then review again."
	unsafe := "Unsafe shared Certbot lock " + name + ". Require a root-owned, one-link regular file with no group or other write permission; inspect and correct it before reviewing again."
	current, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return observation(true, true), ""
	}
	stat, ok := infoSys(current)
	if err != nil {
		return observation(false, false), unknown
	}
	if !ok || !current.Mode().IsRegular() || current.Mode().Perm()&0o022 != 0 || stat.Uid != adapter.ownerUID() || stat.Nlink != 1 {
		return observation(false, true), unsafe
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return observation(false, false), unknown
	}
	defer file.Close()
	info, err := file.Stat()
	stat, ok = infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || stat.Uid != adapter.ownerUID() || stat.Nlink != 1 {
		return observation(false, false), unknown
	}
	// F_GETLK observes Certbot's POSIX lockf lock without creating or writing a file.
	lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: io.SeekStart}
	if syscall.FcntlFlock(file.Fd(), syscall.F_GETLK, &lock) != nil {
		return observation(false, false), unknown
	}
	current, err = os.Lstat(path)
	if err != nil || !os.SameFile(info, current) {
		return observation(false, false), unknown
	}
	if lock.Type != syscall.F_UNLCK {
		return observation(false, true), "Shared Certbot lock " + name + " is busy. Wait for shared Certbot work to finish; do not terminate it."
	}
	return observation(true, true), ""
}
