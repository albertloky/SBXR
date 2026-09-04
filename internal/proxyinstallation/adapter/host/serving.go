package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
	"github.com/albertloky/SBXR/internal/proxyinstallation/subscriptionserving"
)

const ServingRole = "--subscription-serving"
const ServingUnitPath = "/etc/systemd/system/sbxr-subscription.service"
const ServingUnitWantsPath = "/etc/systemd/system/multi-user.target.wants/sbxr-subscription.service"
const ServingTokenPath = "/var/lib/sbxr/subscription-token"
const ServingStatePath = "/var/lib/sbxr/subscription-serving.json"
const ServingStagingPath = "/var/lib/sbxr/subscription-staging"
const servingArchive = "/etc/letsencrypt/archive/sbxr-subscription"
const servingLive = "/etc/letsencrypt/live/sbxr-subscription"

// Optional documentation belongs to the already-owned Certbot lineage; it does
// not expand serialized authority or permit arbitrary directory contents.
const certbotReadmeSHA256 = "7e519cf3c13ff96c0a8e35e6f25fd43cc3c396f7b5c4393bd26ab072dd25c1fa"
const servingCgroup = "/sys/fs/cgroup/system.slice/sbxr-subscription.service"

// No arguments, environment values or separately writable serving file select
// authority. This fixed unit is part of the schema-2 resource contract.
const ServingUnit = `[Unit]
Description=SBXR Subscription Serving
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sbxr --subscription-serving
User=root
Group=root
Restart=no
KillMode=control-group
TimeoutStopSec=10s
SendSIGKILL=yes
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
InaccessiblePaths=/var/lib/sbxr/subscription-token /var/lib/sbxr/subscription-staging -/var/lib/sbxr/client-identity-target.json -/var/lib/sbxr/client-identity-target.json.sbxr-next /proc /run/dbus
TemporaryFileSystem=/run/systemd:ro,mode=000
StandardInput=null
StandardOutput=null
StandardError=null
UMask=0077

[Install]
WantedBy=multi-user.target
`

var previousServingUnit = strings.Replace(strings.Replace(ServingUnit, "TemporaryFileSystem=/run/systemd:ro,mode=000\n", "", 1), " /run/dbus\n", " /run/systemd /run/dbus\n", 1)
var legacyServingUnit = strings.ReplaceAll(strings.ReplaceAll(previousServingUnit, " AF_UNIX", ""), " -/var/lib/sbxr/client-identity-target.json -/var/lib/sbxr/client-identity-target.json.sbxr-next", "")

func knownServingUnit(body []byte) bool {
	return string(body) == ServingUnit || string(body) == previousServingUnit || string(body) == legacyServingUnit
}

// ServingAuthority is an Ownership Record component, never an independent
// authority file. This bounded runtime-only contract has no renewal writer,
// firewall rule, pending credential operation or additional certificate history.
type ServingAuthority struct {
	LinkID                string    `json:"link_id"`
	CredentialSHA256      string    `json:"credential_sha256"`
	CertificateGeneration int       `json:"certificate_generation"`
	CertificateSHA256     [4]string `json:"certificate_sha256"`
}

// CertificateActivationInspection compares the certificate generation
// published by Certbot with the generation accepted by the Ownership Record
// and the generation actually loaded by Subscription Serving.
type CertificateActivationInspection struct {
	Published ServingAuthority
	Loaded    ServingAuthority
	Observed  bool
	Accepted  bool
}

func (ServingAuthority) String() string   { return "Serving authority (redacted)" }
func (ServingAuthority) GoString() string { return "Serving authority (redacted)" }

func (a ServingAuthority) Valid() bool {
	validHex := func(s string, n int) bool {
		b, e := hex.DecodeString(s)
		return e == nil && len(b) == n && hex.EncodeToString(b) == s && s != strings.Repeat("0", 2*n)
	}
	if !validHex(a.LinkID, 16) || !validHex(a.CredentialSHA256, 32) || a.CertificateGeneration < 1 || a.CertificateGeneration > 1000000 {
		return false
	}
	for _, digest := range a.CertificateSHA256 {
		if !validHex(digest, 32) {
			return false
		}
	}
	return true
}

var certificateNames = []string{"cert", "chain", "fullchain", "privkey"}

func (a ServingAuthority) Resources() []string {
	resources := []string{ServingUnitPath + " root:root 0644 one-link fixed-serving-v1", ServingUnitWantsPath + " root-owned symlink ../sbxr-subscription.service", ServingTokenPath + " root:root 0600 one-link credential", ServingStatePath + " root:root 0600 immutable serving state", ServingStagingPath + " root:root 0700 empty-directory", servingArchive + " root:root 0700 directory", servingLive + " root:root 0700 directory"}
	for i, name := range certificateNames {
		archive := servingArchive + "/" + name + strconv.Itoa(a.CertificateGeneration) + ".pem"
		mode := "0644"
		if name == "privkey" {
			mode = "0600"
		}
		resources = append(resources, archive+" root:root "+mode+" one-link "+a.CertificateSHA256[i], servingLive+"/"+name+".pem root:root symlink ../../archive/sbxr-subscription/"+filepath.Base(archive))
	}
	return resources
}

// protectedServingFile returns bytes only after bounded descriptor identity,
// safe-parent, mode, link-count, ownership and expected-content checks.
func (a Adapter) protectedServingFile(path string, mode os.FileMode, expected string) ([]byte, error) {
	return a.protectedServingFileWithLinks(path, mode, expected, 1)
}

func (a Adapter) protectedServingFileWithLinks(path string, mode os.FileMode, expected string, links uint64) ([]byte, error) {
	refused := errors.New("serving material refused")
	if err := a.safeParents(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(a.path(path), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != mode || stat.Uid != a.ownerUID() || uint64(stat.Nlink) != links || info.Size() <= 0 || info.Size() > 64<<10 {
		return nil, refused
	}
	body, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	current, e := os.Lstat(a.path(path))
	if err != nil || e != nil || len(body) > 64<<10 || !os.SameFile(info, current) || expected != "" && digest(body) != expected {
		return nil, refused
	}
	return body, nil
}

func (a Adapter) servingDirectory(path string, allowed []string, missing bool) bool {
	if err := a.safeParents(path); err != nil {
		return missing && errors.Is(err, os.ErrNotExist)
	}
	info, err := os.Lstat(a.path(path))
	if errors.Is(err, os.ErrNotExist) {
		return missing
	}
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.IsDir() || stat.Uid != a.ownerUID() || info.Mode().Perm() != 0700 {
		return false
	}
	entries, err := os.ReadDir(a.path(path))
	if err != nil {
		return false
	}
	archiveGenerations := map[int]int{}
	allowedGeneration := 0
	for _, name := range allowed {
		if generation, ok := servingArchiveIdentity(name); ok {
			allowedGeneration = generation
		}
	}
	for _, entry := range entries {
		if path == servingLive && entry.Name() == "README" && a.safeCertbotReadme() {
			continue
		}
		generation, archiveName := servingArchiveIdentity(entry.Name())
		if !slices.Contains(allowed, entry.Name()) && !(path == servingArchive && archiveName) {
			return false
		}
		if path == servingArchive && archiveName {
			archiveGenerations[generation]++
		}
	}
	for generation, count := range archiveGenerations {
		if count != len(certificateNames) && !(missing && (generation == allowedGeneration || archiveGenerations[allowedGeneration] == 0)) {
			return false
		}
	}
	return true
}

func (a Adapter) safeCertbotReadme() bool {
	path := servingLive + "/README"
	_, err := a.protectedServingFile(path, 0644, certbotReadmeSHA256)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return true
	}
	// The standard file can inherit a restrictive caller umask.
	_, err = a.protectedServingFile(path, 0600, certbotReadmeSHA256)
	return err == nil
}

func servingArchiveIdentity(name string) (int, bool) {
	for _, prefix := range certificateNames {
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".pem") {
			generation, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".pem"))
			return generation, err == nil && generation > 0 && generation <= 1000000 && name == prefix+strconv.Itoa(generation)+".pem"
		}
	}
	return 0, false
}

func (a Adapter) removableServingArchive(authority ServingAuthority) ([]string, bool) {
	entries, err := os.ReadDir(a.path(servingArchive))
	if errors.Is(err, os.ErrNotExist) {
		return nil, true
	}
	if err != nil {
		return nil, false
	}
	counts := map[int]int{}
	current, history := make([]string, 0, len(certificateNames)), make([]string, 0, len(entries))
	for _, entry := range entries {
		generation, valid := servingArchiveIdentity(entry.Name())
		if !valid || generation > authority.CertificateGeneration {
			return nil, false
		}
		mode := os.FileMode(0644)
		if strings.HasPrefix(entry.Name(), "privkey") {
			mode = 0600
		}
		path := servingArchive + "/" + entry.Name()
		if _, err := a.protectedServingFile(path, mode, ""); err != nil {
			return nil, false
		}
		counts[generation]++
		if generation == authority.CertificateGeneration {
			current = append(current, path)
		} else {
			history = append(history, path)
		}
	}
	for _, count := range counts {
		if count > len(certificateNames) {
			return nil, false
		}
	}
	return append(current, history...), true
}

func (a Adapter) InspectServingFiles(authority ServingAuthority, removing bool) Observation {
	return a.inspectServingFiles(authority, removing, false)
}

func (a Adapter) inspectServingFiles(authority ServingAuthority, removing, sandbox bool, stored ...ServingAuthority) Observation {
	if !authority.Valid() {
		return observation(false, true)
	}
	// Unknown staging, renewal, hooks and overrides belong to later complete
	// lifecycle contracts. Never adopt or delete them as this runtime footprint.
	for _, path := range []string{ServingUnitPath + ".d",
		"/run/systemd/system/sbxr-subscription.service", "/run/systemd/system/sbxr-subscription.service.d", "/usr/lib/systemd/system/sbxr-subscription.service", "/usr/lib/systemd/system/sbxr-subscription.service.d",
		"/etc/systemd/system/service.d", "/usr/lib/systemd/system/service.d"} {
		if sandbox && strings.HasPrefix(path, "/run/systemd/") {
			continue
		} // The entire host control directory must be inaccessible below.
		if !a.safelyAbsent(path) {
			return Observation{}
		}
	}
	if !a.servingDirectory("/var/lib/sbxr", []string{"update.json", ".update.json.next", ".installed.json.prior", ".installed.json.candidate", "installed.json", "proxy-ownership.json", ".proxy-ownership.json.next", "client-identity-target.json", "client-identity-target.json.sbxr-next", "subscription-token", "subscription-serving.json", "subscription-staging", "renewal-attempts.json", ".renewal-attempts.json.next", "renewal-admission.lock", "renewal-writer.lock"}, removing) {
		return Observation{}
	}
	if !sandbox && !a.servingDirectory(ServingStagingPath, nil, removing) {
		return Observation{}
	}
	archive, live := []string{}, []string{}
	for _, name := range certificateNames {
		archive = append(archive, name+strconv.Itoa(authority.CertificateGeneration)+".pem")
		live = append(live, name+".pem")
	}
	if !a.servingDirectory(servingArchive, archive, removing) || !a.servingDirectory(servingLive, live, removing) {
		return Observation{}
	}
	for i, name := range certificateNames {
		mode := os.FileMode(0644)
		if name == "privkey" {
			mode = 0600
		}
		_, err := a.protectedServingFile(servingArchive+"/"+archive[i], mode, authority.CertificateSHA256[i])
		if err != nil && !(removing && errors.Is(err, os.ErrNotExist)) {
			return Observation{}
		}
		path := servingLive + "/" + live[i]
		info, err := os.Lstat(a.path(path))
		if removing && errors.Is(err, os.ErrNotExist) {
			continue
		}
		stat, ok := infoSys(info)
		target, e := os.Readlink(a.path(path))
		if err != nil || !ok || stat.Uid != a.ownerUID() || info.Mode()&os.ModeSymlink == 0 || e != nil || target != "../../archive/sbxr-subscription/"+archive[i] {
			return Observation{}
		}
	}
	unit, err := a.protectedServingFile(ServingUnitPath, 0644, "")
	if err != nil && !(removing && errors.Is(err, os.ErrNotExist)) || err == nil && !knownServingUnit(unit) {
		return Observation{}
	}
	wantsInfo, wantsErr := os.Lstat(a.path(ServingUnitWantsPath))
	wantsTarget, targetErr := os.Readlink(a.path(ServingUnitWantsPath))
	wantsStat, wantsOwned := infoSys(wantsInfo)
	if removing && errors.Is(wantsErr, os.ErrNotExist) {
		// Safe partial removal.
	} else if wantsErr != nil || !wantsOwned || wantsStat.Uid != a.ownerUID() || wantsStat.Nlink != 1 || wantsInfo.Mode()&os.ModeSymlink == 0 || targetErr != nil || wantsTarget != "../sbxr-subscription.service" && wantsTarget != ServingUnitPath {
		return Observation{}
	}
	if !sandbox {
		token, err := a.protectedServingFile(ServingTokenPath, 0600, "")
		tokenPresent := err == nil
		if err != nil && !(removing && errors.Is(err, os.ErrNotExist)) || err == nil && (len(token) != 44 || token[43] != '\n' || digest(token[:43]) != authority.CredentialSHA256) {
			return Observation{}
		}
		stateAuthority := authority
		if len(stored) == 1 {
			stateAuthority = stored[0]
		}
		state, err := a.protectedServingFile(ServingStatePath, 0600, digest(servingStateBytes(stateAuthority)))
		if err != nil && !(removing && errors.Is(err, os.ErrNotExist)) || err == nil && !bytes.Equal(state, servingStateBytes(stateAuthority)) {
			return Observation{}
		}
		if tokenPresent {
			decoded, err := base64.RawURLEncoding.Strict().DecodeString(string(token[:43]))
			if err != nil || len(decoded) != 32 {
				return Observation{}
			}
		}
	}
	return observation(true, true)
}

func (a Adapter) LoadServingCertificate(authority ServingAuthority) (subscriptionserving.Certificate, bool) {
	if !authority.Valid() {
		return subscriptionserving.Certificate{}, false
	}
	generation := strconv.Itoa(authority.CertificateGeneration)
	chain, e1 := a.protectedServingFile(servingArchive+"/fullchain"+generation+".pem", 0644, authority.CertificateSHA256[2])
	key, e2 := a.protectedServingFile(servingArchive+"/privkey"+generation+".pem", 0600, authority.CertificateSHA256[3])
	leaf, e3 := a.protectedServingFile(servingArchive+"/cert"+generation+".pem", 0644, authority.CertificateSHA256[0])
	issuers, e4 := a.protectedServingFile(servingArchive+"/chain"+generation+".pem", 0644, authority.CertificateSHA256[1])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !bytes.Equal(chain, append(leaf, issuers...)) {
		return subscriptionserving.Certificate{}, false
	}
	return subscriptionserving.Certificate{Chain: chain, Key: key, ChainSHA256: sha256.Sum256(chain), KeySHA256: sha256.Sum256(key), Lineage: "sbxr-subscription", Generation: authority.CertificateGeneration}, true
}

func (a Adapter) ServingGeneration(authority ServingAuthority) subscriptionserving.Generation {
	var sum [32]byte
	decoded, _ := hex.DecodeString(authority.CredentialSHA256)
	copy(sum[:], decoded)
	return subscriptionserving.Generation{LinkID: authority.LinkID, CredentialSHA256: sum}
}

func (a Adapter) publishedCertificateAuthority(renewal RenewalAuthority, accepted ServingAuthority) (ServingAuthority, bool) {
	if !renewal.Valid() || !accepted.Valid() || renewal.Lineage != "sbxr-subscription" {
		return ServingAuthority{}, false
	}
	target := accepted
	generation := 0
	for index, name := range certificateNames {
		path := servingLive + "/" + name + ".pem"
		info, err := os.Lstat(a.path(path))
		stat, ok := infoSys(info)
		link, linkErr := os.Readlink(a.path(path))
		prefix := "../../archive/" + renewal.Lineage + "/" + name
		candidate, parseErr := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(link, prefix), ".pem"))
		valid := parseErr == nil && candidate > 0 && candidate <= 1000000 && link == prefix+strconv.Itoa(candidate)+".pem"
		if err != nil || !ok || stat.Uid != a.ownerUID() || info.Mode()&os.ModeSymlink == 0 || linkErr != nil || !valid || generation != 0 && generation != candidate {
			return ServingAuthority{}, false
		}
		generation = candidate
		mode := os.FileMode(0644)
		if name == "privkey" {
			mode = 0600
		}
		body, err := a.protectedServingFile(servingArchive+"/"+name+strconv.Itoa(generation)+".pem", mode, "")
		if err != nil {
			return ServingAuthority{}, false
		}
		target.CertificateSHA256[index] = digest(body)
	}
	target.CertificateGeneration = generation
	if !target.Valid() || !a.validRenewalCertificate(renewal, generation) {
		return ServingAuthority{}, false
	}
	return target, true
}

func (a Adapter) publishedServingAuthority(renewal RenewalAuthority, accepted ServingAuthority) (ServingAuthority, bool) {
	target, valid := a.publishedCertificateAuthority(renewal, accepted)
	if !valid || !a.servingDirectory(ServingStagingPath, nil, false) {
		return ServingAuthority{}, false
	}
	unit, unitErr := a.protectedServingFile(ServingUnitPath, 0644, "")
	token, tokenErr := a.protectedServingFile(ServingTokenPath, 0600, "")
	if unitErr != nil || string(unit) != ServingUnit || tokenErr != nil || len(token) != 44 || token[43] != '\n' || digest(token[:43]) != target.CredentialSHA256 {
		return ServingAuthority{}, false
	}
	return target, true
}

func (a Adapter) loadedServingAuthority(ctx context.Context, renewal RenewalAuthority, accepted, published ServingAuthority) (ServingAuthority, bool) {
	if a.servingLoaded != nil {
		return a.servingLoaded(ctx, renewal, accepted, published)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	run := a.subscriptionCommand
	if run == nil {
		run = commandOutput
	}
	output, code, observed := run(ctx, "systemctl", "show", "--property=ActiveState", "--value", "sbxr-subscription.service")
	if !observed || code != 0 {
		return ServingAuthority{}, false
	}
	if strings.TrimSpace(output) != "active" {
		return ServingAuthority{}, true
	}
	pidOutput, pidCode, pidObserved := run(ctx, "systemctl", "show", "--property=MainPID", "--value", "sbxr-subscription.service")
	pid, pidErr := strconv.Atoi(strings.TrimSpace(pidOutput))
	cgroup, cgroupErr := os.ReadFile(a.path(servingCgroup + "/cgroup.procs"))
	listener, listenerCode, listenerObserved := run(ctx, "ss", "-H", "-ltnp", "sport", "=", ":8443")
	lines := strings.Split(strings.TrimSpace(listener), "\n")
	fields := strings.Fields(listener)
	if !pidObserved || pidCode != 0 || pidErr != nil || pid < 1 || cgroupErr != nil || len(cgroup) > 4096 || strings.TrimSpace(string(cgroup)) != strconv.Itoa(pid) || !listenerObserved || listenerCode != 0 || len(lines) != 1 || len(fields) < 5 || fields[3] != net.JoinHostPort(renewal.PublicIPv4, "8443") || !strings.Contains(listener, "pid="+strconv.Itoa(pid)+",") {
		return ServingAuthority{}, false
	}
	token, err := a.protectedServingFile(ServingTokenPath, 0600, "")
	if err != nil || len(token) != 44 || token[43] != '\n' || digest(token[:43]) != published.CredentialSHA256 {
		return ServingAuthority{}, false
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: renewal.PublicIPv4}}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort(renewal.PublicIPv4, "8443")+"/s/"+string(token[:43]), nil)
	if err != nil {
		return ServingAuthority{}, false
	}
	response, err := client.Do(request)
	if err != nil {
		return ServingAuthority{}, false
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	closeErr := response.Body.Close()
	state := response.TLS
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/plain; charset=utf-8" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || len(body) < 1 || len(body) > 4096 || body[len(body)-1] != '\n' || bytes.Count(body, []byte{'\n'}) != 1 || state == nil || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 || !state.VerifiedChains[0][0].Equal(state.PeerCertificates[0]) {
		return ServingAuthority{}, false
	}
	// A valid certificate and envelope do not prove the current Client Identity.
	// Compare the actual response against the protected canonical configuration.
	configuration, err := a.protectedServingFile("/etc/sing-box/config.json", 0640, "")
	facts, factsErr := singboxadapter.New().CurrentConnectionFacts(configuration, renewal.PublicIPv4)
	expected, artifactCode := subscriptionserving.Artifact(facts)
	if err != nil || factsErr != nil || artifactCode != subscriptionserving.Ready || !bytes.Equal(body, expected) {
		return ServingAuthority{}, false
	}
	for _, candidate := range []ServingAuthority{published, accepted} {
		body, err := a.protectedServingFile(servingArchive+"/cert"+strconv.Itoa(candidate.CertificateGeneration)+".pem", 0644, candidate.CertificateSHA256[0])
		block, _ := pemDecodeCertificate(body)
		if err == nil && block != nil && bytes.Equal(block.Raw, state.PeerCertificates[0].Raw) {
			return candidate, true
		}
	}
	return ServingAuthority{}, true
}

func (a Adapter) waitLoadedServingAuthority(ctx context.Context, renewal RenewalAuthority, serving ServingAuthority) bool {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		loaded, observed := a.loadedServingAuthority(ctx, renewal, serving, serving)
		if observed && loaded == serving {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

func pemDecodeCertificate(body []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("certificate refused")
	}
	return x509.ParseCertificate(block.Bytes)
}

// InspectCertificateActivation is read-only. It binds all four published
// certificate files to one generation before reporting a forward target.
func (a Adapter) InspectCertificateActivation(ctx context.Context, renewal RenewalAuthority, accepted ServingAuthority) CertificateActivationInspection {
	if !a.ServingPublicIPv4(ctx, renewal.PublicIPv4) {
		return CertificateActivationInspection{Observed: true}
	}
	published, valid := a.publishedServingAuthority(renewal, accepted)
	if !valid {
		loaded, observed := a.loadedServingAuthority(ctx, renewal, accepted, accepted)
		return CertificateActivationInspection{Loaded: loaded, Observed: observed}
	}
	loaded, observed := a.loadedServingAuthority(ctx, renewal, accepted, published)
	return CertificateActivationInspection{Published: published, Loaded: loaded, Observed: observed, Accepted: true}
}

func (a Adapter) ActivateServing(ctx context.Context, renewal RenewalAuthority, target ServingAuthority) bool {
	published, valid := a.publishedServingAuthority(renewal, target)
	if !valid || published != target || !a.runtimeStart(ctx, ServingRole, func() bool { return a.servingCommand(ctx, "restart", "sbxr-subscription.service") }) || !a.waitLoadedServingAuthority(ctx, renewal, target) {
		return false
	}
	// The caller performs the full published/loaded reinspection under retained
	// whole-host authority before it commits the accepted generation.
	return true
}

// ValidateServingDispatch is read-only. The fixed cgroup, inaccessible host
// control sockets/proc/credentials, and zero capabilities are independent of
// arguments and environment. Nothing here creates missing authority.
func (a Adapter) ValidateServingDispatch(authority ServingAuthority, renewal *RenewalAuthority) bool {
	materialValid := a.inspectServingFiles(authority, false, true).Accepted
	if renewal != nil {
		published, valid := a.publishedCertificateAuthority(*renewal, authority)
		unit, unitErr := a.protectedServingFile(ServingUnitPath, 0644, "")
		materialValid = valid && published == authority && unitErr == nil && string(unit) == ServingUnit
	}
	if a.root != "/" || os.Geteuid() != 0 || !servingCapabilitiesRestricted() || !materialValid {
		return false
	}
	for _, path := range []string{ServingTokenPath, ServingStagingPath, "/proc", "/run/systemd", "/run/dbus"} {
		f, err := os.Open(path)
		if err == nil {
			f.Close()
			return false
		}
		if !errors.Is(err, os.ErrPermission) {
			return false
		}
	}
	procs, err := os.ReadFile(servingCgroup + "/cgroup.procs")
	return err == nil && len(procs) < 4096 && strings.TrimSpace(string(procs)) == strconv.Itoa(os.Getpid())
}

func (a Adapter) ServingPublicIPv4(ctx context.Context, expected string) bool {
	return a.publicIPv4 != nil && a.publicIPv4(ctx) == expected
}

func (a Adapter) WatchServingPublicIPv4(ctx context.Context, expected string) <-chan bool {
	result := make(chan bool, 1)
	go func() {
		defer close(result)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !a.ServingPublicIPv4(ctx, expected) {
					result <- false
					return
				}
			}
		}
	}()
	return result
}

func (a Adapter) BindServingListener(ip string) (net.Listener, error) {
	return net.Listen("tcp4", net.JoinHostPort(ip, "8443"))
}

func (a Adapter) ReadServingConfiguration(spec SetupSpec, expected string) ([]byte, error) {
	// The fixed root-only service can read root-owned 0640 configuration without
	// spawning getent or retaining raw process output inside its sandbox.
	groups, err := a.protectedServingFile("/etc/group", 0644, "")
	if err != nil {
		return nil, errors.New("configuration group refused")
	}
	for _, line := range strings.Split(string(groups), "\n") {
		if strings.HasPrefix(line, spec.Group+":") {
			gid, ok := groupID(line)
			if ok {
				return a.readConfigurationFile(spec.ConfigurationPath, expected, gid)
			}
			break
		}
	}
	return nil, errors.New("configuration group refused")
}

func (a Adapter) servingCommand(ctx context.Context, args ...string) bool {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	run := a.subscriptionCommand
	if run == nil {
		run = commandOutput
	}
	_, code, observed := run(ctx, "systemctl", args...)
	return observed && code == 0
}

func (a Adapter) ServingQuiescent() bool {
	// Cgroup-v2 population includes descendants. Listener absence alone does
	// not prove that old accepted work has ended.
	body, err := os.ReadFile(a.path(servingCgroup + "/cgroup.events"))
	if err == nil {
		if len(body) > 4096 || !slices.Contains(strings.Split(string(body), "\n"), "populated 0") {
			return false
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false
	}
	l, err := net.Listen("tcp4", "0.0.0.0:8443")
	if err != nil {
		return false
	}
	return l.Close() == nil
}

type ServingExclusion struct {
	root    string
	files   []*os.File
	created []*os.File
}

func (e *ServingExclusion) Release() {
	if e != nil {
		for _, file := range e.files {
			if slices.Contains(e.created, file) {
				// Acquisition may have lost a race to a different process.
				lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: io.SeekStart}
				locked := syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &lock) == nil
				opened, err := file.Stat()
				current, currentErr := os.Lstat(file.Name())
				// Unlink our empty inode while still holding its POSIX lock.
				// A contender must recheck the inode after acquiring its lock.
				if locked && err == nil && currentErr == nil && os.SameFile(opened, current) && opened.Size() == 0 {
					_ = os.Remove(file.Name())
				}
			}
			file.Close()
		}
		e.files = nil
		e.created = nil
	}
}

func (a Adapter) AcquireServingExclusion() (*ServingExclusion, bool) {
	exclusion := &ServingExclusion{root: a.root}
	accepted := false
	defer func() {
		if !accepted {
			exclusion.Release()
		}
	}()
	// Certbot removes idle lock files. Use its POSIX lock/inode protocol, creating
	// only missing files under proved existing parents and removing only our inodes.
	for _, path := range certbotDirectoryLocks {
		if a.safeParents(path) != nil {
			return nil, false
		}
		file, err := os.OpenFile(a.path(path), os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		created := err == nil
		if errors.Is(err, os.ErrExist) {
			file, err = os.OpenFile(a.path(path), os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		}
		if err != nil {
			return nil, false
		}
		exclusion.files = append(exclusion.files, file)
		if created {
			exclusion.created = append(exclusion.created, file)
			if file.Chmod(0600) != nil {
				return nil, false
			}
		}
		info, err := file.Stat()
		stat, ok := infoSys(info)
		if err != nil || !ok || !info.Mode().IsRegular() || stat.Uid != a.ownerUID() || stat.Nlink != 1 || info.Mode().Perm()&0022 != 0 {
			return nil, false
		}
		lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: io.SeekStart}
		if syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &lock) != nil {
			return nil, false
		}
		current, err := os.Lstat(a.path(path))
		if err != nil || !os.SameFile(info, current) {
			return nil, false
		}
	}
	accepted = true
	return exclusion, true
}

// RemoveServingRuntime requires retained precommit exclusion. It never opens
// another descriptor for those POSIX lock inodes (closing it would unlock them).
func (a Adapter) RemoveServingRuntime(ctx context.Context, authority ServingAuthority, exclusion *ServingExclusion) bool {
	if !a.validServingExclusion(exclusion) || !a.InspectServingFiles(authority, true).Accepted {
		return false
	}
	archivePaths, validArchive := a.removableServingArchive(authority)
	if !validArchive {
		return false
	}
	for i, file := range exclusion.files {
		info, err := file.Stat()
		current, e := os.Lstat(a.path(certbotDirectoryLocks[i]))
		if err != nil || e != nil || !os.SameFile(info, current) {
			return false
		}
	}
	if !a.safelyAbsent(ServingUnitPath) && !a.servingCommand(ctx, "disable", "--now", "sbxr-subscription.service") || !a.ServingQuiescent() {
		return false
	}
	paths := []string{}
	for _, name := range certificateNames {
		paths = append(paths, servingLive+"/"+name+".pem")
	}
	paths = append(paths, archivePaths...)
	paths = append(paths, servingLive+"/README")
	paths = append(paths, servingLive, servingArchive, ServingTokenPath, ServingStatePath, ServingStagingPath, ServingUnitWantsPath, ServingUnitPath)
	for _, path := range paths {
		if err := os.Remove(a.path(path)); errors.Is(err, os.ErrNotExist) {
			if !a.syncAbsentPath(path) {
				return false
			}
		} else if err != nil || a.syncOwnershipDirectory(a.path(filepath.Dir(path))) != nil {
			return false
		}
	}
	return a.servingCommand(ctx, "daemon-reload") && a.ServingQuiescent()
}

func (a Adapter) validServingExclusion(exclusion *ServingExclusion) bool {
	if exclusion == nil || exclusion.root != a.root || len(exclusion.files) != len(certbotDirectoryLocks) {
		return false
	}
	for i, file := range exclusion.files {
		info, err := file.Stat()
		current, currentErr := os.Lstat(a.path(certbotDirectoryLocks[i]))
		if err != nil || currentErr != nil || !os.SameFile(info, current) {
			return false
		}
	}
	return true
}

func (a Adapter) ServingRuntimeAbsent(authority ServingAuthority) bool {
	for _, resource := range authority.Resources() {
		if !a.safelyAbsent(strings.SplitN(resource, " ", 2)[0]) {
			return false
		}
	}
	return a.ServingQuiescent()
}
