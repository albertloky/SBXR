package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/albertloky/SBXR/internal/proxyinstallation/subscriptionserving"
)

const ServingRole = "--subscription-serving"
const ServingUnitPath = "/etc/systemd/system/sbxr-subscription.service"
const ServingTokenPath = "/var/lib/sbxr/subscription-token"
const ServingStagingPath = "/var/lib/sbxr/subscription-staging"
const servingArchive = "/etc/letsencrypt/archive/sbxr-subscription"
const servingLive = "/etc/letsencrypt/live/sbxr-subscription"
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
RestrictAddressFamilies=AF_INET AF_INET6
InaccessiblePaths=/var/lib/sbxr/subscription-token /var/lib/sbxr/subscription-staging /proc /run/systemd /run/dbus
StandardInput=null
StandardOutput=null
StandardError=null
UMask=0077

[Install]
WantedBy=multi-user.target
`

// ServingAuthority is an Ownership Record component, never an independent
// authority file. This bounded runtime-only contract has no renewal writer,
// firewall rule, pending credential operation or additional certificate history.
type ServingAuthority struct {
	LinkID                string    `json:"link_id"`
	CredentialSHA256      string    `json:"credential_sha256"`
	CertificateGeneration int       `json:"certificate_generation"`
	CertificateSHA256     [4]string `json:"certificate_sha256"`
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
	resources := []string{ServingUnitPath + " root:root 0644 one-link fixed-serving-v1", ServingTokenPath + " root:root 0600 one-link credential", ServingStagingPath + " root:root 0700 empty-directory", servingArchive + " root:root 0700 directory", servingLive + " root:root 0700 directory"}
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
	refused := errors.New("serving material refused")
	if err := a.safeParents(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(a.path(path), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != mode || stat.Uid != a.ownerUID() || stat.Nlink != 1 || info.Size() <= 0 || info.Size() > 64<<10 {
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
	for _, entry := range entries {
		if !slices.Contains(allowed, entry.Name()) {
			return false
		}
	}
	return true
}

func (a Adapter) InspectServingFiles(authority ServingAuthority, removing bool) Observation {
	return a.inspectServingFiles(authority, removing, false)
}

func (a Adapter) inspectServingFiles(authority ServingAuthority, removing, sandbox bool) Observation {
	if !authority.Valid() {
		return observation(false, true)
	}
	// Unknown staging, renewal, hooks and overrides belong to later complete
	// lifecycle contracts. Never adopt or delete them as this runtime footprint.
	for _, path := range []string{"/etc/letsencrypt/renewal/sbxr-subscription.conf", ServingUnitPath + ".d", "/etc/systemd/system/multi-user.target.wants/sbxr-subscription.service",
		"/run/systemd/system/sbxr-subscription.service", "/run/systemd/system/sbxr-subscription.service.d", "/usr/lib/systemd/system/sbxr-subscription.service", "/usr/lib/systemd/system/sbxr-subscription.service.d",
		"/etc/systemd/system/service.d", "/usr/lib/systemd/system/service.d"} {
		if sandbox && strings.HasPrefix(path, "/run/systemd/") {
			continue
		} // The entire host control directory must be inaccessible below.
		if !a.safelyAbsent(path) {
			return Observation{}
		}
	}
	if !a.servingDirectory("/var/lib/sbxr", []string{"installed.json", "proxy-ownership.json", ".proxy-ownership.json.next", "subscription-token", "subscription-staging"}, removing) {
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
	if err != nil && !(removing && errors.Is(err, os.ErrNotExist)) || err == nil && string(unit) != ServingUnit {
		return Observation{}
	}
	if !sandbox {
		token, err := a.protectedServingFile(ServingTokenPath, 0600, "")
		if err != nil && !(removing && errors.Is(err, os.ErrNotExist)) || err == nil && (len(token) != 44 || token[43] != '\n' || digest(token[:43]) != authority.CredentialSHA256) {
			return Observation{}
		}
		if err == nil {
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

// ValidateServingDispatch is read-only. The fixed cgroup, inaccessible host
// control sockets/proc/credentials, and zero capabilities are independent of
// arguments and environment. Nothing here creates missing authority.
func (a Adapter) ValidateServingDispatch(authority ServingAuthority) bool {
	if a.root != "/" || os.Geteuid() != 0 || !servingCapabilitiesRestricted() || !a.inspectServingFiles(authority, false, true).Accepted {
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
	root  string
	files []*os.File
}

func (e *ServingExclusion) Release() {
	if e != nil {
		for _, file := range e.files {
			file.Close()
		}
		e.files = nil
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
	// With no renewal integration in this footprint, use the existing official
	// shared lock inodes to exclude Certbot while removing its owned material.
	// Missing locks refuse; this read/remove path must not create shared state.
	for _, path := range certbotDirectoryLocks {
		if a.safeParents(path) != nil {
			return nil, false
		}
		file, err := os.OpenFile(a.path(path), os.O_RDWR|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, false
		}
		exclusion.files = append(exclusion.files, file)
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
	if exclusion == nil || exclusion.root != a.root || len(exclusion.files) != len(certbotDirectoryLocks) || !a.InspectServingFiles(authority, true).Accepted {
		return false
	}
	for i, file := range exclusion.files {
		info, err := file.Stat()
		current, e := os.Lstat(a.path(certbotDirectoryLocks[i]))
		if err != nil || e != nil || !os.SameFile(info, current) {
			return false
		}
	}
	if !a.safelyAbsent(ServingUnitPath) && !a.servingCommand(ctx, "stop", "sbxr-subscription.service") || !a.ServingQuiescent() {
		return false
	}
	paths := []string{}
	for _, name := range certificateNames {
		paths = append(paths, servingLive+"/"+name+".pem", servingArchive+"/"+name+strconv.Itoa(authority.CertificateGeneration)+".pem")
	}
	paths = append(paths, servingLive, servingArchive, ServingTokenPath, ServingStagingPath, ServingUnitPath)
	for _, path := range paths {
		if !a.InspectServingFiles(authority, true).Accepted {
			return false
		}
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

func (a Adapter) ServingRuntimeAbsent(authority ServingAuthority) bool {
	for _, resource := range authority.Resources() {
		if !a.safelyAbsent(strings.SplitN(resource, " ", 2)[0]) {
			return false
		}
	}
	return a.ServingQuiescent()
}
