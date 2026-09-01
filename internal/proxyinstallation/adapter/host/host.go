// Package host observes Ubuntu facts for Proxy Installation.
package host

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"
)

type Resource struct {
	Kind     ResourceKind
	Name     string
	Present  bool
	Observed bool
}

type ResourceKind uint8

const (
	PathResource ResourceKind = iota + 1
	PackageResource
	UserResource
	GroupResource
	ProcessResource
	TCPListenerResource
)

type Destination struct {
	Address    string
	ServerName string
}

type DestinationObservation struct {
	Destination
	DNS, TCP, TLS13, HTTP2, CertificateName bool
}

func (observation DestinationObservation) Compatible() bool {
	return observation.DNS && observation.TCP && observation.TLS13 && observation.HTTP2 && observation.CertificateName
}

type Inspection struct {
	Resources []Resource
	Complete  bool
}

type Preflight struct {
	Resources             []Resource
	OSID                  string
	OSVersion             string
	Architecture          string
	PublicIPv4            string
	ClockSynchronized     bool
	TCP443Available       bool
	MutationLockAvailable bool
	PackageLocksAvailable bool
	Destinations          []DestinationObservation
}

type Adapter struct {
	subscriptionCommand     func(context.Context, string, ...string) (string, int, bool)
	renewalCommand          func(context.Context, string, ...string) int
	renewalProcessIdentity  func(int) (string, uint64, bool)
	renewalCertificateValid func(RenewalAuthority, int) bool
	renewalTrustRoots       *x509.CertPool
	subscriptionBind        func(string, string) bool
	syncDirectoryFault      func(string) error
	root                    string
	architecture            string
	publicIPv4              func(context.Context) string
	clockSynchronized       func(context.Context) bool
	tcp443Available         func(string) bool
	mutationLockAvailable   func() bool
	packageLocksAvailable   func() bool
	probeDestination        func(context.Context, Destination) DestinationObservation
}

func New() Adapter {
	return Adapter{
		root: "/", architecture: runtime.GOARCH,
		publicIPv4: livePublicIPv4, clockSynchronized: liveClockSynchronized,
		tcp443Available: liveTCP443Available, mutationLockAvailable: liveMutationLockAvailable,
		packageLocksAvailable: livePackageLocksAvailable, probeDestination: liveDestinationObservation,
	}
}

func (adapter Adapter) Inspect(ctx context.Context, requested []Resource) Inspection {
	resources := make([]Resource, 0, len(requested))
	complete := true
	for _, request := range requested {
		observation := adapter.observe(ctx, request)
		resources = append(resources, observation)
		complete = complete && observation.Observed
	}
	return Inspection{Resources: resources, Complete: complete}
}

func (adapter Adapter) Preflight(ctx context.Context, resources []Resource, destinations []Destination) Preflight {
	osID, version := adapter.osRelease()
	publicIPv4 := adapter.publicIPv4(ctx)
	observations := make([]DestinationObservation, 0, len(destinations))
	for _, destination := range destinations {
		observation := adapter.probeDestination(ctx, destination)
		observations = append(observations, observation)
		if observation.Compatible() {
			break
		}
	}
	return Preflight{
		Resources: adapter.Inspect(ctx, resources).Resources, OSID: osID, OSVersion: version, Architecture: adapter.architecture,
		PublicIPv4: publicIPv4, ClockSynchronized: adapter.clockSynchronized(ctx),
		TCP443Available: adapter.tcp443Available(publicIPv4), MutationLockAvailable: adapter.mutationLockAvailable(),
		PackageLocksAvailable: adapter.packageLocksAvailable(), Destinations: observations,
	}
}

func (adapter Adapter) MutationInProgress(name string) (bool, bool) {
	path := adapter.path(name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, true
	}
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != adapter.ownerUID() || stat.Nlink != 1 {
		return false, false
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false, false
	}
	defer file.Close()
	opened, openedErr := file.Stat()
	openedStat, openedOK := infoSys(opened)
	if openedErr != nil || !openedOK || openedStat.Dev != stat.Dev || openedStat.Ino != stat.Ino {
		return false, false
	}
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return true, true
	}
	return false, err == nil && syscall.Flock(int(file.Fd()), syscall.LOCK_UN) == nil
}

func (adapter Adapter) observe(ctx context.Context, request Resource) Resource {
	request.Present, request.Observed = false, false
	switch request.Kind {
	case PathResource:
		_, err := os.Lstat(adapter.path(request.Name))
		request.Present, request.Observed = err == nil, err == nil || os.IsNotExist(err)
	case PackageResource:
		request.Present, request.Observed = commandPresence(ctx, []int{1}, "dpkg-query", "--show", "--showformat=${db:Status-Abbrev}", request.Name)
	case UserResource:
		request.Present, request.Observed = commandPresence(ctx, []int{2}, "getent", "passwd", request.Name)
	case GroupResource:
		request.Present, request.Observed = commandPresence(ctx, []int{2}, "getent", "group", request.Name)
	case ProcessResource:
		request.Present, request.Observed = commandPresence(ctx, []int{1}, "pgrep", "--exact", request.Name)
	case TCPListenerResource:
		body, code, observed := commandOutput(ctx, "ss", "-H", "-ltnp", "sport", "=", ":"+request.Name)
		request.Present, request.Observed = code == 0 && strings.TrimSpace(body) != "", observed && code == 0
	}
	return request
}

func (adapter Adapter) osRelease() (string, string) {
	root, err := os.OpenRoot(adapter.root)
	if err != nil {
		return "", ""
	}
	defer root.Close()
	file, err := root.Open("etc/os-release")
	if err != nil {
		return "", ""
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(body) > 4096 {
		return "", ""
	}
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	values := map[string]string{}
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok && (key == "ID" || key == "VERSION_ID") {
			values[key] = strings.Trim(strings.TrimSpace(value), "\"")
		}
	}
	if scanner.Err() != nil {
		return "", ""
	}
	return values["ID"], values["VERSION_ID"]
}

func (adapter Adapter) path(name string) string {
	if adapter.root == "/" {
		return name
	}
	return filepath.Join(adapter.root, strings.TrimPrefix(name, "/"))
}

func commandPresence(ctx context.Context, absentCodes []int, name string, arguments ...string) (bool, bool) {
	_, code, observed := commandOutput(ctx, name, arguments...)
	if !observed {
		return false, false
	}
	if code == 0 {
		return true, true
	}
	return false, slices.Contains(absentCodes, code)
}

func commandOutput(ctx context.Context, name string, arguments ...string) (string, int, bool) {
	if _, err := exec.LookPath(name); err != nil {
		return "", -1, false
	}
	commandCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	body, err := exec.CommandContext(commandCtx, name, arguments...).Output()
	if err == nil {
		return string(body), 0, true
	}
	if commandCtx.Err() != nil {
		return "", -1, false
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return string(body), exit.ExitCode(), true
	}
	return "", -1, false
}

func livePublicIPv4(ctx context.Context) string {
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	if err != nil {
		return ""
	}
	response, err := client.Do(request)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65))
	if err != nil || len(body) > 64 {
		return ""
	}
	return strings.TrimSpace(string(body))
}

func liveClockSynchronized(ctx context.Context) bool {
	body, code, observed := commandOutput(ctx, "timedatectl", "show", "--property=NTPSynchronized", "--value")
	return observed && code == 0 && strings.TrimSpace(body) == "yes"
}

func liveTCP443Available(publicIPv4 string) bool {
	if net.ParseIP(publicIPv4) == nil {
		return false
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(publicIPv4, "443"))
	if err != nil {
		return false
	}
	return listener.Close() == nil
}

func liveMutationLockAvailable() bool {
	return flockAvailable("/run/lock/sbxr.lock")
}

func livePackageLocksAvailable() bool {
	for _, name := range []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock", "/var/lib/apt/lists/lock", "/var/cache/apt/archives/lock"} {
		if !recordLockAvailable(name) {
			return false
		}
	}
	return true
}

func flockAvailable(name string) bool {
	file, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return true
	}
	if err != nil {
		return false
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return false
	}
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN) == nil
}

func recordLockAvailable(name string) bool {
	file, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return true
	}
	if err != nil {
		return false
	}
	defer file.Close()
	lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: io.SeekStart}
	return syscall.FcntlFlock(file.Fd(), syscall.F_GETLK, &lock) == nil && lock.Type == syscall.F_UNLCK
}

func liveDestinationObservation(ctx context.Context, destination Destination) DestinationObservation {
	result := DestinationObservation{Destination: destination}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	host, _, err := net.SplitHostPort(destination.Address)
	if err != nil {
		return result
	}
	if _, err := net.DefaultResolver.LookupHost(probeCtx, host); err != nil {
		return result
	}
	result.DNS = true
	connection, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", destination.Address)
	if err != nil {
		return result
	}
	result.TCP = true
	secure := tls.Client(connection, &tls.Config{ServerName: destination.ServerName, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}})
	defer secure.Close()
	if err := secure.HandshakeContext(probeCtx); err != nil {
		return result
	}
	state := secure.ConnectionState()
	result.TLS13 = state.Version == tls.VersionTLS13
	result.HTTP2 = state.NegotiatedProtocol == "h2"
	result.CertificateName = len(state.VerifiedChains) > 0
	return result
}
