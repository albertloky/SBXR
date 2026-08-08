// Package subscriptionserving serves the active immutable subscription over IP HTTPS.
package subscriptionserving

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

const (
	configurationPath = "etc/sbxr/subscription.json"
	artifactPath      = "var/lib/sbxr/subscriptions/current"
	certificatePath   = "var/lib/sbxr/certificates/ip/current"
)

var artifactNames = []string{"base64", "karing", "metadata", "mihomo", "raw", "shadowrocket", "sing-box", "v2rayn"}

type Server struct {
	root                   string
	uid, gid               int
	serviceUID, serviceGID int
	roots                  *x509.CertPool
	now                    func() time.Time
	production             bool
}

func New() (Server, error) {
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		return Server{}, failed("SUBSCRIPTION-SERVING-IDENTITY", "service identity is invalid")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return Server{}, failed("SUBSCRIPTION-SERVING-CERTIFICATE", "system trust roots are unavailable")
	}
	return Server{root: "/", uid: 0, gid: os.Getegid(), serviceUID: os.Geteuid(), serviceGID: os.Getegid(), roots: roots, now: time.Now, production: true}, nil
}

// NewAt supplies the published-storage and certificate boundaries used by Seam Verification.
func NewAt(root string, uid, gid int, roots *x509.CertPool, now time.Time) Server {
	return Server{root: root, uid: uid, gid: gid, serviceUID: os.Geteuid(), serviceGID: os.Getegid(), roots: roots, now: func() time.Time { return now }}
}

type configuration struct {
	Token              string `json:"token"`
	ListenPort         uint16 `json:"listen_port"`
	CertificatePointer string `json:"certificate_pointer"`
	PrimaryAddress     string `json:"primary_address"`
}

type servingState struct {
	route       string
	body        []byte
	address     netip.Addr
	certificate tls.Certificate
}

// Run starts the fixed production listener. It has no HTTP or insecure fallback.
func Run(ctx context.Context) error {
	server, err := New()
	if err != nil {
		return err
	}
	state, err := server.load()
	if err != nil {
		return failed("SUBSCRIPTION-SERVING-INPUT", "runtime input is invalid or unsafe")
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(state.address.String(), "10443"))
	if err != nil {
		return failed("SUBSCRIPTION-SERVING-LISTENER", "selected HTTPS listener is unavailable")
	}
	return server.Serve(ctx, listener)
}

// Serve handles full TLS requests on an already-bound listener.
func (server Server) Serve(ctx context.Context, listener net.Listener) error {
	if ctx == nil || listener == nil || server.roots == nil || server.now == nil {
		return failed("SUBSCRIPTION-SERVING-INPUT", "runtime input is unavailable")
	}
	if server.serviceUID == 0 || os.Geteuid() != server.serviceUID || os.Getegid() != server.serviceGID {
		_ = listener.Close()
		return failed("SUBSCRIPTION-SERVING-IDENTITY", "runtime service identity is invalid")
	}
	state, err := server.load()
	if err != nil {
		_ = listener.Close()
		return failed("SUBSCRIPTION-SERVING-INPUT", "runtime input is invalid or unsafe")
	}
	if tcp, ok := listener.Addr().(*net.TCPAddr); !ok || tcp.AddrPort().Addr().BitLen() != state.address.BitLen() || server.production && (tcp.AddrPort().Addr() != state.address || tcp.Port != 10443) {
		_ = listener.Close()
		return failed("SUBSCRIPTION-SERVING-LISTENER", "listener does not match the selected address family")
	}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.RawPath != "" || request.URL.RawQuery != "" || subtle.ConstantTimeCompare([]byte(request.URL.Path), []byte(state.route)) != 1 {
			refuse(response)
			return
		}
		secure(response)
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(state.body)
	})
	httpServer := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog:  log.New(io.Discard, "", 0),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{state.certificate}, MinVersion: tls.VersionTLS13},
	}
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = httpServer.Close()
		case <-stopped:
		}
	}()
	err = httpServer.Serve(&handshakeListener{Listener: listener, config: httpServer.TLSConfig})
	close(stopped)
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	return failed("SUBSCRIPTION-SERVING-RUNTIME", "HTTPS runtime stopped unexpectedly")
}

type handshakeListener struct {
	net.Listener
	config *tls.Config
}

func (listener *handshakeListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		secured := tls.Server(connection, listener.config)
		_ = secured.SetDeadline(time.Now().Add(5 * time.Second))
		if err := secured.Handshake(); err != nil {
			_ = secured.Close()
			continue
		}
		_ = secured.SetDeadline(time.Time{})
		return secured, nil
	}
}

func refuse(response http.ResponseWriter) {
	secure(response)
	response.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(response, "not found\n")
}

func secure(response http.ResponseWriter) {
	response.Header().Set("Content-Type", "text/plain; charset=utf-8")
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Referrer-Policy", "no-referrer")
}

func (server Server) load() (servingState, error) {
	if err := server.safeParents(); err != nil {
		return servingState{}, err
	}
	encoded, err := server.safeFile(configurationPath, 0o640, 64<<10)
	if err != nil {
		return servingState{}, errors.New("Subscription Serving configuration is unsafe")
	}
	var config configuration
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return servingState{}, errors.New("Subscription Serving configuration is invalid")
	}
	address, addressErr := netip.ParseAddr(config.PrimaryAddress)
	token, tokenErr := hex.DecodeString(config.Token)
	if addressErr != nil || !address.IsValid() || server.production && !address.IsGlobalUnicast() || config.ListenPort != 10443 || config.CertificatePointer != "/"+certificatePath || tokenErr != nil || len(token) != 32 || hex.EncodeToString(token) != config.Token {
		return servingState{}, errors.New("Subscription Serving configuration is invalid")
	}
	body, err := server.loadArtifacts()
	if err != nil {
		return servingState{}, err
	}
	certificateDirectory, pointerErr := server.activeCertificateDirectory()
	chain, chainErr := server.safeFile(certificateDirectory+"/fullchain.pem", 0o640, 1<<20)
	key, keyErr := server.safeFile(certificateDirectory+"/privkey.pem", 0o640, 1<<20)
	certificate, pairErr := tls.X509KeyPair(chain, key)
	if pointerErr != nil || chainErr != nil || keyErr != nil || pairErr != nil || !validCertificate(certificate, address, server.roots, server.now()) {
		return servingState{}, errors.New("Subscription Serving certificate is invalid")
	}
	return servingState{route: "/s/" + config.Token, body: body, address: address, certificate: certificate}, nil
}

func (server Server) activeCertificateDirectory() (string, error) {
	target, err := os.Readlink(filepath.Join(server.root, certificatePath))
	if err != nil {
		// systemd's read-only bind exposes the validated active pointer target
		// directly at current inside the service's otherwise empty namespace.
		if !server.safeDirectory(certificatePath, 0o750, server.gid) {
			return "", errors.New("active Subscription Serving certificate pointer is unsafe")
		}
		return certificatePath, nil
	}
	if !safeCertificateTarget(target) {
		return "", errors.New("active Subscription Serving certificate pointer is unsafe")
	}
	if !server.safeDirectory("var/lib/sbxr/certificates/ip/sets", 0o750, server.gid) {
		return "", errors.New("active Subscription Serving certificate sets are unsafe")
	}
	directory := filepath.Join("var/lib/sbxr/certificates/ip", target)
	if !server.safeDirectory(directory, 0o750, server.gid) {
		return "", errors.New("active Subscription Serving certificate set is unsafe")
	}
	return directory, nil
}

func safeCertificateTarget(target string) bool {
	suffix, ok := strings.CutPrefix(target, "sets/ip-")
	if !ok || suffix == "" || len(suffix) > 128 || strings.ContainsAny(suffix, "/\\.") {
		return false
	}
	for _, character := range suffix {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func (server Server) loadArtifacts() ([]byte, error) {
	entries, err := os.ReadDir(filepath.Join(server.root, artifactPath))
	if err != nil || len(entries) != len(artifactNames) {
		return nil, errors.New("active subscription artifact set is incomplete")
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	slices.Sort(names)
	if !slices.Equal(names, artifactNames) {
		return nil, errors.New("active subscription artifact set is invalid")
	}
	var body []byte
	for _, name := range names {
		contents, err := server.safeFile(artifactPath+"/"+name, 0o640, 4<<20)
		if err != nil {
			return nil, errors.New("active subscription artifact is unsafe")
		}
		if name == "base64" {
			if _, err := base64.StdEncoding.DecodeString(string(contents)); err != nil {
				return nil, errors.New("active base64 subscription artifact is invalid")
			}
			body = contents
		}
	}
	return body, nil
}

func validCertificate(pair tls.Certificate, address netip.Addr, roots *x509.CertPool, now time.Time) bool {
	if len(pair.Certificate) < 2 {
		return false
	}
	certificates := make([]*x509.Certificate, len(pair.Certificate))
	for index, der := range pair.Certificate {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return false
		}
		certificates[index] = certificate
	}
	leaf := certificates[0]
	if len(leaf.IPAddresses) != 1 || len(leaf.DNSNames) != 0 || !leaf.IPAddresses[0].Equal(address.AsSlice()) {
		return false
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := leaf.Verify(x509.VerifyOptions{DNSName: address.String(), Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err == nil
}

func (server Server) safeParents() error {
	current, _ := os.Lstat(filepath.Join(server.root, certificatePath))
	syntheticNamespace := server.production && current != nil && current.IsDir() && current.Mode()&os.ModeSymlink == 0
	for _, wanted := range []struct {
		name string
		mode fs.FileMode
	}{
		{"etc", 0o755}, {"etc/sbxr", 0o750}, {"var", 0o755}, {"var/lib", 0o755}, {"var/lib/sbxr", 0o755},
		{"var/lib/sbxr/subscriptions", 0o750}, {artifactPath, 0o750}, {"var/lib/sbxr/certificates", 0o755}, {"var/lib/sbxr/certificates/ip", 0o750},
	} {
		group := server.gid
		if wanted.mode == 0o755 {
			group = -1
		}
		exact := server.safeDirectory(wanted.name, wanted.mode, group)
		synthetic := syntheticNamespace && wanted.name != artifactPath && server.safeDirectory(wanted.name, 0o755, 0)
		if !exact && !synthetic {
			return errors.New("Subscription Serving storage boundary is unsafe")
		}
	}
	return nil
}

func (server Server) safeDirectory(name string, mode fs.FileMode, gid int) bool {
	info, err := os.Lstat(filepath.Join(server.root, name))
	uid, actualGID, ok := identity(info)
	return err == nil && ok && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == mode && uid == server.uid && (gid < 0 || actualGID == gid)
}

func (server Server) safeFile(name string, mode fs.FileMode, limit int64) ([]byte, error) {
	path := filepath.Join(server.root, name)
	info, err := os.Lstat(path)
	uid, gid, ok := identity(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Type() != 0 || info.Mode().Perm() != mode || info.Size() <= 0 || info.Size() > limit || uid != server.uid || gid != server.gid {
		return nil, errors.New("unsafe file")
	}
	return os.ReadFile(path)
}

func identity(info os.FileInfo) (int, int, bool) {
	if info == nil {
		return 0, 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(stat.Uid), int(stat.Gid), true
}
