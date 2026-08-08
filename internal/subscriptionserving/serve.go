// Package subscriptionserving serves the active immutable subscription over IP HTTPS.
package subscriptionserving

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	artifactPath             = "var/lib/sbxr/subscriptions/current"
	configurationName        = "serving.json"
	configurationPath        = artifactPath + "/" + configurationName
	certificatePath          = "var/lib/sbxr/certificates/ip/current"
	maxResponseBytes         = 1 << 20
	maxMetadataBytes         = 64 << 10
	maxRequestBodyBytes      = 1 << 10
	maxHeaderBytes           = 16 << 10
	maxConcurrentConnections = 8
	maxRequestsPerMinute     = 60
	headerReadTimeout        = 5 * time.Second
	requestReadTimeout       = 10 * time.Second
	responseWriteTimeout     = 10 * time.Second
	totalOperationTimeout    = 15 * time.Second
	idleConnectionTimeout    = 30 * time.Second
	tlsHandshakeTimeout      = 5 * time.Second
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

// Health validates the active serving state without changing it.
func (server Server) Health() HealthResult {
	_, err := server.load()
	return Result(err)
}

type configuration struct {
	Token              string `json:"token"`
	ListenPort         uint16 `json:"listen_port"`
	CertificatePointer string `json:"certificate_pointer"`
	PrimaryAddress     string `json:"primary_address"`
}

type servingState struct {
	route       string
	artifacts   map[string][]byte
	address     netip.Addr
	certificate tls.Certificate
}

type representation struct {
	suffix, artifact, identity, contentType string
	omitsXHTTP                              bool
	hints                                   []string
}

var representations = []representation{
	{suffix: "/base64", artifact: "base64", identity: "base64-uri-list", contentType: "text/plain; charset=utf-8"},
	{suffix: "/raw", artifact: "raw", identity: "raw-uri-list", contentType: "text/plain; charset=utf-8"},
	{suffix: "/v2rayn", artifact: "v2rayn", identity: "v2rayn-base64-uri-list", contentType: "text/plain; charset=utf-8", hints: []string{"v2rayn/"}},
	{suffix: "/shadowrocket", artifact: "shadowrocket", identity: "shadowrocket-candidate", contentType: "text/plain; charset=utf-8"},
	{suffix: "/karing", artifact: "karing", identity: "karing-sing-box-json", contentType: "application/json", omitsXHTTP: true},
	{suffix: "/mihomo", artifact: "mihomo", identity: "mihomo-yaml", contentType: "application/yaml", hints: []string{"mihomo", "clashmeta", "clash meta"}},
	{suffix: "/sing-box", artifact: "sing-box", identity: "sing-box-json", contentType: "application/json", omitsXHTTP: true, hints: []string{"sing-box"}},
}

// Run starts the fixed production listener. It has no HTTP or insecure fallback.
func Run(ctx context.Context) error {
	server, err := New()
	if err != nil {
		return err
	}
	state, err := server.load()
	if err != nil {
		return err
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
		return err
	}
	if tcp, ok := listener.Addr().(*net.TCPAddr); !ok || tcp.AddrPort().Addr().BitLen() != state.address.BitLen() || server.production && (tcp.AddrPort().Addr() != state.address || tcp.Port != 10443) {
		_ = listener.Close()
		return failed("SUBSCRIPTION-SERVING-LISTENER", "listener does not match the selected address family")
	}
	limiter := &requestRateLimiter{}
	switcher := &stateSwitcher{server: server, current: state}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		state := switcher.refresh()
		allowed := limiter.allow(time.Now())
		request.Body = http.MaxBytesReader(response, request.Body, maxRequestBodyBytes)
		bodyPresent := request.ContentLength != 0 || len(request.TransferEncoding) != 0
		if bodyPresent {
			response.Header().Set("Connection", "close")
			_, _ = io.Copy(io.Discard, request.Body)
		}
		selected, negotiated, ok := selectRepresentation(state.route, request.URL.Path, request.UserAgent())
		if request.Method != http.MethodGet || request.URL.IsAbs() || request.URL.RawPath != "" || request.URL.RawQuery != "" || bodyPresent || !ok {
			request.Close = true
			plain(response, http.StatusNotFound, "not found\n")
			return
		}
		if !allowed {
			plain(response, http.StatusTooManyRequests, "busy\n")
			return
		}
		secure(response, selected.contentType)
		response.Header().Set("X-SBXR-Representation", selected.identity)
		if negotiated {
			response.Header().Set("Vary", "User-Agent")
		}
		if selected.omitsXHTTP {
			response.Header().Set("X-SBXR-Omitted-Profile", "vless-xhttp")
		}
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(state.artifacts[selected.artifact])
	})
	timedHandler := operationBound(handler)
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			secure(response, "text/plain; charset=utf-8")
			timedHandler.ServeHTTP(response, request)
		}), ReadHeaderTimeout: headerReadTimeout, ReadTimeout: requestReadTimeout,
		WriteTimeout: responseWriteTimeout, IdleTimeout: idleConnectionTimeout, MaxHeaderBytes: maxHeaderBytes,
		ErrorLog:                     log.New(io.Discard, "", 0),
		DisableGeneralOptionsHandler: true,
		TLSConfig:                    &tls.Config{Certificates: []tls.Certificate{state.certificate}, MinVersion: tls.VersionTLS13},
	}
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = httpServer.Close()
		case <-stopped:
		}
	}()
	bounded := &connectionLimitListener{Listener: listener, slots: make(chan struct{}, maxConcurrentConnections)}
	err = httpServer.Serve(&handshakeListener{Listener: bounded, config: httpServer.TLSConfig, switcher: switcher})
	close(stopped)
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	return failed("SUBSCRIPTION-SERVING-RUNTIME", "HTTPS runtime stopped unexpectedly")
}

type stateSwitcher struct {
	mu      sync.Mutex
	server  Server
	current servingState
}

func (switcher *stateSwitcher) refresh() servingState {
	switcher.mu.Lock()
	defer switcher.mu.Unlock()
	if candidate, err := switcher.server.load(); err == nil && candidate.address == switcher.current.address {
		switcher.current = candidate
	}
	return switcher.current
}

func operationBound(handler http.Handler) http.Handler {
	return http.TimeoutHandler(handler, totalOperationTimeout, "busy\n")
}

type handshakeListener struct {
	net.Listener
	config   *tls.Config
	switcher *stateSwitcher
}

type connectionLimitListener struct {
	net.Listener
	slots chan struct{}
}

func (listener *connectionLimitListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case listener.slots <- struct{}{}:
			return &limitedConn{Conn: connection, release: func() { <-listener.slots }}, nil
		default:
			_ = connection.Close()
		}
	}
}

type limitedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (connection *limitedConn) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(connection.release)
	return err
}

func (listener *handshakeListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		config := listener.config.Clone()
		if listener.switcher != nil {
			state := listener.switcher.refresh()
			config.Certificates = []tls.Certificate{state.certificate}
		}
		secured := tls.Server(connection, config)
		_ = secured.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
		if err := secured.Handshake(); err != nil {
			_ = secured.Close()
			continue
		}
		_ = secured.SetDeadline(time.Time{})
		return &requestGuardConn{Conn: secured}, nil
	}
}

type requestGuardConn struct {
	net.Conn
	pending       []byte
	deliver       int
	guarded       bool
	bodyPresent   bool
	bodyRemaining int64
}

func (connection *requestGuardConn) Read(destination []byte) (int, error) {
	if connection.guarded && connection.deliver == 0 {
		if connection.bodyPresent && connection.bodyRemaining == 0 {
			return 0, io.EOF
		}
		if connection.bodyRemaining > 0 && int64(len(destination)) > connection.bodyRemaining {
			destination = destination[:connection.bodyRemaining]
		}
		if len(connection.pending) == 0 {
			count, err := connection.Conn.Read(destination)
			if connection.bodyRemaining > 0 {
				connection.bodyRemaining -= int64(count)
			}
			return count, err
		}
		count := copy(destination, connection.pending)
		connection.pending = connection.pending[count:]
		if connection.bodyRemaining > 0 {
			connection.bodyRemaining -= int64(count)
		}
		return count, nil
	}
	for connection.deliver == 0 {
		remaining := maxHeaderBytes + 1 - len(connection.pending)
		if remaining <= 0 {
			connection.pending = []byte("GET /__oversized HTTP/1.1\r\nHost: invalid\r\nConnection: close\r\n\r\n")
			connection.deliver = len(connection.pending)
			connection.guarded = true
			break
		}
		if remaining > 1024 {
			remaining = 1024
		}
		buffer := make([]byte, remaining)
		count, err := connection.Conn.Read(buffer)
		connection.pending = append(connection.pending, buffer[:count]...)
		if len(connection.pending) > maxHeaderBytes {
			connection.pending = []byte("GET /__oversized HTTP/1.1\r\nHost: invalid\r\nConnection: close\r\n\r\n")
			connection.deliver = len(connection.pending)
			connection.guarded = true
		}
		if headerEnd := bytes.Index(connection.pending, []byte("\r\n\r\n")); connection.deliver == 0 && headerEnd >= 0 {
			connection.deliver = headerEnd + 4
			connection.guarded = true
			connection.bodyPresent, connection.bodyRemaining = headerBody(connection.pending[:connection.deliver])
			lineEnd := bytes.Index(connection.pending[:connection.deliver], []byte("\r\n"))
			line := connection.pending[:lineEnd]
			parts := bytes.SplitN(line, []byte(" "), 3)
			if len(parts) == 3 {
				if _, parseErr := url.ParseRequestURI(string(parts[1])); parseErr != nil {
					replacement := bytes.Join([][]byte{parts[0], []byte("/__invalid"), parts[2]}, []byte(" "))
					connection.pending = append(replacement, connection.pending[lineEnd:]...)
					connection.deliver += len(replacement) - lineEnd
				}
			}
		}
		if err != nil && count == 0 {
			return 0, err
		}
	}
	count := len(destination)
	if count > connection.deliver {
		count = connection.deliver
	}
	copy(destination, connection.pending[:count])
	connection.pending = connection.pending[count:]
	connection.deliver -= count
	if connection.deliver == 0 && !connection.bodyPresent {
		connection.guarded = false
	}
	return count, nil
}

func headerBody(header []byte) (bool, int64) {
	for _, line := range bytes.Split(bytes.ToLower(header), []byte("\r\n")) {
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		name, value = bytes.TrimSpace(name), bytes.TrimSpace(value)
		if bytes.Equal(name, []byte("transfer-encoding")) {
			return true, -1
		}
		if bytes.Equal(name, []byte("content-length")) {
			length, err := strconv.ParseInt(string(value), 10, 64)
			if err != nil || length < 0 {
				return true, -1
			}
			return length != 0, length
		}
	}
	return false, 0
}

func plain(response http.ResponseWriter, status int, body string) {
	secure(response, "text/plain; charset=utf-8")
	response.WriteHeader(status)
	_, _ = io.WriteString(response, body)
}

type requestRateLimiter struct {
	mu          sync.Mutex
	windowStart time.Time
	requests    int
}

func (limiter *requestRateLimiter) allow(now time.Time) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.windowStart.IsZero() || now.Sub(limiter.windowStart) >= time.Minute {
		limiter.windowStart, limiter.requests = now, 0
	}
	if limiter.requests >= maxRequestsPerMinute {
		return false
	}
	limiter.requests++
	return true
}

func secure(response http.ResponseWriter, contentType string) {
	response.Header().Set("Content-Type", contentType)
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Referrer-Policy", "no-referrer")
}

func (server Server) load() (servingState, error) {
	if err := server.safeParents(); err != nil {
		return servingState{}, failed("SUBSCRIPTION-SERVING-ARTIFACT", "active serving snapshot is invalid or unsafe")
	}
	snapshot, err := os.OpenRoot(filepath.Join(server.root, artifactPath))
	if err != nil {
		return servingState{}, failed("SUBSCRIPTION-SERVING-ARTIFACT", "active serving snapshot is invalid or unsafe")
	}
	defer snapshot.Close()
	encoded, err := safeSnapshotFile(snapshot, configurationName, server.uid, server.gid, 64<<10, false)
	if err != nil {
		return servingState{}, failed("SUBSCRIPTION-SERVING-ARTIFACT", "active serving snapshot is invalid or unsafe")
	}
	var config configuration
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return servingState{}, failed("SUBSCRIPTION-SERVING-ARTIFACT", "active serving snapshot is invalid or unsafe")
	}
	address, addressErr := netip.ParseAddr(config.PrimaryAddress)
	token, tokenErr := hex.DecodeString(config.Token)
	if addressErr != nil || !address.IsValid() || server.production && !address.IsGlobalUnicast() || config.ListenPort != 10443 || config.CertificatePointer != "/"+certificatePath || tokenErr != nil || len(token) != 32 || hex.EncodeToString(token) != config.Token {
		return servingState{}, failed("SUBSCRIPTION-SERVING-ARTIFACT", "active serving snapshot is invalid or unsafe")
	}
	artifacts, err := server.loadArtifacts(snapshot, address, server.production)
	if err != nil {
		return servingState{}, failed("SUBSCRIPTION-SERVING-ARTIFACT", "active serving snapshot is invalid or unsafe")
	}
	certificateDirectory, pointerErr := server.activeCertificateDirectory()
	chain, chainErr := server.safeFile(certificateDirectory+"/fullchain.pem", 0o640, 1<<20, false)
	key, keyErr := server.safeFile(certificateDirectory+"/privkey.pem", 0o640, 1<<20, false)
	certificate, pairErr := tls.X509KeyPair(chain, key)
	if pointerErr != nil || chainErr != nil || keyErr != nil || pairErr != nil || !validCertificate(certificate, address, server.roots, server.now()) {
		return servingState{}, failed("SUBSCRIPTION-SERVING-CERTIFICATE", "active HTTPS certificate is invalid or unavailable")
	}
	return servingState{route: "/s/" + config.Token, artifacts: artifacts, address: address, certificate: certificate}, nil
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

func (server Server) loadArtifacts(snapshot *os.Root, expectedAddress netip.Addr, requireAddressMatch bool) (map[string][]byte, error) {
	entries, err := fs.ReadDir(snapshot.FS(), ".")
	if err != nil || len(entries) != len(artifactNames)+1 {
		return nil, errors.New("active subscription artifact set is incomplete")
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	slices.Sort(names)
	expectedNames := append(append([]string(nil), artifactNames...), configurationName)
	slices.Sort(expectedNames)
	if !slices.Equal(names, expectedNames) {
		return nil, errors.New("active subscription artifact set is invalid")
	}
	artifacts := make(map[string][]byte, len(names))
	for _, name := range names {
		limit := int64(maxResponseBytes)
		if name == "metadata" {
			limit = maxMetadataBytes
		}
		contents, err := safeSnapshotFile(snapshot, name, server.uid, server.gid, limit, true)
		if err != nil {
			return nil, errors.New("active subscription artifact is unsafe")
		}
		artifacts[name] = contents
	}
	if !validArtifactSet(artifacts, expectedAddress, requireAddressMatch) {
		return nil, errors.New("active subscription artifact set is invalid")
	}
	return artifacts, nil
}

type artifactMetadata struct {
	Schema              string `json:"schema"`
	ChangeSet           string `json:"change_set"`
	SelectedAddress     string `json:"selected_address"`
	DesiredStateSHA256  string `json:"desired_state_sha256"`
	ManagedInputsSHA256 string `json:"managed_inputs_sha256"`
	RelevantChecksums   struct {
		ConnectionProfiles string `json:"connection_profiles"`
		Subscription       string `json:"subscription"`
	} `json:"relevant_checksums"`
	Compatibility        string `json:"compatibility_definition"`
	DesiredStateRevision uint64 `json:"desired_state_revision"`
	ReleaseIdentity      struct {
		Repository         string `json:"repository"`
		Tag                string `json:"tag"`
		Commit             string `json:"commit"`
		ReleaseIndexSHA256 string `json:"release_index_sha256"`
	} `json:"release_identity"`
	ClientAccessAction string            `json:"client_access_action,omitempty"`
	Representations    []string          `json:"representations"`
	ArtifactSHA256     map[string]string `json:"artifact_sha256"`
	ProfileCount       int               `json:"profile_count"`
	Omissions          []struct {
		ID string `json:"id"`
	} `json:"omissions"`
	ValidationComplete bool `json:"validation_complete"`
}

func validArtifactSet(artifacts map[string][]byte, expectedAddress netip.Addr, requireAddressMatch bool) bool {
	decoded, err := base64.StdEncoding.DecodeString(string(artifacts["base64"]))
	if err != nil || !bytes.Equal(decoded, artifacts["raw"]) || !bytes.Equal(artifacts["base64"], artifacts["v2rayn"]) || !bytes.Equal(artifacts["base64"], artifacts["shadowrocket"]) || !bytes.Equal(artifacts["karing"], artifacts["sing-box"]) || !json.Valid(artifacts["sing-box"]) || len(artifacts["mihomo"]) == 0 {
		return false
	}
	var metadata artifactMetadata
	decoder := json.NewDecoder(bytes.NewReader(artifacts["metadata"]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&metadata) != nil {
		return false
	}
	address, addressErr := netip.ParseAddr(metadata.SelectedAddress)
	validAction := metadata.ClientAccessAction == "" || metadata.ClientAccessAction == "Rotate subscription token" || metadata.ClientAccessAction == "Revoke all client access"
	if decoder.Decode(&struct{}{}) != io.EOF || metadata.Schema != "sbxr-subscription-artifact-set-v1" || !safeMetadataIdentity(metadata.ChangeSet) || addressErr != nil || !address.IsGlobalUnicast() || requireAddressMatch && address != expectedAddress || metadata.DesiredStateRevision == 0 || !validMetadataSHA(metadata.DesiredStateSHA256) || !validMetadataSHA(metadata.ManagedInputsSHA256) || !validMetadataSHA(metadata.RelevantChecksums.ConnectionProfiles) || !validMetadataSHA(metadata.RelevantChecksums.Subscription) || metadata.Compatibility != "sbxr-subscription-representations-v1" || !validMetadataRelease(metadata.ReleaseIdentity.Repository, metadata.ReleaseIdentity.Tag, metadata.ReleaseIdentity.Commit, metadata.ReleaseIdentity.ReleaseIndexSHA256) || !validAction || !metadata.ValidationComplete || !slices.Equal(metadata.Representations, []string{"base64", "raw", "v2rayn", "shadowrocket", "karing", "mihomo", "sing-box"}) {
		return false
	}
	if len(metadata.ArtifactSHA256) != len(metadata.Representations) {
		return false
	}
	for _, name := range metadata.Representations {
		digest := sha256.Sum256(artifacts[name])
		if metadata.ArtifactSHA256[name] != hex.EncodeToString(digest[:]) {
			return false
		}
	}
	profileCount := 0
	if len(artifacts["raw"]) > 0 {
		profileCount = strings.Count(string(artifacts["raw"]), "\n") + 1
	}
	validIDs := map[string]bool{"vless-reality-vision": true, "vless-xhttp": true, "vless-websocket": true, "hysteria2": true, "tuic": true, "anytls": true}
	seen := map[string]bool{}
	for _, omission := range metadata.Omissions {
		if !validIDs[omission.ID] || seen[omission.ID] {
			return false
		}
		seen[omission.ID] = true
	}
	return metadata.ProfileCount == profileCount && profileCount+len(metadata.Omissions) == 6
}

func safeMetadataIdentity(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && !strings.ContainsRune("_.:-", character) {
			return false
		}
	}
	return true
}

func validMetadataHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil
}

func validMetadataSHA(value string) bool { return len(value) == 64 && validMetadataHex(value) }

func validMetadataRelease(repository, tag, commit, index string) bool {
	return repository != "" && tag != "" && (len(commit) == 40 || len(commit) == 64) && validMetadataHex(commit) && validMetadataSHA(index)
}

func selectRepresentation(route, path, userAgent string) (representation, bool, bool) {
	if subtle.ConstantTimeCompare([]byte(path), []byte(route)) == 1 {
		selected, matches := representations[0], 0
		userAgent = strings.ToLower(userAgent)
		for _, candidate := range representations {
			matched := false
			for _, hint := range candidate.hints {
				matched = matched || strings.Contains(userAgent, hint)
			}
			if matched {
				selected, matches = candidate, matches+1
			}
		}
		if matches != 1 {
			selected = representations[0]
		}
		return selected, true, true
	}
	for _, candidate := range representations {
		if subtle.ConstantTimeCompare([]byte(path), []byte(route+candidate.suffix)) == 1 {
			return candidate, false, true
		}
	}
	return representation{}, false, false
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
		{"var", 0o755}, {"var/lib", 0o755}, {"var/lib/sbxr", 0o755},
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

func (server Server) safeFile(name string, mode fs.FileMode, limit int64, allowEmpty bool) ([]byte, error) {
	path := filepath.Join(server.root, name)
	info, err := os.Lstat(path)
	if !safeFileInfo(info, err, server.uid, server.gid, mode, limit, allowEmpty) {
		return nil, errors.New("unsafe file")
	}
	return os.ReadFile(path)
}

func safeSnapshotFile(snapshot *os.Root, name string, uid, gid int, limit int64, allowEmpty bool) ([]byte, error) {
	info, err := snapshot.Lstat(name)
	if !safeFileInfo(info, err, uid, gid, 0o640, limit, allowEmpty) {
		return nil, errors.New("unsafe snapshot file")
	}
	return snapshot.ReadFile(name)
}

func safeFileInfo(info os.FileInfo, err error, uid, gid int, mode fs.FileMode, limit int64, allowEmpty bool) bool {
	actualUID, actualGID, ok := identity(info)
	return err == nil && ok && info.Mode().IsRegular() && info.Mode().Type() == 0 && info.Mode().Perm() == mode && info.Size() >= 0 && (allowEmpty || info.Size() > 0) && info.Size() <= limit && actualUID == uid && actualGID == gid
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
