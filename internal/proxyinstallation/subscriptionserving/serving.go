// Package subscriptionserving owns the private, bounded HTTPS runtime. It has
// no durable authority and performs no filesystem or recovery operations.
package subscriptionserving

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
)

type Code string

const (
	Ready   Code = "SUBSCRIPTION-SERVING-READY"
	Refused Code = "SUBSCRIPTION-SERVING-REFUSED"
	Stopped Code = "SUBSCRIPTION-SERVING-STOPPED"
	Expired Code = "SUBSCRIPTION-SERVING-CERTIFICATE-EXPIRED"
	Failed  Code = "SUBSCRIPTION-SERVING-FAILED"
)

type Generation struct {
	LinkID           string
	CredentialSHA256 [32]byte
}

func (Generation) String() string   { return "Subscription generation (redacted)" }
func (Generation) GoString() string { return "Subscription generation (redacted)" }
func (Generation) MarshalJSON() ([]byte, error) {
	return []byte(`"Subscription generation (redacted)"`), nil
}

// Certificate is one Host-validated immutable archive generation. Identities
// are selected by the Ownership Record, not inferred from canonical symlinks.
type Certificate struct {
	Chain, Key             []byte
	ChainSHA256, KeySHA256 [32]byte
	Lineage                string
	Generation             int
}

func (Certificate) String() string               { return "TLS material (redacted)" }
func (Certificate) GoString() string             { return "TLS material (redacted)" }
func (Certificate) MarshalJSON() ([]byte, error) { return []byte(`"TLS material (redacted)"`), nil }

type State struct {
	artifact    string
	ip          string
	generation  Generation
	certificate tls.Certificate
	expires     time.Time
}

func (*State) String() string   { return "Subscription state (redacted)" }
func (*State) GoString() string { return "Subscription state (redacted)" }

type Module struct {
	roots   *x509.CertPool
	now     func() time.Time
	mu      sync.Mutex
	loaded  *State
	running bool
}

func New(roots *x509.CertPool, now func() time.Time) *Module {
	if roots != nil {
		roots = roots.Clone()
	}
	if now == nil {
		now = time.Now
	}
	return &Module{roots: roots, now: now}
}

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var name = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
var linkID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (m *Module) Prepare(f singbox.ConnectionFacts, generation Generation, cert Certificate) (*State, Code) {
	ip, err := netip.ParseAddr(f.PublicIPv4)
	public, publicErr := base64.RawURLEncoding.Strict().DecodeString(f.PublicKey)
	short, shortErr := hex.DecodeString(f.ShortID)
	if err != nil || !ip.Is4() || ip.String() != f.PublicIPv4 || !uuid.MatchString(f.UUID) || !name.MatchString(f.ServerName) || publicErr != nil || len(public) != 32 || shortErr != nil || len(short) != 4 || hex.EncodeToString(short) != f.ShortID || !linkID.MatchString(generation.LinkID) || generation.CredentialSHA256 == [32]byte{} {
		return nil, Refused
	}
	if cert.Lineage != "sbxr-subscription" || cert.Generation < 1 || cert.Generation > 1000000 || len(cert.Chain) > 64<<10 || len(cert.Key) > 16<<10 || sha256.Sum256(cert.Chain) != cert.ChainSHA256 || sha256.Sum256(cert.Key) != cert.KeySHA256 {
		return nil, Refused
	}
	pair, err := tls.X509KeyPair(cert.Chain, cert.Key)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, Refused
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.IP(ip.AsSlice())) || len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 {
		return nil, Refused
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, Refused
		}
		intermediates.AddCert(cert)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: m.roots, Intermediates: intermediates, DNSName: f.PublicIPv4, CurrentTime: m.now()})
	if err != nil {
		return nil, Refused
	}
	expires := leaf.NotAfter
	for _, cert := range chains[0] {
		if cert.NotAfter.Before(expires) {
			expires = cert.NotAfter
		}
	}
	escape := func(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
	artifact := "vless://" + f.UUID + "@" + f.PublicIPv4 + ":443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=" + escape(f.ServerName) + "&fp=chrome&pbk=" + escape(f.PublicKey) + "&sid=" + escape(f.ShortID) + "&type=tcp#" + escape("SBXR Proxy ("+f.PublicIPv4+")") + "\n"
	if len(artifact) == 0 || len(artifact) > 4096 {
		return nil, Refused
	}
	return &State{artifact: artifact, ip: f.PublicIPv4, generation: generation, certificate: pair, expires: expires}, Ready
}

type Facts struct {
	Code    Code
	LinkID  string
	Expires time.Time
	Runtime Runtime
}

type Runtime string

const (
	RuntimeUnknown Runtime = "cannot be verified"
	RuntimeServing Runtime = "serving"
	RuntimeStopped Runtime = "stopped"
)

func (m *Module) Inspect(state *State) Facts {
	if state == nil || state.artifact == "" {
		return Facts{Code: Refused, Runtime: RuntimeUnknown}
	}
	code := Ready
	if !m.now().Before(state.expires) {
		code = Expired
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	runtime := RuntimeUnknown
	if m.loaded == state {
		runtime = RuntimeStopped
		if m.running {
			runtime = RuntimeServing
		}
	}
	return Facts{Code: code, LinkID: state.generation.LinkID, Expires: state.expires, Runtime: runtime}
}

// Serve owns and closes listener on every path. Eight workers include TLS,
// headers and response writes. No keep-alive, HTTP/2, callbacks or access log.
// A single bounded overload responder never serves an artifact.
func (m *Module) Serve(ctx context.Context, state *State, listener net.Listener) Code {
	if listener == nil {
		return Refused
	}
	defer listener.Close()
	if m.Inspect(state).Code != Ready {
		return Refused
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.IP.String() != state.ip {
		return Refused
	}
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return Refused
	}
	m.loaded, m.running = state, true
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.running = false; m.mu.Unlock() }()
	ctx, cancel := context.WithDeadline(ctx, state.expires)
	defer cancel()
	config := &tls.Config{Certificates: []tls.Certificate{state.certificate}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	var workers sync.WaitGroup
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		<-ctx.Done()
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for conn := range connections {
			conn.Close()
		}
	}()
	defer func() { cancel(); <-closed; workers.Wait() }()
	limiter := sourceLimiter{entries: make(map[netip.Addr]source)}
	for {
		conn, err := listener.Accept()
		if err != nil {
			if !time.Now().Before(state.expires) {
				return Expired
			}
			if ctx.Err() != nil {
				return Stopped
			}
			return Failed
		}
		mu.Lock()
		if ctx.Err() != nil {
			mu.Unlock()
			conn.Close()
			continue
		}
		overloaded := len(connections) >= 8
		connections[conn] = true
		mu.Unlock()
		work := func() {
			defer func() { conn.Close(); mu.Lock(); delete(connections, conn); mu.Unlock() }()
			m.respond(ctx, state, tls.Server(conn, config), &limiter, overloaded)
		}
		if overloaded {
			work()
		} else {
			workers.Add(1)
			go func() { defer workers.Done(); work() }()
		}
	}
}

func (m *Module) respond(ctx context.Context, state *State, conn *tls.Conn, limiter *sourceLimiter, overloaded bool) {
	deadline := time.Now().Add(5 * time.Second)
	if overloaded {
		deadline = time.Now().Add(time.Second)
	}
	if state.expires.Before(deadline) {
		deadline = state.expires
	}
	conn.SetDeadline(deadline)
	if conn.HandshakeContext(ctx) != nil {
		return
	}
	if overloaded {
		writeResponse(conn, 503)
		return
	}
	remote, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil || !limiter.allow(remote.Addr().Unmap(), m.now()) {
		writeResponse(conn, 429)
		return
	}
	request, err := http.ReadRequest(bufio.NewReader(io.LimitReader(conn, 8192)))
	if err != nil {
		writeResponse(conn, 404)
		return
	}
	// Do not close request.Body: that can drain hostile unbounded input.
	path := request.RequestURI
	valid := request.Method == "GET" && request.Proto == "HTTP/1.1" && request.Host != "" && request.ContentLength == 0 && len(request.TransferEncoding) == 0 && request.URL.RawQuery == "" && !request.URL.ForceQuery && len(path) == 46 && strings.HasPrefix(path, "/s/")
	presented := ""
	if valid {
		presented = path[3:]
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(presented)
	digest := sha256.Sum256([]byte(presented))
	if !valid || err != nil || len(decoded) != 32 || subtle.ConstantTimeCompare(digest[:], state.generation.CredentialSHA256[:]) != 1 || m.Inspect(state).Code != Ready || ctx.Err() != nil {
		writeResponse(conn, 404)
		return
	}
	fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(state.artifact), state.artifact)
}

func writeResponse(w io.Writer, status int) {
	text := http.StatusText(status)
	retry := ""
	if status == 429 || status == 503 {
		retry = "Retry-After: 10\r\n"
	}
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n%s\n", status, text, retry, len(text)+1, text)
}

type source struct {
	tokens       float64
	refill, last time.Time
}
type sourceLimiter struct {
	mu      sync.Mutex
	entries map[netip.Addr]source
}

func (l *sourceLimiter) allow(ip netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for address, entry := range l.entries {
		if now.Sub(entry.last) >= 10*time.Minute {
			delete(l.entries, address)
		}
	}
	entry, ok := l.entries[ip]
	if !ok {
		if len(l.entries) >= 1024 {
			return false
		}
		entry = source{tokens: 6, refill: now}
	}
	entry.tokens = min(6, entry.tokens+max(0, now.Sub(entry.refill).Seconds())/10)
	entry.refill, entry.last = now, now
	allowed := entry.tokens >= 1
	if allowed {
		entry.tokens--
	}
	l.entries[ip] = entry
	return allowed
}
