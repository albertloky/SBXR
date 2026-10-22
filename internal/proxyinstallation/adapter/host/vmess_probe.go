package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
)

func websocketReady(ctx context.Context, client *http.Client, address string) bool {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return false
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", key)
	response, err := client.Do(req)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	accept := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return response.StatusCode == http.StatusSwitchingProtocols && strings.EqualFold(response.Header.Get("Upgrade"), "websocket") && headerToken(response.Header.Get("Connection"), "upgrade") && response.Header.Get("Sec-WebSocket-Accept") == base64.StdEncoding.EncodeToString(accept[:])
}

func headerToken(value, expected string) bool {
	for _, token := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(token), expected) {
			return true
		}
	}
	return false
}

// ProbeVMess keeps all credentials in memory/stdin and suppresses subprocess
// output. It changes no service or client profile and always reaps its client.
func (a Adapter) ProbeVMess(ctx context.Context, source []byte, expectedIP string) string {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	facts, err := singboxadapter.New().CurrentConnectionFacts(source, expectedIP)
	if err != nil || facts.VMessHostname == "" {
		return "The protected VMess profile could not be decoded."
	}
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if !websocketReady(ctx, client, "http://127.0.0.1:10000"+singboxadapter.VMessWebSocketPath) {
		return "The local WebSocket origin did not complete a valid upgrade. Check the managed sing-box runtime and TCP 10000; keep the origin on loopback."
	}
	if !websocketReady(ctx, client, "https://"+facts.VMessHostname+singboxadapter.VMessWebSocketPath) {
		return "The public hostname did not complete a trusted TLS/WebSocket upgrade. Check your DNS route, edge certificate, tunnel health, HTTP origin, blank route path, WebSockets and any Access challenge. Do not disable TLS verification or account security."
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "A temporary loopback probe listener could not be allocated."
	}
	port := listener.Addr().(*net.TCPAddr).Port
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		listener.Close()
		return "Probe credentials could not be generated."
	}
	user, password := "sbxr-probe", base64.RawURLEncoding.EncodeToString(secret[:])
	config, err := singboxadapter.New().EncodeVMessProbeConfiguration(source, port, user, password)
	listener.Close()
	if err != nil {
		return "The isolated VMess-only probe configuration was refused."
	}
	command := exec.CommandContext(ctx, a.path("/usr/bin/sing-box"), "run", "-c", "/dev/stdin")
	return vmessTraffic(ctx, command, config, port, user, password, expectedIP, "https://api.ipify.org", nil, probeListenerOwned)
}

var probePIDPattern = regexp.MustCompile(`pid=([0-9]+),`)

func probeListenerOwned(ctx context.Context, port, pid int) bool {
	body, code, observed := commandOutput(ctx, "ss", "-H", "-ltnp", "sport", "=", ":"+strconv.Itoa(port))
	if !observed || code != 0 {
		return false
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "127.0.0.1:"+strconv.Itoa(port)+" ") {
		return false
	}
	pids := probePIDPattern.FindAllStringSubmatch(lines[0], -1)
	return len(pids) == 1 && pids[0][1] == strconv.Itoa(pid)
}

func vmessTraffic(ctx context.Context, command *exec.Cmd, config []byte, port int, user, password, expectedIP, endpoint string, tlsConfig *tls.Config, ownsListener func(context.Context, int, int) bool) string {
	command.Stdin = bytes.NewReader(config)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if command.Start() != nil {
		return "The isolated sing-box probe could not start."
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	defer func() { _ = command.Process.Kill(); <-done }()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	ready := false
	for !ready {
		conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp4", address)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		select {
		case err := <-done:
			done <- err
			return "The isolated sing-box probe exited before readiness."
		case <-ctx.Done():
			return "The VMess connection check was cancelled or timed out."
		case <-deadline.C:
			return "The isolated sing-box probe did not become ready."
		case <-tick.C:
		}
	}
	proxy := &url.URL{Scheme: "http", Host: address, User: url.UserPassword(user, password)}
	if ownsListener == nil || !ownsListener(ctx, port, command.Process.Pid) {
		return "The temporary loopback listener is not proved to belong to the isolated sing-box probe. No traffic result is accepted."
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16 << 10, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	response, err := client.Do(request)
	if err != nil {
		return "Authenticated VMess-only HTTPS traffic failed after the WebSocket upgrade. Check the selected tunnel/origin and Client Identity; local success is not a public connection pass."
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 128))
	ip, parseErr := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil || response.StatusCode != http.StatusOK || parseErr != nil || !ip.Is4() || ip.String() != expectedIP {
		return "VMess traffic did not return the expected server IPv4 from the HTTPS egress check. A redirect, wrong origin, changed egress or check-service failure is not a pass."
	}
	select {
	case err := <-done:
		done <- err
		return "The isolated sing-box probe stopped during the check."
	default:
	}
	return ""
}
