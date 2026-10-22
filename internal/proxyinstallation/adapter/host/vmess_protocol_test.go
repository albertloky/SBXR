package host

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
)

// Opt in with a checksum-verified pinned sing-box binary. All traffic stays on
// ephemeral loopback fixtures; no Cloudflare account, DNS or outside host is used.
func TestVMessTrafficWithPinnedSingBox(t *testing.T) {
	binary := os.Getenv("SBXR_TEST_SINGBOX")
	if binary == "" {
		t.Skip("requires checksum-verified sing-box 1.14.3")
	}
	port := func() int {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	a := singboxadapter.New()
	id, _ := a.PrepareIdentity()
	source, _ := a.EncodeServerConfiguration(id, "google.com:443", "google.com")
	source, _ = a.WithVMessWebSocket(source, "example.com")
	var server map[string]any
	json.Unmarshal(source, &server)
	originPort := port()
	in := server["inbounds"].([]any)[1].(map[string]any)
	in["listen_port"] = originPort
	server["inbounds"] = []any{in}
	body, _ := json.Marshal(server)
	command := exec.CommandContext(ctx, binary, "run", "-c", "/dev/stdin")
	command.Stdin = bytes.NewReader(body)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { command.Process.Kill(); command.Wait() }()
	originURL := "http://127.0.0.1:" + strconv.Itoa(originPort)
	for {
		conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(originPort)))
		if err == nil {
			conn.Close()
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual VMess origin did not start")
		case <-time.After(10 * time.Millisecond):
		}
	}
	origin, _ := url.Parse(originURL)
	edge := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(origin))
	defer edge.Close()
	edgeURL, _ := url.Parse(edge.URL)
	edgePort, _ := strconv.Atoi(edgeURL.Port())
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: edge.Certificate().Raw}))
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "8.8.8.8") }))
	defer endpoint.Close()
	for _, validIdentity := range []bool{true, false} {
		clientPort := port()
		config, err := a.EncodeVMessProbeConfiguration(source, clientPort, "probe", "temporary-password")
		if err != nil {
			t.Fatal(err)
		}
		var client map[string]any
		json.Unmarshal(config, &client)
		out := client["outbounds"].([]any)[0].(map[string]any)
		out["server"], out["server_port"] = "127.0.0.1", edgePort
		out["tls"].(map[string]any)["certificate"] = []string{cert}
		if !validIdentity {
			replacement, _ := a.PrepareIdentity()
			out["uuid"] = replacement.UUID
		}
		config, _ = json.Marshal(client)
		probe := exec.CommandContext(ctx, binary, "run", "-c", "/dev/stdin")
		owns := func(ctx context.Context, port, pid int) bool {
			if runtime.GOOS == "linux" {
				return probeListenerOwned(ctx, port, pid)
			}
			return true
		}
		problem := vmessTraffic(ctx, probe, config, clientPort, "probe", "temporary-password", "8.8.8.8", endpoint.URL, endpoint.Client().Transport.(*http.Transport).TLSClientConfig, owns)
		if (problem == "") != validIdentity {
			t.Fatalf("actual VMess credential acceptance mismatch: valid=%t, diagnostic=%s", validIdentity, problem)
		}
		if probe.ProcessState == nil {
			t.Fatal("actual VMess client was not reaped")
		}
	}
}
