package host

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
)

func TestWebSocketReadinessRequiresTheCompleteUpgrade(t *testing.T) {
	for _, mode := range []string{"valid", "status", "accept", "upgrade", "connection", "redirect", "untrusted"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "redirect" {
					http.Redirect(w, r, "/other", 302)
					return
				}
				if mode == "status" {
					w.WriteHeader(200)
					return
				}
				sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				w.Header().Set("Sec-WebSocket-Accept", base64.StdEncoding.EncodeToString(sum[:]))
				w.Header().Set("Upgrade", "websocket")
				w.Header().Set("Connection", "keep-alive, Upgrade")
				if mode == "accept" {
					w.Header().Set("Sec-WebSocket-Accept", "wrong")
				}
				if mode == "upgrade" {
					w.Header().Set("Upgrade", "other")
				}
				if mode == "connection" {
					w.Header().Set("Connection", "close")
				}
				w.WriteHeader(101)
			}))
			defer server.Close()
			client := server.Client()
			if mode == "untrusted" {
				client = &http.Client{}
			}
			client.Timeout = time.Second
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			if got := websocketReady(t.Context(), client, server.URL+"/sbxr-vmess"); got != (mode == "valid") {
				t.Fatalf("readiness = %t", got)
			}
		})
	}
}

func TestVMessTrafficProbeUsesAuthenticatedProxyTLSAndReapsProcess(t *testing.T) {
	for _, mode := range []string{"pass", "wrong-egress", "redirect", "http-error", "bad-tls", "exit", "cancel", "foreign-listener"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Proxy-Authorization") != "" {
					t.Error("proxy credentials leaked to endpoint")
				}
				switch mode {
				case "wrong-egress":
					io.WriteString(w, "9.9.9.9")
				case "redirect":
					http.Redirect(w, r, "/other", 302)
				case "http-error":
					w.WriteHeader(502)
				default:
					io.WriteString(w, "8.8.8.8")
				}
			}))
			defer server.Close()
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()
			a := singboxadapter.New()
			id, _ := a.PrepareIdentity()
			source, _ := a.EncodeServerConfiguration(id, "google.com:443", "google.com")
			source, _ = a.WithVMessWebSocket(source, "tunnel.example.com")
			config, err := a.EncodeVMessProbeConfiguration(source, port, "probe-user", "probe-password")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if mode == "cancel" {
				ctx, cancel = context.WithTimeout(t.Context(), 150*time.Millisecond)
				defer cancel()
			}
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVMessProbeProcess$")
			command.Env = append(os.Environ(), "SBXR_VMESS_PROBE_HELPER="+mode)
			var tlsConfig *tls.Config
			if mode != "bad-tls" {
				tlsConfig = server.Client().Transport.(*http.Transport).TLSClientConfig
			}
			problem := vmessTraffic(ctx, command, config, port, "probe-user", "probe-password", "8.8.8.8", server.URL, tlsConfig, func(_ context.Context, checkedPort, pid int) bool {
				return mode != "foreign-listener" && checkedPort == port && pid == command.Process.Pid
			})
			if (problem == "") != (mode == "pass") {
				t.Fatal("unexpected traffic outcome", problem)
			}
			if command.ProcessState == nil {
				t.Fatal("probe process was not reaped")
			}
			if strings.Contains(strings.Join(command.Args, " "), id.UUID) || strings.Contains(strings.Join(command.Args, " "), "probe-password") {
				t.Fatal("credential in process args")
			}
		})
	}
}

func TestVMessProbeProcess(t *testing.T) {
	mode := os.Getenv("SBXR_VMESS_PROBE_HELPER")
	if mode == "" {
		return
	}
	if mode == "exit" {
		os.Exit(2)
	}
	if mode == "cancel" {
		time.Sleep(30 * time.Second)
		os.Exit(2)
	}
	var config struct {
		Inbounds []struct {
			Port  int `json:"listen_port"`
			Users []struct{ Username, Password string }
		}
		Outbounds []struct{ Type string }
	}
	if json.NewDecoder(os.Stdin).Decode(&config) != nil || len(config.Inbounds) != 1 || len(config.Inbounds[0].Users) != 1 || len(config.Outbounds) != 1 || config.Outbounds[0].Type != "vmess" {
		os.Exit(3)
	}
	in := config.Inbounds[0]
	server := &http.Server{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(in.Port)), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(in.Users[0].Username+":"+in.Users[0].Password))
		if r.Method != "CONNECT" || r.Header.Get("Proxy-Authorization") != want {
			w.WriteHeader(407)
			return
		}
		remote, err := net.DialTimeout("tcp", r.Host, time.Second)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer remote.Close()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go io.Copy(remote, conn)
		io.Copy(conn, remote)
	})}
	server.ListenAndServe()
	os.Exit(4)
}
