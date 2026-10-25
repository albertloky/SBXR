//go:build ignore

// Run from the repository root using Go 1.26.6. Fixed synthetic inputs only.
package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
)

type vector struct {
	Name        string `json:"name"`
	UUID        string `json:"uuid"`
	Private     string `json:"private_key"`
	ShortID     string `json:"short_id"`
	Destination string `json:"destination"`
	ServerName  string `json:"server_name"`
	VMess       string `json:"vmess_hostname"`
	Accepted    bool   `json:"accepted"`
	Output      string `json:"output"`
}

func main() {
	out := "tests/testdata/server_configuration"
	if len(os.Args) == 2 {
		out = os.Args[1]
	}
	write := func(name string, body []byte) {
		if os.WriteFile(filepath.Join(out, name), body, 0644) != nil {
			panic("fixture write failed")
		}
	}
	base := vector{Name: "standard", UUID: "12345678-1234-4234-8234-123456789abc", Private: strings.Repeat("A", 43), ShortID: "01020304", Destination: "google.com:443", ServerName: "google.com"}
	vectors := []vector{}
	add := func(v vector) {
		// All key inputs decode to the same zero private key. No crypto generation.
		id := singbox.Identity{UUID: v.UUID, PrivateKey: v.Private, PublicKey: "L-V9o0fNYkMVKNqsX7spBzD_9oSvxM_C7ZCZX1jLO3Q", ShortID: v.ShortID}
		b, e := singbox.New().EncodeServerConfiguration(id, v.Destination, v.ServerName)
		if e == nil && v.VMess != "" {
			b, e = singbox.New().WithVMessWebSocket(b, v.VMess)
		}
		v.Accepted = e == nil
		if e == nil {
			v.Output = string(b)
		}
		vectors = append(vectors, v)
	}
	add(base)
	for _, field := range []string{"uuid", "key", "short", "destination", "name", "vmess"} {
		values := map[string][]string{
			"uuid":        {"", strings.ToUpper(base.UUID), "12345678-1234-5234-8234-123456789abc", "12345678-1234-4234-7234-123456789abc", "12345678-1234-4234-b234-123456789abc", base.UUID + "\n"},
			"key":         {"", strings.Repeat("A", 42), strings.Repeat("A", 44), base.Private + "=", base.Private[:42] + "B", "\r\n" + base.Private[:10] + "\n" + base.Private[10:], " " + base.Private, "+" + base.Private[1:]},
			"short":       {"", "00000000", "ABCDEF01", "aBcDeF01", "010203", "0102030405", "0102030g", "01020304\n"},
			"destination": {"", "google.com", "google.com:0", "google.com:65536", "google.com:1", "google.com:65535", "google.com:+0443", "google.com:-443", "google.com: 443", ":443", "[2001:db8::1]:443", "[fe80::1%eth0]:443", "2001:db8::1:443", "[host]:443", "[::1]443", "x]:443", "x:443:1", "[::1]:443]", "x\n:443", "example.com:18446744073709551616"},
			"name":        {"", "EXAMPLE.COM", "a..b", "name\nvalue", "a<&>b", "line\u2028next\u2029last", "é.example"},
			"vmess":       {"tunnel.example.com", "a.b", "127.000.0.1", "127.0.0.1", "localhost", "TUNNEL.example.com", "https://tunnel.example.com", "a..b", "a.b.", "a_b.c", "a.b:443", "a.b\n", strings.Repeat("a", 63) + ".example.com", strings.Repeat("a", 64) + ".example.com"},
		}[field]
		for i, value := range values {
			v := base
			v.Name = field + "-" + strconv.Itoa(i)
			switch field {
			case "uuid":
				v.UUID = value
			case "key":
				v.Private = value
			case "short":
				v.ShortID = value
			case "destination":
				v.Destination = value
			case "name":
				v.ServerName = value
			case "vmess":
				v.VMess = value
			}
			add(v)
		}
	}
	b, e := json.MarshalIndent(vectors, "", "  ")
	if e != nil {
		panic("fixture encode failed")
	}
	write("go-vectors.json", append(b, '\n'))
	standard := vectors[0].Output
	write("standard.json", []byte(standard))
	vmess, e := singbox.New().WithVMessWebSocket([]byte(standard), "tunnel.example.com")
	if e != nil {
		panic("synthetic VMess refused")
	}
	write("vless-vmess.json", vmess)

	// Extract the exact unexported constant and pinned setup values without changing Go source.
	f, e := parser.ParseFile(token.NewFileSet(), "internal/proxyinstallation/adapter/host/tunnel.go", nil, 0)
	if e != nil {
		panic("parse failed")
	}
	for _, d := range f.Decls {
		if g, ok := d.(*ast.GenDecl); ok {
			for _, s := range g.Specs {
				if v, ok := s.(*ast.ValueSpec); ok {
					for i, n := range v.Names {
						if n.Name == "tunnelUnit" {
							lit := v.Values[i].(*ast.BasicLit)
							text, e := strconv.Unquote(lit.Value)
							if e != nil {
								panic("unit failed")
							}
							write("sbxr-tunnel.service", []byte(text))
						}
					}
				}
			}
		}
	}
	authority := host.TunnelAuthority{TunnelID: "12345678-1234-4234-8234-123456789abc", TokenSHA256: strings.Repeat("1", 64), BinarySHA256: strings.Repeat("2", 64)}
	b, _ = json.MarshalIndent(authority.Resources(), "", "  ")
	write("tunnel-resources.json", append(b, '\n'))
	f, e = parser.ParseFile(token.NewFileSet(), "internal/proxyinstallation/proxyinstallation.go", nil, 0)
	if e != nil {
		panic("parse pins failed")
	}
	for _, d := range f.Decls {
		if g, ok := d.(*ast.GenDecl); ok {
			for _, s := range g.Specs {
				if v, ok := s.(*ast.ValueSpec); ok && len(v.Names) == 1 && v.Names[0].Name == "hostSetupSpec" {
					pins := map[string]any{}
					for _, elt := range v.Values[0].(*ast.CompositeLit).Elts {
						kv := elt.(*ast.KeyValueExpr)
						lit := kv.Value.(*ast.BasicLit)
						if lit.Kind == token.STRING {
							pins[kv.Key.(*ast.Ident).Name], _ = strconv.Unquote(lit.Value)
						} else {
							pins[kv.Key.(*ast.Ident).Name], _ = strconv.Atoi(lit.Value)
						}
					}
					b, _ = json.MarshalIndent(pins, "", "  ")
					write("standard-pins.json", append(b, '\n'))
				}
			}
		}
	}
}
