//go:build ignore

// Run from the repository root with Go 1.26.6. No randomness or network is used.
package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
)

type facts singbox.ConnectionFacts // Deliberately bypass diagnostic redaction for synthetic fixtures.
type vector struct {
	Name     string `json:"name"`
	Facts    facts  `json:"facts"`
	Artifact string `json:"artifact"`
	Accepted bool   `json:"accepted"`
}

func main() {
	out := "tests/testdata/subscription_artifact"
	if len(os.Args) == 2 {
		out = os.Args[1]
	}
	write := func(name string, body []byte) {
		if err := os.WriteFile(filepath.Join(out, name), body, 0644); err != nil {
			panic("fixture write failed")
		}
	}
	a := singbox.New()
	id := singbox.Identity{UUID: "12345678-1234-4234-8234-123456789abc", PrivateKey: strings.Repeat("A", 43), PublicKey: "L-V9o0fNYkMVKNqsX7spBzD_9oSvxM_C7ZCZX1jLO3Q", ShortID: "01020304"}
	server, err := a.EncodeServerConfiguration(id, "www.example.com:443", "www.example.com")
	if err != nil {
		panic("synthetic server refused")
	}
	base, err := a.CurrentConnectionFacts(server, "198.51.100.42")
	if err != nil {
		panic("synthetic facts refused")
	}
	for _, mode := range []string{"vless", "vless-vmess"} {
		if mode == "vless-vmess" {
			server, err = a.WithVMessWebSocket(server, "tunnel.example.com")
			if err != nil {
				panic("synthetic VMess refused")
			}
		}
		f, err := a.CurrentConnectionFacts(server, base.PublicIPv4)
		if err != nil {
			panic("synthetic facts refused")
		}
		body, err := a.EncodeSubscriptionArtifact(f)
		if err != nil {
			panic("synthetic artifact refused")
		}
		write(mode+".txt", body)
		client, err := a.EncodeClientConfiguration(server, base.PublicIPv4)
		if err != nil {
			panic("synthetic client refused")
		}
		write("client-"+mode+".json", client)
		if mode == "vless-vmess" {
			line := strings.Split(string(body), "\n")[1]
			node, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "vmess://"))
			if err != nil {
				panic("synthetic VMess decode failed")
			}
			write("vmess-v2.json", append(node, '\n'))
		}
	}
	vectors := []vector{}
	add := func(name string, f singbox.ConnectionFacts) {
		artifact, err := a.EncodeSubscriptionArtifact(f)
		vectors = append(vectors, vector{name, facts(f), string(artifact), err == nil})
	}
	add("standard", base)
	change := func(field, value string) singbox.ConnectionFacts {
		f := base
		switch field {
		case "ip":
			f.PublicIPv4 = value
		case "uuid":
			f.UUID = value
		case "server":
			f.ServerName = value
		case "key":
			f.PublicKey = value
		case "short":
			f.ShortID = value
		case "vmess":
			f.VMessHostname = value
		}
		return f
	}
	valuesByField := map[string][]string{
		"ip":     {"127.0.0.1", "0.0.0.0", "255.255.255.255", "192.168.1.1", "::1", "::ffff:198.51.100.42", "198.051.100.42", "198.51.100.42 ", "198.51.100.42:443", "", "example.com"},
		"uuid":   {"12345678-1234-4234-9234-123456789abc", "12345678-1234-4234-a234-123456789abc", "12345678-1234-4234-b234-123456789abc", strings.ToUpper(base.UUID), "12345678-1234-5234-8234-123456789abc", "12345678-1234-4234-7234-123456789abc", base.UUID + "\n", ""},
		"server": {"A", "EXAMPLE.COM", "a..b", "a.-.b", "a_b", "-a", "a-", "a.", "a b", "a&x=y", "é.example", "a\nnode", "", strings.Repeat("a", 253), strings.Repeat("a", 254)},
		"key":    {strings.Repeat("A", 43), base.PublicKey + "=", base.PublicKey[:42] + "R", base.PublicKey[:42], base.PublicKey + "A", "+" + base.PublicKey[1:], "/" + base.PublicKey[1:], " " + base.PublicKey, "\t" + base.PublicKey, "\r\n" + base.PublicKey[:8] + "\n" + base.PublicKey[8:] + "\r", ""},
		"short":  {"00000000", "ffffffff", "ABCDEF01", "010203", "0102030405", "0102030g", "01020304\n", ""},
		"vmess":  {"tunnel.example.com", "a.b", "1.2", "127.000.0.1", "TUNNEL.example.com", "https://tunnel.example.com", "127.0.0.1", "localhost", "a..b", "a.b.", "-a.b", "a-.b", "a_b.c", "a.b:443", "é.example", strings.Repeat("a", 63) + ".example.com", strings.Repeat("a", 64) + ".example.com", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61), strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62)},
	}
	fields := []string{}
	for field := range valuesByField {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	for _, field := range fields {
		for i, value := range valuesByField[field] {
			add(field+"-"+string(rune('a'+i)), change(field, value))
		}
	}
	// Strict Go base64 ignores CR/LF; percent expansion makes the 4096 bound reachable.
	bare, _ := a.EncodeSubscriptionArtifact(base)
	for _, size := range []int{4095, 4096, 4097} {
		f := base
		remainder := size - len(bare)
		if remainder%3 != 0 {
			f.ServerName += strings.Repeat("x", remainder%3)
			remainder -= remainder % 3
		}
		f.PublicKey += strings.Repeat("\n", remainder/3)
		add("artifact-limit-"+string(rune('a'+size-4095)), f)
	}
	body, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		panic("synthetic vectors failed")
	}
	write("go-vectors.json", append(body, '\n'))
}
