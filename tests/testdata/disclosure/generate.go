//go:build ignore

// Run from repository root using Go 1.26.6. Synthetic inputs; no host effects.
package main

import (
	"os"
	"path/filepath"

	"github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
)

func main() {
	for _, name := range []string{"standard", "vless-vmess"} {
		server, err := os.ReadFile(filepath.Join("tests/testdata/server_configuration", name+".json"))
		if err != nil {
			panic("synthetic server fixture unavailable")
		}
		client, err := singbox.New().EncodeClientConfiguration(server, "8.8.8.8")
		if err != nil {
			panic("synthetic client encoding refused")
		}
		if err := os.WriteFile(filepath.Join("tests/testdata/disclosure", "client-"+name+".json"), client, 0644); err != nil {
			panic("fixture publication failed")
		}
	}
}
