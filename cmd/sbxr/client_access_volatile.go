package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/subscriptionpublication"
)

func clientAccessVolatileSHA(root string) (string, error) {
	return clientAccessVolatileSHAAt(root, func(ctx context.Context, name string, arguments ...string) ([]byte, error) {
		command := exec.CommandContext(ctx, name, arguments...)
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
		command.Stdin, command.Stderr = bytes.NewReader(nil), io.Discard
		return command.Output()
	})
}

func clientAccessVolatileSHAAt(root string, output func(context.Context, string, ...string) ([]byte, error)) (string, error) {
	if output == nil {
		return "", errors.New("Client Access volatile observation unavailable")
	}
	hash := sha256.New()
	paths := []string{"etc/sbxr/xray/config.json", "etc/sbxr/sing-box/config.json"}
	for _, name := range subscriptionpublication.Names() {
		paths = append(paths, filepath.Join("var/lib/sbxr/subscriptions/current", name))
	}
	paths = append(paths, "var/lib/sbxr/subscriptions/current/serving.json")
	for _, name := range paths {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || len(body) == 0 {
			return "", errors.New("Client Access volatile artifacts are unavailable")
		}
		_, _ = hash.Write([]byte(name + "\x00"))
		_, _ = hash.Write(body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, command := range [][]string{{"nft", "-j", "list", "table", "inet", "sbxr"}, {"ss", "-H", "-lntup"}, {"systemctl", "is-active", "xray.service", "sing-box.service", "sbxr-subscription.service", "cloudflared.service"}} {
		body, err := output(ctx, command[0], command[1:]...)
		if err != nil {
			return "", errors.New("Client Access volatile system state is unavailable")
		}
		if command[0] == "ss" {
			var owned []string
			for _, line := range strings.Split(string(body), "\n") {
				if strings.Contains(line, `(("xray",`) || strings.Contains(line, `(("sing-box",`) || strings.Contains(line, `(("sbxr",`) {
					owned = append(owned, line)
				}
			}
			body = []byte(strings.Join(owned, "\n"))
		}
		_, _ = hash.Write([]byte(command[0] + "\x00"))
		_, _ = hash.Write(body)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
