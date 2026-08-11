package ubuntu

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type NativeRunner func(context.Context, string, []string, int64) ([]byte, error)

type NativeValidator struct {
	run                        NativeRunner
	xray, singBox, cloudflared string
	certbot, mihomo            string
}

func NewNativeValidator(runner NativeRunner) NativeValidator {
	validator, _ := NewNativeValidatorAt(runner, "/snap/bin/certbot")
	return validator
}

func NewNativeValidatorAt(runner NativeRunner, certbot string) (NativeValidator, error) {
	if runner == nil {
		runner = runNative
	}
	if !supportedCertbotPath(certbot) {
		return NativeValidator{}, errors.New("unsupported Certbot distribution")
	}
	return NativeValidator{run: runner, xray: "/usr/bin/xray", singBox: "/usr/bin/sing-box", cloudflared: "/usr/bin/cloudflared", certbot: certbot, mihomo: "/usr/bin/mihomo"}, nil
}

func newNativeValidatorForComponents(runner NativeRunner, root string) NativeValidator {
	if runner == nil {
		runner = runNative
	}
	return NativeValidator{
		run:  runner,
		xray: filepath.Join(root, "xray"), singBox: filepath.Join(root, "sing-box"), cloudflared: filepath.Join(root, "cloudflared"),
		certbot: filepath.Join(root, "certbot/bin/certbot"), mihomo: filepath.Join(root, "mihomo"),
	}
}

func (validator NativeValidator) Validate(ctx context.Context, metadata softwarelifecycle.PayloadMetadata) error {
	if validator.run == nil || validator.certbot == "" || !validSubscriptions(metadata.Artifacts) {
		return errors.New("release qualification refused")
	}
	directory, err := os.MkdirTemp("", "sbxr-qualification-")
	if err != nil {
		return errors.New("release qualification unavailable")
	}
	defer os.RemoveAll(directory)
	if os.Chmod(directory, 0o700) != nil {
		return errors.New("release qualification unavailable")
	}
	paths := map[string]string{}
	for name, body := range metadata.Artifacts {
		path := filepath.Join(directory, name)
		if os.WriteFile(path, body, 0o600) != nil {
			return errors.New("release qualification unavailable")
		}
		paths[name] = path
	}
	certificate, key, err := qualificationCertificate()
	if err != nil {
		return errors.New("release qualification unavailable")
	}
	certificatePath, keyPath := filepath.Join(directory, "fullchain.pem"), filepath.Join(directory, "privkey.pem")
	if os.WriteFile(certificatePath, certificate, 0o600) != nil || os.WriteFile(keyPath, key, 0o600) != nil {
		return errors.New("release qualification unavailable")
	}
	singBox := bytes.ReplaceAll(metadata.Artifacts["sing-box.json"], []byte("/var/lib/sbxr/certificates/domain/current/fullchain.pem"), []byte(certificatePath))
	singBox = bytes.ReplaceAll(singBox, []byte("/var/lib/sbxr/certificates/domain/current/privkey.pem"), []byte(keyPath))
	if bytes.Equal(singBox, metadata.Artifacts["sing-box.json"]) || os.WriteFile(paths["sing-box.json"], singBox, 0o600) != nil {
		return errors.New("release qualification unavailable")
	}
	checks := []struct {
		code string
		name string
		args []string
		ok   func(string) bool
	}{
		{"xray-version", validator.xray, []string{"version"}, func(value string) bool { return versionFields(value, "Xray", "26.3.27") }},
		{"xray-config", validator.xray, []string{"run", "-test", "-config", paths["xray.json"]}, exitSuccess},
		{"sing-box-version", validator.singBox, []string{"version"}, func(value string) bool { return versionFields(value, "sing-box", "version", "1.13.16") }},
		{"sing-box-config", validator.singBox, []string{"check", "-c", paths["sing-box.json"]}, exitSuccess},
		{"sing-box-subscription", validator.singBox, []string{"check", "-c", paths["subscription-sing-box.json"]}, exitSuccess},
		{"cloudflared-version", validator.cloudflared, []string{"--version"}, func(value string) bool { return strings.HasPrefix(value, "cloudflared version 2026.7.3 ") }},
		{"cloudflared-config", validator.cloudflared, []string{"--config", paths["cloudflared.yml"], "tunnel", "ingress", "validate"}, exitSuccess},
		{"certbot-version", validator.certbot, []string{"--version"}, certbotAtLeast54},
		{"certbot-capabilities", validator.certbot, []string{"certonly", "--help", "all"}, func(value string) bool {
			return strings.Contains(value, "--required-profile") && strings.Contains(value, "--ip-address") && strings.Contains(value, "--staging")
		}},
		{"mihomo-version", validator.mihomo, []string{"-v"}, func(value string) bool { return versionFields(value, "Mihomo", "Meta", "v1.19.29") }},
		{"mihomo-config", validator.mihomo, []string{"-t", "-f", paths["subscription-mihomo.yaml"]}, exitSuccess},
	}
	for _, check := range checks {
		output, err := validator.run(ctx, check.name, check.args, 1<<20)
		if err != nil || !check.ok(string(output)) {
			return errors.New("release qualification refused: " + check.code)
		}
	}
	return nil
}

func qualificationCertificate() ([]byte, []byte, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "direct.example.com"}, DNSNames: []string{"direct.example.com"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	key, keyErr := x509.MarshalPKCS8PrivateKey(private)
	if err != nil || keyErr != nil {
		return nil, nil, errors.New("qualification certificate unavailable")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), nil
}

func supportedCertbotPath(path string) bool {
	if path == "/snap/bin/certbot" {
		return true
	}
	if !filepath.IsAbs(path) || filepath.Base(filepath.Dir(path)) != "bin" {
		return false
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	line, _, _ := strings.Cut(string(body), "\n")
	python := strings.TrimPrefix(line, "#!")
	root := filepath.Dir(filepath.Dir(path))
	configuration, configErr := os.ReadFile(filepath.Join(root, "pyvenv.cfg"))
	return configErr == nil && filepath.Dir(python) == filepath.Join(root, "bin") && bytes.Contains(configuration, []byte("home ="))
}

func validSubscriptions(artifacts map[string][]byte) bool {
	raw := artifacts["subscription-raw.txt"]
	lines := strings.Split(string(raw), "\n")
	if len(lines) != 6 {
		return false
	}
	for index, line := range lines {
		parsed, err := url.Parse(line)
		if err != nil || parsed.Scheme != []string{"vless", "vless", "vless", "hysteria2", "tuic", "anytls"}[index] || parsed.Host == "" {
			return false
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(string(artifacts["subscription-base64.txt"]))
	return err == nil && bytes.Equal(decoded, raw) && bytes.Equal(artifacts["subscription-v2rayn.txt"], artifacts["subscription-base64.txt"]) && bytes.Equal(artifacts["subscription-shadowrocket.txt"], artifacts["subscription-base64.txt"]) && json.Valid(artifacts["subscription-karing.json"]) && bytes.Equal(artifacts["subscription-karing.json"], artifacts["subscription-sing-box.json"]) && len(artifacts["subscription-mihomo.yaml"]) > 0
}

func exitSuccess(string) bool { return true }

func versionFields(value string, want ...string) bool {
	fields := strings.Fields(value)
	return len(fields) >= len(want) && slices.Equal(fields[:len(want)], want)
}

var certbotVersionPattern = regexp.MustCompile(`^certbot ([0-9]+)\.([0-9]+)(?:\.[0-9]+)?\s*$`)

func certbotAtLeast54(value string) bool {
	match := certbotVersionPattern.FindStringSubmatch(value)
	if match == nil {
		return false
	}
	major, majorErr := strconv.Atoi(match[1])
	minor, minorErr := strconv.Atoi(match[2])
	return majorErr == nil && minorErr == nil && (major > 5 || major == 5 && minor >= 4)
}

func runNative(ctx context.Context, name string, arguments []string, limit int64) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{"PATH=/usr/bin:/bin"}
	command.Stdin, command.Stderr = bytes.NewReader(nil), io.Discard
	var output bytes.Buffer
	command.Stdout = &boundedWriter{writer: &output, remaining: limit}
	if err := command.Run(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

type boundedWriter struct {
	writer    io.Writer
	remaining int64
}

func (writer *boundedWriter) Write(value []byte) (int, error) {
	if int64(len(value)) > writer.remaining {
		return 0, errors.New("validator output limit exceeded")
	}
	written, err := writer.writer.Write(value)
	writer.remaining -= int64(written)
	return written, err
}
