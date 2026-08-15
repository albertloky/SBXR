//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestGeneratedBootstrapCarriesTheExactSessionThroughRootInstallationPreflight(t *testing.T) {
	if _, err := exec.LookPath("sudo"); err != nil {
		t.Skip("Ubuntu command journey requires sudo")
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skip("Ubuntu command journey requires passwordless sudo")
	}
	record := filepath.Join(t.TempDir(), "preflight")
	helper := buildSSHLaunchJourneyHelper(t, record)
	stamped := stampSSHLaunchJourneyHelper(t, helper)
	fixture := newBootstrapFixture(t)
	oldDigest := sha256.Sum256(fixture.archive)
	newDigest := sha256.Sum256(stamped)
	fixture.index = strings.ReplaceAll(fixture.index, fmt.Sprintf(`"size":%d,"sha256":"%x"`, len(fixture.archive), oldDigest), fmt.Sprintf(`"size":%d,"sha256":"%x"`, len(stamped), newDigest))
	fixture.archive = stamped
	fixture.executablePath = helper
	fixture.ownerUID = fmt.Sprint(os.Geteuid())
	metadata, _, err := softwarelifecycle.ReadPayloadMetadata(bytes.NewReader(stamped), int64(len(stamped)))
	if err != nil {
		t.Fatal(err)
	}
	fixture.version = fmt.Sprintf(`{"build":{"repository":"%s","tag":"%s","commit":"%s","payload_sha256":"%s"},"architecture":"%s","state_schema":%d}`, metadata.Build.Repository, metadata.Build.Tag, metadata.Build.Commit, metadata.Build.PayloadSHA256, metadata.Architecture, metadata.StateSchema)
	fixture.writeBoundaries(t)

	output, err := fixture.run()
	result, readErr := os.ReadFile(record)
	if err != nil || readErr != nil || string(result) != "PORT=2222\nCLEAN=true\n" || strings.Contains(output, fixture.sshConnection) || strings.Contains(output, "PRIVATE-SECRET-MARKER") {
		redacted := strings.ReplaceAll(strings.ReplaceAll(output, fixture.sshConnection, "[redacted SSH identity]"), "PRIVATE-SECRET-MARKER", "[redacted marker]")
		t.Fatalf("command-level SSH Preservation journey failed safely: run=%v read=%v output=%q", err, readErr, redacted)
	}
}

func buildSSHLaunchJourneyHelper(t *testing.T, record string) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	repository := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	source, err := os.MkdirTemp(filepath.Join(repository, "cmd", "sbxr-release"), ".ssh-journey-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(source) })
	body := fmt.Sprintf(`package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/albertloky/SBXR/internal/networkpolicy"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type adapter struct{}

func (adapter) Observe(networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	identity := os.Getenv("SBXR_SSH_CONNECTION")
	digest := sha256.Sum256([]byte(identity))
	return networkpolicy.Observations{PublicIPv4: []string{"8.8.8.8"}, Listeners: []networkpolicy.Listener{{Address: "0.0.0.0", Port: 2222, Protocol: networkpolicy.TCP, Process: "sshd", Service: "ssh.service"}}, SSH: networkpolicy.SSHFacts{DetectedPort: 2222, ServerAddress: "203.0.113.10", CurrentSessions: []string{hex.EncodeToString(digest[:])}, SessionsComplete: true, Service: "ssh.service", Listener: net.JoinHostPort("0.0.0.0", "2222") + "/tcp"}}, nil
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "version" && os.Args[2] == "--json" {
		executable, _ := os.Open(os.Args[0])
		info, _ := executable.Stat()
		metadata, _, err := softwarelifecycle.ReadPayloadMetadata(executable, info.Size())
		if err != nil { os.Exit(1) }
		_ = json.NewEncoder(os.Stdout).Encode(struct { Build softwarelifecycle.EmbeddedBuildIdentity `+"`json:\"build\"`"+`; Architecture softwarelifecycle.Architecture `+"`json:\"architecture\"`"+`; StateSchema uint64 `+"`json:\"state_schema\"`"+` }{metadata.Build, metadata.Architecture, metadata.StateSchema})
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "private" && os.Args[2] == "owner-launch" {
		if err := softwareubuntu.LaunchOwnerConsole(context.Background()); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "private" && os.Args[2] == "root-owner-console" {
		err := softwareubuntu.ServeRootOwnerConsole(func() error {
			clean := os.Getenv("SSH_CONNECTION") == "" && os.Getenv("CLOUDFLARE_API_TOKEN") == "" && os.Getenv("LD_PRELOAD") == ""
			result := networkpolicy.New(adapter{}).InstallationPreflight(os.Getenv("SBXR_SSH_CONNECTION"))
			if result.Failure != nil || result.ActiveSSHPort == 0 { return fmt.Errorf("preflight refused") }
			return os.WriteFile(%q, []byte(fmt.Sprintf("PORT=%%d\nCLEAN=%%t\n", result.ActiveSSHPort, clean)), 0644)
		})
		if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
		return
	}
	if strings.Contains(strings.Join(os.Args, " "), "PRIVATE-SECRET-MARKER") { os.Exit(1) }
	os.Exit(1)
}
`, record)
	if err := os.WriteFile(filepath.Join(source, "main.go"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(t.TempDir(), "sbxr")
	command := exec.Command("go", "build", "-trimpath", "-o", helper, source)
	command.Dir = repository
	command.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build SSH launch journey helper: %v: %s", err, output)
	}
	return helper
}

func stampSSHLaunchJourneyHelper(t *testing.T, helper string) []byte {
	t.Helper()
	body, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := releaseMetadata(softwarelifecycle.EmbeddedBuildIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: "0123456789abcdef0123456789abcdef01234567"}, softwarelifecycle.Architecture(runtime.GOARCH))
	if err != nil {
		t.Fatal(err)
	}
	stamped, err := softwarelifecycle.StampPayload(body, metadata)
	if err != nil || os.WriteFile(helper, stamped, 0700) != nil {
		t.Fatal(err)
	}
	return stamped
}
