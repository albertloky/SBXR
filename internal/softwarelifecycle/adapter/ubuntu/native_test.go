package ubuntu_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	ubuntuadapter "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
)

func TestNativeValidatorReturnsOnlyTheExactSafeFailedCheck(t *testing.T) {
	codes := []string{"xray-version", "xray-config", "sing-box-version", "sing-box-config", "sing-box-subscription", "cloudflared-version", "cloudflared-config", "certbot-version", "certbot-capabilities", "mihomo-version", "mihomo-config"}
	for failedAt, code := range codes {
		t.Run(code, func(t *testing.T) {
			calls := 0
			runner := func(_ context.Context, name string, arguments []string, _ int64) ([]byte, error) {
				if calls == failedAt {
					return nil, errors.New("SECRET-MARKER")
				}
				calls++
				switch name + " " + strings.Join(arguments, " ") {
				case "/usr/bin/xray version":
					return []byte("Xray 26.3.27\n"), nil
				case "/usr/bin/sing-box version":
					return []byte("sing-box version 1.13.16\n"), nil
				case "/usr/bin/cloudflared --version":
					return []byte("cloudflared version 2026.7.3 (built 2026-08-01)\n"), nil
				case "/snap/bin/certbot --version":
					return []byte("certbot 5.4.0\n"), nil
				case "/snap/bin/certbot certonly --help all":
					return []byte("--required-profile --ip-address --staging\n"), nil
				case "/usr/bin/mihomo -v":
					return []byte("Mihomo Meta v1.19.29\n"), nil
				default:
					return nil, nil
				}
			}
			err := ubuntuadapter.NewNativeValidator(runner).Validate(t.Context(), qualificationMetadata(softwarelifecycle.AMD64))
			if err == nil || err.Error() != "release qualification refused: "+code {
				t.Fatalf("failed check = %v", err)
			}
		})
	}
}

func TestNativeValidatorUsesEveryExactQualifiedBaselineAndRepresentation(t *testing.T) {
	metadata := qualificationMetadata(softwarelifecycle.AMD64)
	commands := [][]string{}
	certbotVersion := "certbot 5.4.0\n"
	mihomoVersion := "Mihomo Meta v1.19.29\n"
	runner := func(_ context.Context, name string, arguments []string, _ int64) ([]byte, error) {
		commands = append(commands, append([]string{name}, arguments...))
		switch name + " " + strings.Join(arguments, " ") {
		case "/usr/bin/xray version":
			return []byte("Xray 26.3.27\n"), nil
		case "/usr/bin/sing-box version":
			return []byte("sing-box version 1.13.16\n"), nil
		case "/usr/bin/cloudflared --version":
			return []byte("cloudflared version 2026.7.3 (built 2026-08-01)\n"), nil
		case "/snap/bin/certbot --version":
			return []byte(certbotVersion), nil
		case "/snap/bin/certbot certonly --help all":
			return []byte("--required-profile --ip-address --staging\n"), nil
		case "/usr/bin/mihomo -v":
			return []byte(mihomoVersion), nil
		default:
			return []byte("native validator success details\n"), nil
		}
	}
	if err := ubuntuadapter.NewNativeValidator(runner).Validate(t.Context(), metadata); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 11 || !reflect.DeepEqual(commands[0], []string{"/usr/bin/xray", "version"}) {
		t.Fatalf("native commands = %#v", commands)
	}
	certbotVersion = "certbot 6.0.0\n"
	if err := ubuntuadapter.NewNativeValidator(runner).Validate(t.Context(), metadata); err != nil {
		t.Fatal("newer supported Certbot refused")
	}
	certbotVersion = "certbot 5.3.9\n"
	if err := ubuntuadapter.NewNativeValidator(runner).Validate(t.Context(), metadata); err == nil {
		t.Fatal("Certbot below 5.4 accepted")
	}
	certbotVersion = "certbot 6.0.garbage\n"
	if err := ubuntuadapter.NewNativeValidator(runner).Validate(t.Context(), metadata); err == nil {
		t.Fatal("malformed Certbot version accepted")
	}
	certbotVersion = "certbot 5.4.0\n"
	mihomoVersion = "unrelated-program v1.19.29\n"
	if err := ubuntuadapter.NewNativeValidator(runner).Validate(t.Context(), metadata); err == nil {
		t.Fatal("spoofed Mihomo version accepted")
	}
	mihomoVersion = "Mihomo Meta v1.19.29\n"
	metadata.Artifacts["subscription-v2rayn.txt"] = []byte("changed")
	if err := ubuntuadapter.NewNativeValidator(runner).Validate(t.Context(), metadata); err == nil {
		t.Fatal("changed subscription representation accepted")
	}
	root := t.TempDir()
	certbot := filepath.Join(root, "bin", "certbot")
	if os.MkdirAll(filepath.Dir(certbot), 0o700) != nil || os.WriteFile(certbot, []byte("#!"+filepath.Join(root, "bin", "python3")+"\n"), 0o700) != nil || os.WriteFile(filepath.Join(root, "pyvenv.cfg"), []byte("home = /usr/bin\n"), 0o600) != nil {
		t.Fatal("pip fixture unavailable")
	}
	if _, err := ubuntuadapter.NewNativeValidatorAt(runner, certbot); err != nil {
		t.Fatal("supported pip virtual environment refused")
	}
	if _, err := ubuntuadapter.NewNativeValidatorAt(runner, filepath.Join(root, "certbot")); err == nil {
		t.Fatal("unproved Certbot distribution accepted")
	}
}
