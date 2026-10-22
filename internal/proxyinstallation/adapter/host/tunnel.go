package host

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const TunnelTokenPath = "/etc/cloudflared/sbxr.token"
const TunnelBinaryPath = "/usr/bin/cloudflared"
const TunnelUnitPath = "/etc/systemd/system/sbxr-tunnel.service"
const TunnelWantsPath = "/etc/systemd/system/multi-user.target.wants/sbxr-tunnel.service"
const tunnelService = "sbxr-tunnel.service"
const tunnelExec = "/usr/bin/cloudflared --config /dev/null --no-autoupdate tunnel --metrics 127.0.0.1:0 run --token-file /run/credentials/sbxr-tunnel.service/tunnel-token"
const tunnelUnit = `[Unit]
Description=SBXR dedicated Cloudflare Tunnel connector
Wants=network-online.target
After=network-online.target sing-box.service

[Service]
Type=simple
DynamicUser=yes
LoadCredential=tunnel-token:/etc/cloudflared/sbxr.token
ExecStart=/usr/bin/cloudflared --config /dev/null --no-autoupdate tunnel --metrics 127.0.0.1:0 run --token-file %d/tunnel-token
Restart=on-failure
RestartSec=5s
TimeoutStopSec=15s
KillMode=control-group
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
UMask=0077
StandardInput=null
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
`

// TunnelAuthority owns only the dedicated unit and enablement link. The
// Owner-provisioned binary and token are bound prerequisites, never removed.
type TunnelAuthority struct {
	TunnelID     string `json:"tunnel_id"`
	TokenSHA256  string `json:"token_sha256"`
	BinarySHA256 string `json:"binary_sha256"`
}

var tunnelIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var tunnelDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (t TunnelAuthority) Valid() bool {
	return tunnelIDPattern.MatchString(t.TunnelID) && tunnelDigestPattern.MatchString(t.TokenSHA256) && tunnelDigestPattern.MatchString(t.BinarySHA256)
}

func (t TunnelAuthority) Resources() []string {
	return []string{TunnelUnitPath + " root:root 0644 one-link sha256:" + digest([]byte(tunnelUnit)), TunnelUnitPath + ".sbxr-next root-owned synchronized no-replace publication", TunnelWantsPath + " root-owned symlink ../sbxr-tunnel.service"}
}

func TunnelUnitSHA256() string { return digest([]byte(tunnelUnit)) }

func (a Adapter) tunnelRun(ctx context.Context, name string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	run := a.tunnelCommand
	if run == nil {
		run = commandOutput
	}
	body, code, observed := run(ctx, name, args...)
	return strings.TrimSpace(body), observed && code == 0 && ctx.Err() == nil
}

func (a Adapter) tunnelPrerequisites(ctx context.Context) (TunnelAuthority, string) {
	token, err := a.protectedServingFile(TunnelTokenPath, 0o600, "")
	if err != nil || len(token) > 16384 {
		return TunnelAuthority{}, "Save the dedicated tunnel token in /etc/cloudflared/sbxr.token as a root-owned 0600 regular file with one link; see the VMess setup guide. Never enter a token in the hostname prompt."
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(token)))
	var claims struct {
		Account string `json:"a"`
		ID      string `json:"t"`
		Secret  string `json:"s"`
	}
	if err != nil || json.Unmarshal(decoded, &claims) != nil || !tunnelIDPattern.MatchString(claims.ID) || claims.Account == "" || claims.Secret == "" {
		return TunnelAuthority{}, "The protected file is not a remotely managed tunnel token. Copy only the token from your dedicated tunnel's connector instructions, then try again."
	}
	binaryDigest, ok := a.tunnelBinaryDigest()
	if !ok {
		return TunnelAuthority{}, "Install official cloudflared at /usr/bin/cloudflared (root-owned 0755, one link), version 2025.4.0 or newer; see the VMess setup guide."
	}
	version, ok := a.tunnelRun(ctx, a.path(TunnelBinaryPath), "--version")
	match := regexp.MustCompile(`^cloudflared version ([0-9]{4})\.([0-9]{1,2})\.([0-9]+)(?: |$)`).FindStringSubmatch(version)
	year, month := 0, 0
	if len(match) == 4 {
		year, _ = strconv.Atoi(match[1])
		month, _ = strconv.Atoi(match[2])
	}
	if !ok || year < 2025 || year == 2025 && month < 4 || month < 1 || month > 12 {
		return TunnelAuthority{}, "cloudflared must support --token-file (2025.4.0 or newer). Update it from Cloudflare's official package source, then try again."
	}
	return TunnelAuthority{TunnelID: claims.ID, TokenSHA256: digest(token), BinarySHA256: binaryDigest}, ""
}

func (a Adapter) tunnelBinaryDigest() (string, bool) {
	if a.safeParents(TunnelBinaryPath) != nil {
		return "", false
	}
	f, err := os.OpenFile(a.path(TunnelBinaryPath), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", false
	}
	defer f.Close()
	info, err := f.Stat()
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 || stat.Uid != a.ownerUID() || stat.Nlink != 1 || info.Size() <= 0 || info.Size() > 128<<20 {
		return "", false
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(f, 128<<20+1)); err != nil {
		return "", false
	}
	current, err := os.Lstat(a.path(TunnelBinaryPath))
	if err != nil || !os.SameFile(info, current) {
		return "", false
	}
	return hex.EncodeToString(hash.Sum(nil)), true
}

func (a Adapter) PreflightTunnel(ctx context.Context) (TunnelAuthority, string) {
	t, problem := a.tunnelPrerequisites(ctx)
	if problem != "" {
		return t, problem
	}
	if a.safeParents(TunnelUnitPath) != nil || a.safeParents(TunnelWantsPath) != nil {
		return TunnelAuthority{}, "The root-owned systemd unit directories are missing or unsafe. Restore the standard /etc/systemd/system/multi-user.target.wants directory without replacing existing files or links, then review setup again."
	}
	if !a.tunnelFilesSafe(false) || !a.tunnelQuiescent(ctx) {
		return TunnelAuthority{}, "The dedicated sbxr-tunnel.service name is occupied or cannot be inspected. Preserve existing services; use a fresh host or resolve only the dedicated name before reviewing setup again."
	}
	return t, ""
}

func (a Adapter) tunnelFilesSafe(allowOwned bool) bool {
	for _, directory := range []string{"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient"} {
		if directory == "/lib/systemd/system" {
			if info, err := os.Lstat(a.path("/lib")); err == nil && info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(a.path("/lib"))
				if err != nil || target != "usr/lib" && target != "/usr/lib" {
					return false
				}
				continue
			}
		}
		for _, suffix := range []string{tunnelService, tunnelService + ".d", "multi-user.target.wants/" + tunnelService, "multi-user.target.requires/" + tunnelService} {
			path := directory + "/" + suffix
			if allowOwned && (path == TunnelUnitPath || path == TunnelWantsPath) {
				continue
			}
			if !a.safelyAbsent(path) {
				return false
			}
		}
	}
	for _, path := range []string{TunnelUnitPath, TunnelWantsPath} {
		if err := a.safeParents(path); err != nil && !(errors.Is(err, os.ErrNotExist) && a.safelyAbsent(path)) {
			return false
		}
	}
	main, mainErr := os.Lstat(a.path(TunnelUnitPath))
	stage, stageErr := os.Lstat(a.path(TunnelUnitPath + ".sbxr-next"))
	links := uint64(1)
	if mainErr == nil && stageErr == nil && os.SameFile(main, stage) {
		links = 2
	}
	for _, path := range []string{TunnelUnitPath, TunnelUnitPath + ".sbxr-next"} {
		if a.safelyAbsent(path) {
			continue
		}
		body, err := a.protectedServingFileWithLinks(path, 0o644, digest([]byte(tunnelUnit)), links)
		if !allowOwned || err != nil || string(body) != tunnelUnit {
			return false
		}
	}
	if a.safelyAbsent(TunnelWantsPath) {
		return true
	}
	info, err := os.Lstat(a.path(TunnelWantsPath))
	stat, ok := infoSys(info)
	target, targetErr := os.Readlink(a.path(TunnelWantsPath))
	return allowOwned && err == nil && ok && stat.Uid == a.ownerUID() && stat.Nlink == 1 && info.Mode()&os.ModeSymlink != 0 && targetErr == nil && target == "../sbxr-tunnel.service"
}

func (a Adapter) tunnelShow(ctx context.Context, property string) (string, bool) {
	return a.tunnelRun(ctx, "systemctl", "show", "--property="+property, "--value", tunnelService)
}

func (a Adapter) tunnelQuiescent(ctx context.Context) bool {
	for _, property := range []string{"MainPID", "ControlPID"} {
		if v, ok := a.tunnelShow(ctx, property); !ok || v != "0" {
			return false
		}
	}
	v, ok := a.tunnelShow(ctx, "ActiveState")
	return ok && (v == "inactive" || v == "failed")
}

func (a Adapter) tunnelEffective(ctx context.Context) bool {
	for property, expected := range map[string]string{"LoadState": "loaded", "FragmentPath": TunnelUnitPath, "DropInPaths": "", "ExecCondition": "", "ExecStartPre": "", "ExecStartPost": "", "ExecReload": "", "ExecStop": "", "ExecStopPost": ""} {
		if v, ok := a.tunnelShow(ctx, property); !ok || v != expected {
			return false
		}
	}
	v, ok := a.tunnelShow(ctx, "ExecStart")
	path, argv, valid := exactSystemdExecStart(v)
	return ok && valid && path == TunnelBinaryPath && argv == tunnelExec
}

func (a Adapter) InstallTunnel(ctx context.Context, t TunnelAuthority) bool {
	current, problem := a.tunnelPrerequisites(ctx)
	if !t.Valid() || problem != "" || current != t || !a.tunnelFilesSafe(true) || a.safeParents(TunnelUnitPath) != nil || a.safeParents(TunnelWantsPath) != nil {
		return false
	}
	if a.safelyAbsent(TunnelUnitPath) && !a.tunnelQuiescent(ctx) {
		return false
	}
	if !a.publishSubscriptionFile(TunnelUnitPath, []byte(tunnelUnit), 0o644) {
		return false
	}
	if a.safelyAbsent(TunnelWantsPath) && (os.Symlink("../sbxr-tunnel.service", a.path(TunnelWantsPath)) != nil || a.syncOwnershipDirectory(a.path(filepath.Dir(TunnelWantsPath))) != nil) {
		return false
	}
	_, ok := a.tunnelRun(ctx, "systemctl", "daemon-reload")
	return ok && a.tunnelEffective(ctx)
}

func (a Adapter) StartTunnel(ctx context.Context, t TunnelAuthority) bool {
	current, problem := a.tunnelPrerequisites(ctx)
	if !t.Valid() || problem != "" || current != t || !a.tunnelFilesSafe(true) || a.safelyAbsent(TunnelUnitPath) || !a.tunnelEffective(ctx) {
		return false
	}
	_, ok := a.tunnelRun(ctx, "systemctl", "start", tunnelService)
	_, active := a.tunnelRun(ctx, "systemctl", "is-active", "--quiet", tunnelService)
	return ok && active
}

func (a Adapter) RemoveTunnel(ctx context.Context, t TunnelAuthority) bool {
	if !t.Valid() || !a.tunnelFilesSafe(true) {
		return false
	}
	if a.safelyAbsent(TunnelUnitPath) {
		if !a.tunnelQuiescent(ctx) {
			return false
		}
	} else {
		if _, ok := a.tunnelRun(ctx, "systemctl", "daemon-reload"); !ok || !a.tunnelEffective(ctx) {
			return false
		}
		if _, ok := a.tunnelRun(ctx, "systemctl", "stop", tunnelService); !ok || !a.tunnelQuiescent(ctx) {
			return false
		}
	}
	for _, path := range []string{TunnelWantsPath, TunnelUnitPath + ".sbxr-next", TunnelUnitPath} {
		if err := os.Remove(a.path(path)); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return false
		}
		if a.syncOwnershipDirectory(a.path(filepath.Dir(path))) != nil {
			return false
		}
	}
	_, ok := a.tunnelRun(ctx, "systemctl", "daemon-reload")
	return ok && a.tunnelFilesSafe(false)
}

func (a Adapter) TunnelRemovalSafe(ctx context.Context, t TunnelAuthority) bool {
	if !t.Valid() || !a.tunnelFilesSafe(true) {
		return false
	}
	if a.safelyAbsent(TunnelUnitPath) {
		return a.tunnelQuiescent(ctx)
	}
	return a.tunnelEffective(ctx)
}

const tunnelCapability = "SBXR-DEDICATED-TUNNEL-V1"

func TunnelCapability() string { return strings.Clone(tunnelCapability) }
