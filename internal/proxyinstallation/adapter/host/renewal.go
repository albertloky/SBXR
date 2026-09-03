package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
	"github.com/albertloky/SBXR/internal/proxyinstallation/subscriptionserving"
)

const (
	RenewalRecorderRole       = "--certbot-recorder"
	RenewalDeployRole         = "--certbot-deploy-hook"
	RenewalPostRole           = "--certbot-post-hook"
	OfficialRenewalInvocation = "snap-certbot-renew-v1"
	OwnerRenewalInvocation    = "snap-certbot-certonly-v1"
	RenewalDropInPath         = "/etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf"
	RenewalDeployHookPath     = "/etc/letsencrypt/renewal-hooks/deploy/sbxr-subscription"
	RenewalPostHookPath       = "/etc/letsencrypt/renewal-hooks/post/sbxr-subscription"
	RenewalEvidencePath       = "/var/lib/sbxr/renewal-attempts.json"
	RenewalEvidenceNextPath   = "/var/lib/sbxr/.renewal-attempts.json.next"
	RenewalAdmissionPath      = "/var/lib/sbxr/renewal-admission.lock"
	RenewalWriterPath         = "/var/lib/sbxr/renewal-writer.lock"

	RenewalRecorderRefused = 125
	maxRenewalAttempts     = 32
	maxRenewalEvidenceAge  = 48 * time.Hour
)

const RenewalDropIn = `[Service]
ExecStart=
ExecStart=/usr/local/bin/sbxr --certbot-recorder
`

const RenewalDeployHook = `#!/bin/sh
exec /usr/local/bin/sbxr --certbot-deploy-hook
`

const RenewalPostHook = `#!/bin/sh
exec /usr/local/bin/sbxr --certbot-post-hook
`

var renewalManagedFiles = []struct {
	path, body string
	mode       os.FileMode
}{
	{RenewalDropInPath, RenewalDropIn, 0644},
	{RenewalDeployHookPath, RenewalDeployHook, 0700},
	{RenewalPostHookPath, RenewalPostHook, 0700},
	{RenewalAdmissionPath, "sbxr renewal admission v1\n", 0600},
	{RenewalWriterPath, "sbxr renewal writer v1\n", 0600},
}

type RenewalAuthority struct {
	RecorderID string `json:"recorder_id"`
	Lineage    string `json:"lineage"`
	PublicIPv4 string `json:"public_ipv4"`
	Invocation string `json:"invocation"`
}

func (a RenewalAuthority) Valid() bool {
	id, err := hex.DecodeString(a.RecorderID)
	ip := net.ParseIP(a.PublicIPv4)
	return err == nil && len(id) == 16 && hex.EncodeToString(id) == a.RecorderID && a.RecorderID != strings.Repeat("0", 32) && a.Lineage == "sbxr-subscription" && ip != nil && ip.To4() != nil && ip.String() == a.PublicIPv4 && a.Invocation == OfficialRenewalInvocation
}

func (a RenewalAuthority) Resources() []string {
	return []string{
		RenewalDropInPath + " root:root 0644 one-link recorder-v1",
		RenewalDeployHookPath + " root:root 0700 one-link deploy-writer-v1",
		RenewalPostHookPath + " root:root 0700 one-link post-writer-v1",
		RenewalEvidencePath + " root:root 0600 one-link bounded-evidence-v1",
		RenewalAdmissionPath + " root:root 0600 one-link admission-v1",
		RenewalWriterPath + " root:root 0600 one-link writer-v1",
	}
}

type RenewalCompletion struct {
	ExitCode     int    `json:"exit_code"`
	CompletedAt  string `json:"completed_at"`
	OwnedOutcome string `json:"owned_outcome"`
	LineageAfter string `json:"lineage_after"`
}

type RenewalHookOutcome struct {
	Role          string `json:"role"`
	Outcome       string `json:"outcome"`
	RecordedAt    string `json:"recorded_at"`
	LineageTarget string `json:"lineage_target,omitempty"`
}

type RenewalAttempt struct {
	AttemptID     string              `json:"attempt_id"`
	Invocation    string              `json:"invocation"`
	StartedAt     string              `json:"started_at"`
	BootID        string              `json:"boot_id"`
	RecorderPID   int                 `json:"recorder_pid"`
	ProcessTick   uint64              `json:"process_tick"`
	LineageBefore string              `json:"lineage_before"`
	Completion    *RenewalCompletion  `json:"completion,omitempty"`
	DeployHook    *RenewalHookOutcome `json:"owned_deploy_hook,omitempty"`
	PostHook      *RenewalHookOutcome `json:"owned_post_hook,omitempty"`
}

type RenewalEvidence struct {
	Schema        int              `json:"schema"`
	RecorderID    string           `json:"recorder_id"`
	EstablishedAt string           `json:"established_at"`
	Attempts      []RenewalAttempt `json:"attempts"`
}

type RenewalAttemptState string

const (
	RenewalAttemptHealthy   RenewalAttemptState = "healthy"
	RenewalAttemptLive      RenewalAttemptState = "live"
	RenewalAttemptAbandoned RenewalAttemptState = "abandoned"
	RenewalAttemptFailed    RenewalAttemptState = "failed"
	RenewalAttemptUnsafe    RenewalAttemptState = "unsafe"
)

type RenewalInspection struct {
	Observation
	State    RenewalAttemptState
	Evidence RenewalEvidence
}

var activeRenewalAttempts sync.Map
var localProcessTick = uint64(time.Now().UnixNano())

func (a Adapter) InspectRenewal(authority RenewalAuthority) RenewalInspection {
	if !authority.Valid() || !a.renewalFiles(authority) || !a.renewalRoute() {
		return RenewalInspection{State: RenewalAttemptUnsafe}
	}
	evidence, body, err := a.synchronizeRenewalEvidence(authority)
	if err != nil || len(body) == 0 {
		return RenewalInspection{State: RenewalAttemptUnsafe}
	}
	lineageTarget, ok := a.renewalLineageTarget(authority)
	lineageGeneration, generationOK := renewalLineageGeneration(authority, lineageTarget)
	if !ok || !generationOK || !a.validRenewalCertificate(authority, lineageGeneration) {
		return RenewalInspection{State: RenewalAttemptUnsafe, Evidence: evidence}
	}
	state := RenewalAttemptHealthy
	for _, attempt := range evidence.Attempts {
		if attempt.Completion == nil {
			live, known := a.attemptLive(attempt)
			if !known {
				state = RenewalAttemptUnsafe
			} else if live {
				state = RenewalAttemptLive
			} else {
				state = RenewalAttemptAbandoned
			}
			break
		}
		if attempt.Completion.ExitCode != 0 || attempt.Completion.OwnedOutcome == "incomplete" {
			state = RenewalAttemptFailed
		}
	}
	observedAt, _ := time.Parse(time.RFC3339Nano, evidence.EstablishedAt)
	if len(evidence.Attempts) > 0 {
		latest := evidence.Attempts[len(evidence.Attempts)-1]
		observedAt, _ = time.Parse(time.RFC3339Nano, latest.StartedAt)
		if latest.Completion != nil {
			observedAt, _ = time.Parse(time.RFC3339Nano, latest.Completion.CompletedAt)
		}
	}
	if observedAt.Before(time.Now().UTC().Add(-maxRenewalEvidenceAge)) {
		state = RenewalAttemptUnsafe
	}
	if state == RenewalAttemptUnsafe {
		return RenewalInspection{State: state, Evidence: evidence}
	}
	return RenewalInspection{Observation: observation(state == RenewalAttemptHealthy, true), State: state, Evidence: evidence}
}

func (a Adapter) synchronizeRenewalEvidence(authority RenewalAuthority) (RenewalEvidence, []byte, error) {
	lock, ok := a.openRenewalLock(RenewalWriterPath, false)
	if !ok {
		return RenewalEvidence{}, nil, errors.New("renewal evidence busy")
	}
	defer lock.Close()
	_, body, err := a.readRenewalEvidence(authority)
	if err != nil {
		return RenewalEvidence{}, nil, err
	}
	info, err := os.Lstat(a.path(RenewalEvidencePath))
	if err != nil {
		return RenewalEvidence{}, nil, err
	}
	file, err := os.OpenFile(a.path(RenewalEvidencePath), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return RenewalEvidence{}, nil, err
	}
	opened, statErr := file.Stat()
	syncErr := file.Sync()
	closeErr := file.Close()
	if statErr != nil || !os.SameFile(info, opened) || syncErr != nil || closeErr != nil || a.syncOwnershipDirectory(a.path(filepath.Dir(RenewalEvidencePath))) != nil {
		return RenewalEvidence{}, nil, errors.New("renewal evidence durability uncertain")
	}
	current, currentBody, err := a.readRenewalEvidence(authority)
	if err != nil || !bytes.Equal(body, currentBody) {
		return RenewalEvidence{}, nil, errors.New("renewal evidence changed")
	}
	return current, currentBody, nil
}

func (a Adapter) renewalFiles(authority RenewalAuthority) bool {
	if absent, inspected := a.inspectRecorderDirectory(); absent || !inspected.Accepted {
		return false
	}
	for _, file := range renewalManagedFiles {
		body, err := a.protectedServingFile(file.path, file.mode, "")
		if err != nil || string(body) != file.body {
			return false
		}
	}
	_, _, err := a.readRenewalEvidence(authority)
	return err == nil
}

func (a Adapter) renewalRoute() bool {
	return a.certbotRoute("/usr/local/bin/sbxr", "/usr/local/bin/sbxr --certbot-recorder")
}

func (a Adapter) officialRenewalRoute() bool {
	return a.certbotRoute("/usr/bin/snap", "/usr/bin/snap run --timer=00:00~24:00/2 certbot.renew") || a.certbotRoute("/usr/bin/snap", `/usr/bin/snap run --timer="00:00~24:00/2" certbot.renew`)
}

func (a Adapter) certbotRoute(expectedPath, expectedArguments string) bool {
	run := a.subscriptionCommand
	if run == nil {
		run = commandOutput
	}
	body, code, observed := run(context.Background(), "systemctl", "show", "--property=ExecStart", "--value", "snap.certbot.renew.service")
	path, arguments, exact := exactSystemdExecStart(body)
	if !observed || code != 0 || !exact || path != expectedPath || arguments != expectedArguments {
		return false
	}
	body, code, observed = run(context.Background(), "systemctl", "show", "--property=FragmentPath", "--value", "snap.certbot.renew.service")
	if !observed || code != 0 || strings.TrimSpace(body) != "/etc/systemd/system/snap.certbot.renew.service" {
		return false
	}
	body, code, observed = run(context.Background(), "systemctl", "show", "--property=LoadState", "--value", "snap.certbot.renew.timer")
	if !observed || code != 0 || strings.TrimSpace(body) != "loaded" {
		return false
	}
	for property, expected := range map[string]string{
		"FragmentPath": "/etc/systemd/system/snap.certbot.renew.timer",
		"DropInPaths":  "",
		"Unit":         "snap.certbot.renew.service",
	} {
		body, code, observed = run(context.Background(), "systemctl", "show", "--property="+property, "--value", "snap.certbot.renew.timer")
		if !observed || code != 0 || strings.TrimSpace(body) != expected {
			return false
		}
	}
	body, code, observed = run(context.Background(), "systemctl", "show", "--property=TimersCalendar", "--value", "snap.certbot.renew.timer")
	if !observed || code != 0 || !officialTimersCalendar(body) {
		return false
	}
	for _, property := range []string{"UnitFileState", "ActiveState"} {
		body, code, observed = run(context.Background(), "systemctl", "show", "--property="+property, "--value", "snap.certbot.renew.timer")
		if !observed || code != 0 || strings.TrimSpace(body) != map[string]string{"UnitFileState": "enabled", "ActiveState": "active"}[property] {
			return false
		}
	}
	body, code, observed = run(context.Background(), "snap", "list", "certbot", "--unicode=always", "--color=never")
	if !observed || code != 0 {
		return false
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) != 2 || strings.Join(strings.Fields(lines[0]), " ") != "Name Version Rev Tracking Publisher Notes" {
		return false
	}
	fields := strings.Fields(lines[1])
	if len(fields) != 6 || fields[0] != "certbot" || fields[4] != "certbot-eff✓" || fields[5] != "classic" && fields[5] != "classic,held" {
		return false
	}
	version := strings.Split(fields[1], ".")
	if len(version) != 3 {
		return false
	}
	major, e1 := strconv.Atoi(version[0])
	minor, e2 := strconv.Atoi(version[1])
	_, e3 := strconv.Atoi(version[2])
	if e1 != nil || e2 != nil || e3 != nil || major < 5 || major == 5 && minor < 4 {
		return false
	}
	body, code, observed = run(context.Background(), "snap", "changes")
	if !observed || code != 0 {
		return false
	}
	changeLines := strings.Split(strings.TrimSpace(body), "\n")
	if strings.TrimSpace(body) != "" && strings.Join(strings.Fields(changeLines[0]), " ") != "ID Status Spawn Ready Summary" {
		return false
	}
	for _, line := range changeLines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[1] != "Done" && fields[1] != "Error" && fields[1] != "Undone" {
			return false
		}
	}
	return a.renewalHooksSafe()
}

var timerCalendar = regexp.MustCompile(`OnCalendar=\*-\*-\* ([0-9]{2}):([0-9]{2}):([0-9]{2})`)

func officialTimersCalendar(value string) bool {
	matches := timerCalendar.FindAllStringSubmatch(value, -1)
	if len(matches) != 2 || strings.Count(value, "OnCalendar=") != 2 {
		return false
	}
	morning := 0
	for _, match := range matches {
		hour, hourErr := strconv.Atoi(match[1])
		minute, minuteErr := strconv.Atoi(match[2])
		second, secondErr := strconv.Atoi(match[3])
		if hourErr != nil || minuteErr != nil || secondErr != nil || hour > 23 || minute > 59 || second > 59 {
			return false
		}
		if hour < 12 {
			morning++
		}
	}
	return morning == 1
}

func exactSystemdExecStart(body string) (string, string, bool) {
	value := strings.TrimSpace(body)
	if !strings.HasPrefix(value, "{") || !strings.HasSuffix(value, "}") || strings.Count(value, "{") != 1 || strings.Count(value, "}") != 1 {
		fields := strings.Fields(value)
		if len(fields) == 0 {
			return "", "", false
		}
		return fields[0], value, true
	}
	parts := strings.Split(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(value, "{"), "}")), " ; ")
	values := map[string]string{}
	seen := map[string]bool{}
	for _, part := range parts {
		name, field, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || seen[name] || !slices.Contains([]string{"path", "argv[]", "ignore_errors", "start_time", "stop_time", "pid", "code", "status"}, name) {
			return "", "", false
		}
		seen[name] = true
		values[name] = field
	}
	if values["path"] == "" || values["argv[]"] == "" || values["ignore_errors"] != "no" {
		return "", "", false
	}
	return values["path"], values["argv[]"], true
}

func (a Adapter) renewalHooksSafe() bool {
	for _, directory := range []string{"/etc/letsencrypt/renewal-hooks/pre", "/etc/letsencrypt/renewal-hooks/deploy", "/etc/letsencrypt/renewal-hooks/post"} {
		entries, err := os.ReadDir(a.path(directory))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		info, infoErr := os.Lstat(a.path(directory))
		stat, ok := infoSys(info)
		if err != nil || infoErr != nil || !ok || !info.IsDir() || stat.Uid != a.ownerUID() || info.Mode().Perm()&0o022 != 0 || len(entries) > 128 {
			return false
		}
		for _, entry := range entries {
			path := filepath.Join(directory, entry.Name())
			body, mode, ok := a.safeRenewalConfig(path)
			if !ok {
				return false
			}
			if mode&0o111 != 0 && strings.Contains(string(body), "/usr/local/bin/sbxr") && path != RenewalDeployHookPath && path != RenewalPostHookPath {
				return false
			}
		}
	}
	paths := []string{"/etc/letsencrypt/cli.ini"}
	entries, err := os.ReadDir(a.path("/etc/letsencrypt/renewal"))
	if err == nil {
		if len(entries) > 128 {
			return false
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
				return false
			}
			paths = append(paths, filepath.Join("/etc/letsencrypt/renewal", entry.Name()))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false
	}
	for _, path := range paths {
		body, _, ok := a.safeRenewalConfig(path)
		if !ok {
			if a.safelyAbsent(path) {
				continue
			}
			return false
		}
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
			name, value, found := strings.Cut(line, "=")
			name = strings.ReplaceAll(strings.TrimSpace(name), "-", "_")
			if found && name == "no_directory_hooks" && !slices.Contains([]string{"false", "0", "no", "off"}, strings.ToLower(strings.TrimSpace(value))) {
				return false
			}
			if found && slices.Contains([]string{"pre_hook", "post_hook", "deploy_hook", "renew_hook"}, name) && strings.Contains(strings.TrimSpace(value), "/usr/local/bin/sbxr") {
				return false
			}
		}
	}
	return true
}

func (a Adapter) safeRenewalConfig(path string) ([]byte, os.FileMode, bool) {
	if a.safeParents(path) != nil {
		return nil, 0, false
	}
	info, err := os.Lstat(a.path(path))
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || stat.Uid != a.ownerUID() || stat.Nlink != 1 || info.Size() < 0 || info.Size() > 64<<10 {
		return nil, 0, false
	}
	file, err := os.OpenFile(a.path(path), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, false
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, 0, false
	}
	body, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	return body, info.Mode().Perm(), err == nil && len(body) <= 64<<10
}

func (a Adapter) renewalLineageTarget(authority RenewalAuthority) (string, bool) {
	path := "/etc/letsencrypt/live/" + authority.Lineage + "/cert.pem"
	if a.safeParents(path) != nil {
		return "", false
	}
	info, err := os.Lstat(a.path(path))
	stat, ok := infoSys(info)
	if err != nil || !ok || info.Mode()&os.ModeSymlink == 0 || stat.Uid != a.ownerUID() || stat.Nlink != 1 {
		return "", false
	}
	target, err := os.Readlink(a.path(path))
	_, valid := renewalLineageGeneration(authority, target)
	return target, err == nil && valid
}

func renewalLineageGeneration(authority RenewalAuthority, target string) (int, bool) {
	prefix := "../../archive/" + authority.Lineage + "/cert"
	generation, parseErr := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(target, prefix), ".pem"))
	return generation, parseErr == nil && strings.HasPrefix(target, prefix) && strings.HasSuffix(target, ".pem") && generation > 0 && target == prefix+strconv.Itoa(generation)+".pem"
}

func (a Adapter) validRenewalCertificate(authority RenewalAuthority, generation int) bool {
	if a.renewalCertificateValid != nil {
		return a.renewalCertificateValid(authority, generation)
	}
	suffix := strconv.Itoa(generation) + ".pem"
	leaf, e1 := a.protectedServingFile(servingArchive+"/cert"+suffix, 0644, "")
	issuers, e2 := a.protectedServingFile(servingArchive+"/chain"+suffix, 0644, "")
	chain, e3 := a.protectedServingFile(servingArchive+"/fullchain"+suffix, 0644, "")
	key, e4 := a.protectedServingFile(servingArchive+"/privkey"+suffix, 0600, "")
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !bytes.Equal(chain, append(append([]byte{}, leaf...), issuers...)) {
		return false
	}
	certificate := subscriptionserving.Certificate{Chain: chain, Key: key, ChainSHA256: sha256.Sum256(chain), KeySHA256: sha256.Sum256(key), Lineage: authority.Lineage, Generation: generation}
	profile := singboxadapter.ConnectionFacts{PublicIPv4: authority.PublicIPv4, UUID: "00000000-0000-4000-8000-000000000000", ServerName: authority.PublicIPv4, PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ShortID: "00000000"}
	generationID := subscriptionserving.Generation{LinkID: strings.Repeat("a", 32), CredentialSHA256: sha256.Sum256([]byte("renewal validation"))}
	_, code := subscriptionserving.New(a.renewalTrustRoots, nil).Prepare(profile, generationID, certificate)
	return code == subscriptionserving.Ready
}

func (a Adapter) readRenewalEvidence(authority RenewalAuthority) (RenewalEvidence, []byte, error) {
	body, err := a.protectedServingFile(RenewalEvidencePath, 0600, "")
	if err != nil || len(body) > 16<<10 {
		return RenewalEvidence{}, nil, errors.New("renewal evidence unavailable")
	}
	var evidence RenewalEvidence
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&evidence) != nil || decoder.Decode(&struct{}{}) != io.EOF || evidence.Schema != 1 || evidence.RecorderID != authority.RecorderID || len(evidence.Attempts) > maxRenewalAttempts {
		return RenewalEvidence{}, nil, errors.New("renewal evidence invalid")
	}
	seen := map[string]bool{}
	maximum := time.Now().UTC().Add(5 * time.Minute)
	established, timeErr := time.Parse(time.RFC3339Nano, evidence.EstablishedAt)
	if timeErr != nil || established.After(maximum) {
		return RenewalEvidence{}, nil, errors.New("renewal evidence anchor invalid")
	}
	latest := established
	for _, attempt := range evidence.Attempts {
		id, e := hex.DecodeString(attempt.AttemptID)
		started, timeErr := time.Parse(time.RFC3339Nano, attempt.StartedAt)
		_, lineageValid := renewalLineageGeneration(authority, attempt.LineageBefore)
		if e != nil || len(id) != 16 || hex.EncodeToString(id) != attempt.AttemptID || seen[attempt.AttemptID] || attempt.Invocation != authority.Invocation && attempt.Invocation != OwnerRenewalInvocation || attempt.RecorderPID < 1 || attempt.ProcessTick == 0 || attempt.BootID == "" || !lineageValid || timeErr != nil || started.Before(latest) || started.After(maximum) {
			return RenewalEvidence{}, nil, errors.New("renewal attempt invalid")
		}
		seen[attempt.AttemptID] = true
		var completed time.Time
		if attempt.Completion != nil {
			completed, timeErr = time.Parse(time.RFC3339Nano, attempt.Completion.CompletedAt)
			_, lineageValid = renewalLineageGeneration(authority, attempt.Completion.LineageAfter)
			expectedOutcome := ownedRenewalOutcome(authority, attempt, attempt.Completion.LineageAfter)
			if attempt.Completion.ExitCode < 0 || attempt.Completion.ExitCode > 255 || !lineageValid || timeErr != nil || completed.Before(started) || completed.After(maximum) || attempt.Completion.OwnedOutcome != expectedOutcome {
				return RenewalEvidence{}, nil, errors.New("renewal completion invalid")
			}
		}
		if attempt.DeployHook != nil && attempt.PostHook != nil {
			deployAt, _ := time.Parse(time.RFC3339Nano, attempt.DeployHook.RecordedAt)
			postAt, _ := time.Parse(time.RFC3339Nano, attempt.PostHook.RecordedAt)
			if postAt.Before(deployAt) {
				return RenewalEvidence{}, nil, errors.New("renewal hook order invalid")
			}
		}
		for role, hook := range map[string]*RenewalHookOutcome{RenewalDeployRole: attempt.DeployHook, RenewalPostRole: attempt.PostHook} {
			if hook != nil {
				recorded, parseErr := time.Parse(time.RFC3339Nano, hook.RecordedAt)
				_, targetValid := renewalLineageGeneration(authority, hook.LineageTarget)
				if hook.Role != role || hook.Outcome != "succeeded" && hook.Outcome != "failed" || role == RenewalDeployRole && !targetValid || role == RenewalPostRole && hook.LineageTarget != "" || parseErr != nil || recorded.Before(started) || recorded.After(maximum) || !completed.IsZero() && recorded.After(completed) {
					return RenewalEvidence{}, nil, errors.New("renewal hook invalid")
				}
			}
		}
		latest = started
		if !completed.IsZero() {
			latest = completed
		}
	}
	return evidence, body, nil
}

func ownedRenewalOutcome(authority RenewalAuthority, attempt RenewalAttempt, lineageAfter string) string {
	before, beforeValid := renewalLineageGeneration(authority, attempt.LineageBefore)
	after, afterValid := renewalLineageGeneration(authority, lineageAfter)
	if beforeValid && afterValid && before == after && attempt.DeployHook == nil && attempt.PostHook == nil {
		return "no-op"
	}
	if beforeValid && afterValid && after > before && (attempt.Invocation == OwnerRenewalInvocation && attempt.DeployHook == nil && attempt.PostHook == nil || attempt.DeployHook != nil && attempt.PostHook != nil && attempt.DeployHook.LineageTarget == lineageAfter && attempt.DeployHook.Outcome == "succeeded" && attempt.PostHook.Outcome == "succeeded") {
		return "renewed"
	}
	return "incomplete"
}

func (a Adapter) attemptLive(attempt RenewalAttempt) (bool, bool) {
	if attempt.RecorderPID == os.Getpid() {
		_, active := activeRenewalAttempts.Load(attempt.AttemptID)
		return active, true
	}
	boot, tick, known := a.observeProcessIdentity(attempt.RecorderPID)
	return known && boot == attempt.BootID && tick == attempt.ProcessTick, known
}

func (a Adapter) observeProcessIdentity(pid int) (string, uint64, bool) {
	if a.renewalProcessIdentity != nil {
		return a.renewalProcessIdentity(pid)
	}
	return processIdentity(pid)
}

func processIdentity(pid int) (string, uint64, bool) {
	if runtime.GOOS != "linux" {
		if pid == os.Getpid() {
			return "local-test-process", localProcessTick, true
		}
		return "", 0, false
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(boot) > 128 {
		return "", 0, false
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if errors.Is(err, os.ErrNotExist) {
		return "", 0, true
	}
	if err != nil || len(stat) > 4096 {
		return "", 0, false
	}
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return "", 0, false
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return "", 0, false
	}
	tick, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return strings.TrimSpace(string(boot)), tick, true
}

type RenewalAttemptRunner interface {
	Run(context.Context) int
	Abort()
}

type renewalAttemptRunner struct {
	adapter       Adapter
	authority     RenewalAuthority
	attempt       RenewalAttempt
	admission     *os.File
	command       []string
	holdAdmission bool
	finished      bool
}

// PrepareRenewalRecorder publishes the receipt while the caller still owns
// whole-host authority. Run releases admission before waiting for Certbot.
func (a Adapter) PrepareRenewalRecorder(authority RenewalAuthority) (RenewalAttemptRunner, bool) {
	return a.prepareRenewalAttempt(authority, OfficialRenewalInvocation, false, false, []string{"/usr/bin/snap", "run", "--timer=00:00~24:00/2", "certbot.renew"})
}

func (a Adapter) prepareRenewalAttempt(authority RenewalAuthority, invocation string, allowAbandoned, exclusive bool, command []string) (RenewalAttemptRunner, bool) {
	admission, ok := a.openRenewalLock(RenewalAdmissionPath, exclusive)
	if !ok {
		return nil, false
	}
	inspection := a.InspectRenewal(authority)
	if inspection.State == RenewalAttemptUnsafe || inspection.State == RenewalAttemptLive || inspection.State == RenewalAttemptAbandoned && !allowAbandoned {
		admission.Close()
		return nil, false
	}
	evidence, expected, err := a.readRenewalEvidence(authority)
	if err != nil {
		admission.Close()
		return nil, false
	}
	if len(evidence.Attempts) == maxRenewalAttempts {
		removable := -1
		for i, attempt := range evidence.Attempts {
			if attempt.Completion != nil && attempt.Completion.ExitCode == 0 && attempt.Completion.OwnedOutcome != "incomplete" {
				removable = i
				break
			}
		}
		if removable < 0 {
			admission.Close()
			return nil, false
		}
		evidence.Attempts = append(evidence.Attempts[:removable], evidence.Attempts[removable+1:]...)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		admission.Close()
		return nil, false
	}
	boot, tick, known := a.observeProcessIdentity(os.Getpid())
	if !known || boot == "" || tick == 0 {
		admission.Close()
		return nil, false
	}
	lineageBefore, ok := a.renewalLineageTarget(authority)
	lineageGeneration, generationOK := renewalLineageGeneration(authority, lineageBefore)
	if !ok || !generationOK || !a.validRenewalCertificate(authority, lineageGeneration) {
		admission.Close()
		return nil, false
	}
	attempt := RenewalAttempt{AttemptID: hex.EncodeToString(id), Invocation: invocation, StartedAt: time.Now().UTC().Format(time.RFC3339Nano), BootID: boot, RecorderPID: os.Getpid(), ProcessTick: tick, LineageBefore: lineageBefore}
	activeRenewalAttempts.Store(attempt.AttemptID, true)
	evidence.Attempts = append(evidence.Attempts, attempt)
	if !a.publishRenewalEvidence(authority, expected, evidence) {
		activeRenewalAttempts.Delete(attempt.AttemptID)
		admission.Close()
		return nil, false
	}
	return &renewalAttemptRunner{adapter: a, authority: authority, attempt: attempt, admission: admission, command: command, holdAdmission: exclusive}, true
}

func certbotCommand(ctx context.Context, name string, arguments ...string) *exec.Cmd {
	// Set the mask in the child only; changing Go's process-wide umask would
	// race unrelated secret writers. Certbot explicitly creates private keys 0600.
	args := append([]string{"-c", `umask 022; exec "$@"`, "sbxr-certbot", name}, arguments...)
	return exec.CommandContext(ctx, "/bin/sh", args...)
}

func (r *renewalAttemptRunner) Abort() {
	if r == nil || r.finished {
		return
	}
	r.finished = true
	activeRenewalAttempts.Delete(r.attempt.AttemptID)
	if r.admission != nil {
		r.admission.Close()
		r.admission = nil
	}
}

func (r *renewalAttemptRunner) Run(ctx context.Context) int {
	if r == nil || r.finished {
		return RenewalRecorderRefused
	}
	r.finished = true
	if r.admission != nil && !r.holdAdmission {
		r.admission.Close()
		r.admission = nil
	}
	if r.admission != nil {
		defer func() {
			r.admission.Close()
			r.admission = nil
		}()
	}
	defer activeRenewalAttempts.Delete(r.attempt.AttemptID)
	if len(r.command) == 0 {
		return RenewalRecorderRefused
	}
	run := r.adapter.renewalCommand
	code := 0
	if run != nil {
		code = run(ctx, r.command[0], r.command[1:]...)
	} else {
		command := certbotCommand(ctx, r.command[0], r.command[1:]...)
		environment := slices.DeleteFunc(os.Environ(), func(value string) bool {
			name, _, _ := strings.Cut(value, "=")
			return slices.Contains([]string{"SBXR_RENEWAL_ATTEMPT_ID", "RENEWED_LINEAGE", "RENEWED_DOMAINS", "FAILED_DOMAINS"}, name)
		})
		command.Env = append(environment, "SBXR_RENEWAL_ATTEMPT_ID="+r.attempt.AttemptID)
		command.Stdin, command.Stdout, command.Stderr = nil, nil, nil
		err := command.Run()
		if err != nil {
			code = RenewalRecorderRefused
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				code = exit.ExitCode()
			}
		}
	}
	if code < 0 || code > 255 {
		code = RenewalRecorderRefused
	}
	latest, expected, err := r.adapter.readRenewalEvidence(r.authority)
	if err != nil || len(latest.Attempts) == 0 || latest.Attempts[len(latest.Attempts)-1].AttemptID != r.attempt.AttemptID || latest.Attempts[len(latest.Attempts)-1].Completion != nil {
		return RenewalRecorderRefused
	}
	lineageAfter, ok := r.adapter.renewalLineageTarget(r.authority)
	if !ok {
		return RenewalRecorderRefused
	}
	attempt := &latest.Attempts[len(latest.Attempts)-1]
	attempt.Completion = &RenewalCompletion{ExitCode: code, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano), OwnedOutcome: ownedRenewalOutcome(r.authority, *attempt, lineageAfter), LineageAfter: lineageAfter}
	if !r.adapter.publishRenewalEvidence(r.authority, expected, latest) {
		return RenewalRecorderRefused
	}
	return code
}

func (a Adapter) RecordRenewalHook(authority RenewalAuthority, role string, environment map[string]string) bool {
	if role != RenewalDeployRole && role != RenewalPostRole || !a.renewalFiles(authority) {
		return false
	}
	for _, name := range []string{"SBXR_RENEWAL_ATTEMPT_ID", "RENEWED_LINEAGE", "RENEWED_DOMAINS", "FAILED_DOMAINS"} {
		if len(environment[name]) > 4096 {
			return false
		}
	}
	evidence, expected, err := a.readRenewalEvidence(authority)
	if err != nil || len(evidence.Attempts) == 0 {
		return false
	}
	index := len(evidence.Attempts) - 1
	attempt := &evidence.Attempts[index]
	live, known := a.attemptLive(*attempt)
	if attempt.AttemptID != environment["SBXR_RENEWAL_ATTEMPT_ID"] || attempt.Completion != nil || !known || !live {
		return false
	}
	outcome := "succeeded"
	lineageTarget := ""
	if role == RenewalDeployRole {
		lineage := filepath.Clean(environment["RENEWED_LINEAGE"])
		if !strings.HasPrefix(lineage, "/etc/letsencrypt/live/") {
			return false
		}
		if lineage != "/etc/letsencrypt/live/"+authority.Lineage {
			return !strings.Contains(lineage, authority.Lineage)
		}
		if attempt.DeployHook != nil {
			return false
		}
		var targetOK bool
		lineageTarget, targetOK = a.renewalLineageTarget(authority)
		generation, generationOK := renewalLineageGeneration(authority, lineageTarget)
		if !targetOK || !generationOK {
			return false
		}
		if !slices.Contains(strings.Fields(environment["RENEWED_DOMAINS"]), authority.PublicIPv4) || !a.validRenewalCertificate(authority, generation) {
			outcome = "failed"
		}
	} else {
		if attempt.PostHook != nil {
			return false
		}
		if slices.Contains(strings.Fields(environment["FAILED_DOMAINS"]), authority.PublicIPv4) {
			outcome = "failed"
		} else if !slices.Contains(strings.Fields(environment["RENEWED_DOMAINS"]), authority.PublicIPv4) {
			return true
		}
	}
	hook := &RenewalHookOutcome{Role: role, Outcome: outcome, RecordedAt: time.Now().UTC().Format(time.RFC3339Nano), LineageTarget: lineageTarget}
	if role == RenewalDeployRole {
		attempt.DeployHook = hook
	} else {
		attempt.PostHook = hook
	}
	return a.publishRenewalEvidence(authority, expected, evidence) && outcome == "succeeded"
}

func (a Adapter) publishRenewalEvidence(authority RenewalAuthority, expected []byte, evidence RenewalEvidence) bool {
	lock, ok := a.openRenewalLock(RenewalWriterPath, true)
	if !ok {
		return false
	}
	defer lock.Close()
	current, currentBody, err := a.readRenewalEvidence(authority)
	if err != nil || !bytes.Equal(currentBody, expected) || current.RecorderID != evidence.RecorderID || len(evidence.Attempts) > maxRenewalAttempts {
		return false
	}
	body, err := json.Marshal(evidence)
	if err != nil || len(body) > 16<<10 {
		return false
	}
	body = append(body, '\n')
	temporary := a.path(RenewalEvidenceNextPath)
	if staged, stagedErr := a.protectedServingFile(RenewalEvidenceNextPath, 0600, ""); stagedErr == nil {
		if !bytes.Equal(staged, body) {
			return false
		}
		file, err := os.OpenFile(temporary, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return false
		}
		syncErr, closeErr := file.Sync(), file.Close()
		if syncErr != nil || closeErr != nil || os.Rename(temporary, a.path(RenewalEvidencePath)) != nil {
			return false
		}
		return a.syncOwnershipDirectory(a.path(filepath.Dir(RenewalEvidencePath))) == nil
	} else if !errors.Is(stagedErr, os.ErrNotExist) {
		return false
	}
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return false
	}
	written, writeErr := file.Write(body)
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil || written != len(body) || syncErr != nil || closeErr != nil || os.Rename(temporary, a.path(RenewalEvidencePath)) != nil {
		_ = os.Remove(temporary)
		return false
	}
	return a.syncOwnershipDirectory(a.path(filepath.Dir(RenewalEvidencePath))) == nil
}

func (a Adapter) openRenewalLock(path string, exclusive bool) (*os.File, bool) {
	body := "sbxr renewal admission v1\n"
	if path == RenewalWriterPath {
		body = "sbxr renewal writer v1\n"
	}
	protected, err := a.protectedServingFile(path, 0600, "")
	if err != nil || string(protected) != body {
		return nil, false
	}
	file, err := os.OpenFile(a.path(path), os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, false
	}
	opened, openedErr := file.Stat()
	current, currentErr := os.Lstat(a.path(path))
	if openedErr != nil || currentErr != nil || !os.SameFile(opened, current) {
		file.Close()
		return nil, false
	}
	how := syscall.LOCK_SH | syscall.LOCK_NB
	if exclusive {
		how = syscall.LOCK_EX | syscall.LOCK_NB
	}
	if syscall.Flock(int(file.Fd()), how) != nil {
		file.Close()
		return nil, false
	}
	return file, true
}

type RenewalExclusion struct {
	authority         RenewalAuthority
	admission, writer *os.File
}

func (e *RenewalExclusion) Release() {
	if e == nil {
		return
	}
	if e.writer != nil {
		e.writer.Close()
		e.writer = nil
	}
	if e.admission != nil {
		e.admission.Close()
		e.admission = nil
	}
}

func (a Adapter) AcquireRenewalExclusion(authority RenewalAuthority) (*RenewalExclusion, bool) {
	entryPointsAbsent := a.renewalEntryPointsAbsent()
	if entryPointsAbsent {
		openRemaining := func(path string) (*os.File, bool) {
			file, ok := a.openRenewalLock(path, true)
			if ok {
				return file, true
			}
			return nil, a.safelyAbsent(path)
		}
		admission, admissionOK := openRemaining(RenewalAdmissionPath)
		writer, writerOK := openRemaining(RenewalWriterPath)
		exclusion := &RenewalExclusion{authority: authority, admission: admission, writer: writer}
		if !admissionOK || !writerOK || !a.renewalFilesSafeForRemoval(authority) {
			exclusion.Release()
			return nil, false
		}
		return exclusion, true
	}
	admission, ok := a.openRenewalLock(RenewalAdmissionPath, true)
	if !ok {
		return nil, false
	}
	writer, ok := a.openRenewalLock(RenewalWriterPath, true)
	if !ok {
		admission.Close()
		return nil, false
	}
	exclusion := &RenewalExclusion{authority: authority, admission: admission, writer: writer}
	if !a.renewalFilesSafeForRemoval(authority) {
		exclusion.Release()
		return nil, false
	}
	if !a.renewalEntryPointsAbsent() {
		evidence, _, err := a.readRenewalEvidence(authority)
		if err != nil {
			exclusion.Release()
			return nil, false
		}
		for _, attempt := range evidence.Attempts {
			live, known := a.attemptLive(attempt)
			if attempt.Completion == nil && (!known || live) {
				exclusion.Release()
				return nil, false
			}
		}
	}
	return exclusion, true
}

// RepairSubscriptionCertificate performs one reviewed replacement attempt.
// The caller retains whole-host authority and activates the published target.
func (a Adapter) RepairSubscriptionCertificate(ctx context.Context, authority RenewalAuthority) bool {
	if !authority.Valid() || !a.renewalFiles(authority) || !a.renewalRoute() || !a.renewalHooksSafe() {
		return false
	}
	beforeTarget, ok := a.renewalLineageTarget(authority)
	beforeGeneration, valid := renewalLineageGeneration(authority, beforeTarget)
	if !ok || !valid || !a.validRenewalCertificate(authority, beforeGeneration) {
		return false
	}
	for _, path := range certbotDirectoryLocks {
		if !a.certbotLockAvailable(path) {
			return false
		}
	}
	command := []string{"/snap/bin/certbot", "certonly", "--non-interactive", "--agree-tos", "--register-unsafely-without-email", "--standalone", "--preferred-challenges", "http", "--no-directory-hooks", "--force-renewal", "--cert-name", authority.Lineage, "--required-profile", "shortlived", "--ip-address", authority.PublicIPv4}
	runner, prepared := a.prepareRenewalAttempt(authority, OwnerRenewalInvocation, true, true, command)
	if !prepared || runner.Run(ctx) != 0 {
		return false
	}
	// Certbot unlinks its own lock files at exit. Establish fresh exclusion
	// before inspecting the result, rather than requiring those inodes to survive.
	exclusion, locked := a.AcquireServingExclusion()
	if !locked {
		return false
	}
	defer exclusion.Release()
	afterTarget, ok := a.renewalLineageTarget(authority)
	afterGeneration, valid := renewalLineageGeneration(authority, afterTarget)
	return ok && valid && afterGeneration > beforeGeneration && a.validRenewalCertificate(authority, afterGeneration)
}

// ResolveRenewalFailure clears only diagnosed evidence after the reviewed
// replacement is published, accepted, loaded, and freshly validated.
func (a Adapter) ResolveRenewalFailure(authority RenewalAuthority, accepted ServingAuthority) bool {
	if !authority.Valid() || !accepted.Valid() || !a.renewalFiles(authority) || !a.renewalRoute() {
		return false
	}
	target, ok := a.renewalLineageTarget(authority)
	generation, valid := renewalLineageGeneration(authority, target)
	published, publishedOK := a.publishedCertificateAuthority(authority, accepted)
	if !ok || !valid || generation != accepted.CertificateGeneration || !publishedOK || published != accepted {
		return false
	}
	evidence, expected, err := a.readRenewalEvidence(authority)
	if err != nil {
		return false
	}
	if len(evidence.Attempts) == 0 {
		return true
	}
	for _, attempt := range evidence.Attempts {
		if attempt.Completion == nil {
			live, known := a.attemptLive(attempt)
			if !known || live {
				return false
			}
		}
	}
	evidence.EstablishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	evidence.Attempts = nil
	return a.publishRenewalEvidence(authority, expected, evidence)
}

func (a Adapter) RemoveRenewalIntegration(ctx context.Context, authority RenewalAuthority, exclusion *RenewalExclusion) bool {
	if exclusion == nil || exclusion.authority != authority || !a.renewalFilesSafeForRemoval(authority) || (exclusion.admission == nil || exclusion.writer == nil) && !a.renewalEntryPointsAbsent() {
		return false
	}
	for _, path := range []string{RenewalDeployHookPath, RenewalPostHookPath, RenewalDropInPath} {
		if err := os.Remove(a.path(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false
		}
		if a.syncOwnershipDirectory(a.path(filepath.Dir(path))) != nil {
			return false
		}
	}
	if !a.renewalEntryPointsAbsent() {
		return false
	}
	run := a.subscriptionCommand
	if run == nil {
		run = commandOutput
	}
	_, code, observed := run(ctx, "systemctl", "daemon-reload")
	if !observed || code != 0 || !a.officialRenewalRoute() {
		return false
	}
	for _, path := range []string{RenewalEvidencePath, RenewalEvidenceNextPath} {
		if err := os.Remove(a.path(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false
		}
		if a.syncOwnershipDirectory(a.path(filepath.Dir(path))) != nil {
			return false
		}
	}
	for _, path := range []string{RenewalAdmissionPath, RenewalWriterPath} {
		if err := os.Remove(a.path(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	if a.syncOwnershipDirectory(a.path(filepath.Dir(RenewalAdmissionPath))) != nil {
		return false
	}
	return true
}

func (a Adapter) renewalEntryPointsAbsent() bool {
	return a.safelyAbsent(RenewalDropInPath) && a.safelyAbsent(RenewalDeployHookPath) && a.safelyAbsent(RenewalPostHookPath)
}

func (a Adapter) renewalFilesSafeForRemoval(authority RenewalAuthority) bool {
	if !authority.Valid() || !a.safelyAbsent(RenewalEvidenceNextPath) {
		return false
	}
	for _, file := range renewalManagedFiles {
		body, err := a.protectedServingFile(file.path, file.mode, "")
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || string(body) != file.body {
			return false
		}
	}
	if a.safelyAbsent(RenewalEvidencePath) {
		return true
	}
	_, _, err := a.readRenewalEvidence(authority)
	return err == nil
}

func (a Adapter) RenewalIntegrationAbsent(authority RenewalAuthority) bool {
	for _, resource := range authority.Resources() {
		if !a.safelyAbsent(strings.SplitN(resource, " ", 2)[0]) {
			return false
		}
	}
	return a.safelyAbsent(RenewalEvidenceNextPath)
}
