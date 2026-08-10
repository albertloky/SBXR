package ubuntu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"syscall"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

const (
	maxInstallHandoffBytes = int64((softwarelifecycle.MaxAssetBytes*2*4)/3 + softwarelifecycle.MaxIndexBytes)
	installReady           = "READY\n"
	installApply           = "APPLY\n"
	installDone            = "DONE\n"
	installKeep            = "KEEP\n"
	installCancel          = "CANCEL\n"
	installCompleted       = "C\n"
	installRolledBack      = "R\n"
	installRecovery        = "X\n"
)

var (
	handoffTag        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	handoffCloudflare = regexp.MustCompile(`^[0-9a-f]{32}$`)
	handoffToken      = regexp.MustCompile(`^cfat_[A-Za-z0-9_-]{35,75}$`)
	handoffHostname   = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// InstallHandoffRequest is the one typed request allowed across the private
// inherited Unix socket. It contains no command, path, script, or operation.
type InstallHandoffRequest struct {
	Schema              int                                       `json:"schema"`
	Session             string                                    `json:"session"`
	Tag                 string                                    `json:"tag"`
	Architecture        softwarelifecycle.Architecture            `json:"architecture"`
	Draft               softwarelifecycle.InstallationDraft       `json:"draft"`
	CloudflareAccountID string                                    `json:"cloudflare_account_id"`
	CloudflareZoneID    string                                    `json:"cloudflare_zone_id"`
	CloudflareToken     string                                    `json:"cloudflare_token"`
	RealityTarget       string                                    `json:"reality_target"`
	RealityServerName   string                                    `json:"reality_server_name"`
	ReviewedPlanSHA256  string                                    `json:"reviewed_plan_sha256"`
	Entropy             []byte                                    `json:"entropy"`
	Candidate           softwarelifecycle.InstallCandidateHandoff `json:"candidate"`
}

func (InstallHandoffRequest) String() string {
	return "Software Lifecycle install handoff: protected"
}
func (InstallHandoffRequest) GoString() string {
	return "Software Lifecycle install handoff: protected"
}

type InstallApplyOutcome uint8

const (
	InstallCompleted InstallApplyOutcome = iota + 1
	InstallRolledBack
	InstallRecoveryRequired
)

type InstallApplyPreparer func(context.Context, InstallHandoffRequest) (func() InstallApplyOutcome, error)
type installProcessVerifier func(*os.File, *os.File) error
type installProcessStarter func(context.Context, *os.File, *os.File) (func() error, error)

func validInstallHandoffRequest(request InstallHandoffRequest) bool {
	host, port, err := net.SplitHostPort(request.RealityTarget)
	return request.Schema == 1 && validLowerHex(request.Session, 64) && handoffTag.MatchString(request.Tag) &&
		(request.Architecture == softwarelifecycle.AMD64 || request.Architecture == softwarelifecycle.ARM64) && request.Draft.Valid() &&
		handoffCloudflare.MatchString(request.CloudflareAccountID) && handoffCloudflare.MatchString(request.CloudflareZoneID) && handoffToken.MatchString(request.CloudflareToken) &&
		err == nil && port == "443" && host == request.RealityServerName && handoffHostname.MatchString(host) && validLowerHex(request.ReviewedPlanSHA256, 64) &&
		len(request.Entropy) == 32 && !bytes.Equal(request.Entropy, make([]byte, 32)) &&
		request.Candidate.Valid() && request.Candidate.Staged.Architecture == request.Architecture && request.Candidate.Staged.Identity.Tag == request.Tag
}

func validLowerHex(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return len(value) == size && err == nil && hex.EncodeToString(decoded) == value
}

func encodeInstallHandoffRequest(request InstallHandoffRequest) ([]byte, error) {
	if !validInstallHandoffRequest(request) {
		return nil, errors.New("install handoff request refused")
	}
	body, err := json.Marshal(request)
	if err != nil || int64(len(body)) > maxInstallHandoffBytes {
		return nil, errors.New("install handoff request refused")
	}
	return body, nil
}

func decodeInstallHandoffRequest(body []byte) (InstallHandoffRequest, error) {
	if len(body) == 0 || int64(len(body)) > maxInstallHandoffBytes || softwarelifecycle.ValidateUniqueJSON(body) != nil {
		return InstallHandoffRequest{}, errors.New("install handoff request refused")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var request InstallHandoffRequest
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validInstallHandoffRequest(request) {
		return InstallHandoffRequest{}, errors.New("install handoff request refused")
	}
	return request, nil
}

func writeInstallHandoffRequest(socket *os.File, request InstallHandoffRequest) error {
	body, err := encodeInstallHandoffRequest(request)
	if err != nil {
		return err
	}
	header := make([]byte, 8)
	binary.BigEndian.PutUint64(header, uint64(len(body)))
	if written, err := socket.Write(header); err != nil || written != len(header) {
		return errors.New("install handoff unavailable")
	}
	if written, err := socket.Write(body); err != nil || written != len(body) {
		return errors.New("install handoff unavailable")
	}
	return nil
}

func serveInstallApply(ctx context.Context, socket, executable *os.File, verify installProcessVerifier, prepare InstallApplyPreparer) error {
	if ctx == nil || socket == nil || executable == nil || verify == nil || prepare == nil || verify(socket, executable) != nil {
		return errors.New("privileged install process refused")
	}
	request, err := readInstallHandoffRequest(socket)
	if err != nil {
		return err
	}
	if err := verifyInstallExecutableCandidate(executable, request.Candidate.Staged); err != nil {
		return err
	}
	applyContext, cancel := context.WithCancel(ctx)
	defer cancel()
	apply, err := prepare(applyContext, request)
	if err != nil || apply == nil {
		return errors.New("privileged install preparation refused")
	}
	if written, err := socket.Write([]byte(installReady)); err != nil || written != len(installReady) {
		return errors.New("install handoff unavailable")
	}
	approval := make([]byte, len(installApply)+len(installDone))
	if _, err := io.ReadFull(socket, approval); err != nil || string(approval[:len(installApply)]) != installApply || string(approval[len(installApply):]) != installDone && string(approval[len(installApply):]) != installKeep {
		return errors.New("final install approval unavailable")
	}
	if string(approval[len(installApply):]) == installKeep {
		go func() {
			message, err := io.ReadAll(io.LimitReader(socket, int64(len(installCancel)+1)))
			if err == nil && string(message) == installCancel {
				cancel()
			}
		}()
	}
	if applyContext.Err() != nil {
		return applyContext.Err()
	}
	outcome := apply()
	terminal := map[InstallApplyOutcome]string{InstallCompleted: installCompleted, InstallRolledBack: installRolledBack, InstallRecoveryRequired: installRecovery}[outcome]
	if terminal == "" {
		return errors.New("privileged install result unavailable")
	}
	if written, err := socket.Write([]byte(terminal)); err != nil || written != len(terminal) {
		return errors.New("install handoff unavailable")
	}
	return nil
}

func readInstallHandoffRequest(reader io.Reader) (InstallHandoffRequest, error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(reader, header); err != nil {
		return InstallHandoffRequest{}, errors.New("install handoff unavailable")
	}
	size := binary.BigEndian.Uint64(header)
	if size == 0 || size > uint64(maxInstallHandoffBytes) {
		return InstallHandoffRequest{}, errors.New("install handoff unavailable")
	}
	body := make([]byte, int(size))
	if _, err := io.ReadFull(reader, body); err != nil {
		return InstallHandoffRequest{}, errors.New("install handoff unavailable")
	}
	return decodeInstallHandoffRequest(body)
}

// ServeInstallApply runs only inside the exact sudo child selected by cmd/sbxr.
func ServeInstallApply(ctx context.Context, prepare InstallApplyPreparer) error {
	executable := os.NewFile(3, "verified-sbxr")
	if executable == nil {
		return errors.New("verified executable descriptor unavailable")
	}
	defer executable.Close()
	return serveInstallApply(ctx, os.Stdin, executable, verifyInstallApplyProcess, prepare)
}

// LaunchInstallApply performs the only supported privilege transition after
// the Owner has reviewed the exact Plan represented by request.
func LaunchInstallApply(ctx context.Context, request InstallHandoffRequest) (InstallApplyOutcome, error) {
	executable, err := openVerifiedInstallExecutable(request.Candidate.Staged)
	if err != nil {
		return 0, err
	}
	defer executable.Close()
	return launchInstallApplyWithCancellation(ctx, request, executable, startInstallApplyProcess, nil)
}

func LaunchInstallApplyWithCancellation(ctx context.Context, request InstallHandoffRequest, cancellation <-chan struct{}) (InstallApplyOutcome, error) {
	executable, err := openVerifiedInstallExecutable(request.Candidate.Staged)
	if err != nil {
		return 0, err
	}
	defer executable.Close()
	return launchInstallApplyWithCancellation(ctx, request, executable, startInstallApplyProcess, cancellation)
}

func verifyInstallExecutableCandidate(executable *os.File, staged softwarelifecycle.StagedRelease) error {
	if executable == nil {
		return errors.New("install executable unavailable")
	}
	info, err := executable.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		return errors.New("install executable unavailable")
	}
	metadata, _, err := softwarelifecycle.ReadPayloadMetadata(executable, info.Size())
	digest := sha256.New()
	_, digestErr := io.Copy(digest, io.NewSectionReader(executable, 0, info.Size()))
	if err != nil || digestErr != nil || metadata.Build != staged.Build || metadata.Architecture != staged.Architecture || metadata.StateSchema != staged.StateSchema || hex.EncodeToString(digest.Sum(nil)) != staged.ExecutableSHA256 {
		return errors.New("install executable does not match reviewed candidate")
	}
	return nil
}

func launchInstallApply(ctx context.Context, request InstallHandoffRequest, executable *os.File, start installProcessStarter) (InstallApplyOutcome, error) {
	return launchInstallApplyWithCancellation(ctx, request, executable, start, nil)
}

func launchInstallApplyWithCancellation(ctx context.Context, request InstallHandoffRequest, executable *os.File, start installProcessStarter, cancellation <-chan struct{}) (InstallApplyOutcome, error) {
	if ctx == nil || executable == nil || start == nil || !validInstallHandoffRequest(request) {
		return 0, errors.New("privileged install launch refused")
	}
	descriptors, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return 0, errors.New("private install socket unavailable")
	}
	parent := os.NewFile(uintptr(descriptors[0]), "sbxr-install-parent")
	child := os.NewFile(uintptr(descriptors[1]), "sbxr-install-child")
	defer parent.Close()
	wait, err := start(ctx, child, executable)
	child.Close()
	if err != nil {
		return 0, errors.New("ordinary system sudo failed")
	}
	if err := writeInstallHandoffRequest(parent, request); err != nil {
		return 0, err
	}
	ready := make([]byte, len(installReady))
	if _, err := io.ReadFull(parent, ready); err != nil || string(ready) != installReady {
		return 0, errors.New("privileged install recheck failed")
	}
	mode := installDone
	if cancellation != nil {
		mode = installKeep
	}
	approval := installApply + mode
	if written, err := parent.Write([]byte(approval)); err != nil || written != len(approval) {
		return 0, errors.New("final install approval unavailable")
	}
	readOutcome := func() (InstallApplyOutcome, error) {
		terminal := make([]byte, len(installCompleted))
		if _, err := io.ReadFull(parent, terminal); err != nil {
			return 0, errors.New("privileged install result unavailable")
		}
		switch string(terminal) {
		case installCompleted:
			return InstallCompleted, nil
		case installRolledBack:
			return InstallRolledBack, nil
		case installRecovery:
			return InstallRecoveryRequired, nil
		default:
			return 0, errors.New("privileged install result unavailable")
		}
	}
	if cancellation == nil {
		if err := syscall.Shutdown(int(parent.Fd()), syscall.SHUT_WR); err != nil {
			return 0, errors.New("final install approval unavailable")
		}
		outcome, outcomeErr := readOutcome()
		if err := wait(); err != nil {
			return 0, errors.New("privileged install failed")
		}
		return outcome, outcomeErr
	}
	done := make(chan struct {
		outcome InstallApplyOutcome
		err     error
	}, 1)
	go func() {
		outcome, outcomeErr := readOutcome()
		waitErr := wait()
		if waitErr != nil {
			outcome, outcomeErr = 0, errors.New("privileged install failed")
		}
		done <- struct {
			outcome InstallApplyOutcome
			err     error
		}{outcome, outcomeErr}
	}()
	select {
	case result := <-done:
		return result.outcome, result.err
	case <-cancellation:
		if written, err := parent.Write([]byte(installCancel)); err != nil || written != len(installCancel) {
			return 0, errors.New("install cancellation request unavailable")
		}
		if err := syscall.Shutdown(int(parent.Fd()), syscall.SHUT_WR); err != nil {
			return 0, errors.New("install cancellation request unavailable")
		}
		result := <-done
		return result.outcome, result.err
	case <-ctx.Done():
		return 0, errors.New("final install approval unavailable")
	}
}

func startInstallApplyProcess(ctx context.Context, socket, executable *os.File) (func() error, error) {
	command := installApplyCommand(ctx, socket, executable)
	if err := command.Start(); err != nil {
		return nil, err
	}
	return command.Wait, nil
}

func installApplyCommand(ctx context.Context, socket, executable *os.File) *exec.Cmd {
	command := exec.CommandContext(ctx, "/usr/bin/sudo", "--preserve-fds=3", "--", "/proc/self/fd/3", "private", "install-apply")
	command.Stdin, command.Stdout, command.Stderr = socket, os.Stdout, os.Stderr
	command.ExtraFiles = []*os.File{executable}
	return command
}
