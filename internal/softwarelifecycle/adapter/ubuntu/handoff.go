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
	Candidate           softwarelifecycle.InstallCandidateHandoff `json:"candidate"`
}

func (InstallHandoffRequest) String() string {
	return "Software Lifecycle install handoff: protected"
}
func (InstallHandoffRequest) GoString() string {
	return "Software Lifecycle install handoff: protected"
}

type InstallApplyPreparer func(context.Context, InstallHandoffRequest) (func() error, error)
type installProcessVerifier func(*os.File, *os.File) error
type installProcessStarter func(context.Context, *os.File, *os.File) (func() error, error)

func validInstallHandoffRequest(request InstallHandoffRequest) bool {
	host, port, err := net.SplitHostPort(request.RealityTarget)
	return request.Schema == 1 && validLowerHex(request.Session, 64) && handoffTag.MatchString(request.Tag) &&
		(request.Architecture == softwarelifecycle.AMD64 || request.Architecture == softwarelifecycle.ARM64) && request.Draft.Valid() &&
		handoffCloudflare.MatchString(request.CloudflareAccountID) && handoffCloudflare.MatchString(request.CloudflareZoneID) && handoffToken.MatchString(request.CloudflareToken) &&
		err == nil && port == "443" && host == request.RealityServerName && handoffHostname.MatchString(host) && validLowerHex(request.ReviewedPlanSHA256, 64) &&
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
	apply, err := prepare(ctx, request)
	if err != nil || apply == nil {
		return errors.New("privileged install preparation refused")
	}
	if written, err := socket.Write([]byte(installReady)); err != nil || written != len(installReady) {
		return errors.New("install handoff unavailable")
	}
	approval, err := io.ReadAll(io.LimitReader(socket, int64(len(installApply)+1)))
	if err != nil || string(approval) != installApply {
		return errors.New("final install approval unavailable")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return apply()
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
func LaunchInstallApply(ctx context.Context, request InstallHandoffRequest) error {
	executable, err := openVerifiedInstallExecutable(request.Candidate.Staged)
	if err != nil {
		return err
	}
	defer executable.Close()
	return launchInstallApply(ctx, request, executable, startInstallApplyProcess)
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

func launchInstallApply(ctx context.Context, request InstallHandoffRequest, executable *os.File, start installProcessStarter) error {
	if ctx == nil || executable == nil || start == nil || !validInstallHandoffRequest(request) {
		return errors.New("privileged install launch refused")
	}
	descriptors, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return errors.New("private install socket unavailable")
	}
	parent := os.NewFile(uintptr(descriptors[0]), "sbxr-install-parent")
	child := os.NewFile(uintptr(descriptors[1]), "sbxr-install-child")
	defer parent.Close()
	wait, err := start(ctx, child, executable)
	child.Close()
	if err != nil {
		return errors.New("ordinary system sudo failed")
	}
	if err := writeInstallHandoffRequest(parent, request); err != nil {
		return err
	}
	ready := make([]byte, len(installReady))
	if _, err := io.ReadFull(parent, ready); err != nil || string(ready) != installReady {
		return errors.New("privileged install recheck failed")
	}
	if written, err := parent.Write([]byte(installApply)); err != nil || written != len(installApply) {
		return errors.New("final install approval unavailable")
	}
	if err := syscall.Shutdown(int(parent.Fd()), syscall.SHUT_WR); err != nil {
		return errors.New("final install approval unavailable")
	}
	if err := wait(); err != nil {
		return errors.New("privileged install failed")
	}
	return nil
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
