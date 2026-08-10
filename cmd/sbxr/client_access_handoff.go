package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

const maxClientAccessHandoffBytes = 16 << 10

type clientAccessHandoffRequest struct {
	Schema    int                `json:"schema"`
	Mode      string             `json:"mode"`
	Action    clientAccessAction `json:"action"`
	Profile   string             `json:"profile,omitempty"`
	ChangeSet string             `json:"change_set"`
}

func (clientAccessHandoffRequest) String() string { return "Client Access handoff request: protected" }
func (clientAccessHandoffRequest) GoString() string {
	return "Client Access handoff request: protected"
}

type clientAccessHandoffReview struct {
	Identity, SHA256, DesiredStateSHA256, VolatileSHA256 string
	StartingRevision, CandidateRevision                  uint64
	TotalSteps                                           uint16
}

type clientAccessRecoveryResult struct {
	Status systemchanges.InstallationStatus
}

type clientAccessHandoffSession struct {
	mu     sync.Mutex
	socket *os.File
	wait   func() error
	used   bool
	review clientAccessHandoffReview
}

func validClientAccessHandoff(request clientAccessHandoffRequest) bool {
	if request.Schema != 1 || request.Mode != "change" && request.Mode != "view" && request.Mode != "recover" {
		return false
	}
	if request.Mode == "view" {
		return request.Action == "" && request.Profile == "" && request.ChangeSet == ""
	}
	if !validClientAccessChangeSet(request.ChangeSet) {
		return false
	}
	if request.Mode == "recover" {
		return request.Action == "" && request.Profile == ""
	}
	if !validClientAccessAction(request.Action) {
		return false
	}
	profile := connectionprofiles.ProfileID(request.Profile)
	profileAction := request.Action == clientAccessEnableProfile || request.Action == clientAccessDisableProfile || request.Action == clientAccessRotateProfile
	if !profileAction {
		return request.Profile == ""
	}
	switch profile {
	case connectionprofiles.VLESSRealityVisionProfileID, connectionprofiles.VLESSXHTTPProfileID, connectionprofiles.VLESSWebSocketProfileID, connectionprofiles.Hysteria2ProfileID, connectionprofiles.TUICProfileID, connectionprofiles.AnyTLSProfileID:
		return true
	default:
		return false
	}
}

func validClientAccessChangeSet(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func writeClientAccessMessage(writer io.Writer, value any) error {
	body, err := json.Marshal(value)
	if err != nil || len(body) == 0 || len(body) > maxClientAccessHandoffBytes {
		return errors.New("Client Access handoff refused")
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(body)))
	if _, err = io.Copy(writer, bytes.NewReader(append(header, body...))); err != nil {
		return errors.New("Client Access handoff unavailable")
	}
	return nil
}

func readClientAccessMessage(reader io.Reader, value any) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return errors.New("Client Access handoff unavailable")
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 || size > maxClientAccessHandoffBytes {
		return errors.New("Client Access handoff refused")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(reader, body); err != nil || softwarelifecycle.ValidateUniqueJSON(body) != nil {
		return errors.New("Client Access handoff refused")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("Client Access handoff refused")
	}
	return nil
}

func serveClientAccess(ctx context.Context, socket, executable *os.File, verify func(*os.File, *os.File) error) error {
	if ctx == nil || socket == nil || executable == nil || verify == nil || verify(socket, executable) != nil {
		return errors.New("privileged Client Access process refused")
	}
	var request clientAccessHandoffRequest
	if readClientAccessMessage(socket, &request) != nil || !validClientAccessHandoff(request) {
		return errors.New("Client Access request refused")
	}
	if request.Mode == "view" {
		presentation, err := managedClientAccessPresentation(ctx)
		if err != nil {
			return err
		}
		return writeClientAccessMessage(socket, presentation)
	}
	if request.Mode == "recover" {
		entries, err := os.ReadDir(installTransactions)
		if err != nil || len(entries) != 1 || entries[0].Name() != request.ChangeSet {
			return errors.New("Client Access recovery request refused")
		}
		if _, err := systemubuntu.RecoveryStartingStatus("/"); err != nil || runInstallRecovery(recoveryCertbotPath) != nil {
			return errors.New("Client Access recovery failed")
		}
		observed, err := installRecoveryObservation()
		pending, pendingErr := pendingInstallRecovery()
		status := systemchanges.InstallationStatus("")
		if err == nil && pendingErr == nil && !pending && (observed.Status == systemchanges.Managed || observed.Status == systemchanges.NotInstalled) {
			status = observed.Status
		}
		return writeClientAccessMessage(socket, clientAccessRecoveryResult{Status: status})
	}
	disk := systemchanges.DiskRequirement{PreparationBytes: 8 << 20, TemporaryBytes: 8 << 20, SnapshotBytes: 32 << 20, JournalBytes: 8 << 20, RollbackBytes: 8 << 20, OverheadBytes: 256 << 20}
	built, module, err := prepareManagedClientAccess(ctx, clientAccessBuildRequest{Action: request.Action, Profile: connectionprofiles.ProfileID(request.Profile), ChangeSet: request.ChangeSet, Disk: disk})
	if err != nil {
		return err
	}
	review := clientAccessHandoffReview{Identity: built.plan.Identity(), SHA256: built.plan.SHA256(), DesiredStateSHA256: built.candidateSHA, VolatileSHA256: built.volatileSHA, StartingRevision: built.starting.Revision, CandidateRevision: built.starting.Revision + 1, TotalSteps: uint16(built.totalSteps)}
	if writeClientAccessMessage(socket, review) != nil {
		return errors.New("Client Access review unavailable")
	}
	approval := make([]byte, 6)
	if _, err := io.ReadFull(socket, approval); err != nil || string(approval) != "APPLY\n" {
		return errors.New("Client Access approval unavailable")
	}
	result := applyClientAccess(ctx, built, module)
	terminal := byte('X')
	if result.Outcome == systemchanges.Completed {
		terminal = 'C'
	} else if result.Outcome == systemchanges.RollbackSucceeded {
		terminal = 'R'
	}
	_, err = socket.Write([]byte{terminal})
	return err
}

func retryClientAccessRecovery(ctx context.Context, changeSet string) (systemchanges.InstallationStatus, error) {
	request := clientAccessHandoffRequest{Schema: 1, Mode: "recover", ChangeSet: changeSet}
	if ctx == nil || !validClientAccessHandoff(request) {
		return "", errors.New("Client Access recovery launch refused")
	}
	executable, err := openCurrentClientAccessExecutable()
	if err != nil {
		return "", err
	}
	parent, wait, err := startClientAccessProcess(ctx, executable)
	executable.Close()
	if err != nil {
		return "", err
	}
	defer wait()
	defer parent.Close()
	if writeClientAccessMessage(parent, request) != nil {
		return "", errors.New("Client Access recovery unavailable")
	}
	var result clientAccessRecoveryResult
	if readClientAccessMessage(parent, &result) != nil || result.Status != systemchanges.Managed && result.Status != systemchanges.NotInstalled {
		return "", errors.New("Client Access recovery did not prove a terminal installation status")
	}
	return result.Status, nil
}

func launchClientAccessReview(ctx context.Context, request clientAccessHandoffRequest) (*clientAccessHandoffSession, error) {
	if ctx == nil || !validClientAccessHandoff(request) {
		return nil, errors.New("Client Access launch refused")
	}
	executable, err := openCurrentClientAccessExecutable()
	if err != nil {
		return nil, err
	}
	parent, wait, err := startClientAccessProcess(ctx, executable)
	executable.Close()
	if err != nil {
		return nil, err
	}
	if err := writeClientAccessMessage(parent, request); err != nil {
		parent.Close()
		_ = wait()
		return nil, err
	}
	var review clientAccessHandoffReview
	if err := readClientAccessMessage(parent, &review); err != nil || review.Identity == "" || len(review.SHA256) != 64 || len(review.DesiredStateSHA256) != 64 || len(review.VolatileSHA256) != 64 || review.CandidateRevision != review.StartingRevision+1 || review.TotalSteps == 0 {
		parent.Close()
		_ = wait()
		return nil, errors.New("privileged Client Access review unavailable")
	}
	return &clientAccessHandoffSession{socket: parent, wait: wait, review: review}, nil
}

func loadClientAccessPresentation(ctx context.Context) clientAccessPresentation {
	request := clientAccessHandoffRequest{Schema: 1, Mode: "view"}
	executable, err := openCurrentClientAccessExecutable()
	if err != nil {
		return clientAccessPresentation{}
	}
	parent, wait, err := startClientAccessProcess(ctx, executable)
	executable.Close()
	if err != nil {
		return clientAccessPresentation{}
	}
	defer wait()
	defer parent.Close()
	if writeClientAccessMessage(parent, request) != nil {
		return clientAccessPresentation{}
	}
	var presentation clientAccessPresentation
	if readClientAccessMessage(parent, &presentation) != nil || wait() != nil {
		return clientAccessPresentation{}
	}
	return presentation
}

func (session *clientAccessHandoffSession) discard() {
	if session == nil {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.used {
		return
	}
	session.used = true
	if session.socket != nil {
		_ = session.socket.Close()
	}
	if session.wait != nil {
		_ = session.wait()
	}
}

func (session *clientAccessHandoffSession) apply() (byte, error) {
	if session == nil {
		return 0, errors.New("Client Access review is unavailable")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.used || session.socket == nil || session.wait == nil {
		return 0, errors.New("Client Access review is unavailable")
	}
	session.used = true
	defer session.socket.Close()
	if _, err := session.socket.Write([]byte("APPLY\n")); err != nil {
		return 0, err
	}
	terminal := []byte{0}
	_, readErr := io.ReadFull(session.socket, terminal)
	waitErr := session.wait()
	if readErr != nil || waitErr != nil || terminal[0] != 'C' && terminal[0] != 'R' && terminal[0] != 'X' {
		return 0, errors.New("privileged Client Access result unavailable")
	}
	return terminal[0], nil
}

func servePrivateClientAccess(ctx context.Context) error {
	executable := os.NewFile(3, "verified-sbxr")
	if executable == nil {
		return errors.New("verified executable descriptor unavailable")
	}
	defer executable.Close()
	return serveClientAccess(ctx, os.Stdin, executable, verifyClientAccessProcess)
}
